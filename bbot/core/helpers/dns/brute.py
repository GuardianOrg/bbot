import json
import os
import random
import asyncio
import logging
import sqlite3
import subprocess
import threading
import time
from collections import Counter
from itertools import islice
from .resolvers import ResolverPool
from bbot.errors import DNSError


class DNSQueryLedger:
    """Exact, disk-backed deduplication for scans without a query count limit."""

    def __init__(self):
        # An empty filename creates a temporary on-disk database, deleted on close.
        self.connection = sqlite3.connect("", check_same_thread=False, isolation_level=None)
        self.connection.execute("PRAGMA cache_size=-8192")
        self.connection.execute("PRAGMA journal_mode=OFF")
        self.connection.execute("PRAGMA synchronous=OFF")
        self.connection.execute(
            "CREATE TABLE queries (hostname TEXT NOT NULL, rdtype TEXT NOT NULL, "
            "PRIMARY KEY (hostname, rdtype)) WITHOUT ROWID"
        )
        self.lock = threading.Lock()
        self.count = 0

    def __contains__(self, key):
        with self.lock:
            return self.connection.execute(
                "SELECT 1 FROM queries WHERE hostname=? AND rdtype=?", key
            ).fetchone() is not None

    def add(self, key):
        with self.lock:
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO queries (hostname, rdtype) VALUES (?, ?)", key
            )
            self.count += cursor.rowcount
            return cursor.rowcount == 1

    def update(self, keys):
        for key in keys:
            self.add(key)

    def __len__(self):
        return self.count

    def __del__(self):
        connection = getattr(self, "connection", None)
        if connection is not None:
            connection.close()


class DNSBrute:
    """
    Helper for DNS brute-forcing.

    Examples:
    >>> domain = "evilcorp.com"
    >>> subdomains = ["www", "mail"]
    >>> results = await self.helpers.dns.brute(self, domain, subdomains)
    """

    _nameservers_url = (
        "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
    )

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.log = logging.getLogger("bbot.helper.dns.brute")
        self.dns_config = self.parent_helper.config.get("dns", {})
        self.num_canaries = 100
        self.max_resolvers = int(self.dns_config.get("brute_threads", 1000))
        if self.max_resolvers <= 0:
            raise ValueError("dns.brute_threads must be positive")
        self.nameservers_url = self.dns_config.get("brute_nameservers", "")
        self.devops_mutations = list(self.parent_helper.word_cloud.devops_mutations)
        self.digit_regex = self.parent_helper.re.compile(r"\d+")
        self._resolver_file = None
        self._dnsbrute_lock = None
        self.parallel_batches = int(self.dns_config.get("brute_parallel_batches", 2))
        self.per_resolver_threads = int(self.dns_config.get("brute_threads_per_resolver", 50))
        if not 0 < self.parallel_batches <= 4 or not 0 < self.per_resolver_threads <= 100:
            raise ValueError("DNS parallel batches must be 1..4 and per-resolver concurrency 1..100")
        # Concurrency halves on a batch with many transport errors and climbs back after clean ones,
        # never above the configured value.
        self.max_per_resolver_threads = self.per_resolver_threads
        self.concurrency_cuts = 0
        self.concurrency_raises = 0
        self.resolver_pool = ResolverPool()
        self.transport_failures = 0
        self.transport_retries = 0
        self.transport_retry_failures = 0
        self.transport_unretried = 0
        # Bounded extra massdns passes over names without a DNS answer. Names still unanswered after
        # them are kept in ``unanswered`` as (name, rdtype) so callers never count them as checked.
        self.transport_retry_passes = int(self.dns_config.get("brute_transport_retry_passes", 3))
        if not 0 <= self.transport_retry_passes <= 5:
            raise ValueError("dns.brute_transport_retry_passes must be 0..5")
        self.unanswered = set()
        self.unanswered_queries = 0
        # A massdns process silent for this long is killed; its unfinished names stay unanswered.
        self.stall_timeout = float(self.dns_config.get("brute_stall_timeout", 180))
        if not 1 <= self.stall_timeout <= 3600:
            raise ValueError("dns.brute_stall_timeout must be 1..3600 seconds")
        self.stalls = 0
        # Final response codes of brute-forced names; REFUSED after massdns' own retries signals rate limiting.
        self.response_status = Counter()
        self.started = None
        self._resolver_lock = asyncio.Lock()
        self.max_candidates = int(self.dns_config.get("brute_max_candidates", 400000))
        if self.max_candidates < 0:
            raise ValueError("dns.brute_max_candidates must be nonnegative (0 means unlimited)")
        # Exact keys are shared by every brute/permutation module in this scan.
        self.queries_tried = DNSQueryLedger() if self.max_candidates == 0 else set()
        self._budget_reported = False
        self.max_runtime = float(self.dns_config.get("brute_max_runtime", 7200))
        if not 0 < self.max_runtime < float("inf"):
            raise ValueError("dns.brute_max_runtime must be finite and positive")
        self.deadline = None
        self.strategy_queries = Counter()
        self.strategy_results = {}
        self.strategy_seconds = Counter()
        active = set(self.parent_helper.preset.scan_modules)
        self.reservations = {} if self.max_candidates == 0 else {
            name: min(amount, self.max_candidates // 4)
            for name, amount in (("dnsgen", 40000), ("dnsdepth", 4000))
            if name in active
        }
        self.reservations_released = asyncio.Event()
        if not self.reservations:
            self.reservations_released.set()
        self.wildcard_deadline = None
        self.wildcard_candidates = Counter()
        self.wildcard_verified_names = set()
        self.wildcard_domains = set()
        self.wildcard_limits = {}
        for key, default in (("max_candidates", 100), ("max_domains", 20), ("max_results", 50), ("max_runtime", 60)):
            value = float(self.dns_config.get(f"brute_wildcard_{key}", default))
            if not 0 < value < float("inf"):
                raise ValueError(f"dns.brute_wildcard_{key} must be finite and positive")
            self.wildcard_limits[key] = value

    async def __call__(self, *args, **kwargs):
        return await self.dnsbrute(*args, **kwargs)

    @property
    def dnsbrute_lock(self):
        if self._dnsbrute_lock is None:
            self._dnsbrute_lock = asyncio.Semaphore(self.parallel_batches)
        return self._dnsbrute_lock

    def remaining_candidates(self, module):
        if self.max_candidates == 0:
            return None
        name = getattr(module, "name", str(module))
        held = sum(
            max(0, amount - self.strategy_queries[strategy])
            for strategy, amount in self.reservations.items()
            if strategy != name
        )
        return max(0, self.max_candidates - len(self.queries_tried) - held)

    def claim(self, module, key):
        if self.max_candidates and not self.remaining_candidates(module):
            return False
        if self.max_candidates:
            if key in self.queries_tried:
                return False
            self.queries_tried.add(key)
        elif not self.queries_tried.add(key):
            return False
        self.strategy_queries[getattr(module, "name", str(module))] += 1
        return True

    def release_reservation(self, name):
        self.reservations.pop(name, None)
        if not self.reservations:
            self.reservations_released.set()

    def metrics(self):
        return {
            name: {
                "queries": count,
                "names": len(self.strategy_results.get(name, ())),
                "call_seconds": round(self.strategy_seconds[name], 3),
            }
            for name, count in self.strategy_queries.items()
        }

    def resolver_metrics(self):
        return {
            "transport_failures": self.transport_failures,
            "transport_retry_failures": self.transport_retry_failures,
            "transport_unretried": self.transport_unretried,
            "unanswered_queries": self.unanswered_queries,
            "massdns_stalls": self.stalls,
            "servfail": self.response_status["SERVFAIL"],
            "refused": self.response_status["REFUSED"],
            "answered": sum(self.response_status.values()),
            "concurrency_cuts": self.concurrency_cuts,
            "concurrency_raises": self.concurrency_raises,
            "per_resolver_threads": self.per_resolver_threads,
        }

    async def dnsbrute(self, module, domain, subdomains, type=None, timeout=None):
        if self.started is None:
            self.started = time.monotonic()
        if self.deadline is None:
            self.deadline = time.monotonic() + self.max_runtime
        remaining = self.deadline - time.monotonic()
        if timeout is not None:
            remaining = min(remaining, timeout)
        if remaining <= 0:
            self.log.info("DNS brute-force stopped at its shared runtime deadline")
            return []
        started = time.monotonic()
        name = getattr(module, "name", str(module))
        try:
            results = await asyncio.wait_for(self._dnsbrute(module, domain, subdomains, type, remaining), remaining)
            self.strategy_results.setdefault(name, set()).update(results)
            return results
        except asyncio.TimeoutError:
            self.log.info("DNS brute-force reached its runtime budget; subprocess work cancelled")
            return []
        finally:
            self.strategy_seconds[name] += time.monotonic() - started

    async def _dnsbrute(self, module, domain, subdomains, type=None, timeout=None):
        domain = str(domain).lower().rstrip(".")

        if type is None:
            type = "A"
        type = str(type).strip().upper()

        if self.remaining_candidates(module) == 0:
            if not self._budget_reported:
                self.log.info(
                    f"DNS brute-force stopped at its scan-wide budget of {self.max_candidates:,} candidate queries"
                )
                self._budget_reported = True
            return []

        try:
            # The DNS engine reply has no deadline of its own; never let one parent hang the batch.
            wildcard_domains = await asyncio.wait_for(
                self.parent_helper.dns.is_wildcard_domain(domain, (type, "CNAME")), self.stall_timeout
            )
        except asyncio.TimeoutError:
            # The canaries sandwiching every batch still reject a wildcard parent.
            self.log.warning(f"Wildcard check of {domain} took over {self.stall_timeout:.0f}s; relying on canaries")
            wildcard_domains = {}
        wildcard_rdtypes = set()
        for wildcard_domain, rdtypes in wildcard_domains.items():
            wildcard_rdtypes.update(rdtypes)
        if wildcard_domains:
            return await self._wildcard_brute(module, domain, subdomains, type)

        # Claim after the wildcard await, without yielding, so concurrent modules cannot
        # submit the same full name/type through different parents or batches.
        selected = []
        for prefix in subdomains:
            prefix = str(prefix).lower().rstrip(".")
            hostname = f"{prefix}.{domain}" if domain else prefix
            key = (hostname, type)
            if key in self.queries_tried:
                continue
            if not self.claim(module, key):
                break
            selected.append(prefix)
        if not selected:
            return []

        canaries_list = list(self.gen_random_subdomains(self.num_canaries))
        canary_set = set(canaries_list)
        canaries_pre = canaries_list[: int(self.num_canaries / 2)]
        canaries_post = canaries_list[int(self.num_canaries / 2) :]
        # sandwich subdomains between canaries
        subdomains = canaries_pre + selected + canaries_post

        results = []
        canaries_triggered = []
        timeout_kwargs = {} if timeout is None else {"timeout": timeout}
        async for hostname, ip, rdtype in self._massdns(module, domain, subdomains, rdtype=type, **timeout_kwargs):
            suffix = f".{domain}"
            sub = hostname[: -len(suffix)] if hostname.endswith(suffix) else hostname
            if sub in canary_set:
                canaries_triggered.append(sub)
            else:
                results.append(hostname)

        if len(canaries_triggered) > 5:
            self.log.info(
                f"Aborting massdns on {domain} due to false positive: ({len(canaries_triggered):,} canaries triggered - {','.join(canaries_triggered)})"
            )
            return []

        # everything checks out
        if results and self.resolver_pool.selected:
            names = list(dict.fromkeys(results))
            verified = await asyncio.gather(*(self.resolver_pool.confirm(host, type) for host in names))
            results = [host for host, valid in zip(names, verified) if valid]
        return list(dict.fromkeys(results))

    async def _wildcard_brute(self, module, domain, subdomains, rdtype):
        limits = self.wildcard_limits
        if self.wildcard_deadline is None:
            self.wildcard_deadline = time.monotonic() + limits["max_runtime"]
        if time.monotonic() >= self.wildcard_deadline or len(self.wildcard_verified_names) >= limits["max_results"]:
            return []
        if domain not in self.wildcard_domains and len(self.wildcard_domains) >= limits["max_domains"]:
            return []
        self.wildcard_domains.add(domain)
        remaining = min(self.wildcard_deadline, self.deadline) - time.monotonic()
        if remaining <= 0:
            return []
        found = []
        try:
            return await asyncio.wait_for(
                self._wildcard_evidence(module, domain, subdomains, rdtype, found), remaining
            )
        except asyncio.TimeoutError:
            self.log.info("Wildcard discovery reached its bounded runtime budget")
            return found

    async def _wildcard_evidence(self, module, domain, subdomains, rdtype, results):
        types = ("CNAME", "TXT", "MX", "HTTPS", "SVCB", "NS")
        controls = [f"{prefix}.{domain}" for prefix in islice(self.gen_random_subdomains(3), 3)]

        async def evidence(host, record_type):
            response = await self.parent_helper.dns.resolve_status(host, type=record_type, timeout=1)
            if response["status"] not in ("NOERROR", "NXDOMAIN"):
                return None
            values = set()
            for record in response["answers"]:
                if record["type"] != record_type or record["owner"].lower() != host:
                    continue
                values.add(record["answer"].lower())
            return frozenset(values)

        baseline = await asyncio.gather(*(evidence(host, kind) for kind in types for host in controls))
        safe_types = {}
        for index, kind in enumerate(types):
            samples = baseline[index * 3 : index * 3 + 3]
            # Rotating/random/name-dependent control records cannot establish existence.
            if None not in samples and len(set(samples)) == 1:
                safe_types[kind] = samples[0]
        if not safe_types:
            return []
        remaining = max(0, int(self.wildcard_limits["max_candidates"]) - self.wildcard_candidates[domain])
        for prefix in islice(subdomains, remaining):
            if self.wildcard_candidates[domain] >= self.wildcard_limits["max_candidates"]:
                break
            hostname = f"{str(prefix).lower().rstrip('.')}.{domain}"
            if (hostname, rdtype) in self.queries_tried or hostname in self.wildcard_verified_names:
                continue
            if not self.claim(module, (hostname, rdtype)):
                break
            self.wildcard_candidates[domain] += 1
            first = await asyncio.gather(*(evidence(hostname, kind) for kind in safe_types))
            interesting = [
                (kind, value) for (kind, base), value in zip(safe_types.items(), first) if value and value != base
            ]
            for kind, value in interesting:
                if await evidence(hostname, kind) == value:
                    if len(self.wildcard_verified_names) >= self.wildcard_limits["max_results"]:
                        break
                    self.wildcard_verified_names.add(hostname)
                    results.append(hostname)
                    break
            if len(self.wildcard_verified_names) >= self.wildcard_limits["max_results"]:
                break
        return results

    async def _massdns(self, module, domain, subdomains, rdtype, timeout=None):
        """
        {
            "name": "www.blacklanternsecurity.com.",
            "type": "A",
            "class": "IN",
            "status": "NOERROR",
            "data": {
            "answers": [
                {
                "ttl": 3600,
                "type": "CNAME",
                "class": "IN",
                "name": "www.blacklanternsecurity.com.",
                "data": "blacklanternsecurity.github.io."
                },
                {
                "ttl": 3600,
                "type": "A",
                "class": "IN",
                "name": "blacklanternsecurity.github.io.",
                "data": "185.199.108.153"
                }
            ]
            },
            "resolver": "168.215.165.186:53"
        }
        """
        resolver_file = await self.resolver_file()
        command = (
            str(self.parent_helper.tools_dir / "massdns"),
            "-r",
            resolver_file,
            "-s",
            min(self.max_resolvers, max(1, len(self.resolver_pool.selected)) * self.per_resolver_threads),
            "-t",
            rdtype,
            "-o",
            "Je",
            "-c",
            3,
            "--verify-ip",
            "-q",
        )
        subdomains = [f"{prefix}.{domain}" if domain else prefix for prefix in subdomains]
        hosts_yielded = set()
        requested = set(subdomains)
        resolvers = max(1, len(self.resolver_pool.selected))
        started = time.monotonic()
        async with self.dnsbrute_lock:
            output, stalled = await self._run_massdns(module, command, subdomains, timeout)
            if not output and not stalled:
                self._leave_unanswered(subdomains, rdtype)
                raise DNSError("massdns failed to execute; DNS discovery results are incomplete")
            answered = set()
            failures, refused = self._read_massdns_pass(output, requested, answered)
            if stalled:
                # A killed process never reported the names it had not finished.
                failures += [name for name in subdomains if name not in answered]
            retry_names = [name for name in dict.fromkeys(failures) if name not in answered]
            self.transport_failures += len(retry_names)
            # Timeouts and refusals both mean the resolvers are shedding load.
            pressure = len(retry_names)
            if pressure > max(5, len(subdomains) // 100) and self.per_resolver_threads > 5:
                self.per_resolver_threads = max(5, self.per_resolver_threads // 2)
                self.concurrency_cuts += 1
                self.log.info(
                    f"DNS initial transport errors: {len(retry_names)}, refusals: {refused}; reducing per-resolver concurrency to {self.per_resolver_threads}"
                )
            elif (pressure <= len(subdomains) // 200
                  and self.per_resolver_threads < self.max_per_resolver_threads):
                # At most 0.5% transport errors: the resolvers keep up, so take back one step.
                self.per_resolver_threads = min(self.max_per_resolver_threads, self.per_resolver_threads + 5)
                self.concurrency_raises += 1
            # Retry every unanswered name in bounded passes, each with half the concurrency and twice
            # massdns' wait between tries of the previous one. Retry passes accept SERVFAIL as an answer;
            # only REFUSED (a resolver shedding load) is retried inside massdns.
            retried = set()
            for retry_pass in range(1, self.transport_retry_passes + 1):
                if not retry_names:
                    break
                remaining = None if timeout is None else timeout - (time.monotonic() - started)
                if remaining is not None and remaining <= 0:
                    break
                retry_command = list(command)
                retry_command[retry_command.index("-s") + 1] = min(
                    self.max_resolvers, resolvers * max(1, self.per_resolver_threads >> retry_pass)
                )
                retry_command += ["-i", 500 << retry_pass, "--retry", "REFUSED"]
                retry_output, stalled = await self._run_massdns(module, retry_command, retry_names, remaining)
                self.transport_retries += len(retry_names)
                retried.update(retry_names)
                self._read_massdns_pass(retry_output, set(retry_names), answered, first=False)
                output.extend(retry_output)
                retry_names = [name for name in retry_names if name not in answered]
                if not retry_output and not stalled:
                    self.log.warning("massdns transport retry produced no output; its names stay unanswered")
                    break
            unanswered = [name for name in subdomains if name not in answered]
            failed = set(failures)
            self.transport_retry_failures += sum(name in retried for name in unanswered)
            self.transport_unretried += sum(name in failed and name not in retried for name in unanswered)
            self._leave_unanswered(unanswered, rdtype)
            for line in output:
                try:
                    j = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.log.debug(f"Failed to decode line: {line}")
                    continue
                answers = j.get("data", {}).get("answers", [])
                if type(answers) == list and len(answers) > 0:
                    for answer in answers:
                        hostname = answer.get("name", "").strip(".").lower()
                        if not hostname.endswith(f".{domain}"):
                            continue
                        answer_type = answer.get("type", "").upper()
                        if answer_type not in {rdtype, "CNAME"}:
                            continue
                        data = answer.get("data", "")
                        if data and answer_type:
                            hostname_hash = hash((hostname, answer_type))
                            if hostname_hash not in hosts_yielded:
                                hosts_yielded.add(hostname_hash)
                                yield hostname, data, answer_type

    async def _run_massdns(self, module, command, names, timeout):
        """Run massdns over ``names``; return its output lines and whether it was killed as stalled.

        massdns is killed after ``stall_timeout`` seconds without output (or at ``timeout``), so a hung
        process costs a bounded wait. The lines it wrote before that are kept.
        """
        idle = self.stall_timeout if timeout is None else min(self.stall_timeout, timeout)
        if os.environ.get("BBOT_THREADED_COMMANDS") == "1":
            # Threaded commands only support a timeout on the whole run.
            idle = timeout
        lines = []
        try:
            async for line in module.run_process_live(
                *command, stderr=subprocess.DEVNULL, input=names, idle_timeout=idle
            ):
                lines.append(line)
        except asyncio.TimeoutError:
            self.stalls += 1
            self.log.warning(
                f"massdns gave no output for {idle:.0f}s and was killed; {len(names) - len(lines):,} of "
                f"{len(names):,} names may be unanswered"
            )
            return lines, True
        return lines, False

    def _leave_unanswered(self, names, rdtype):
        self.unanswered_queries += len(names)
        self.unanswered.update((name, rdtype) for name in names)

    def _read_massdns_pass(self, lines, requested, answered, first=True):
        """Record the names one massdns run answered; return its unanswered names and refusal count.

        Any response code is an answer except REFUSED, which a resolver sends when shedding load.
        """
        failures = []
        refused = 0
        for line in lines:
            record = self._parse_massdns_line(line)
            name = str(record.get("name", "")).lower().rstrip(".")
            if name not in requested:
                continue
            status = str(record.get("status") or "").upper()
            if record.get("error") or status in ("", "REFUSED"):
                failures.append(name)
                refused += status == "REFUSED"
                if status and first:
                    self.response_status[status] += 1
            elif name not in answered:
                answered.add(name)
                self.response_status[status] += 1
        return failures, refused

    @staticmethod
    def _parse_massdns_line(line):
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return {}
        return record if isinstance(record, dict) else {}

    async def resolver_file(self):
        async with self._resolver_lock:
            if not self.resolver_pool.selected:
                candidates = await self.prepare_resolvers()
                selected = await self.resolver_pool.validate(
                    candidates, fallback=self.parent_helper.dns.system_resolvers
                )
                self._resolver_file = self.parent_helper.tempfile(selected, pipe=False)
                self.log.info(
                    f"Validated DNS resolvers (A/AAAA, NXDOMAIN and latency): {self.resolver_pool.measurements}"
                )
        return self._resolver_file

    async def prepare_resolvers(self):
        # Dependency warmup prepares inputs but does not cache a validation result
        # from a different network. Every real scan validates its own endpoints.
        if not self.nameservers_url:
            return list(ResolverPool.defaults)
        path = await self.parent_helper.wordlist(self.nameservers_url, cache_hrs=24 * 7)
        candidates = []
        for line in self.parent_helper.read_file(path):
            try:
                ResolverPool.endpoint(line)
            except (ValueError, TypeError):
                continue
            if line not in candidates:
                candidates.append(line)
            if len(candidates) >= 64:
                break
        return candidates

    def gen_random_subdomains(self, n=50):
        delimiters = (".", "-")
        lengths = list(range(3, 8))
        for i in range(0, max(0, n - 5)):
            d = delimiters[i % len(delimiters)]
            l = lengths[i % len(lengths)]
            segments = [random.choice(self.devops_mutations) for _ in range(l)]
            segments.append(self.parent_helper.rand_string(length=8, digits=False))
            subdomain = d.join(segments)
            yield subdomain
        for _ in range(5):
            yield self.parent_helper.rand_string(length=8, digits=False)

    def has_excessive_digits(self, d):
        """
        Identifies dns names with excessive numbers, e.g.:
            - w1-2-3.evilcorp.com
            - ptr1234.evilcorp.com
        """
        is_ptr = self.parent_helper.is_ptr(d)
        digits = self.digit_regex.findall(d)
        excessive_digits = len(digits) > 2
        long_digits = any(len(d) > 3 for d in digits)
        return is_ptr or excessive_digits or long_digits
