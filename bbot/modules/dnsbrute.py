import asyncio
import hashlib
import json
import os
import time
from pathlib import Path

from bbot.errors import WordlistError
from bbot.modules.dnsbrute_queue import DNSBruteQueue
from bbot.modules.templates.subdomain_enum import subdomain_enum


class dnsbrute(subdomain_enum):
    flags = ["subdomain-enum", "active", "aggressive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Brute-force subdomains with massdns + static wordlist",
        "author": "@TheTechromancer",
        "created_date": "2024-04-24",
    }
    options = {
        "wordlist": "",
        "wordlists": [],
        "max_words": 10000,
        "child_words": 1000,
        "max_depth": 5,
        "dns_batch_size": 5000,
        "max_batch_parents": 5,
        "resume_file": "",
        "resume_only": False,
        "coverage_file": "",
    }
    options_desc = {
        "wordlist": "Wordlist path/URL; empty uses the bundled ranked list without HTTP",
        "wordlists": "Additional wordlist paths/URLs merged in order with exact deduplication",
        "max_words": "Maximum unique words retained across all lists",
        "child_words": "Maximum highest-ranked words tried beneath each observed subdomain",
        "max_depth": "How many subdomains deep to brute force, i.e. 5.4.3.2.1.evilcorp.com",
        "dns_batch_size": "Maximum labels across all parents in one fair scheduling round",
        "max_batch_parents": "Maximum parents sharing one scheduling round",
        "resume_file": "JSON of an earlier run's coverage; its parents continue after the words it already checked",
        "resume_only": "Brute-force only the parents named in resume_file",
        "coverage_file": "Where to write words checked per parent, the wordlist hash and resolver metrics as JSON",
    }
    deps_common = ["massdns"]
    reject_wildcards = False
    dedup_strategy = "lowest_parent"
    _qsize = 10000

    @property
    def has_pending_work(self):
        # Brute-forcing runs in its own task after handle_event returns.
        return super().has_pending_work or (self.worker_task is not None and not self.worker_task.done())

    def make_query(self, event):
        # The validated hostname itself is an eligible parent. The generic
        # subdomain_enum template instead chooses its nearest parent.
        return str(event.host).lower().rstrip(".")

    async def _fetch_required_wordlist(self, fetcher, description):
        last_error = None
        for attempt in range(1, 4):
            try:
                return await fetcher()
            except WordlistError as e:
                last_error = e
                if attempt >= 3:
                    break
                self.warning(f"Failed to download {description} on attempt {attempt}/3: {e}")
                await asyncio.sleep(attempt)
        raise WordlistError(f"Failed to download {description} after 3 attempts: {last_error}")

    async def setup_deps(self):
        self.subdomain_file = await self._fetch_required_wordlist(
            lambda: self.helpers.wordlist(
                self.config.get("wordlist") or str(Path(__file__).parent.parent / "wordlists/subdomains-ranked.txt")
            ),
            "dnsbrute wordlist",
        )
        # tell the dnsbrute helper to fetch the resolver file
        await self._fetch_required_wordlist(
            lambda: self.helpers.dns.brute.prepare_resolvers(),
            "dnsbrute resolver list",
        )
        return True

    async def setup(self):
        self.max_depth = max(1, self.config.get("max_depth", 5))
        self.max_words = int(self.config.get("max_words", 10000))
        self.child_words = int(self.config.get("child_words", 1000))
        self.dns_batch_size = int(self.config.get("dns_batch_size", 5000))
        self.max_batch_parents = int(self.config.get("max_batch_parents", 5))
        if (self.max_words <= 0 or self.child_words <= 0 or not 0 < self.dns_batch_size <= 5000
                or not 0 < self.max_batch_parents <= 10):
            raise ValueError("dnsbrute word and batch limits must be positive and within bounds")
        self.emitted_hosts = set()
        self.worker_task = None
        lists = [self.subdomain_file]
        for extra in self.config.get("wordlists", []):
            lists.append(await self.helpers.wordlist(extra))
        ordered = {}
        for wordlist in lists:
            for word in self.helpers.read_file(wordlist):
                word = word.strip().lower().rstrip(".")
                if word and not word.startswith("#"):
                    ordered.setdefault(word, None)
                if len(ordered) >= self.max_words:
                    break
            if len(ordered) >= self.max_words:
                break
        self.subdomain_list = list(ordered)
        self.wordlist_size = len(self.subdomain_list)
        # Offsets are only meaningful for the exact same ordered list.
        self.wordlist_sha256 = hashlib.sha256("\n".join(self.subdomain_list).encode()).hexdigest()
        self.queue = DNSBruteQueue(self.wordlist_size)
        self.coverage_file = str(self.config.get("coverage_file") or "")
        self.coverage_written = 0.0
        self.resume_only = bool(self.config.get("resume_only", False))
        self.resume_parents, self.resume_matched = {}, False
        self.skipped_parents = {}
        resume_file = str(self.config.get("resume_file") or "")
        if resume_file:
            resume = json.loads(Path(resume_file).read_text())
            self.resume_matched = resume.get("wordlist_sha256") == self.wordlist_sha256
            for parent, entry in (resume.get("parents") or {}).items():
                offset, limit = (list(entry) + [None])[:2]
                self.resume_parents[str(parent).lower().rstrip(".")] = (
                    int(offset) if self.resume_matched else 0, int(limit) if limit else None)
            if not self.resume_matched:
                self.warning("dnsbrute resume file was made with a different wordlist; its parents start from the first word")
        if self.resume_only and not self.resume_parents:
            return False, "resume_only needs a resume_file naming parents"
        return await super().setup()

    async def filter_event(self, event):
        accepted, reason = await self._filter_parent(event)
        query = self.make_query(event)
        if accepted:
            self.skipped_parents.pop(query, None)
        elif (query in self.resume_parents and query not in self.queue.positions
              and not (self.helpers.dns.brute.deadline is not None
                       and time.monotonic() >= self.helpers.dns.brute.deadline)):
            # A parent a resumed run was asked to continue but never brute-forces is reported, so whoever
            # planned it does not ask again.
            self.skipped_parents[query] = reason
        return accepted, reason

    async def _filter_parent(self, event):
        brute = self.helpers.dns.brute
        if brute.deadline is not None and time.monotonic() >= brute.deadline:
            return False, "shared brute-force runtime budget exhausted"
        query = self.make_query(event)

        if event.scope_distance != 0:
            return False, "host is not in scope"
        if any(tag.startswith("cloud-") for tag in event.tags) and event not in self.scan.target.whitelist:
            return False, "Event is a cloud resource and not a direct target"
        if "unresolved" in event.tags or ("wildcard-child" in event.tags and "wildcard-dns-verified" not in event.tags):
            return False, "host has no independently validated DNS name"
        if "_wildcard" in query.split("."):
            return False, "wildcard placeholder is not a DNS parent"
        if self.resume_only and query not in self.resume_parents:
            return False, "not a parent this resumed run continues"

        # limit brute force depth
        subdomain_depth = self.helpers.subdomain_depth(query) + 1
        if subdomain_depth > self.max_depth:
            return False, f"subdomain depth of *.{query} ({subdomain_depth}) > max_depth ({self.max_depth})"

        # don't brute-force things that look like autogenerated PTRs
        if self.helpers.dns.brute.has_excessive_digits(query):
            return False, f'"{query}" looks like an autogenerated PTR'

        # DNSBrute checks wildcard behavior once per parent inside the shared
        # helper. The inherited filter would re-query it for every DNS_NAME.
        return True, ""

    async def handle_event(self, event):
        query = self.make_query(event)
        root = self.helpers.split_domain(query)[1]
        limit = self.wordlist_size if query == root else min(self.child_words, self.wordlist_size)
        start, resumed_limit = self.resume_parents.get(query, (0, None))
        if resumed_limit:
            limit = min(limit, resumed_limit)
        added = self.queue.add(query, event, limit=limit, start=start)
        if added:
            self.info(f"Queued {query} for ranked DNS discovery (source: {event.data})")
        if added and (self.worker_task is None or self.worker_task.done()):
            if self.worker_task is not None:
                await self.worker_task
            self.worker_task = asyncio.create_task(self._run_queue())

    async def _query_parent(self, reservation):
        query, start, end, event, _order = reservation
        end = min(end, self.queue.limits[query])
        if start >= end:
            return reservation, [], False, None, None
        words = self.subdomain_list[start:end]
        brute = self.helpers.dns.brute
        wildcard_before = brute.wildcard_candidates[query]
        results = await asyncio.gather(*(brute(self, query, words, type=kind) for kind in ("A", "AAAA")))
        limited = query in brute.wildcard_domains
        answered = None
        if limited:
            checked = brute.wildcard_candidates[query] - wildcard_before
        else:
            # Other DNS modules may claim names while massdns is running.
            # Count only the consecutive names actually submitted.
            checked = 0
            for word in words:
                hostname = f"{word}.{query}"
                if not all((hostname, kind) in brute.queries_tried for kind in ("A", "AAAA")):
                    break
                checked += 1
            # A word is covered only when every query for it got a DNS answer.
            answered = checked
            for index, word in enumerate(words[:checked]):
                keys = [(f"{word}.{query}", kind) for kind in ("A", "AAAA")]
                if answered == checked and any(key in brute.unanswered for key in keys):
                    answered = index
                brute.unanswered.difference_update(keys)
        names = list(dict.fromkeys(host for group in results for host in group))
        return reservation, names, limited, checked, answered

    async def _run_queue(self):
        brute = self.helpers.dns.brute
        if brute.deadline is None:
            brute.deadline = time.monotonic() + brute.max_runtime
        while self.queue and time.monotonic() < brute.deadline:
            remaining = brute.remaining_candidates(self)
            if remaining == 0:
                if len(brute.queries_tried) >= brute.max_candidates:
                    break
                await brute.reservations_released.wait()
                continue
            # When a query count limit is configured, A and AAAA count
            # separately. Never reserve words that cannot be sent as both.
            batch_size = self.dns_batch_size if remaining is None else min(self.dns_batch_size, remaining // 2)
            if batch_size <= 0:
                if len(brute.queries_tried) >= brute.max_candidates - 1:
                    break
                await brute.reservations_released.wait()
                continue
            reservations = self.queue.reserve(batch_size, self.max_batch_parents)
            outcomes = await asyncio.gather(*(self._query_parent(entry) for entry in reservations),
                                            return_exceptions=True)
            failed = None
            for reservation, outcome in zip(reservations, outcomes):
                if isinstance(outcome, BaseException):
                    self.queue.retry(reservation)
                    failed = outcome
                    continue
                _entry, names, limited, checked, answered = outcome
                if time.monotonic() >= brute.deadline:
                    self.queue.retry(reservation)
                    continue
                self.queue.complete(reservation, limited=limited, checked=checked, answered=answered)
                event = reservation[3]
                for hostname in names:
                    if hostname in self.emitted_hosts:
                        continue
                    self.emitted_hosts.add(hostname)
                    await self.emit_event(
                        hostname, "DNS_NAME", parent=event,
                        context=f'{{module}} checked ranked DNS words beneath "{reservation[0]}" and found {{event.type}}: {{event.data}}',
                    )
            if failed is not None:
                raise failed
            if time.monotonic() - self.coverage_written >= 60:
                # A run stopped from outside still leaves its progress for the next one.
                self.write_coverage()

    async def finish(self):
        brute = self.helpers.dns.brute
        # Priority modules release unused reservations at their first finish.
        for name in list(brute.reservations):
            module = self.scan.modules.get(name)
            if module is None or module.errored:
                brute.release_reservation(name)
        if self.worker_task is not None:
            await self.worker_task

    async def cleanup(self):
        if self.worker_task is not None and not self.worker_task.done():
            self.worker_task.cancel()
            await asyncio.gather(self.worker_task, return_exceptions=True)
        await super().cleanup()

    def coverage(self):
        brute = self.helpers.dns.brute
        metrics = brute.metrics().get(self.name, {})
        return {
            "wordlist_sha256": self.wordlist_sha256,
            "word_count": self.wordlist_size,
            "resumed_parents": len(self.resume_parents),
            "resume_matched": self.resume_matched,
            # Per parent: words checked (every word before it got a DNS answer), words it may check,
            # and whether wildcard DNS stopped it early.
            "parents": {parent: [self.queue.covered[parent], self.queue.limits[parent], parent in self.queue.limited]
                        for parent in sorted(self.queue.positions)},
            # Resumed parents dnsbrute rejected (unresolved, too deep, PTR-like...) and why.
            "skipped_parents": dict(sorted(self.skipped_parents.items())),
            "queries": metrics.get("queries", 0),
            "call_seconds": metrics.get("call_seconds", 0),
            "elapsed_seconds": round(time.monotonic() - brute.started, 3) if brute.started is not None else 0,
            "resolver": brute.resolver_metrics(),
        }

    def write_coverage(self):
        self.coverage_written = time.monotonic()
        if not self.coverage_file:
            return
        path = Path(self.coverage_file)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(json.dumps(self.coverage(), separators=(",", ":")))
        os.replace(temporary, path)

    async def report(self):
        self.write_coverage()
        self.info(f"DNS discovery metrics: {self.helpers.dns.brute.metrics()}")
        positions = sorted(self.queue.covered.values())
        if positions:
            self.info(f"Ranked DNS coverage: {len(positions)} parents; words checked per parent min/median/max "
                      f"{positions[0]}/{positions[len(positions) // 2]}/{positions[-1]}; "
                      f"wildcard-limited parents {len(self.queue.limited)}")
        helper = self.helpers.dns.brute
        self.info(
            f"DNS resolver metrics: {len(helper.resolver_pool.selected)} validated, {helper.resolver_pool.confirmations} confirmations, {helper.resolver_pool.rejected} rejected names, {helper.transport_failures} initial transport errors, {helper.transport_retries} bounded retries, {helper.transport_retry_failures} errors after retry, {helper.transport_unretried} not retried before deadline, {helper.unanswered_queries} left unanswered, {helper.per_resolver_threads} slots/resolver/process, {helper.concurrency_cuts} concurrency cuts, {helper.concurrency_raises} raises, {helper.response_status['SERVFAIL']} SERVFAIL, {helper.response_status['REFUSED']} REFUSED"
        )
