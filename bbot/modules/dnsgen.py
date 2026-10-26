import asyncio
import re
import time
from collections import Counter, defaultdict, deque
from itertools import chain, islice

from bbot.core.helpers.dns.permutations import iter_dnsgen_candidates
from bbot.modules.base import BaseModule


class dnsgen(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "active", "aggressive"]
    meta = {
        "description": "Discover deep subdomains with budgeted DNSGen permutations",
        "author": "@carlospolop",
        "created_date": "2026-10-14",
    }
    deps_pip = ["dnsgen==1.0.4"]
    deps_common = ["massdns"]
    options = {
        "max_candidates": 50000,
        "max_candidates_per_domain": 10000,
        "max_candidates_per_seed": 300,
        "max_seeds": 5000,
        "max_words": 64,
        "max_rounds": 2,
        "dns_batch_size": 1000,
        "max_runtime": 180,
        "record_types": ["A", "AAAA"],
        "incremental": True,
        "incremental_seeds": 25,
    }
    options_desc = {
        "max_candidates": "Maximum distinct candidate hostnames across the entire scan (must be positive)",
        "max_candidates_per_domain": "Maximum distinct candidates per registrable domain across all rounds",
        "max_candidates_per_seed": "Maximum distinct candidates per observed hostname across all rounds",
        "max_seeds": "Maximum observed hostnames retained for permutation generation",
        "max_words": "Maximum target-derived and common words used by the static rules",
        "max_rounds": "Maximum finish rounds, including expansion of newly discovered names",
        "dns_batch_size": "Maximum candidates per DNS batch",
        "max_runtime": "Total seconds allowed for generation and DNS batches across all finish rounds",
        "record_types": "Address record types to query (A and/or AAAA)",
        "incremental": "Run a bounded batch on the first subdomain and every incremental_seeds new names",
        "incremental_seeds": "New seeds between early batches; finish drains the remaining bounded candidates",
    }
    common_words = (
        "dev test stg staging stage prod production uat qa preprod sandbox beta alpha demo "
        "api auth app admin cms websocket bastion pgadmin www mail vpn sso portal backend internal tools jenkins gitlab grafana "
        "kibana monitoring ci cd cdn static assets secure cloud aws azure gcp k8s svc service "
        "eu us uk apac us-east us-west eu-west eu-central v1 v2 db storage"
    ).split()
    priority_children = ("api", "auth", "cms", "websocket", "bastion", "pgadmin")

    async def setup(self):
        for option in self.options:
            if option in ("record_types", "incremental"):
                continue
            value = self.config.get(option, self.options[option])
            value = float(value) if option == "max_runtime" else int(value)
            if value <= 0 or (option == "max_runtime" and not value < float("inf")):
                raise ValueError(f"dnsgen.{option} must be finite and positive")
            setattr(self, option, value)
        self.record_types = list(dict.fromkeys(str(t).upper() for t in self.config.get("record_types", ["A", "AAAA"])))
        if not self.record_types or any(t not in ("A", "AAAA") for t in self.record_types):
            raise ValueError("dnsgen.record_types must contain A and/or AAAA")
        self.seeds = {}
        self.known_hosts = set()
        self.words_by_root = defaultdict(Counter)
        self.candidates_tried = set()
        self.domain_counts = Counter()
        self.seed_counts = Counter()
        self.rounds = 0
        self.deadline = None
        self.brute = self.helpers.dns.brute
        self.incremental = self.config.get("incremental", True)
        self.new_seeds = 0
        self.started_early = False
        self.runtime_used = 0.0
        self.discovery_lock = asyncio.Lock()
        return True

    async def filter_event(self, event):
        if event.scope_distance != 0:
            return False, "host is not in scope"
        if "wildcard" in event.tags or "_wildcard" in str(event.host).split("."):
            return False, "host is a wildcard placeholder"
        return True, ""

    async def handle_event(self, event):
        host = str(getattr(event, "host_original", event.host)).lower().rstrip(".")
        self.known_hosts.add(host)
        if host in self.seeds or len(self.seeds) >= self.max_seeds:
            return
        self.seeds[host] = event
        subdomain, root = self.helpers.split_domain(host)
        words = self.words_by_root[root]
        for word in re.findall(r"[a-z][a-z0-9-]*", subdomain):
            for token in dict.fromkeys([word, *word.split("-")]):
                if len(token) <= 32 and (token in words or len(words) < self.max_words * 2):
                    words[token] += 1
        self.new_seeds += 1
        if self.incremental and subdomain and (not self.started_early or self.new_seeds >= self.incremental_seeds):
            self.started_early = True
            self.new_seeds = 0
            await self._run_discovery(max_batches=1)

    def _candidate_stream(self, seeds, word_counts):
        roots = defaultdict(deque)
        for host, event in seeds:
            root = self.helpers.split_domain(host)[1]
            roots[root].append((host, event))
        queue = deque(roots)
        while queue and time.monotonic() < self.deadline and len(self.candidates_tried) < self.max_candidates:
            root = queue.popleft()
            host, event = roots[root].popleft()
            if roots[root]:
                queue.append(root)
            if self._seed_budget_exhausted(host, root):
                continue
            observed = [word for word, _ in word_counts.get(root, Counter()).most_common(self.max_words // 2)]
            words = list(dict.fromkeys([*observed, *self.common_words]))[: self.max_words]
            stream = chain(
                (f"{word}.{host}" for word in self.priority_children if word in words),
                iter_dnsgen_candidates(host, root, words),
            )
            # Bound work even if most generated names are duplicates, invalid, or out of scope.
            for candidate in islice(stream, self.max_candidates_per_seed * 20):
                if self._seed_budget_exhausted(host, root) or time.monotonic() >= self.deadline:
                    break
                try:
                    candidate = self.helpers.validators.validate_host(candidate)
                except ValueError:
                    continue
                if candidate in self.known_hosts or candidate in self.candidates_tried:
                    continue
                if not self.scan.in_scope(candidate):
                    continue
                tried = self.brute.queries_tried
                if all((candidate, rdtype) in tried for rdtype in self.record_types):
                    continue
                self.candidates_tried.add(candidate)
                self.seed_counts[host] += 1
                self.domain_counts[root] += 1
                yield root, candidate, event

    def _seed_budget_exhausted(self, host, root):
        return (
            self.seed_counts[host] >= self.max_candidates_per_seed
            or self.domain_counts[root] >= self.max_candidates_per_domain
            or len(self.candidates_tried) >= self.max_candidates
        )

    async def finish(self):
        try:
            await self._run_discovery(finish=True)
        finally:
            self.brute.release_reservation(self.name)

    async def _run_discovery(self, finish=False, max_batches=None):
        async with self.discovery_lock:
            if not self.seeds or len(self.candidates_tried) >= self.max_candidates:
                return
            if finish and self.rounds >= self.max_rounds:
                return
            remaining = self.max_runtime - self.runtime_used
            if self.brute.deadline is not None:
                remaining = min(remaining, self.brute.deadline - time.monotonic())
            if remaining <= 0 or self.brute.remaining_candidates(self) == 0:
                return
            if finish:
                self.rounds += 1
            started = time.monotonic()
            self.deadline = started + remaining
            stream = self._candidate_stream(
                list(self.seeds.items()), {root: words.copy() for root, words in self.words_by_root.items()}
            )
            batches = 0
            try:
                while time.monotonic() < self.deadline:
                    batch = await self.helpers.run_in_executor(lambda: list(islice(stream, self.dns_batch_size)))
                    if not batch:
                        break
                    groups = defaultdict(dict)
                    for root, candidate, parent in batch:
                        groups[root][candidate] = parent
                    for root, candidates in groups.items():
                        if not await self._query_candidates(root, candidates):
                            return
                    batches += 1
                    if max_batches is not None and batches >= max_batches:
                        break
            finally:
                self.runtime_used += time.monotonic() - started
            self.info(
                f"DNSGen: {len(self.candidates_tried):,}/{self.max_candidates:,} candidates, {self.runtime_used:.2f}s active work"
            )

    async def _query_candidates(self, root, candidates):
        prefixes = [candidate[: -(len(root) + 1)] for candidate in candidates]
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            groups = await asyncio.wait_for(
                asyncio.gather(
                    *(self.brute(self, root, prefixes, type=kind, timeout=remaining) for kind in self.record_types)
                ),
                remaining,
            )
        except asyncio.TimeoutError:
            self.info("DNSGen stopped at its active runtime budget")
            return False
        for hostname in dict.fromkeys(host for group in groups for host in group):
            if hostname in self.known_hosts or hostname not in candidates:
                continue
            self.known_hosts.add(hostname)
            await self.emit_event(
                hostname,
                "DNS_NAME",
                parent=candidates[hostname],
                tags=["dnsgen-permutation"],
                context="{module} found a static DNSGen permutation: {event.data} (A/AAAA)",
            )
        return True
