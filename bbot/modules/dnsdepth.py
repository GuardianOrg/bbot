"""Explore DNS parents with NODATA using small, ranked, bounded DNS-only batches."""

import asyncio
import time
from pathlib import Path

from bbot.modules.base import BaseModule


class dnsdepth(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "active", "safe"]
    meta = {
        "description": "Discover children beneath DNS parents without address records",
        "author": "@carlospolop",
        "created_date": "2026-10-14",
    }
    deps_common = ["massdns"]
    options = {"max_parent_probes": 100, "max_empty_parents": 20, "words_per_parent": 100, "max_runtime": 60}
    options_desc = {
        "max_parent_probes": "Maximum distinct DNS parents to classify per scan",
        "max_empty_parents": "Maximum confirmed NOERROR parents without A/AAAA answers to explore",
        "words_per_parent": "Number of ranked labels to try below each confirmed empty parent",
        "max_runtime": "Hard total seconds across all parent checks and brute batches",
    }

    async def setup(self):
        for key, default in self.options.items():
            value = (
                float(self.config.get(key, default)) if key == "max_runtime" else int(self.config.get(key, default))
            )
            if not 0 < value < float("inf"):
                raise ValueError(f"dnsdepth.{key} must be finite and positive")
            setattr(self, key, value)
        wordlist = Path(__file__).parent.parent / "wordlists" / "subdomains-ranked.txt"
        self.words = list(dict.fromkeys(self.helpers.read_file(wordlist)))[: self.words_per_parent]
        self.parents = {}
        self.checked = set()
        self.empty_parents = set()
        self.deadline = None
        # Classification is independent of emit_unresolved: empty target parents must not disappear.
        for event in self.scan.target.seeds:
            if self.helpers.is_dns_name(str(event.host)):
                parent = self.scan.make_event(str(event.host), "DNS_NAME", parent=self.scan.root_event)
                self.parents[str(event.host)] = parent
        return True

    async def filter_event(self, event):
        return event.scope_distance == 0 and "_wildcard" not in str(event.host).split(
            "."
        ), "host outside scope or synthetic"

    async def handle_event(self, event):
        host = str(getattr(event, "host_original", event.host))
        hosts = [host, *self.helpers.domain_parents(host)]
        for host in hosts:
            if len(self.parents) >= self.max_parent_probes:
                break
            if self.scan.in_scope(host):
                self.parents.setdefault(host, event)

    async def finish(self):
        if self.deadline is None:
            self.deadline = time.monotonic() + self.max_runtime
        brute = self.helpers.dns.brute
        if brute.deadline is None:
            brute.deadline = time.monotonic() + brute.max_runtime
        self.deadline = min(self.deadline, brute.deadline)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or len(self.empty_parents) >= self.max_empty_parents:
            return
        try:
            await asyncio.wait_for(self._explore(), remaining)
        except asyncio.TimeoutError:
            self.info("Empty-parent discovery stopped at its total runtime budget")

    async def _explore(self):
        queue = list(self.parents.items())
        # A small first-level parent survey finds namespaces such as dev with no addresses.
        for host, event in list(self.parents.items()):
            if host == self.helpers.split_domain(host)[1]:
                queue.extend((f"{word}.{host}", event) for word in self.words)
        for host, event in queue:
            if len(self.checked) >= self.max_parent_probes or len(self.empty_parents) >= self.max_empty_parents:
                return
            if host in self.checked or not self.scan.in_scope(host):
                continue
            self.checked.add(host)
            responses = await asyncio.gather(
                *(self.helpers.dns.resolve_status(host, type=kind, timeout=1) for kind in ("A", "AAAA"))
            )
            if not all(response["status"] == "NOERROR" and not response["answers"] for response in responses):
                continue
            self.empty_parents.add(host)
            found = set()
            for kind in ("A", "AAAA"):
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    return
                for child in await self.helpers.dns.brute(self, host, self.words, type=kind, timeout=remaining):
                    if child in found:
                        continue
                    found.add(child)
                    await self.emit_event(
                        child,
                        "DNS_NAME",
                        parent=event,
                        tags=["dns-empty-parent-child"],
                        context=f"{{module}} found {{event.data}} beneath NOERROR parent {host}",
                    )
