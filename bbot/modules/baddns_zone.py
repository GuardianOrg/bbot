from .baddns import baddns as baddns_module
import asyncio
import time


class baddns_zone(baddns_module):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY", "DNS_NAME"]
    domain_seed_scope_only = False
    flags = ["active", "safe", "subdomain-enum", "baddns", "cloud-enum"]
    meta = {
        "description": "Check hosts for DNS zone transfers and NSEC walks",
        "created_date": "2024-01-29",
        "author": "@liquidsec",
    }
    options = {
        "custom_nameservers": [],
        "only_high_confidence": False,
        "max_parent_checks": 100,
        "max_zones": 20,
        "max_results": 5000,
        "max_runtime": 120,
    }
    options_desc = {
        "custom_nameservers": "Force BadDNS to use a list of custom nameservers",
        "only_high_confidence": "Do not emit low-confidence or generic detections",
        "max_parent_checks": "Maximum distinct parent names checked for zone boundaries",
        "max_zones": "Maximum independently checked in-scope zones including delegations",
        "max_results": "Maximum discovered DNS names emitted by zone transfers and walks",
        "max_runtime": "Total wall-clock seconds for zone classification and enumeration",
    }
    module_threads = 8
    deps_pip = ["baddns~=1.12.294"]

    def set_modules(self):
        self.enabled_submodules = ["NSEC", "zonetransfer"]

    async def setup(self):
        self.parent_checks = set()
        self.zones_checked = set()
        self.zone_results = set()
        self.zone_deadline = None
        for key in ("max_parent_checks", "max_zones", "max_results", "max_runtime"):
            value = int(self.config.get(key, self.options[key]))
            if value <= 0:
                raise ValueError(f"baddns_zone.{key} must be positive")
            setattr(self, key, value)
        return await super().setup()

    async def filter_event(self, event):
        # Actual zone deduplication prevents NSEC feedback loops, while allowing a
        # discovered delegation to be inspected even when it came from another walk.
        return event.scope_distance == 0 and "_wildcard" not in str(event.host).split(
            "."
        ), "outside scope or synthetic"

    async def handle_event(self, event):
        if self.zone_deadline is None:
            self.zone_deadline = time.monotonic() + self.max_runtime
        remaining = self.zone_deadline - time.monotonic()
        if remaining <= 0:
            return
        try:
            await asyncio.wait_for(self._enumerate_zones(event), remaining)
        except asyncio.TimeoutError:
            self.info("Zone enumeration stopped at its total runtime budget")

    async def finish(self):
        # Target seeds and confirmed empty parents remain available even when
        # DNS_NAME_UNRESOLVED is omitted from the event pipeline.
        for event in self.scan.target.seeds:
            if self.helpers.is_dns_name(str(event.host)):
                seed = self.make_event(str(event.host), "DNS_NAME", parent=self.scan.root_event)
                if seed is not None:
                    await self.handle_event(seed)
        depth = self.scan.modules.get("dnsdepth")
        if depth is not None:
            for host in sorted(depth.empty_parents):
                event = self.make_event(host, "DNS_NAME", parent=self.scan.root_event)
                if event is not None:
                    await self.handle_event(event)

    async def _enumerate_zones(self, event):
        host = str(getattr(event, "host_original", event.host))
        for parent in [host, *self.helpers.domain_parents(host)]:
            if len(self.parent_checks) >= self.max_parent_checks or len(self.zones_checked) >= self.max_zones:
                return
            if parent in self.parent_checks or not self.scan.in_scope(parent):
                continue
            self.parent_checks.add(parent)
            responses = await asyncio.gather(
                *(self.helpers.dns.resolve_status(parent, type=kind, timeout=1) for kind in ("NS", "SOA"))
            )
            zones = set()
            for response in responses:
                if response["status"] != "NOERROR":
                    continue
                for record in response["answers"] + response["authority"]:
                    if record["type"] in ("NS", "SOA") and self.scan.in_scope(record["owner"]):
                        zones.add(record["owner"])
            for zone in sorted(zones):
                if zone in self.zones_checked or len(self.zones_checked) >= self.max_zones:
                    continue
                self.zones_checked.add(zone)
                zone_event = self.make_event(zone, "DNS_NAME", parent=event)
                if zone_event is not None:
                    await super().handle_event(zone_event)

    async def emit_event(self, data, event_type=None, *args, **kwargs):
        if event_type == "DNS_NAME":
            name = str(data).lower().rstrip(".")
            if name in self.zone_results or len(self.zone_results) >= self.max_results:
                return
            self.zone_results.add(name)
        return await super().emit_event(data, event_type, *args, **kwargs)
