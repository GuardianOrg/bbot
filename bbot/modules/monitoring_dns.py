"""Initial DNS facts for later monitoring, including verified empty answers."""

import asyncio
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.resolver

from bbot.modules.base import BaseModule


class monitoring_dns(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DOMAIN_DNS_CONFIG"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Record corroborated initial DNS monitoring values",
        "created_date": "2026-11-13",
        "author": "@carlospolop",
    }
    in_scope_only = True
    per_host_only = True
    _module_threads = 4
    RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "SRV")
    RESOLVERS = ("1.1.1.1", "8.8.8.8")

    async def filter_event(self, event):
        return "_wildcard" not in str(event.host).split(".")

    async def query_record(self, host, kind, nameserver):
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        try:
            answer = await resolver.resolve(host, kind, lifetime=5)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return True, []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
            return False, []
        values = []
        for row in answer:
            if kind == "TXT":
                value = b"".join(row.strings).decode("utf-8", errors="replace")
            else:
                value = row.to_text().strip().lower().rstrip(".")
            values.append(value)
        return True, sorted(set(values))

    @staticmethod
    def comparison_values(kind, values):
        if kind != "SOA":
            return values
        # Zone serials change routinely; a provider's serial lag is not a change
        # to the security-relevant SOA identity or timing values.
        return sorted(" ".join(parts[:2] + parts[3:]) if len(parts := row.split()) >= 7 else row for row in values)

    async def collect(self, host):
        async def query(kind):
            results = await asyncio.gather(*(self.query_record(host, kind, provider) for provider in self.RESOLVERS))
            if not all(success for success, _ in results):
                return kind, None, "lookup-unavailable"
            answers = [values for _, values in results]
            if self.comparison_values(kind, answers[0]) != self.comparison_values(kind, answers[1]):
                return kind, None, "resolvers-disagree"
            return kind, answers[0], None

        rows = await asyncio.gather(*(query(kind) for kind in self.RECORD_TYPES))
        return {
            "host": host,
            "monitoring_records": {kind: values for kind, values, error in rows if error is None},
            "monitoring_errors": {kind: error for kind, _, error in rows if error is not None},
            "monitoring_resolvers": list(self.RESOLVERS),
            "monitoring_observed_at": datetime.now(timezone.utc).isoformat(),
        }

    async def handle_event(self, event):
        host = str(event.host).lower().rstrip(".")
        payload = await self.collect(host)
        emitted = await self.emit_event(
            payload,
            "DOMAIN_DNS_CONFIG",
            parent=event,
            context=f'{{module}} recorded initial DNS monitoring observations for "{host}"',
        )
        if emitted is None:
            raise RuntimeError(f"Initial DNS monitoring facts were not persisted for {host}")
