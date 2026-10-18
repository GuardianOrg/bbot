import asyncio
import ipaddress
import json
from datetime import datetime, timezone

from bbot.modules.base import BaseModule


class robtex(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DOMAIN_DNS_HISTORY"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query Robtex free passive DNS for historical A and AAAA records",
        "created_date": "2026-10-18",
        "author": "@carlospolop",
    }
    options = {"max_queries": 8}
    options_desc = {"max_queries": "Maximum Robtex lookups per scan (free API allows 10 per hour per egress IP)"}
    _qsize = 1

    async def setup(self):
        self.max_queries = max(0, min(10, int(self.config.get("max_queries", 8))))
        self.queries_done = set()
        self.quota_exhausted = False
        self.query_lock = asyncio.Lock()
        return True

    async def filter_event(self, event):
        if event.scope_distance != 0:
            return False, "Robtex budget is reserved for in-scope DNS names"
        if self.quota_exhausted or len(self.queries_done) >= self.max_queries:
            return False, "Robtex query budget exhausted"
        return True

    async def handle_event(self, event):
        host = str(event.data).lower().rstrip(".")
        async with self.query_lock:
            if self.quota_exhausted or host in self.queries_done or len(self.queries_done) >= self.max_queries:
                return
            self.queries_done.add(host)
            try:
                response = await self.helpers.request(
                    f"https://freeapi.robtex.com/pdns/forward/{self.helpers.quote(host)}"
                )
            except Exception as exc:
                self.warning(f"Robtex lookup failed for {host}: {exc}")
                return
            if response is None:
                return
            if response.status_code == 429:
                self.quota_exhausted = True
                self.warning("Robtex free API rate limit reached; skipping further requests in this scan")
                return
            if response.status_code != 200:
                self.warning(f"Robtex lookup for {host} returned HTTP {response.status_code}")
                return

        records = self.parse_records(response.text, host)
        if records:
            await self.emit_event(
                {"host": host, "records": records},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} queried Robtex passive DNS for "{host}" and found {{event.type}} records',
            )

    @staticmethod
    def parse_records(body, host):
        records = {}
        for line in body.splitlines():
            try:
                row = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(row, dict) or str(row.get("rrname", "")).lower().rstrip(".") != host:
                continue
            record_type = str(row.get("rrtype", "")).upper()
            if record_type not in ("A", "AAAA"):
                continue
            try:
                ip = ipaddress.ip_address(str(row["rrdata"]))
            except (KeyError, ValueError):
                continue
            if (record_type == "A") != (ip.version == 4):
                continue
            record = {"ip": str(ip), "record_type": record_type, "source": "robtex"}
            for source_key, output_key in (("time_first", "first_seen"), ("time_last", "last_seen")):
                timestamp = row.get(source_key)
                if isinstance(timestamp, (int, float)) and timestamp > 0:
                    record[output_key] = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
            records[(str(ip), record.get("first_seen"), record.get("last_seen"))] = record
        return list(records.values())
