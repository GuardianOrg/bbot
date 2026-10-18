import asyncio
import ipaddress
from datetime import datetime, timezone

from bbot.modules.base import BaseModule


class mnemonic(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DOMAIN_DNS_HISTORY"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Query mnemonic public PassiveDNS for historical A and AAAA records",
        "created_date": "2026-10-18",
        "author": "@carlospolop",
    }
    options = {"max_queries": 300, "max_pages": 2}
    options_desc = {
        "max_queries": "Maximum public PassiveDNS requests per scan (shared free allowance: 1,000/day per IP)",
        "max_pages": "Maximum 1,000-record result pages per DNS name",
    }
    _qsize = 1
    base_url = "https://api.mnemonic.no/pdns/v3"
    request_interval = 6.1  # Unauthenticated API: 10 requests per minute per egress IP.

    async def setup(self):
        self.max_queries = max(0, min(1000, int(self.config.get("max_queries", 300))))
        self.max_pages = max(1, int(self.config.get("max_pages", 2)))
        self.request_count = 0
        self.queries_done = set()
        self.quota_exhausted = False
        self.next_request_at = 0.0
        self.query_lock = asyncio.Lock()
        return True

    async def filter_event(self, event):
        if event.scope_distance != 0:
            return False, "mnemonic lookups are reserved for in-scope DNS names"
        if self.quota_exhausted or self.request_count >= self.max_queries:
            return False, "mnemonic query budget exhausted"
        return True

    async def handle_event(self, event):
        host = str(event.data).lower().rstrip(".")
        if host in self.queries_done:
            return
        self.queries_done.add(host)
        records = {}
        for page in range(self.max_pages):
            response = await self.request_page(host, page)
            if response is None:
                break
            try:
                data = response.json()
            except ValueError:
                self.warning(f'mnemonic returned invalid JSON for "{host}"')
                break
            rows = data.get("data", []) if isinstance(data, dict) else []
            if not isinstance(rows, list):
                break
            for record in self.parse_records(rows, host):
                records[(record["ip"], record.get("first_seen"), record.get("last_seen"))] = record
            if len(rows) < 1000:
                break

        if records:
            await self.emit_event(
                {"host": host, "records": list(records.values())},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} queried mnemonic PassiveDNS for "{host}" and found {{event.type}} records',
            )

    async def request_page(self, host, page):
        async with self.query_lock:
            loop = asyncio.get_running_loop()
            url = f"{self.base_url}/{self.helpers.quote(host)}?rrType=a&rrType=aaaa&limit=1000&offset={page * 1000}"
            for attempt in range(2):
                if self.quota_exhausted or self.request_count >= self.max_queries:
                    return None
                delay = self.next_request_at - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
                self.next_request_at = loop.time() + self.request_interval
                self.request_count += 1
                try:
                    response = await self.helpers.request(url)
                except Exception as exc:
                    self.warning(f'mnemonic lookup failed for "{host}": {exc}')
                    return None
                if response is None:
                    return None
                if response.status_code == 402 and attempt == 0:
                    try:
                        wait_ms = response.json().get("metaData", {}).get("millisUntilResourcesAvailable", 0)
                    except (AttributeError, ValueError):
                        wait_ms = 0
                    if isinstance(wait_ms, (int, float)) and 0 < wait_ms <= 60_000:
                        self.next_request_at = max(self.next_request_at, loop.time() + wait_ms / 1000 + 0.5)
                        continue
                if response.status_code in (402, 429):
                    self.quota_exhausted = True
                    self.warning("mnemonic public API quota reached; skipping further requests in this scan")
                    return None
                if response.status_code != 200:
                    self.warning(f'mnemonic lookup for "{host}" returned HTTP {response.status_code}')
                    return None
                return response
            return None

    @staticmethod
    def parse_records(rows, host):
        records = []
        for row in rows:
            if not isinstance(row, dict) or str(row.get("query", "")).lower().rstrip(".") != host:
                continue
            record_type = str(row.get("rrtype", "")).upper()
            if record_type not in ("A", "AAAA"):
                continue
            try:
                ip = ipaddress.ip_address(str(row["answer"]))
            except (KeyError, ValueError):
                continue
            if (record_type == "A") != (ip.version == 4):
                continue
            record = {"ip": str(ip), "record_type": record_type, "source": "mnemonic"}
            for source_key, output_key in (("firstSeenTimestamp", "first_seen"), ("lastSeenTimestamp", "last_seen")):
                timestamp = row.get(source_key)
                if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool) and timestamp > 0:
                    try:
                        record[output_key] = datetime.fromtimestamp(timestamp / 1000, timezone.utc).isoformat()
                    except (OverflowError, OSError, ValueError):
                        pass
            records.append(record)
        return records
