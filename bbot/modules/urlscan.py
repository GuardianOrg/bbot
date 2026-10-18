import ipaddress
from collections import defaultdict

from bbot.modules.templates.subdomain_enum import subdomain_enum


class urlscan(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED", "DOMAIN_DNS_HISTORY"]
    meta = {
        "description": "Query urlscan.io for subdomains",
        "created_date": "2022-06-09",
        "author": "@TheTechromancer",
    }
    options = {"urls": True, "max_pages": 3, "page_size": 100}
    options_desc = {
        "urls": "Emit URLs in addition to DNS_NAMEs",
        "max_pages": "Maximum historical website scan result pages per domain",
        "page_size": "Website scan results per page",
    }

    base_url = "https://urlscan.io/api/v1"

    async def setup(self):
        self.urls = self.config.get("urls", False)
        self.max_pages = max(1, min(10, int(self.config.get("max_pages", 3))))
        self.page_size = max(1, min(1000, int(self.config.get("page_size", 100))))
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        results, histories = await self.query(query)
        for domain, url in results:
            parent_event = event
            if domain and domain != query:
                domain_event = self.make_event(domain, "DNS_NAME", parent=event)
                if domain_event:
                    if str(domain_event.host).endswith(f".{query}") and not str(domain_event.host) == str(event.host):
                        await self.emit_event(
                            domain_event,
                            abort_if=self.abort_if,
                            context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.data}}',
                        )
                        parent_event = domain_event
            if url:
                url_event = self.make_event(url, "URL_UNVERIFIED", parent=parent_event)
                if url_event:
                    if str(url_event.host) == query or str(url_event.host).endswith(f".{query}"):
                        if self.urls:
                            await self.emit_event(
                                url_event,
                                abort_if=self.abort_if,
                                context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.data}}',
                            )
                        else:
                            await self.emit_event(
                                str(url_event.host),
                                "DNS_NAME",
                                parent=event,
                                abort_if=self.abort_if,
                                context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.data}}',
                            )
                    else:
                        self.debug(f"{url_event.host} does not match {query}")

        for host, records in histories.items():
            await self.emit_event(
                {"host": host, "records": list(records.values())},
                "DOMAIN_DNS_HISTORY",
                parent=event,
                context=f'{{module}} found historical website scan addresses for "{host}" in {{event.type}}',
            )

    async def query(self, query):
        results = set()
        histories = defaultdict(dict)
        cursor = None
        for _ in range(self.max_pages):
            url = f"{self.base_url}/search/?q={self.helpers.quote(f'page.domain:{query}')}&size={self.page_size}"
            if cursor:
                url += f"&search_after={self.helpers.quote(cursor)}"
            response = await self.helpers.request(url)
            if response is None or response.status_code != 200:
                break
            try:
                response_data = response.json()
            except ValueError:
                self.verbose(f'Invalid urlscan response for "{query}"')
                break
            if not isinstance(response_data, dict):
                break
            page_results = response_data.get("results")
            if not isinstance(page_results, list):
                break
            for result in page_results:
                if not isinstance(result, dict):
                    continue
                task = result.get("task") if isinstance(result.get("task"), dict) else {}
                page = result.get("page") if isinstance(result.get("page"), dict) else {}
                for item in (task, page):
                    domain, page_url = item.get("domain", ""), item.get("url", "")
                    if domain or page_url:
                        results.add((domain, page_url))
                host = str(page.get("domain", "")).lower().rstrip(".")
                if host == query or host.endswith(f".{query}"):
                    try:
                        ip = ipaddress.ip_address(page.get("ip", ""))
                    except ValueError:
                        continue
                    record = {"ip": str(ip), "record_type": "A" if ip.version == 4 else "AAAA", "source": "urlscan"}
                    observed_at = task.get("time")
                    if isinstance(observed_at, str) and observed_at:
                        record["first_seen"] = observed_at
                        record["last_seen"] = observed_at
                    histories[host][(record["ip"], observed_at)] = record
            sort = page_results[-1].get("sort") if page_results and isinstance(page_results[-1], dict) else None
            next_cursor = ",".join(map(str, sort)) if isinstance(sort, list) and len(sort) == 2 else None
            if len(page_results) < self.page_size or not next_cursor or next_cursor == cursor:
                break
            cursor = next_cursor
        return results, histories
