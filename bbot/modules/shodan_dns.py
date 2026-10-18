import ipaddress

from bbot.modules.templates.shodan import shodan


class shodan_dns(shodan):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "DOMAIN_DNS_HISTORY"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Shodan for subdomains and historical DNS addresses",
        "created_date": "2022-07-03",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "history": True, "max_pages": 100}
    options_desc = {
        "api_key": "Shodan API key",
        "history": "Include historical DNS records in the domain query",
        "max_pages": "Maximum Shodan DNS result pages per domain (one query credit per page)",
    }

    base_url = "https://api.shodan.io"

    async def setup(self):
        result = await super().setup()
        self.history = bool(self.config.get("history", True))
        self.max_pages = max(1, int(self.config.get("max_pages", 100)))
        return result

    def make_url(self, query):
        history = "true" if self.history else "false"
        return (
            f"{self.base_url}/dns/domain/{self.helpers.quote(query)}?key={{api_key}}&page={{page}}&history={history}"
        )

    @staticmethod
    def record_host(query, subdomain):
        subdomain = str(subdomain or "").strip(".* ").lower()
        query = query.lower()
        if not subdomain or subdomain == query:
            return query
        if subdomain.endswith(f".{query}"):
            return subdomain
        return f"{subdomain}.{query}"

    @classmethod
    def parse_page(cls, data, query):
        names = set()
        histories = {}
        if not isinstance(data, dict):
            return names, histories
        for subdomain in data.get("subdomains", []):
            names.add(cls.record_host(query, subdomain))
        for record in data.get("data", []):
            if not isinstance(record, dict):
                continue
            host = cls.record_host(query, record.get("subdomain"))
            if host != query and host.endswith(f".{query}"):
                names.add(host)
            record_type = str(record.get("type") or "").upper()
            if record_type not in ("A", "AAAA"):
                continue
            value = str(record.get("value") or "").strip()
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if (record_type == "A") != (ip.version == 4):
                continue
            history_record = {"ip": value, "record_type": record_type, "source": "shodan"}
            for field in ("first_seen", "last_seen"):
                if record.get(field):
                    history_record[field] = record[field]
            histories.setdefault(host, []).append(history_record)
        return names, histories

    async def handle_event(self, event):
        query = self.make_query(event)
        names = set()
        histories = {}
        for page in range(1, self.max_pages + 1):
            response = await self.api_request(self.make_url(query).replace("{page}", str(page)))
            if response is None:
                break
            try:
                data = response.json()
            except ValueError:
                self.warning(f'Invalid Shodan DNS response for "{query}", page {page}')
                break
            page_names, page_histories = self.parse_page(data, query)
            names.update(page_names)
            for host, records in page_histories.items():
                histories.setdefault(host, []).extend(records)
            if not data.get("more"):
                break

        for hostname in sorted(names):
            try:
                hostname = self.helpers.validators.validate_host(hostname)
            except ValueError as error:
                self.verbose(error)
                continue
            if hostname != event.data and hostname.endswith(f".{query}"):
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    event,
                    abort_if=self.abort_if,
                    context=f'{{module}} searched Shodan DNS for "{query}" and found {{event.type}}: {{event.data}}',
                )
        for host, records in sorted(histories.items()):
            if host != query and not host.endswith(f".{query}"):
                continue
            unique = list(
                {(r["ip"], r.get("first_seen"), r.get("last_seen"), r["record_type"]): r for r in records}.values()
            )
            await self.emit_event(
                {"host": host, "records": unique},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} queried Shodan DNS history for "{host}" and found {{event.type}} records',
            )
