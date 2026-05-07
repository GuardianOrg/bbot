from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class otx(subdomain_enum_apikey):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME", "IP_ADDRESS"]
    produced_events = ["DNS_NAME", "DOMAIN_DNS_HISTORY"]
    meta = {
        "description": "Query otx.alienvault.com for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "OTX API key"}

    base_url = "https://otx.alienvault.com"

    async def setup(self):
        await super().setup()
        self.queries_done = set()
        return True

    def _incoming_dedup_hash(self, event):
        return hash(str(event.data).strip().lower())

    async def handle_event(self, event):
        query = str(event.data).strip() if event.type == "IP_ADDRESS" else self.make_query(event)
        if query in self.queries_done:
            return
        self.queries_done.add(query)

        response = await self.request_url(query)
        if response is None:
            return
        data = response.json()
        results, histories = self.parse_passive_dns(data)
        is_ip_query = event.type == "IP_ADDRESS"

        for hostname in results:
            try:
                hostname = self.helpers.validators.validate_host(hostname)
            except ValueError as e:
                self.verbose(e)
                continue
            if hostname and is_ip_query:
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    event,
                    context=f'{{module}} searched {self.source_pretty_name} passive DNS for "{query}" and found {{event.type}}: {{event.data}}',
                )
            elif hostname and hostname.endswith(f".{query}") and not hostname == event.data:
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    event,
                    abort_if=self.abort_if,
                    context=f'{{module}} searched {self.source_pretty_name} for "{query}" and found {{event.type}}: {{event.data}}',
                )

        for host, records in histories.items():
            await self.emit_event(
                {"host": host, "records": records},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} queried OTX passive DNS for "{host}" and found {{event.type}} records',
            )

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["X-OTX-API-KEY"] = self.api_key
        return url, kwargs

    def request_url(self, query):
        if self.helpers.is_ip(query):
            indicator_type = "IPv6" if ":" in query else "IPv4"
            url = f"{self.base_url}/api/v1/indicators/{indicator_type}/{self.helpers.quote(query)}/passive_dns"
        else:
            url = f"{self.base_url}/api/v1/indicators/domain/{self.helpers.quote(query)}/passive_dns"
        return self.api_request(url)

    async def parse_results(self, r, query):
        results, _histories = self.parse_passive_dns(r.json())
        return results

    def parse_passive_dns(self, data):
        results = set()
        histories = {}
        if not isinstance(data, dict):
            return results, histories

        for entry in data.get("passive_dns", []):
            if not isinstance(entry, dict):
                continue
            hostname = str(entry.get("hostname", "")).strip().lower()
            if hostname:
                results.add(hostname)

            record_type = str(entry.get("record_type", "")).upper()
            address = str(entry.get("address", "")).strip()
            if hostname and address and record_type in ("A", "AAAA"):
                histories.setdefault(hostname, []).append(
                    {
                        "ip": address,
                        "first_seen": entry.get("first"),
                        "last_seen": entry.get("last"),
                        "record_type": record_type,
                        "source": "otx",
                    }
                )
        return results, histories
