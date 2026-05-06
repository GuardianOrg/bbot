from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class virustotal(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "DOMAIN_DNS_HISTORY"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query VirusTotal's API for subdomains",
        "created_date": "2022-08-25",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    base_url = "https://www.virustotal.com/api/v3"
    api_page_iter_kwargs = {"json": False, "next_key": lambda r: r.json().get("links", {}).get("next", "")}
    options = {"api_key": "", "max_history_pages": 2}
    options_desc = {"api_key": "VirusTotal API Key", "max_history_pages": "Maximum /resolutions pages to fetch per DNS name"}

    async def setup(self):
        await super().setup()
        self.max_history_pages = max(0, int(self.config.get("max_history_pages", 2)))
        self.subdomain_queries_done = set()
        self.history_queries_done = set()
        return True

    def _incoming_dedup_hash(self, event):
        return hash(str(event.data).strip().lower())

    async def handle_event(self, event):
        query = self.make_query(event)
        if query not in self.subdomain_queries_done:
            self.subdomain_queries_done.add(query)
            await super().handle_event(event)

        host = str(event.data).strip().lower()
        if host and host not in self.history_queries_done:
            self.history_queries_done.add(host)
            await self.emit_resolution_history(host, event)

    def make_url(self, query):
        return f"{self.base_url}/domains/{self.helpers.quote(query)}/subdomains"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-apikey"] = self.api_key
        return url, kwargs

    async def emit_resolution_history(self, host, event):
        if self.max_history_pages <= 0:
            return

        records = []
        url = f"{self.base_url}/domains/{self.helpers.quote(host)}/resolutions"
        for _ in range(self.max_history_pages):
            response = await self.api_request(url)
            if response is None:
                break
            data = response.json()
            records.extend(self.parse_resolution_records(data, host))
            url = data.get("links", {}).get("next", "") if isinstance(data, dict) else ""
            if not url:
                break

        if records:
            await self.emit_event(
                {"host": host, "records": records},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} queried VirusTotal resolutions for "{host}" and found {{event.type}} records',
            )

    def parse_resolution_records(self, data, host):
        records = []
        if not isinstance(data, dict):
            return records
        for entry in data.get("data", []):
            attributes = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            if not isinstance(attributes, dict):
                continue
            ip = attributes.get("ip_address")
            date = attributes.get("date")
            record_host = str(attributes.get("host_name") or host).strip().lower()
            if ip and record_host == host:
                records.append({"ip": ip, "first_seen": date, "last_seen": date, "source": "virustotal"})
        return records

    async def parse_results(self, r, query):
        text = getattr(r, "text", "")
        return await self.scan.extract_in_scope_hostnames(text)
