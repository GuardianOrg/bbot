from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class securitytrails(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "DOMAIN_DNS_HISTORY"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the SecurityTrails API for subdomains",
        "created_date": "2022-07-03",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "max_history_pages": 1}
    options_desc = {
        "api_key": "SecurityTrails API key",
        "max_history_pages": "Maximum DNS history pages to fetch per DNS name",
    }

    base_url = "https://api.securitytrails.com/v1"
    ping_url = f"{base_url}/ping?apikey={{api_key}}"

    async def setup(self):
        self.limit = 100
        self.max_history_pages = max(0, int(self.config.get("max_history_pages", 1)))
        self.subdomain_queries_done = set()
        self.history_queries_done = set()
        return await super().setup()

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
            await self.emit_dns_history(host, event)

    async def request_url(self, query):
        url = f"{self.base_url}/domain/{query}/subdomains?apikey={{api_key}}"
        response = await self.api_request(url)
        return response

    async def parse_results(self, r, query):
        results = set()
        j = self.parse_json_response(r, f'subdomain query "{query}"')
        if isinstance(j, dict):
            for host in j.get("subdomains", []):
                results.add(f"{host}.{query}")
        return results

    def parse_json_response(self, response, description):
        try:
            return response.json()
        except Exception as e:
            status_code = getattr(response, "status_code", "unknown")
            self.verbose(f"Error parsing SecurityTrails {description} response (status code {status_code}): {e}")
            self.trace(repr(getattr(response, "text", "")))

    async def emit_dns_history(self, host, event):
        if self.max_history_pages <= 0:
            return

        records = []
        for record_type in ("a", "aaaa"):
            for page in range(1, self.max_history_pages + 1):
                url = f"{self.base_url}/history/{self.helpers.quote(host)}/dns/{record_type}?apikey={{api_key}}&page={page}"
                response = await self.api_request(url)
                if response is None:
                    break
                data = self.parse_json_response(response, f'DNS {record_type.upper()} history for "{host}"')
                if not isinstance(data, dict):
                    break
                records.extend(self.parse_history_records(data, record_type))
                total_pages = data.get("pages", 1)
                if page >= int(total_pages or 1):
                    break

        if records:
            await self.emit_event(
                {"host": host, "records": records},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} queried SecurityTrails DNS history for "{host}" and found {{event.type}} records',
            )

    def parse_history_records(self, data, record_type):
        records = []
        if not isinstance(data, dict):
            return records

        for record in data.get("records", []):
            if not isinstance(record, dict):
                continue
            first_seen = record.get("first_seen") or record.get("firstSeen")
            last_seen = record.get("last_seen") or record.get("lastSeen")
            for value in self.extract_history_values(record):
                records.append(
                    {
                        "ip": value,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "record_type": record_type.upper(),
                        "source": "securitytrails",
                    }
                )
        return records

    def extract_history_values(self, record):
        values = []
        for raw_value in record.get("values", []):
            if isinstance(raw_value, dict):
                value = raw_value.get("ip") or raw_value.get("ipv6") or raw_value.get("value")
            else:
                value = raw_value
            if value:
                values.append(str(value))
        return values
