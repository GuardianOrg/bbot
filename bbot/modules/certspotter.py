from bbot.modules.templates.subdomain_enum import subdomain_enum


class certspotter(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Certspotter's API for subdomains",
        "created_date": "2022-07-28",
        "author": "@TheTechromancer",
    }

    base_url = "https://api.certspotter.com/v1"

    handle_event = subdomain_enum.handle_event_paginated

    def request_url(self, query, after=None):
        url = f"{self.base_url}/issuances?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
        if after is not None:
            url += f"&after={self.helpers.quote(str(after))}"
        return self.api_request(url)

    async def query_paginated(self, query):
        after = None
        cursors_seen = set()
        while True:
            try:
                response = await self.request_url(query, after=after)
                if response is None or not response.is_success:
                    return
                issuances = response.json()
                if not isinstance(issuances, list) or not issuances:
                    return
                yield await self.parse_results(response, query)
                last_issuance = issuances[-1]
                cursor = last_issuance.get("id") if isinstance(last_issuance, dict) else None
                if cursor is None:
                    self.warning(f'CertSpotter returned no pagination cursor for "{query}"')
                    return
                cursor = str(cursor)
                if cursor in cursors_seen:
                    self.warning(f'CertSpotter repeated pagination cursor for "{query}"')
                    return
                cursors_seen.add(cursor)
                after = cursor
            except Exception as e:
                self.info(f'Error retrieving CertSpotter results for "{query}": {e}', trace=True)
                return

    async def parse_results(self, r, query):
        results = set()
        json = r.json()
        if isinstance(json, dict):
            return results
        if json:
            for r in json:
                if not isinstance(r, dict):
                    continue
                for dns_name in r.get("dns_names", []):
                    if not isinstance(dns_name, str):
                        continue
                    domain = dns_name.lower().strip().rstrip(".")
                    while domain.startswith("*."):
                        domain = domain[2:]
                    while domain.startswith("_wildcard."):
                        domain = domain[len("_wildcard.") :]
                    if domain:
                        results.add(domain)
        return results
