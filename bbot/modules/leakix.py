from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class leakix(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    options = {"api_key": ""}
    options_desc = {"api_key": "LeakIX API Key"}
    meta = {
        "description": "Query leakix.net for subdomains",
        "created_date": "2022-07-11",
        "author": "@TheTechromancer",
        "auth_required": True,
    }

    base_url = "https://leakix.net"
    ping_url = f"{base_url}/host/1.1.1.1"

    async def setup(self):
        await super(subdomain_enum_apikey, self).setup()
        self.api_key = self.config.get("api_key", "")
        return await self.require_api_key()

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"]["api-key"] = self.api_key
            kwargs["headers"]["Accept"] = "application/json"
        return url, kwargs

    async def request_url(self, query):
        url = f"{self.base_url}/api/subdomains/{self.helpers.quote(query)}"
        response = await self.api_request(url)
        return response

    async def parse_results(self, r, query=None):
        results = set()
        json = r.json()
        if isinstance(json, list):
            for entry in json:
                if not isinstance(entry, dict):
                    continue
                subdomain = entry.get("subdomain", "")
                if subdomain:
                    results.add(subdomain)
        return results
