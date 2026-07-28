from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query crt.sh (certificate transparency) for subdomains",
        "created_date": "2022-05-13",
        "author": "@TheTechromancer",
    }

    base_url = "https://crt.sh"
    certspotter_url = "https://api.certspotter.com/v1"

    async def setup(self):
        self.cert_ids = set()
        return await super().setup()

    async def request_url(self, query):
        params = {"q": f"%.{query}", "output": "json"}
        url = self.helpers.add_get_params(self.base_url, params).geturl()
        response = await self.api_request(url, timeout=self.http_timeout + 30)
        if response is not None and getattr(response, "status_code", 0) < 500:
            return response
        self.verbose(f'crt.sh HTTP lookup unavailable for "{query}", falling back to CertSpotter')
        certspotter = (
            f"{self.certspotter_url}/issuances"
            f"?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
        )
        return await self.api_request(certspotter, timeout=self.http_timeout + 30)

    def _api_response_is_success(self, response):
        # crt.sh uses 404 for transient overloads, not only empty results.
        return getattr(response, "is_success", False)

    async def parse_results(self, r, query):
        results = set()
        try:
            j = r.json()
        except Exception:
            return results
        if not isinstance(j, list):
            return results
        for cert_info in j:
            if not type(cert_info) == dict:
                continue
            dns_names = cert_info.get("dns_names")
            if isinstance(dns_names, list):
                for domain in dns_names:
                    if not isinstance(domain, str):
                        continue
                    d = domain.lower().strip().rstrip(".")
                    while d.startswith("*."):
                        d = d[2:]
                    while d.startswith("_wildcard."):
                        d = d[len("_wildcard.") :]
                    if d:
                        results.add(d)
                continue
            cert_id = cert_info.get("id")
            if cert_id:
                if hash(cert_id) not in self.cert_ids:
                    self.cert_ids.add(hash(cert_id))
                    domain = cert_info.get("name_value")
                    if domain:
                        for d in domain.splitlines():
                            d = d.lower().strip().rstrip(".")
                            while d.startswith("*."):
                                d = d[2:]
                            while d.startswith("_wildcard."):
                                d = d[len("_wildcard.") :]
                            if d:
                                results.add(d)
        return results
