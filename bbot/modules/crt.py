import re

from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "DOMAIN_CERTIFICATE_HISTORY"]
    meta = {
        "description": "Query crt.sh (certificate transparency) for subdomains",
        "created_date": "2022-05-13",
        "author": "@TheTechromancer",
    }

    base_url = "https://crt.sh"
    certspotter_url = "https://api.certspotter.com/v1"

    async def setup(self):
        self.cert_ids = set()
        self.certificate_history_by_query = {}
        return await super().setup()

    async def request_url(self, query):
        params = {"q": query, "output": "json", "exclude": "expired"}
        url = self.helpers.add_get_params(self.base_url, params).geturl()
        response = await self.api_request(url, timeout=self.http_timeout + 30)
        if response is not None and getattr(response, "status_code", 0) < 500:
            return response
        self.verbose(f'crt.sh HTTP lookup unavailable for "{query}", falling back to CertSpotter')
        certspotter = (
            f"{self.certspotter_url}/issuances"
            f"?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names&expand=issuer"
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
        histories = getattr(self, "certificate_history_by_query", None)
        if histories is None:
            histories = self.certificate_history_by_query = {}
        history = histories.setdefault(query, {})
        for cert_info in j:
            if not isinstance(cert_info, dict):
                continue
            cert_id = cert_info.get("id")
            identity = (query, str(cert_id))
            if cert_id and identity in self.cert_ids:
                continue
            if cert_id:
                self.cert_ids.add(identity)
            names = cert_info.get("dns_names")
            if not isinstance(names, list):
                names = str(cert_info.get("name_value") or "").splitlines()
            names = sorted(
                {name.lower().strip().rstrip(".") for name in names if isinstance(name, str) and name.strip()}
            )
            normalized = {name.removeprefix("*.").removeprefix("_wildcard.") for name in names}
            results.update(normalized)
            if not any(name == query or name.endswith("." + query) for name in normalized):
                continue
            issuer = cert_info.get("issuer_name")
            if not issuer and isinstance(cert_info.get("issuer"), dict):
                issuer = cert_info["issuer"].get("name")
            if not isinstance(issuer, str) or not issuer.strip():
                continue
            organization = re.search(r'(?:^|,)\s*O=("(?:[^"\\]|\\.)*"|[^,]+)', issuer)
            issuer_key = (organization.group(1).strip(' "') if organization else issuer).casefold()
            valid_from = cert_info.get("not_before")
            valid_to = cert_info.get("not_after")
            observed_at = cert_info.get("entry_timestamp")
            entry = {
                "host": query,
                "subject_name": cert_info.get("common_name") or names[0],
                "issuer": issuer,
                "san_domains": names,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "first_seen": observed_at,
                "last_seen": observed_at,
                "source": "crt",
            }
            # A verified CT response seeds every known issuer, taking its newest certificate.
            if issuer_key not in history or str(valid_from or "") > str(history[issuer_key].get("valid_from") or ""):
                history[issuer_key] = entry
        return results

    async def handle_event(self, event):
        query = self.make_query(event)
        await super().handle_event(event)
        for entry in self.certificate_history_by_query.pop(query, {}).values():
            await self.emit_event(
                entry,
                "DOMAIN_CERTIFICATE_HISTORY",
                event,
                context="{module} recorded an initial certificate issuer for {event.host}",
            )
