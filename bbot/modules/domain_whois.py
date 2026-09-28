import asyncio
from datetime import date, datetime
from urllib.parse import quote, urljoin

from bbot.core.helpers.whois import normalize_whois_ownership, whois_first_string, whois_result_with_registrant
from bbot.modules.base import BaseModule


class domain_whois(BaseModule):
    fatal_on_error = True
    watched_events = ["DNS_NAME"]
    produced_events = ["DOMAIN_WHOIS"]
    flags = ["passive", "safe", "subdomain-enum"]
    meta = {
        "description": "Query domain WHOIS data and emit structured registrar/registrant metadata",
        "created_date": "2026-05-06",
        "author": "@carlospolop + @copilot",
    }
    deps_pip = ["python-whois~=0.9.5"]
    in_scope_only = True
    per_domain_only = True
    RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
    RDAP_HEADERS = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "GuardianSentry-WHOIS/1.0",
    }

    async def handle_event(self, event):
        _, registered_domain = self.helpers.split_domain(str(event.data).lower())
        target = registered_domain.lower() if registered_domain else str(event.data).lower()
        if not target:
            return

        try:
            result = await asyncio.to_thread(self.lookup_whois, target)
            if not isinstance(result, dict) or not self.string_list(result.get("status")):
                raise ValueError("WHOIS returned no registration statuses")
        except Exception as whois_error:
            self.debug(f"WHOIS lookup failed for {target}; trying RDAP: {whois_error}")
            try:
                result = await self.lookup_rdap(target)
            except Exception as rdap_error:
                raise RuntimeError(f"WHOIS and RDAP coverage failed for {target}: {rdap_error}") from rdap_error

        payload = self.normalize_result(target, result)
        emitted = await self.emit_event(
            payload,
            "DOMAIN_WHOIS",
            parent=event,
            context=f'{{module}} queried WHOIS for "{target}" and produced {{event.type}}',
        )
        if emitted is None:
            raise RuntimeError(f"DOMAIN_WHOIS event was not delivered for {target}")

    def lookup_whois(self, domain):
        import whois

        return whois_result_with_registrant(whois.whois(domain))

    async def lookup_rdap(self, domain):
        bootstrap = await self.request_rdap_json(self.RDAP_BOOTSTRAP_URL)
        services = bootstrap.get("services")
        if not isinstance(services, list):
            raise ValueError("IANA RDAP bootstrap has no service list")

        best_match = None
        best_url = None
        for service in services:
            if not isinstance(service, list) or len(service) != 2:
                continue
            labels, urls = service
            if not isinstance(labels, list) or not isinstance(urls, list):
                continue
            for label in labels:
                if not isinstance(label, str):
                    continue
                suffix = label.lower().strip(".")
                if not suffix or not (domain == suffix or domain.endswith(f".{suffix}")):
                    continue
                if best_match is None or len(suffix) > len(best_match):
                    candidate = next((url for url in urls if isinstance(url, str) and url.startswith("https://")), None)
                    if candidate:
                        best_match, best_url = suffix, candidate
        if not best_url:
            raise ValueError(f"No authoritative RDAP service found for {domain}")

        url = urljoin(best_url.rstrip("/") + "/", "domain/" + quote(domain, safe=""))
        rdap = await self.request_rdap_json(url)
        statuses = rdap.get("status")
        if (
            rdap.get("objectClassName") != "domain"
            or str(rdap.get("ldhName", "")).lower().rstrip(".") != domain
            or not isinstance(statuses, list)
            or not statuses
            or not all(isinstance(status, str) and status.strip() for status in statuses)
        ):
            raise ValueError(f"RDAP returned an invalid domain response for {domain}")
        return self.rdap_to_whois(rdap)

    async def request_rdap_json(self, url):
        response = await self.helpers.request(url, headers=self.RDAP_HEADERS, timeout=15)
        if response is None or response.status_code != 200:
            status = getattr(response, "status_code", "no response")
            raise RuntimeError(f"RDAP request failed: HTTP {status} ({url})")
        try:
            data = response.json()
        except ValueError as error:
            raise ValueError(f"RDAP returned malformed JSON ({url})") from error
        if not isinstance(data, dict):
            raise ValueError(f"RDAP returned a non-object response ({url})")
        return data

    @staticmethod
    def rdap_to_whois(rdap):
        entities = [entity for entity in rdap.get("entities", []) if isinstance(entity, dict)]

        def entity_for_role(role):
            return next((entity for entity in entities if role in entity.get("roles", [])), None)

        def vcard(entity, key):
            if not isinstance(entity, dict):
                return None
            entries = entity.get("vcardArray", [])
            if not isinstance(entries, list) or len(entries) < 2 or not isinstance(entries[1], list):
                return None
            return next((entry[3].strip() for entry in entries[1]
                         if isinstance(entry, list) and len(entry) > 3 and entry[0] == key
                         and isinstance(entry[3], str) and entry[3].strip()), None)

        def event_date(*actions):
            return next((event.get("eventDate") for event in rdap.get("events", [])
                         if isinstance(event, dict) and event.get("eventAction") in actions
                         and isinstance(event.get("eventDate"), str)), None)

        registrant = entity_for_role("registrant")
        registrar = entity_for_role("registrar")
        secure_dns = rdap.get("secureDNS")
        return {
            "registrar": vcard(registrar, "fn") or vcard(registrar, "org"),
            "creation_date": event_date("registration"),
            "expiration_date": event_date("expiration", "expiry"),
            "updated_date": event_date("last changed", "last update of rdap database", "last update"),
            "registrant_name": vcard(registrant, "fn"),
            "registrant_email": vcard(registrant, "email"),
            "registrant_org": vcard(registrant, "org"),
            "country": vcard(registrant, "country"),
            "dnssec": secure_dns.get("delegationSigned") if isinstance(secure_dns, dict) else None,
            "status": rdap["status"],
            "rdap": rdap,
        }

    def normalize_result(self, host, result):
        ownership = normalize_whois_ownership(result)
        return {
            "host": host,
            "registrar": ownership["registrar"],
            "registration_date": ownership["registration_date"],
            "expiration_date": self.to_iso(result.get("expiration_date")),
            "updated_date": self.to_iso(result.get("updated_date")),
            "registrant_name": ownership["registrant_name"],
            "registrant_email": ownership["registrant_email"],
            "registrant_org": ownership["registrant_org"],
            "registrant_country": ownership["registrant_country"],
            "dnssec": self.parse_dnssec(result.get("dnssec")),
            "whois_status": self.string_list(result.get("status")),
            "raw": {k: self.json_safe(v) for k, v in result.items() if v is not None},
        }

    def first_string(self, value):
        return whois_first_string(value)

    def string_list(self, value):
        if isinstance(value, (list, tuple, set)):
            items = [str(item).strip() for item in value if str(item).strip()]
            return list(dict.fromkeys(items)) or None
        text = self.first_string(value)
        return [text] if text else None

    def to_iso(self, value):
        if isinstance(value, (list, tuple, set)):
            for item in value:
                converted = self.to_iso(item)
                if converted:
                    return converted
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, date):
            return datetime.combine(value, datetime.min.time()).isoformat()
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    def parse_dnssec(self, value):
        if isinstance(value, bool):
            return value
        text = self.first_string(value)
        if not text:
            return None
        lowered = text.lower()
        if lowered in {"signed", "yes", "true", "1", "delegation signed"}:
            return True
        if lowered in {"unsigned", "no", "false", "0", "delegation unsigned"}:
            return False
        return None

    def json_safe(self, value):
        if isinstance(value, dict):
            return {str(k): self.json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self.json_safe(v) for v in value]
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, date):
            return datetime.combine(value, datetime.min.time()).isoformat()
        return value
