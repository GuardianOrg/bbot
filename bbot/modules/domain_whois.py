import asyncio
from datetime import date, datetime

from bbot.core.helpers.whois import normalize_whois_ownership, whois_first_string
from bbot.modules.base import BaseModule


class domain_whois(BaseModule):
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

    async def handle_event(self, event):
        _, registered_domain = self.helpers.split_domain(str(event.data).lower())
        target = registered_domain.lower() if registered_domain else str(event.data).lower()
        if not target:
            return

        try:
            result = await asyncio.to_thread(self.lookup_whois, target)
        except Exception:
            self.verbose(f"Error retrieving WHOIS for {target}", trace=True)
            return

        if not isinstance(result, dict):
            return

        payload = self.normalize_result(target, result)
        if len(payload) <= 2:
            return

        await self.emit_event(
            payload,
            "DOMAIN_WHOIS",
            parent=event,
            context=f'{{module}} queried WHOIS for "{target}" and produced {{event.type}}',
        )

    def lookup_whois(self, domain):
        import whois

        data = whois.whois(domain)
        if isinstance(data, dict):
            return data
        return dict(data) if data else {}

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
