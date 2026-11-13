from urllib.parse import urlsplit

from bbot.modules.base import BaseInterceptModule
from bbot.modules.retirejs import RETIREJS_REPOSITORY_URL

# Discovery around a website: none of it belongs to a scan that was given only exact origins.
NON_WEBSITE_EVENT_TYPES = {
    "DNS_NAME",
    "DNS_NAME_UNRESOLVED",
    "RAW_DNS_RECORD",
    "IP_ADDRESS",
    "IP_RANGE",
    "OPEN_TCP_PORT",
    "OPEN_UDP_PORT",
    "PROTOCOL",
    "TLS_CERTIFICATE",
    "EMAIL_ADDRESS",
    "CODE_REPOSITORY",
    "CODE_REPOSITORY_OWNER",
}
SCAN_LIFECYCLE_EVENT_TYPES = {"SCAN", "FINISHED"}
GROUPED_SUMMARY_MODULE = "hardening_aggregate"
GROUPED_SUMMARY_CATEGORY = "grouped-hardening"
# Engine downloads that are tooling input, never a scan target; they go out without the scan's headers.
TOOLING_URLS = {RETIREJS_REPOSITORY_URL}
# How far up an event's parents to look for the website it came from.
MAX_ORIGIN_ANCESTORS = 10
DEFAULT_PORTS = {"http": 80, "https": 443}


def event_url(value):
    data = getattr(value, "data", value)
    if isinstance(data, dict):
        data = data.get("url")
    return data if isinstance(data, str) and data.startswith(("http://", "https://")) else None


def url_origin(value):
    """(scheme, host, port) of a URL or URL-bearing event; None for anything else or a URL with credentials."""
    try:
        parsed = urlsplit(event_url(value) or "")
        if parsed.scheme not in DEFAULT_PORTS or not parsed.hostname or parsed.username or parsed.password:
            return None
        return parsed.scheme, parsed.hostname.lower().rstrip("."), parsed.port or DEFAULT_PORTS[parsed.scheme]
    except ValueError:
        return None


class website_origin_policy(BaseInterceptModule):
    """Keeps a website-only scan on the exact origins it was given. Without origins it lets everything through."""

    watched_events = ["*"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Limit a website-only scan to its exact HTTP origins",
        "created_date": "2026-11-07",
        "author": "@carlospolop",
    }
    options = {"website_origins": []}
    options_desc = {"website_origins": "Exact website origins of a website-only scan; empty for an organisation scan"}
    scope_distance_modifier = None
    # Ahead of every other intercept module, so nothing resolves or classifies a refused event.
    _priority = -1
    _disable_auto_module_deps = True

    async def setup(self):
        self.origins = {url_origin(value) for value in self.config.get("website_origins", [])}
        self.origins.discard(None)
        if self.origins:
            self._bound_engine_requests()
        return True

    def _bound_engine_requests(self):
        """Engine requests made by any module stay on the origins, carry the scan's headers and never follow a
        redirect off them."""
        web = self.helpers.web
        for method in ("request", "download"):
            original = getattr(web, method)

            async def bounded(url, *args, _original=original, **kwargs):
                if str(url) in TOOLING_URLS:
                    kwargs["headers"] = {}
                elif url_origin(str(url)) in self.origins:
                    kwargs["headers"] = {**(kwargs.get("headers") or {}), **dict(self.scan.custom_http_headers)}
                else:
                    return None
                kwargs.pop("allow_redirects", None)
                kwargs["follow_redirects"] = False
                return await _original(url, *args, **kwargs)

            setattr(web, method, bounded)

    async def handle_event(self, event, **kwargs):
        if not self.origins or event.type in SCAN_LIFECYCLE_EVENT_TYPES:
            return True
        if event.type == "TLS_CERTIFICATE":
            # Keep the certificate of the supplied HTTPS endpoint, never SAN
            # discoveries or an unbound certificate borrowed from an ancestor.
            origin = url_origin(event)
            if origin in self.origins and origin[0] == "https":
                return True
            return False, "certificate is not tied to an explicit HTTPS origin"
        if event.type in NON_WEBSITE_EVENT_TYPES:
            return False, "website-only scan does not discover around its origins"
        if self._is_grouped_summary(event):
            # The summary's parent is the scan root, so its origins are the endpoints it lists.
            endpoints = event.data.get("affected_endpoints")
            origins = {url_origin(endpoint) for endpoint in endpoints} if isinstance(endpoints, list) else set()
            if origins and origins <= self.origins:
                return True
            return False, "grouped summary names a website outside the scan's origins"
        candidate = event
        for _ in range(MAX_ORIGIN_ANCESTORS):
            origin = url_origin(candidate)
            if origin:
                return True if origin in self.origins else (False, "URL is outside the scan's website origins")
            parent = getattr(candidate, "parent", None)
            if parent is None or parent is candidate:
                break
            candidate = parent
        return False, "event is not tied to one of the scan's website origins"

    @staticmethod
    def _is_grouped_summary(event):
        data = getattr(event, "data", None)
        return (
            getattr(event, "type", "") in {"FINDING", "VULNERABILITY"}
            and isinstance(data, dict)
            and data.get("category") == GROUPED_SUMMARY_CATEGORY
            and str(getattr(event, "module", "") or "") == GROUPED_SUMMARY_MODULE
        )
