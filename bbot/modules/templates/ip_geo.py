from bbot.modules.base import BaseModule


class ip_geo_template(BaseModule):
    """
    A free API-based IP geolocation module.
    Inherited by ipwhois, ipquery, etc.
    """

    # NOTE: watched_events / produced_events / flags / meta are read straight out of each module's
    # source by the AST preloader (see core/modules.py), so subclasses must declare their own even
    # though these defaults would be inherited at runtime.
    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe", "ip-enum"]

    base_url = "https://api.example.com"

    # geolocation is enrichment for addresses the scan already found, not a way to widen scope
    scope_distance_modifier = 1
    _priority = 2
    # the same address can be re-enriched by a later, better-informed answer
    suppress_dupes = False

    # human-readable service name, used in the emitted event context
    api_name = "example.com"
    # address used to health-check the API
    ping_ip = "8.8.8.8"

    async def ping(self, url=None):
        await super().ping(url or f"{self.base_url}/{self.ping_ip}")

    async def emit_geolocation(self, event, geo_data):
        country = geo_data.get("country", "unknown country")
        region = geo_data.get("region", "unknown region")
        city = geo_data.get("city", "unknown city")
        lat = geo_data.get("latitude", "")
        long = geo_data.get("longitude", "")
        description = f"{city}, {region}, {country} ({lat}, {long})"
        await self.emit_event(
            geo_data,
            "GEOLOCATION",
            event,
            context=f'{{module}} queried {self.api_name} API for "{event.data}" and found {{event.type}}: {description}',
        )

    def clean_string(self, value):
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def clean_asn(self, value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            value = value.strip().upper()
            if value.startswith("AS"):
                value = value[2:]
            if value.isdigit():
                return int(value)
        return None
