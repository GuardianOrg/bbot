from bbot.modules.base import BaseModule


class Ipstack(BaseModule):
    """
    Ipstack GeoIP
    Leverages the ipstack.com API to geolocate a host by IP address.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe", "ip-enum"]
    meta = {
        "description": "Query IPStack's GeoIP API",
        "created_date": "2022-11-26",
        "author": "@tycoonslive",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "IPStack GeoIP API Key"}
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "http://api.ipstack.com"
    ping_url = f"{base_url}/check?access_key={{api_key}}"

    async def setup(self):
        return await self.require_api_key()

    async def handle_event(self, event):
        geo_data = {}
        try:
            url = f"{self.base_url}/{event.data}?access_key={{api_key}}"
            result = await self.api_request(url)
            if not result:
                self.verbose(f"No response from {url}")
                return
            geo_data = result.json()
            if not isinstance(geo_data, dict) or not geo_data:
                self.verbose(f"No JSON response from {url}")
                return
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            return
        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if "error" in geo_data:
            error = geo_data.get("error") or {}
            if not isinstance(error, dict):
                error = {"info": str(error)}
            error_msg = error.get("info", "")
            if error_msg:
                self.warning(error_msg)
            return
        elif geo_data:
            normalized_geo_data = {
                **geo_data,
                "country": self.clean_string(geo_data.get("country_name")),
                "region": self.clean_string(geo_data.get("region_name")),
                "city": self.clean_string(geo_data.get("city")),
                "latitude": geo_data.get("latitude") if isinstance(geo_data.get("latitude"), (int, float)) else None,
                "longitude": geo_data.get("longitude") if isinstance(geo_data.get("longitude"), (int, float)) else None,
            }
            normalized_geo_data = {k: v for k, v in normalized_geo_data.items() if v not in (None, "", [])}
            country = normalized_geo_data.get("country", "unknown country")
            region = normalized_geo_data.get("region", "unknown region")
            city = normalized_geo_data.get("city", "unknown city")
            lat = normalized_geo_data.get("latitude", "")
            long = normalized_geo_data.get("longitude", "")
            description = f"{city}, {region}, {country} ({lat}, {long})"
            await self.emit_event(
                normalized_geo_data,
                "GEOLOCATION",
                event,
                context=f'{{module}} queried ipstack.com\'s API for "{event.data}" and found {{event.type}}: {description}',
            )

    def clean_string(self, value):
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None
