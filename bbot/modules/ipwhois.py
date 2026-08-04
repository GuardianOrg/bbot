from bbot.modules.templates.ip_geo import ip_geo_template


class ipwhois(ip_geo_template):
    """
    ipwho.is geolocation API (free, no API key required for basic use).
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe", "ip-enum"]
    meta = {
        "description": "Query ipwho.is API for geolocation information.",
        "created_date": "2026-02-23",
        "author": "@carlospolop",
    }
    options = {"lang": ""}
    options_desc = {
        "lang": "Optional language for localized location names (ISO 639-1).",
    }

    base_url = "https://ipwho.is"
    api_name = "ipwho.is"

    async def setup(self):
        self.lang = str(self.config.get("lang", "")).strip()
        return True

    def build_url(self, data):
        url = f"{self.base_url}/{data}"
        if self.lang:
            url = f"{url}?lang={self.lang}"
        return url

    async def handle_event(self, event):
        try:
            url = self.build_url(event.data)
            result = await self.helpers.request(url)
            if result:
                geo_data = result.json()
                if not geo_data:
                    self.verbose(f"No JSON response from {url}")
            else:
                self.verbose(f"No response from {url}")
                return
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            return

        if not isinstance(geo_data, dict):
            return
        geo_data = {k: v for k, v in geo_data.items() if v is not None}
        if not geo_data.get("success", True):
            error_msg = geo_data.get("message", "")
            if error_msg:
                self.warning(error_msg)
            return

        normalized_geo_data = {
            **geo_data,
            "ip": self.clean_string(geo_data.get("ip")) or str(event.data),
            "country": self.clean_string(geo_data.get("country")),
            "countryCode": self.clean_string(geo_data.get("country_code")),
            "region": self.clean_string(geo_data.get("region")),
            "city": self.clean_string(geo_data.get("city")),
            "latitude": geo_data.get("latitude") if isinstance(geo_data.get("latitude"), (int, float)) else None,
            "longitude": geo_data.get("longitude") if isinstance(geo_data.get("longitude"), (int, float)) else None,
            "isp": self.clean_string(geo_data.get("connection", {}).get("isp") if isinstance(geo_data.get("connection"), dict) else None),
            "asn": self.clean_asn(geo_data.get("connection", {}).get("asn") if isinstance(geo_data.get("connection"), dict) else None),
            "cloudProvider": self.clean_string(geo_data.get("datacenter", {}).get("datacenter") if isinstance(geo_data.get("datacenter"), dict) else None),
            "providerType": self.clean_string(geo_data.get("company", {}).get("type") if isinstance(geo_data.get("company"), dict) else None),
        }
        normalized_geo_data = {k: v for k, v in normalized_geo_data.items() if v not in (None, "", [])}

        await self.emit_geolocation(event, normalized_geo_data)
