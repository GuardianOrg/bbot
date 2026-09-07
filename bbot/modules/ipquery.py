from bbot.modules.templates.ip_geo import ip_geo_template


class ipquery(ip_geo_template):
    """
    ipquery.io geolocation + privacy risk API (free, no API key required).
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe", "ip-enum"]
    meta = {
        "description": "Query ipquery.io API for geolocation and VPN/Tor/proxy/mobile/datacenter risk signals.",
        "created_date": "2026-08-04",
        "author": "@carlospolop",
    }

    base_url = "https://api.ipquery.io"
    api_name = "ipquery.io"

    async def handle_event(self, event):
        try:
            url = f"{self.base_url}/{event.data}"
            result = await self.helpers.request(url)
            if result:
                ip_data = result.json()
                if not ip_data:
                    self.verbose(f"No JSON response from {url}")
                    return
            else:
                self.verbose(f"No response from {url}")
                return
        except Exception:
            self.verbose(f"Error retrieving results for {event.data}", trace=True)
            return

        if not isinstance(ip_data, dict):
            return

        isp = ip_data.get("isp") if isinstance(ip_data.get("isp"), dict) else {}
        location = ip_data.get("location") if isinstance(ip_data.get("location"), dict) else {}
        risk = ip_data.get("risk") if isinstance(ip_data.get("risk"), dict) else {}

        normalized_geo_data = {
            "ip": self.clean_string(ip_data.get("ip")) or str(event.data),
            "country": self.clean_string(location.get("country")),
            "countryCode": self.clean_string(location.get("country_code")),
            "region": self.clean_string(location.get("state")),
            "city": self.clean_string(location.get("city")),
            "latitude": location.get("latitude") if isinstance(location.get("latitude"), (int, float)) else None,
            "longitude": location.get("longitude") if isinstance(location.get("longitude"), (int, float)) else None,
            "isp": self.clean_string(isp.get("org")) or self.clean_string(isp.get("isp")),
            "asn": self.clean_asn(isp.get("asn")),
            "isMobile": risk.get("is_mobile") if isinstance(risk.get("is_mobile"), bool) else None,
            "isDatacenter": risk.get("is_datacenter") if isinstance(risk.get("is_datacenter"), bool) else None,
        }
        normalized_geo_data = {k: v for k, v in normalized_geo_data.items() if v is not None}

        # vpn/proxy/tor are risk classifications: a false here means "ipquery does not flag it",
        # not "confirmed clean", so only positives are reported. is_mobile/is_datacenter are
        # network attributes and are reported in both polarities so a reassigned address corrects.
        for field, risk_key in (("isVpn", "is_vpn"), ("isProxy", "is_proxy"), ("isTor", "is_tor")):
            if risk.get(risk_key) is True:
                normalized_geo_data[field] = True

        # only "ip" survived, so the response carried nothing worth emitting
        if len(normalized_geo_data) <= 1:
            return

        await self.emit_geolocation(event, normalized_geo_data)
