from .base import ModuleTestBase


class TestIpquery(ModuleTestBase):
    module_name = "ipquery"
    targets = ["8.8.8.8"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.ipquery.io/8.8.8.8",
            json={
                "ip": "8.8.8.8",
                "isp": {"asn": "AS15169", "org": "Google LLC", "isp": "Google LLC"},
                "location": {
                    "country": "United States",
                    "country_code": "US",
                    "city": "Mountain View",
                    "state": "California",
                    "zipcode": "94043",
                    "latitude": 37.4056,
                    "longitude": -122.0775,
                    "timezone": "America/Los_Angeles",
                    "localtime": "2026-08-04T00:00:00",
                },
                "risk": {
                    "is_mobile": False,
                    "is_vpn": False,
                    "is_tor": False,
                    "is_proxy": False,
                    "is_datacenter": True,
                    "risk_score": 0,
                },
            },
        )

    def check(self, module_test, events):
        geo_events = [e for e in events if e.type == "GEOLOCATION" and e.data.get("ip") == "8.8.8.8"]
        assert geo_events, "Failed to emit GEOLOCATION event for ipquery.io result"
        data = geo_events[0].data

        assert data["country"] == "United States"
        assert data["countryCode"] == "US"
        assert data["region"] == "California"
        assert data["city"] == "Mountain View"
        assert data["asn"] == 15169
        assert data["isp"] == "Google LLC"
        assert data["isDatacenter"] is True
        assert data["isMobile"] is False

        # Explicitly not emitted: not needed downstream and would silently downgrade
        # a positive VPN/Tor/proxy match from another source if ever true here.
        assert "isVpn" not in data
        assert "isProxy" not in data
        assert "isTor" not in data

        # Never emitted by this module at all.
        assert "zipcode" not in data
        assert "timezone" not in data
        assert "localtime" not in data
