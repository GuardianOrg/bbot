from .base import ModuleTestBase


class TestShodan_IDB(ModuleTestBase):
    config_overrides = {"dns": {"minimal": False}, "modules": {"shodan_idb": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "autodiscover.blacklanternsecurity.com": {"A": ["2.3.4.5"]},
                "mail.blacklanternsecurity.com": {"A": ["3.4.5.6"]},
            }
        )

        module_test.httpx_mock.add_response(
            url="https://internetdb.shodan.io/1.2.3.4",
            json={
                "cpes": [
                    "cpe:/a:microsoft:internet_information_services",
                    "cpe:/a:microsoft:outlook_web_access:15.0.1367",
                ],
                "hostnames": [
                    "autodiscover.blacklanternsecurity.com",
                    "mail.blacklanternsecurity.com",
                ],
                "ip": "1.2.3.4",
                "ports": [
                    25,
                    80,
                    443,
                ],
                "tags": ["starttls", "self-signed", "eol-os", "vpn"],
                "vulns": ["CVE-2021-26857", "CVE-2021-26855"],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/shodan/host/1.2.3.4?key=asdf",
            json={
                "ip_str": "1.2.3.4",
                "country_name": "United States",
                "region_code": "CA",
                "city": "San Francisco",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "asn": "AS13335",
                "isp": "Cloudflare, Inc.",
                "org": "Cloudflare, Inc.",
                "os": "Linux",
                "hostnames": ["edge.example.com", "cdn.example.com"],
                "tags": ["cdn", "vpn"],
                "cloud": {"provider": "Amazon", "region": "us-east-1", "service": "AMAZON"},
                "data": [{"port": 443, "os": None}],
            },
        )
        for ip in ("2.3.4.5", "3.4.5.6"):
            module_test.httpx_mock.add_response(
                url=f"https://internetdb.shodan.io/{ip}",
                status_code=404,
                json={"detail": "No information available for that IP."},
            )
            module_test.httpx_mock.add_response(
                url=f"https://api.shodan.io/shodan/host/{ip}?key=asdf",
                status_code=404,
                json={"error": "No information available for that IP."},
            )

    def check(self, module_test, events):
        assert len([e for e in events if str(e.module) == "shodan_idb"]) >= 10
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "autodiscover.blacklanternsecurity.com"]
        )
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "mail.blacklanternsecurity.com"])
        assert 3 == len(
            [
                e
                for e in events
                if e.type == "OPEN_TCP_PORT" and e.host == "blacklanternsecurity.com" and str(e.module) == "shodan_idb"
            ]
        )
        assert 1 == len([e for e in events if e.type == "FINDING" and str(e.module) == "shodan_idb"])
        assert 1 == len([e for e in events if e.type == "FINDING" and "CVE-2021-26857" in e.data["description"]])
        assert 2 == len([e for e in events if e.type == "TECHNOLOGY" and str(e.module) == "shodan_idb"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:/a:microsoft:outlook_web_access:15.0.1367"
            ]
        )
        assert any(
            e.type == "GEOLOCATION"
            and e.data["ip"] == "1.2.3.4"
            and e.data["isVpn"] is True
            and "reverseDns" not in e.data
            for e in events
        ), "Failed to emit InternetDB IP metadata"
        assert any(
            e.type == "GEOLOCATION"
            and e.data["ip"] == "1.2.3.4"
            and e.data.get("os") == "Linux"
            and e.data.get("asn") == 13335
            and e.data.get("cloudProvider") == "aws"
            and e.data.get("providerType") == "vpn"
            and e.data.get("isCdn") is True
            and e.data.get("cdnName") == "cloudflare"
            and "reverseDns" not in e.data
            for e in events
        ), "Failed to emit Shodan host API IP metadata"
