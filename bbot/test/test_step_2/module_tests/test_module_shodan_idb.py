import re

from .base import ModuleTestBase


class TestShodan_IDB(ModuleTestBase):
    config_overrides = {"dns": {"minimal": False}, "modules": {"shodan_idb": {"api_key": '"asdf" # inline comment'}}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

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
                "data": [
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.25.4",
                        "os": None,
                        "data": "HTTP/1.1 200 OK",
                        "cpe23": ["cpe:/a:nginx:nginx:1.25.4"],
                        "ssl": {"versions": ["TLSv1.3"], "cipher": {"name": "TLS_AES_256_GCM_SHA384"}},
                        "_shodan": {"module": "https"},
                    },
                    {
                        "port": 53,
                        "transport": "udp",
                        "product": "domain",
                        "data": "recursive resolver",
                        "_shodan": {"module": "dns-udp"},
                    },
                    {
                        "port": 8080,
                        "transport": "tcp",
                        "product": "cloudflare",
                        "data": "HTTP/1.1 403 Forbidden\r\nServer: cloudflare",
                    },
                ],
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
        assert 4 == len(
            [
                e
                for e in events
                if e.type == "OPEN_TCP_PORT" and e.host == "blacklanternsecurity.com" and str(e.module) == "shodan_idb"
            ]
        )
        assert 1 == len(
            [e for e in events if e.type == "OPEN_UDP_PORT" and e.host == "blacklanternsecurity.com" and str(e.module) == "shodan_idb"]
        )
        assert 2 == len([e for e in events if e.type == "VULNERABILITY" and str(e.module) == "shodan_idb"])
        assert any(e.type == "VULNERABILITY" and e.data["title"] == "Shodan detected CVE-2021-26857" for e in events)
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
            and e.data.get("reverseDns") == ["autodiscover.blacklanternsecurity.com", "mail.blacklanternsecurity.com"]
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
            and e.data.get("reverseDns") == ["cdn.example.com", "edge.example.com"]
            for e in events
        ), "Failed to emit Shodan host API IP metadata"
        assert any(
            e.type == "PROTOCOL"
            and e.data.get("host") == "blacklanternsecurity.com"
            and e.data.get("port") == 443
            and e.data.get("protocol") == "HTTPS"
            and e.data.get("banner") == "HTTP/1.1 200 OK"
            for e in events
        ), "Failed to emit Shodan host API service metadata"
        assert any(
            e.type == "PROTOCOL"
            and e.data.get("host") == "blacklanternsecurity.com"
            and e.data.get("port") == 8080
            and e.data.get("protocol") == "HTTP"
            and e.data.get("banner") == "HTTP/1.1 403 Forbidden\r\nServer: cloudflare"
            for e in events
        ), "Failed to infer protocol from Shodan host API HTTP banner"


class TestShodan_IDB_RangeSearch(ModuleTestBase):
    module_name = "shodan_idb"
    targets = ["1.2.3.0/24"]
    config_overrides = {"scope": {"report_distance": 2}, "modules": {"shodan_idb": {"api_key": "asdf", "max_range_pages": 1}}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)
        await module_test.mock_dns({"edge.blacklanternsecurity.com": {"A": ["1.2.3.44"]}})

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=re.compile(r"https://api\.shodan\.io/shodan/host/search\?key=asdf&query=net%3A1\.2\.3\.0.*page=1&minify=false"),
            json={
                "total": 1,
                "matches": [
                    {
                        "ip_str": "1.2.3.44",
                        "hostnames": ["edge.blacklanternsecurity.com"],
                        "data": [
                            {
                                "port": 8443,
                                "transport": "tcp",
                                "product": "nginx",
                                "version": "1.25.4",
                                "data": "HTTP/1.1 200 OK",
                                "_shodan": {"module": "https"},
                            }
                        ],
                        "vulns": {
                            "CVE-2024-12345": {
                                "summary": "Example vulnerable service fingerprint.",
                                "cvss": 8.1,
                            }
                        },
                    }
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.type == "IP_ADDRESS" and e.data == "1.2.3.44" for e in events), (
            "Failed to emit IP_ADDRESS from Shodan range search"
        )
        assert any(e.type == "DNS_NAME" and e.data == "edge.blacklanternsecurity.com" for e in events), (
            "Failed to emit hostname from Shodan range search"
        )
        assert any(
            e.type == "PROTOCOL"
            and e.data.get("ip") == "1.2.3.44"
            and e.data.get("port") == 8443
            and e.data.get("protocol") == "HTTPS"
            and e.data.get("product") == "nginx"
            for e in events
        ), "Failed to emit protocol details from Shodan range search"
        assert any(
            e.type == "VULNERABILITY"
            and e.data.get("host") == "1.2.3.44"
            and e.data.get("severity") == "HIGH"
            and e.data.get("cve") == "CVE-2024-12345"
            and "Example vulnerable service fingerprint" in e.data.get("description", "")
            for e in events
        ), "Failed to emit vulnerability details from Shodan range search"
