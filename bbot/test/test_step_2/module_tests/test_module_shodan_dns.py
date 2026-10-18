from .base import ModuleTestBase


class TestShodan_DNS(ModuleTestBase):
    config_overrides = {"modules": {"shodan": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/api-info?key=asdf",
        )
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/dns/domain/blacklanternsecurity.com?key=asdf&page=1&history=true",
            json={
                "subdomains": ["asdf"],
                "data": [
                    {"subdomain": "asdf", "type": "A", "value": "198.51.100.10", "last_seen": "2025-01-02T03:04:05Z"},
                    {"subdomain": "", "type": "AAAA", "value": "2001:db8::1", "last_seen": "2025-01-03T03:04:05Z"},
                    {"subdomain": "asdf", "type": "MX", "value": "mail.example.com"},
                ],
                "more": True,
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/dns/domain/blacklanternsecurity.com?key=asdf&page=2&history=true",
            json={
                "subdomains": ["www"],
                "data": [
                    {
                        "subdomain": "www",
                        "type": "A",
                        "value": "198.51.100.20",
                        "first_seen": "2024-01-01",
                        "last_seen": "2025-01-01",
                    }
                ],
                "more": False,
            },
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {
                    "A": ["127.0.0.11"],
                },
                "www.blacklanternsecurity.com": {"A": ["127.0.0.22"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.33"]},
            }
        )

    def check(self, module_test, events):
        assert {e.data for e in events if e.type == "DNS_NAME"} == {
            "blacklanternsecurity.com",
            "asdf.blacklanternsecurity.com",
            "www.blacklanternsecurity.com",
        }, "Failed to detect both subdomains"
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "www.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        histories = {e.data["host"]: e.data["records"] for e in events if e.type == "DOMAIN_DNS_HISTORY"}
        assert histories["asdf.blacklanternsecurity.com"] == [
            {"ip": "198.51.100.10", "record_type": "A", "source": "shodan", "last_seen": "2025-01-02T03:04:05Z"}
        ]
        assert histories["blacklanternsecurity.com"][0]["record_type"] == "AAAA"
        assert histories["www.blacklanternsecurity.com"][0]["first_seen"] == "2024-01-01"
