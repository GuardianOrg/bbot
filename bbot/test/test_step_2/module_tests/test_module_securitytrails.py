from .base import ModuleTestBase


class TestSecurityTrails(ModuleTestBase):
    config_overrides = {"modules": {"securitytrails": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/ping?apikey=asdf",
        )
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/domain/blacklanternsecurity.com/subdomains?apikey=asdf",
            json={
                "subdomains": [
                    "asdf",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/history/blacklanternsecurity.com/dns/a?apikey=asdf&page=1",
            json={
                "records": [
                    {
                        "first_seen": "2020-01-01",
                        "last_seen": "2020-06-01",
                        "values": [{"ip": "1.2.3.4"}],
                    }
                ]
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/history/blacklanternsecurity.com/dns/aaaa?apikey=asdf&page=1",
            json={"records": []},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(
            e.type == "DOMAIN_DNS_HISTORY"
            and e.data["host"] == "blacklanternsecurity.com"
            and e.data["records"][0]["ip"] == "1.2.3.4"
            for e in events
        ), "Failed to emit DNS history"
