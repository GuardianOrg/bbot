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


class TestSecurityTrailsInvalidHistoryJson(ModuleTestBase):
    module_name = "securitytrails"
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
            text="",
        )
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/history/blacklanternsecurity.com/dns/aaaa?apikey=asdf&page=1",
            json={"records": []},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert not any(e.type == "DOMAIN_DNS_HISTORY" for e in events), "Unexpected DNS history from invalid JSON"


class TestSecurityTrailsOSINTverse(ModuleTestBase):
    module_name = "securitytrails"
    config_overrides = {"modules": {"securitytrails": {"osintverse_api_key": "ov_test"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json={
                "provider": "securitytrails",
                "available": True,
                "sufficient_balance": True,
                "unit_cost_usd": "0.50",
            },
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            match_json={"provider": "securitytrails", "input_type": "domain", "query": "blacklanternsecurity.com"},
            json={
                "id": "550e8400-e29b-41d4-a716-446655440003",
                "status": "completed",
                "provider": "securitytrails",
                "result": {
                    "sources": [{"name": "securitytrails", "lookup": "subdomains", "returned": 2}],
                    "matches": [
                        {
                            "type": "domain_overview",
                            "hostname": "blacklanternsecurity.com",
                            "a_records": [{"ip": "1.2.3.4", "ip_count": 1}],
                        },
                        {"type": "subdomain", "label": "asdf", "hostname": "asdf.blacklanternsecurity.com"},
                        {"type": "subdomain", "label": "api"},
                    ],
                },
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "api.blacklanternsecurity.com" for e in events), "Failed to build subdomain from label"
        assert not any(e.type == "DOMAIN_DNS_HISTORY" for e in events)
