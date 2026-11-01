from .base import ModuleTestBase
from .test_module_dehashed import osintverse_quote


class TestSnusbase(ModuleTestBase):
    config_overrides = {"modules": {"snusbase": {"osintverse_api_key": "ov_test"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json=dict(osintverse_quote, provider="snusbase"),
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            match_json={"provider": "snusbase", "input_type": "domain", "query": "blacklanternsecurity.com"},
            json={
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "status": "completed",
                "provider": "snusbase",
                "input_type": "domain",
                "query": "blacklanternsecurity.com",
                "cost_usd": "0.30",
                "balance_after": "24.00",
                "result": {
                    "sources": [{"name": "snusbase", "type": "email", "returned": 2, "total": 2}],
                    "matches": [
                        {
                            "type": "breach_record",
                            "email": "alex@blacklanternsecurity.com",
                            "username": "arivera",
                            "hashed_password": "$argon2i$v=19$example",
                            "ip_address": "203.0.113.45",
                            "database_name": "2123_BREACHFORUMS_BF_323K_HACKING_012026",
                            "leaked_at": "2024-10-19",
                        },
                        {
                            "type": "breach_record",
                            "email": "alex@blacklanternsecurity.com",
                            "password": "Summer2021!",
                            "host": "mail.blacklanternsecurity.com",
                            "database_name": "0001_STEALERLOGS_NA_121M_MALWARE_2023",
                            "leaked_at": "2023-12-01",
                        },
                    ],
                },
                "error": None,
                "poll_url": None,
            },
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "mail.blacklanternsecurity.com": {"A": ["127.0.0.2"]},
            }
        )

    def check(self, module_test, events):
        assert any(e.type == "EMAIL_ADDRESS" and e.data == "alex@blacklanternsecurity.com" for e in events)
        assert any(e.type == "USERNAME" and e.data == "alex@blacklanternsecurity.com:arivera" for e in events)
        assert any(
            e.type == "HASHED_PASSWORD" and e.data == "alex@blacklanternsecurity.com:$argon2i$v=19$example"
            for e in events
        )
        assert any(e.type == "PASSWORD" and e.data == "alex@blacklanternsecurity.com:Summer2021!" for e in events)
        assert any(e.type == "DNS_NAME" and e.data == "mail.blacklanternsecurity.com" for e in events)
