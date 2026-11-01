from .base import ModuleTestBase
from .test_module_dehashed import osintverse_quote


class TestLeakosintbot(ModuleTestBase):
    config_overrides = {"modules": {"leakosintbot": {"osintverse_api_key": "ov_test"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json=dict(osintverse_quote, provider="leakosintbot", unit_cost_usd="0.20"),
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            match_json={"provider": "leakosintbot", "input_type": "domain", "query": "blacklanternsecurity.com"},
            json={
                "id": "550e8400-e29b-41d4-a716-446655440002",
                "status": "completed",
                "provider": "leakosintbot",
                "input_type": "domain",
                "query": "blacklanternsecurity.com",
                "cost_usd": "0.20",
                "balance_after": "24.00",
                "result": {
                    "sources": [
                        {
                            "name": "leakosintbot",
                            "type": "username",
                            "num_of_databases": 3,
                            "num_of_results": 6,
                            "price": 0,
                        }
                    ],
                    "matches": [
                        {
                            "type": "breach_database",
                            "name": "Alien TxtBase",
                            "info_leak": "Stealer logs",
                            "num_of_results": 3,
                            "data": [
                                {
                                    "Email": "alex@blacklanternsecurity.com",
                                    "Password": "Summer2021!",
                                    "Url": "portal.blacklanternsecurity.com/login/",
                                },
                                {
                                    "NickName": "arivera",
                                    "Password": "Winter2022!",
                                    "Url": "blacklanternsecurity.com/wp-login.php",
                                },
                                {
                                    "Phone": "15555550100",
                                    "Password": "Spring2023!",
                                    "Url": "blacklanternsecurity.com/",
                                },
                                {
                                    "Email": "bob@gmail.com",
                                    "Password": "hunter2",
                                    "Url": "evil.example.com/login",
                                },
                            ],
                        },
                        {
                            "type": "breach_database",
                            "name": "RockYou 2024",
                            "num_of_results": 1,
                            "data": [{"Password": "Blacklantern1"}],
                        },
                        {
                            "type": "breach_database",
                            "name": "Collection #1",
                            "num_of_results": 2,
                            "data": [
                                {
                                    "Email": "jane@blacklanternsecurity.com",
                                    "Password(MD5)": "5f4dcc3b5aa765d61d8327deb882cf99",
                                },
                                {"Login": "jdoe", "Hash": "$2y$10$example"},
                            ],
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
                "portal.blacklanternsecurity.com": {"A": ["127.0.0.2"]},
            }
        )

    def check(self, module_test, events):
        assert any(e.type == "EMAIL_ADDRESS" and e.data == "alex@blacklanternsecurity.com" for e in events)
        assert any(e.type == "PASSWORD" and e.data == "alex@blacklanternsecurity.com:Summer2021!" for e in events)
        assert any(e.type == "USERNAME" and e.data == "arivera" for e in events)
        assert any(e.type == "PASSWORD" and e.data == "arivera:Winter2022!" for e in events)
        assert any(e.type == "PASSWORD" and e.data == "15555550100:Spring2023!" for e in events)
        assert any(
            e.type == "HASHED_PASSWORD" and e.data == "jane@blacklanternsecurity.com:5f4dcc3b5aa765d61d8327deb882cf99"
            for e in events
        )
        assert any(e.type == "HASHED_PASSWORD" and e.data == "jdoe:$2y$10$example" for e in events)
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://portal.blacklanternsecurity.com/login/" for e in events
        )
        # leaked URLs outside the searched domain are not emitted
        assert not any(e.type == "URL_UNVERIFIED" and "evil.example.com" in e.data for e in events)
        # password-only rows (e.g. RockYou) have no account: they are tied to the searched domain
        assert any(e.type == "PASSWORD" and e.data == "blacklanternsecurity.com:Blacklantern1" for e in events)
        assert any("db-alien-txtbase" in e.tags for e in events if e.type == "EMAIL_ADDRESS")

        leaks = [e for e in events if e.type == "LEAKED_CREDENTIAL"]
        phone = next(e for e in leaks if e.data.get("phone") == "15555550100")
        assert phone.data["password"] == "Spring2023!"
        assert phone.data["login_url"] == "https://blacklanternsecurity.com/"
        assert phone.data["database_description"] == "Stealer logs"
        assert phone.parent.type == "DNS_NAME"
        jane = next(e for e in leaks if e.data.get("email") == "jane@blacklanternsecurity.com")
        assert jane.data["hash_type"] == "md5"
        assert jane.data["database_name"] == "Collection #1"
        assert jane.parent.type == "EMAIL_ADDRESS"
        # leaks for addresses at other domains stay attached to the searched domain, not the foreign address
        gmail = next(e for e in leaks if e.data.get("email") == "bob@gmail.com")
        assert gmail.data["domain"] == "blacklanternsecurity.com"
        assert gmail.parent.type == "DNS_NAME"
        rockyou = next(e for e in leaks if e.data.get("password") == "Blacklantern1")
        assert rockyou.data["host"] == "blacklanternsecurity.com"
        assert rockyou.data["domain"] == "blacklanternsecurity.com"
        assert rockyou.data["database_name"] == "RockYou 2024"
        assert not any(rockyou.data.get(k) for k in ("email", "username", "phone"))
        assert rockyou.parent.type == "DNS_NAME" and rockyou.parent.data == "blacklanternsecurity.com"
