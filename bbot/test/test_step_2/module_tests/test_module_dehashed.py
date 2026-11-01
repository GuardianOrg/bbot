from .base import ModuleTestBase


class TestDehashed(ModuleTestBase):
    modules_overrides = ["dehashed", "speculate"]
    config_overrides = {
        "scope": {"report_distance": 2},
        "modules": {"dehashed": {"api_key": "deadbeef"}},
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={
                "balance": 10000,
                "entries": [
                    {
                        "id": "4363462346",
                        "email": ["bob@blacklanternsecurity.com"],
                        "ip_address": ["127.0.0.9"],
                        "username": ["bob@bob.com"],
                        "hashed_password": ["$2a$12$pVmwJ7pXEr3mE.DmCCE4fOUDdeadbeefd2KuCy/tq1ZUFyEOH2bve"],
                        "name": ["Bob Smith"],
                        "phone": ["+91283423839"],
                        "database_name": "eatstreet",
                        "raw_record": {"le_only": True, "unstructured": True},
                    },
                    {
                        "id": "234623453454",
                        "email": ["tim@blacklanternsecurity.com"],
                        "username": ["timmy"],
                        "password": ["TimTamSlam69"],
                        "name": "Tim Tam",
                        "phone": ["+123455667"],
                        "database_name": "eatstreet",
                    },
                ],
                "took": "61ms",
                "total": 2,
            },
        )
        await module_test.mock_dns(
            {
                "bob.com": {"A": ["127.0.0.1"]},
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com"])
        assert 1 == len([e for e in events if e.type == "ORG_STUB" and e.data == "blacklanternsecurity"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "EMAIL_ADDRESS"
                and e.data == "bob@bob.com"
                and e.scope_distance == 1
                and "affiliate" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "bob.com" and e.scope_distance == 1 and "affiliate" in e.tags
            ]
        )
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "bob@blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "USERNAME"
                and e.data == "bob@blacklanternsecurity.com:bob@bob.com"
                and e.parent.data == "bob@blacklanternsecurity.com"
            ]
        )
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "tim@blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HASHED_PASSWORD"
                and e.data
                == "bob@blacklanternsecurity.com:$2a$12$pVmwJ7pXEr3mE.DmCCE4fOUDdeadbeefd2KuCy/tq1ZUFyEOH2bve"
            ]
        )
        assert 1 == len(
            [e for e in events if e.type == "PASSWORD" and e.data == "tim@blacklanternsecurity.com:TimTamSlam69"]
        )
        assert 1 == len([e for e in events if e.type == "USERNAME" and e.data == "tim@blacklanternsecurity.com:timmy"])
        self.check_structured(events)

    def check_structured(self, events):
        leaks = [e for e in events if e.type == "LEAKED_CREDENTIAL"]
        assert 2 == len(leaks)
        bob = next(e for e in leaks if e.data.get("email") == "bob@blacklanternsecurity.com")
        assert bob.data["domain"] == "blacklanternsecurity.com"
        assert bob.data["provider"] == "dehashed"
        assert bob.data["username"] == "bob@bob.com"
        assert bob.data["hashed_password"].startswith("$2a$12$")
        assert "password" not in bob.data
        assert bob.data["database_name"] == "eatstreet"
        assert bob.parent.type == "EMAIL_ADDRESS" and bob.parent.data == "bob@blacklanternsecurity.com"
        tim = next(e for e in leaks if e.data.get("email") == "tim@blacklanternsecurity.com")
        assert tim.data["password"] == "TimTamSlam69"
        profiles = {e.data["email"]: e for e in events if e.type == "EMAIL_PROFILE"}
        assert profiles["bob@blacklanternsecurity.com"].data["full_name"] == "Bob Smith"
        assert profiles["bob@blacklanternsecurity.com"].data["phone_number"] == "+91283423839"
        assert profiles["bob@blacklanternsecurity.com"].data["ip_address"] == "127.0.0.9"
        assert profiles["bob@blacklanternsecurity.com"].data["provider"] == "dehashed"
        assert profiles["bob@blacklanternsecurity.com"].data["sources"] == ["eatstreet"]
        assert profiles["tim@blacklanternsecurity.com"].data["full_name"] == "Tim Tam"
        assert profiles["tim@blacklanternsecurity.com"].parent.data == "tim@blacklanternsecurity.com"


class TestDehashedNoLegacyEvents(TestDehashed):
    config_overrides = {
        "scope": {"report_distance": 2},
        "modules": {"dehashed": {"api_key": "deadbeef", "legacy_events": False}},
    }

    def check(self, module_test, events):
        assert not any(e.type in ("PASSWORD", "HASHED_PASSWORD", "USERNAME") for e in events)
        self.check_structured(events)


class TestDehashedBadEmail(TestDehashed):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={
                "balance": 10000,
                "entries": [
                    {
                        "id": "EZxg4Lz-INLUt6uRXZaV",
                        "email": ["foo.example.com"],
                        "database_name": "Collections",
                    },
                ],
                "took": "41ms",
                "total": 1,
            },
        )

    def check(self, module_test, events):
        debug_log_content = open(module_test.scan.home / "debug.log").read()
        assert "Invalid email from dehashed.com: foo.example.com" in debug_log_content


class TestDehashedHTTPError(TestDehashed):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={"error": "issue with request body"},
            status_code=400,
        )

    def check(self, module_test, events):
        scan_log_content = open(module_test.scan.home / "scan.log").read()
        assert (
            'Error retrieving results from dehashed.com (status code 400): {"error":"issue with request body"}'
            in scan_log_content
        )


class TestDehashedTooManyResults(TestDehashed):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.dehashed.com/v2/search",
            method="POST",
            json={
                "balance": 10000,
                "entries": [
                    {
                        "id": "VXhNxj46SGsW4Lworh-G",
                        "email": ["bob@bob.com"],
                        "database_name": "Collections",
                    },
                ],
                "took": "40ms",
                "total": 10001,
            },
        )

    def check(self, module_test, events):
        scan_log_content = open(module_test.scan.home / "scan.log").read()
        assert "has 10,001 results in Dehashed. The API can only process the first 10,000 results." in scan_log_content


osintverse_quote = {
    "provider": "dehashed",
    "input_type": "domain",
    "count": 1,
    "premium": False,
    "available": True,
    "unit_cost_usd": "0.30",
    "total_cost_usd": "0.30",
    "balance_usd": "24.30",
    "sufficient_balance": True,
    "shortfall_usd": "0.00",
    "top_up_url": "https://osintverse.com/dashboard/billing",
}


class TestDehashedOSINTverse(ModuleTestBase):
    module_name = "dehashed"
    modules_overrides = ["dehashed", "speculate"]
    config_overrides = {
        "scope": {"report_distance": 2},
        "modules": {"dehashed": {"osintverse_api_key": "ov_test"}},
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            match_headers={"x-api-key": "ov_test"},
            json=osintverse_quote,
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            match_headers={"x-api-key": "ov_test"},
            match_json={"provider": "dehashed", "input_type": "domain", "query": "blacklanternsecurity.com"},
            json={
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "completed",
                "provider": "dehashed",
                "input_type": "domain",
                "query": "blacklanternsecurity.com",
                "cost_usd": "0.30",
                "balance_after": "24.00",
                "result": {
                    "sources": [{"name": "dehashed", "type": "email", "returned": 3, "total": 3}],
                    "matches": [
                        {
                            "type": "breach_record",
                            "id": "1",
                            "email": "tim@blacklanternsecurity.com",
                            "username": "timmy",
                            "password": "TimTamSlam69",
                            "database_name": "eatstreet",
                            "leaked_at": "2021-06-15",
                        },
                        {
                            "type": "breach_record",
                            "id": "2",
                            "email": "bob@blacklanternsecurity.com",
                            "hashed_password": "5f4dcc3b5aa765d61d8327deb882cf99",
                            "database_name": "Collection_1",
                        },
                        {
                            "type": "breach_record",
                            "id": "3",
                            "username": "svc_backup",
                            "password": "Backup2020",
                            "database_name": "Collection_1",
                        },
                    ],
                },
                "error": None,
                "poll_url": None,
            },
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.type == "USERNAME" and e.data == "tim@blacklanternsecurity.com:timmy"])
        assert 1 == len(
            [e for e in events if e.type == "PASSWORD" and e.data == "tim@blacklanternsecurity.com:TimTamSlam69"]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HASHED_PASSWORD"
                and e.data == "bob@blacklanternsecurity.com:5f4dcc3b5aa765d61d8327deb882cf99"
                and "db-collection-1" in e.tags
            ]
        )
        assert 1 == len([e for e in events if e.type == "USERNAME" and e.data == "svc_backup"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "PASSWORD" and e.data == "svc_backup:Backup2020" and e.parent.data == "svc_backup"
            ]
        )
        leaks = [e for e in events if e.type == "LEAKED_CREDENTIAL"]
        assert 3 == len(leaks)
        svc = next(e for e in leaks if e.data.get("username") == "svc_backup")
        assert svc.data["password"] == "Backup2020" and "email" not in svc.data
        # without an email the leak hangs off the searched domain
        assert svc.parent.type == "DNS_NAME" and svc.parent.data == "blacklanternsecurity.com"
        tim = next(e for e in leaks if e.data.get("email") == "tim@blacklanternsecurity.com")
        assert tim.data["leaked_at"] == "2021-06-15"


class TestDehashedOSINTverseRawEntries(ModuleTestBase):
    """OSINTverse passes DeHashed's own entries through: they keep the login URLs and every hash."""

    module_name = "dehashed"
    modules_overrides = ["dehashed", "speculate"]
    config_overrides = {
        "scope": {"report_distance": 2},
        "modules": {"dehashed": {"osintverse_api_key": "ov_test"}},
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote", method="POST", json=osintverse_quote
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            json={
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "status": "completed",
                "result": {
                    "sources": [{"name": "dehashed", "type": "email", "returned": 2, "total": 2}],
                    "matches": [
                        {"type": "breach_record", "id": "1", "email": "tim@blacklanternsecurity.com"},
                        {"type": "breach_record", "id": "2", "password": "x", "hashed_password": "a, b"},
                    ],
                    "raw": {
                        "entries": [
                            {
                                "id": "1",
                                "email": ["tim@blacklanternsecurity.com"],
                                "password": ["TimTamSlam69"],
                                "database_name": "eatstreet",
                            },
                            {
                                "id": "2",
                                "password": ["StealerPass1"],
                                "hashed_password": ["5f4dcc3b5aa765d61d8327deb882cf99", "$2a$12$deadbeef"],
                                "url": ["https://vpn.blacklanternsecurity.com/login"],
                                "database_name": "ALIEN TXTBASE",
                            },
                        ]
                    },
                },
            },
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "vpn.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        leaks = [e for e in events if e.type == "LEAKED_CREDENTIAL"]
        tim = next(e for e in leaks if e.data.get("email") == "tim@blacklanternsecurity.com")
        assert tim.data["password"] == "TimTamSlam69"
        # a record with no email, username or phone is kept and tied to the domain, one leak per secret
        stealer = [e for e in leaks if e.data.get("database_name") == "ALIEN TXTBASE"]
        assert {e.data.get("password") or e.data.get("hashed_password") for e in stealer} == {
            "StealerPass1",
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "$2a$12$deadbeef",
        }
        for leak in stealer:
            assert leak.data["login_url"] == "https://vpn.blacklanternsecurity.com/login"
            assert leak.data["host"] == "vpn.blacklanternsecurity.com"
            assert leak.data["domain"] == "blacklanternsecurity.com"
            assert not any(leak.data.get(k) for k in ("email", "username", "phone"))
            assert leak.parent.type == "DNS_NAME" and leak.parent.data == "blacklanternsecurity.com"
        assert any(e.type == "DNS_NAME" and e.data == "vpn.blacklanternsecurity.com" for e in events)
        assert any(
            e.type == "PASSWORD" and e.data == "https://vpn.blacklanternsecurity.com/login:StealerPass1"
            for e in events
        )


class TestDehashedOSINTverseInsufficientBalance(TestDehashedOSINTverse):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json=dict(osintverse_quote, balance_usd="0.10", sufficient_balance=False, shortfall_usd="0.20"),
        )

    def check(self, module_test, events):
        # setup soft-fails on the free price quote, so no billed search is ever made
        assert "dehashed" not in module_test.scan.modules
        assert not any(e.type in ("PASSWORD", "HASHED_PASSWORD", "USERNAME") for e in events)
