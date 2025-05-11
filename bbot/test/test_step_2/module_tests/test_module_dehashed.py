from .base import ModuleTestBase

dehashed_domain_response = {
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
}


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
            json=dehashed_domain_response,
        )
        await module_test.mock_dns(
            {
                "bob.com": {"A": ["127.0.0.1"]},
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        assert len(events) == 12
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
