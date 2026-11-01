from .base import ModuleTestBase
from .test_module_dehashed import osintverse_quote


leakradar_search = {
    "id": "550e8400-e29b-41d4-a716-446655440002",
    "status": "completed",
    "provider": "leakradar",
    "input_type": "domain",
    "query": "blacklanternsecurity.com",
    "cost_usd": "1.00",
    "balance_after": "24.00",
    "result": {
        "sources": [
            {
                "name": "leakradar",
                "type": "domain",
                "total": 1071,
                "employees_compromised": 128,
                "third_parties_compromised": 41,
                "customers_compromised": 902,
                "total_unlocked": 1000,
            }
        ],
        "matches": [
            {"type": "domain_summary", "domain": "blacklanternsecurity.com", "employees_compromised": 128},
            {"type": "password_strength", "category": "employee_passwords", "total_pass": 128},
            {
                "type": "leak",
                "id": "lr_emp_01",
                "url": "https://mail.blacklanternsecurity.com/login",
                "username": "jane.doe@blacklanternsecurity.com",
                "password": "Winter2022!",
                "unlocked": True,
                "is_email": True,
                "added_at": "2025-01-15T10:30:00Z",
                "password_strength": 6,
                "category": "employees",
            },
            {
                "type": "leak",
                "id": "lr_emp_02",
                "url": "https://vpn.blacklanternsecurity.com",
                "username": "jdoe",
                "password": "CorpVPN#99",
                "unlocked": True,
                "is_email": False,
                "added_at": "2024-08-02T14:12:00Z",
                "password_strength": "strong",
                "category": "employees",
            },
            {
                "type": "leak",
                "id": "lr_cust_01",
                "url": "https://shop.blacklanternsecurity.com/account",
                "username": "shopper42@mail.com",
                "password": "hunter2-demo",
                "unlocked": True,
                "is_email": True,
                "added_at": "2023-11-20T09:05:00Z",
                "category": "customers",
            },
            {
                "type": "leak",
                "id": "lr_tp_01",
                "url": "android://abc@com.example.app/",
                "username": "vendor.ops",
                "password": None,
                "unlocked": False,
                "is_email": False,
                "category": "third_parties",
            },
        ],
    },
    "error": None,
    "poll_url": None,
}


class TestLeakradar(ModuleTestBase):
    config_overrides = {
        "modules": {"leakradar": {"osintverse_api_key": "ov_test", "categories": ["employees", "third_parties"]}}
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json=dict(osintverse_quote, provider="leakradar", unit_cost_usd="1.00"),
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            match_json={"provider": "leakradar", "input_type": "domain", "query": "blacklanternsecurity.com"},
            json=leakradar_search,
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "vpn.blacklanternsecurity.com": {"A": ["127.0.0.2"]},
            }
        )

    def check(self, module_test, events):
        assert any(
            e.type == "PASSWORD"
            and e.data == "jane.doe@blacklanternsecurity.com:Winter2022!"
            and "leakradar-employees" in e.tags
            and any(t.startswith("leak-indexed-at-") for t in e.tags)
            for e in events
        )
        assert any(e.type == "PASSWORD" and e.data == "jdoe:CorpVPN#99" for e in events)
        assert any(e.type == "USERNAME" and e.data == "vendor.ops" for e in events)
        assert any(e.type == "URL_UNVERIFIED" and e.data == "https://vpn.blacklanternsecurity.com/" for e in events)
        # customers are filtered out by the categories option
        assert not any("shopper42" in str(e.data) for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "android" in e.data for e in events)
        scan_log_content = open(module_test.scan.home / "scan.log").read()
        assert "LeakRadar has 71 more locked credentials" in scan_log_content
        leaks = [e for e in events if e.type == "LEAKED_CREDENTIAL"]
        jane = next(e for e in leaks if e.data.get("email") == "jane.doe@blacklanternsecurity.com")
        assert jane.data["password"] == "Winter2022!"
        assert jane.data["category"] == "employees"
        assert jane.data["password_strength"] == 6
        assert jane.data["login_url"] == "https://mail.blacklanternsecurity.com/login"
        assert jane.data["indexed_at"] == "2025-01-15T10:30:00Z"
        # a leak for a subdomain login is kept on that subdomain, which is reported too
        jdoe = next(e for e in leaks if e.data.get("username") == "jdoe")
        assert jdoe.data["host"] == "vpn.blacklanternsecurity.com"
        # a score that is not a number is dropped, not the leak
        assert "password_strength" not in jdoe.data
        assert jdoe.data["domain"] == "blacklanternsecurity.com"
        assert any(e.type == "DNS_NAME" and e.data == "vpn.blacklanternsecurity.com" for e in events)
        vendor = next(e for e in leaks if e.data.get("username") == "vendor.ops")
        assert "password" not in vendor.data and vendor.data["category"] == "third_parties"


class TestLeakradarRunning(TestLeakradar):
    """Searches that come back "running" are polled until they complete."""

    module_name = "leakradar"

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json=dict(osintverse_quote, provider="leakradar", unit_cost_usd="1.00"),
        )
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search",
            method="POST",
            json=dict(leakradar_search, status="running", result=None),
        )
        module_test.httpx_mock.add_response(
            url=f"https://apiv1.osintverse.com/v1/search/{leakradar_search['id']}",
            method="GET",
            json=leakradar_search,
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "vpn.blacklanternsecurity.com": {"A": ["127.0.0.2"]},
            }
        )


class TestLeakradarSubdomainTarget(ModuleTestBase):
    """Only registrable domains are searched: a subdomain target never triggers a billed search."""

    module_name = "leakradar"
    targets = ["www.blacklanternsecurity.com"]
    config_overrides = {"modules": {"leakradar": {"osintverse_api_key": "ov_test"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://apiv1.osintverse.com/v1/search/quote",
            method="POST",
            json=dict(osintverse_quote, provider="leakradar", unit_cost_usd="1.00"),
        )

    def check(self, module_test, events):
        assert not any(r.url.path == "/v1/search" for r in module_test.httpx_mock.get_requests())
        assert not any(e.type == "LEAKED_CREDENTIAL" for e in events)
