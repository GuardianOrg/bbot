from .base import ModuleTestBase
from bbot.modules.chaos import PER_PARENT_CAP, _collapse


def test_chaos_collapse_filters_ptr_noise_and_keeps_normal_names():
    results, capped = _collapse(
        [
            "001.106.103.218.static",
            "000-1-246-220.static",
            "2026.release",
            "www",
        ],
        "example.com",
        "example.com",
    )

    assert results == {"2026.release.example.com", "www.example.com"}
    assert capped == []


def test_chaos_collapse_caps_nested_sibling_floods():
    children = [f"child-{index}.flood" for index in range(PER_PARENT_CAP + 1)]
    results, capped = _collapse(children, "example.com", "example.com")

    assert results == {"flood.example.com"}
    assert capped == [("flood.example.com", PER_PARENT_CAP + 1)]


class TestChaos(ModuleTestBase):
    config_overrides = {"modules": {"chaos": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/example.com",
            match_headers={"Authorization": "asdf"},
            json={"domain": "example.com", "subdomains": 65},
        )
        module_test.httpx_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/blacklanternsecurity.com/subdomains",
            match_headers={"Authorization": "asdf"},
            json={
                "domain": "blacklanternsecurity.com",
                "subdomains": [
                    "*.asdf.cloud",
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.cloud.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
