from .base import ModuleTestBase


class TestCRT(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        for t in self.targets:
            module_test.httpx_mock.add_response(
                url="https://crt.sh?q=blacklanternsecurity.com&output=json&exclude=expired",
                json=[{"id": 1, "name_value": "asdf.blacklanternsecurity.com\nzzzz.blacklanternsecurity.com"}],
            )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestCRTBadGateway(ModuleTestBase):
    modules_overrides = ["crt"]

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["crt"].abort_if = lambda e: False
        module_test.httpx_mock.add_response(
            url="https://crt.sh?q=blacklanternsecurity.com&output=json&exclude=expired",
            text="<html><body><h1>502 Bad Gateway</h1></body></html>",
            status_code=502,
        )

    def check(self, module_test, events):
        assert not any(e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com" for e in events)


def test_crt_preserves_issuer_baselines_and_shared_certificate_names_per_root():
    import asyncio
    from types import SimpleNamespace
    from bbot.modules.crt import crt

    module = object.__new__(crt)
    module.cert_ids = set()
    rows = [
        {
            "id": 1,
            "name_value": "app.example.com\napp.other.org",
            "common_name": "app.example.com",
            "issuer_name": "C=US, O=Google Trust Services, CN=WE1",
            "not_before": "2026-10-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "entry_timestamp": "2026-10-01T00:00:05Z",
        }
    ]
    response = SimpleNamespace(json=lambda: rows)
    first = asyncio.run(module.parse_results(response, "example.com"))
    second = asyncio.run(module.parse_results(response, "other.org"))
    assert "app.example.com" in first
    assert "app.other.org" in second
    histories = module.certificate_history_by_query
    assert len(histories["example.com"]) == 1
    assert len(histories["other.org"]) == 1
    history = next(iter(histories["example.com"].values()))
    assert history["host"] == "example.com"
    assert history["issuer"] == rows[0]["issuer_name"]
    assert history["valid_to"] == rows[0]["not_after"]
    assert history["san_domains"] == ["app.example.com", "app.other.org"]
