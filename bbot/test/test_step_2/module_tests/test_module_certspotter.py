from .base import ModuleTestBase


class TestCertspotter(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        for t in self.targets:
            module_test.httpx_mock.add_response(
                url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names",
                json=[{"id": "first", "dns_names": ["*.asdf.blacklanternsecurity.com"]}],
            )
            module_test.httpx_mock.add_response(
                url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names&after=first",
                json=[{"id": "second", "dns_names": ["api.dev.asdf.blacklanternsecurity.com"]}],
            )
            module_test.httpx_mock.add_response(
                url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names&after=second",
                json=[],
            )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "api.dev.asdf.blacklanternsecurity.com" for e in events), "Failed to paginate"
        requests = module_test.httpx_mock.get_requests()
        assert sum(request.url.host == "api.certspotter.com" for request in requests) == 3


class TestCertspotterPlanError(ModuleTestBase):
    module_name = "certspotter"

    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        module_test.httpx_mock.add_response(
            url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names",
            json={"code": "not_allowed_by_plan", "message": "plan restriction"},
            status_code=403,
        )

    def check(self, module_test, events):
        assert not any(e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com" for e in events)
