from .base import ModuleTestBase


class TestCRT(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        for t in self.targets:
            module_test.httpx_mock.add_response(
                url="https://crt.sh?q=%25.blacklanternsecurity.com&output=json",
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
            url="https://crt.sh?q=%25.blacklanternsecurity.com&output=json",
            text="<html><body><h1>502 Bad Gateway</h1></body></html>",
            status_code=502,
        )

    def check(self, module_test, events):
        assert not any(e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com" for e in events)
