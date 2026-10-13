from .base import ModuleTestBase

from werkzeug.wrappers import Response


class TestWafw00f(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wafw00f"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "WAF" and "LiteSpeed" in e.data["waf"] for e in events)


class TestWafw00f_all(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wafw00f"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(expect_args={"method": "GET", "uri": "/"},
                                        respond_args={"response_data": "alive"})

        class StackedWafs:
            def __init__(self, url, followredirect=False):
                self.url = url

            def identwaf(self, findall=False):
                assert findall is True
                return ["Cloudfront (Amazon)", "Cloudflare (Cloudflare Inc.)"], self.url

        module_test.monkeypatch.setattr("bbot.modules.wafw00f.wafw00f_main.WAFW00F", StackedWafs)

    def check(self, module_test, events):
        assert {e.data["waf"] for e in events if e.type == "WAF"} == {
            "Cloudfront (Amazon)", "Cloudflare (Cloudflare Inc.)"
        }


class TestWafw00f_noredirect(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wafw00f"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"status": 301, "headers": {"Location": "/redirect"}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = {"method": "GET", "uri": "/redirect"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert not any(e.type == "WAF" for e in events)


class TestWafw00f_genericdetection(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wafw00f"]

    async def setup_after_prep(self, module_test):
        def handler(request):
            if "SLEEP" in request.url:
                return Response("nope", status=403)
            return Response("yep")

        module_test.httpserver.expect_request("/").respond_with_handler(handler)

    def check(self, module_test, events):
        waf_events = [e for e in events if e.type == "WAF"]
        assert len(waf_events) == 1
        assert waf_events[0].data["waf"] == "generic detection"
