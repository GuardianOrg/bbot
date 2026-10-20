from types import SimpleNamespace
from unittest.mock import AsyncMock

from .base import ModuleTestBase


class TestWhatweb(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    config_overrides = {"deps": {"behavior": "disable"}}

    async def setup_before_prep(self, module_test):
        # HTTP execution is tested separately; inject a saved response into the real event pipeline.
        module_test.scan.preset.exclude_modules.add("httpx")
        module_test.monkeypatch.setattr(
            module_test.scan.helpers, "run", AsyncMock(return_value=SimpleNamespace(returncode=0))
        )

    async def setup_after_prep(self, module_test):
        module_test.module.fingerprint = AsyncMock(return_value={"WordPress": {"version": ["6.6.2"]}})
        module_test.module.find_favicon = AsyncMock(
            return_value={
                "url": "http://127.0.0.1:8888/favicon.ico",
                "sha256": "a" * 64,
                "mmh3": -123,
            }
        )
        await module_test.module.emit_event(
            {
                "url": self.targets[0] + "/",
                "method": "GET",
                "status_code": 200,
                "raw_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
                "body": "<html></html>",
            },
            "HTTP_RESPONSE",
            parent=module_test.scan.root_event,
            context="Saved response fixture",
        )

    def check(self, module_test, events):
        responses = [event for event in events if event.type == "HTTP_RESPONSE"]
        assert len(responses) == 1
        assert responses[0].data["technologies"][0]["version"] == "6.6.2"
        assert responses[0].data["favicon"]["mmh3"] == -123
        technologies = [event for event in events if event.type == "TECHNOLOGY"]
        assert len(technologies) == 1
        assert technologies[0].data["version"] == "6.6.2"
