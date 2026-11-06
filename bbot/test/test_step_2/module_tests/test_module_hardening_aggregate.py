import asyncio

from .base import ModuleTestBase


class TestHardeningAggregate(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "hardening_aggregate"]
    config_overrides = {"hardening_aggregate": True}

    async def setup_before_prep(self, module_test):
        from bbot.modules.base import BaseModule

        class FakeNuclei(BaseModule):
            _name = "nuclei"
            watched_events = ["URL"]

            async def handle_event(self, event):
                url = event.data
                for header in ("x-frame-options", "content-security-policy"):
                    await self.emit_event(
                        {
                            "host": str(event.host),
                            "url": f"{url}page",
                            "title": header,
                            "description": header,
                            "template": "missing-security-headers",
                        },
                        "FINDING",
                        parent=event,
                    )
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": url,
                        "title": "Env file",
                        "description": "Env file",
                        "severity": "HIGH",
                        "template": "generic-env",
                    },
                    "VULNERABILITY",
                    parent=event,
                )

        class FakeRetirejs(BaseModule):
            _name = "retirejs"
            watched_events = ["URL"]

            async def handle_event(self, event):
                # arrives late, while the scan is already winding down
                await asyncio.sleep(1)
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": event.data,
                        "description": "jquery 1.8.1",
                        "severity": "MEDIUM",
                        "component": "jquery",
                        "version": "1.8.1",
                        "cves": ["CVE-2020-11022"],
                    },
                    "FINDING",
                    parent=event,
                )

        module_test.scan.modules["nuclei"] = FakeNuclei(module_test.scan)
        module_test.scan.modules["retirejs"] = FakeRetirejs(module_test.scan)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": "<html>ok</html>"})

    def check(self, module_test, events):
        vulns = [e for e in events if e.type in ("FINDING", "VULNERABILITY")]
        # the individual low-risk findings never reach the output
        assert not [e for e in vulns if e.data.get("template") == "missing-security-headers"]
        assert not [e for e in vulns if e.data.get("component") == "jquery"]
        # the severe one does, unchanged
        assert [e.data["template"] for e in vulns if e.data.get("severity") == "HIGH"] == ["generic-env"]

        grouped = {e.data["dedupe_key"]: e for e in vulns if "grouped" in e.tags}
        assert sorted(grouped) == ["grouped:retirejs", "grouped:security_headers"]
        headers = grouped["grouped:security_headers"]
        assert headers.type == "VULNERABILITY"
        assert headers.module == module_test.scan.modules["hardening_aggregate"]
        assert headers.data["table"] == {
            "columns": ["Website", "content-security-policy", "x-frame-options"],
            "rows": [["http://127.0.0.1:8888", "missing", "missing"]],
        }
        assert grouped["grouped:retirejs"].data["table"]["rows"] == [
            ["http://127.0.0.1:8888", "jquery", "1.8.1", "MEDIUM", "CVE-2020-11022"]
        ]
