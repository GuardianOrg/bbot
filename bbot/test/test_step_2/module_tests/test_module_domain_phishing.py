import json

from .base import ModuleTestBase


class TestDomainPhishing(ModuleTestBase):
    module_name = "domain_phishing"
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {
            "domain_phishing": {
                "binary": "/bin/echo",
                "young_domain_days": 45,
                "min_score": 3,
            }
        },
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        from bbot.modules.base import BaseModule

        async def fake_run_process(self_module, cmd, *args, **kwargs):
            class FakeResult:
                returncode = 0
                stdout = json.dumps(
                    [
                        {
                            "domain": "blacklanternsecur1ty.com",
                            "fuzzer": "replacement",
                            "dns-a": ["1.2.3.4"],
                            "dns-mx": ["mx1.example.com"],
                            "dns-ns": ["ns1.example.com"],
                            "created": "2026-05-01",
                        },
                        {
                            "domain": "blacklanternsecurity.com",
                            "fuzzer": "replacement",
                        },
                    ]
                )
                stderr = ""

            return FakeResult()

        module_test.monkeypatch.setattr(BaseModule, "run_process", fake_run_process)

    def check(self, module_test, events):
        phishing_events = [
            e
            for e in events
            if e.type in ("FINDING", "VULNERABILITY") and e.data.get("category") == "phishing-lookalike-domain"
        ]
        assert len(phishing_events) == 1

        event = phishing_events[0]
        assert event.type == "VULNERABILITY"
        assert event.data["host"] == "blacklanternsecur1ty.com"
        assert event.data["category"] == "phishing-lookalike-domain"
        assert event.data["source-domain"] == "blacklanternsecurity.com"
        assert event.data["probability"] == event.data["score"]
        assert event.data["probability"] >= 4
        assert event.data["title"] == "Potential phishing look-alike domain: blacklanternsecur1ty.com"
        assert "Candidate domain: blacklanternsecur1ty.com" in event.data["evidence"]
