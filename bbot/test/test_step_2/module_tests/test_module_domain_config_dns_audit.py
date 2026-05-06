import json

from .base import ModuleTestBase


class TestDomainConfigDnsAudit(ModuleTestBase):
    module_name = "domain_config_dns_audit"
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {
            "domain_config_dns_audit": {
                "binary": "/bin/echo",
                "wildcard_nameservers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
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

        self.captured_commands = []

        async def fake_run_process(self_module, cmd, *args, **kwargs):
            self.captured_commands.append(cmd)

            class FakeResult:
                returncode = 0
                stdout = json.dumps(
                    [
                        {
                            "domain": "blacklanternsecurity.com",
                            "findings": [
                                {
                                    "title": "Weak DMARC policy",
                                    "severity": "medium",
                                    "category": "Email",
                                    "description": "DMARC policy is monitor-only.",
                                    "evidence": "p=none",
                                    "recommendation": "Move to quarantine or reject.",
                                    "command": "domain-config-dns-audit blacklanternsecurity.com",
                                }
                            ],
                        }
                    ]
                )
                stderr = ""

            return FakeResult()

        async def fake_check_zone_transfer(host):
            return {
                "zone_transfer_possible": False,
                "zone_transfer_nameservers": ["ns1.blacklanternsecurity.com"],
            }

        async def fake_check_wildcard(host):
            return {
                "is_wildcard": True,
                "wildcard_ips": ["1.2.3.4", "2001:db8::1"],
            }

        module_test.monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
        module_test.monkeypatch.setattr(module_test.module, "check_zone_transfer", fake_check_zone_transfer)
        module_test.monkeypatch.setattr(module_test.module, "check_wildcard", fake_check_wildcard)

    def check(self, module_test, events):
        domain_config_events = [e for e in events if e.type == "DOMAIN_DNS_CONFIG"]
        findings = [e for e in events if e.type == "FINDING"]
        vulnerabilities = [e for e in events if e.type == "VULNERABILITY"]

        assert len(domain_config_events) == 1
        assert domain_config_events[0].data["host"] == "blacklanternsecurity.com"
        assert domain_config_events[0].data["zone_transfer_possible"] is False
        assert domain_config_events[0].data["is_wildcard"] is True
        assert domain_config_events[0].data["wildcard_ips"] == ["1.2.3.4", "2001:db8::1"]

        assert any(e.data.get("title") == "Weak DMARC policy" for e in vulnerabilities)
        assert any("domain security grade" in e.data.get("description", "").lower() for e in findings)
        assert all("--quick" not in cmd for cmd in self.captured_commands)
