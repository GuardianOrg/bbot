import json

from .base import ModuleTestBase


class TestTestssl(ModuleTestBase):
    targets = ["https://blacklanternsecurity.com/", "http://blacklanternsecurity.com/"]
    module_name = "testssl"
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {
            "testssl": {
                "binary": "/bin/echo",
                "timeout": 5,
            }
        },
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.88"]}})

    async def setup_after_prep(self, module_test):
        self.commands = []

        async def fake_run_process(command, *args, **kwargs):
            self.commands.append(command)
            output_file = command[command.index("--jsonfile-pretty") + 1]
            with open(output_file, "w") as f:
                json.dump(
                    [
                        {
                            "id": "TLS1",
                            "severity": "MEDIUM",
                            "finding": "TLS 1.0 is offered",
                            "cwe": "CWE-326",
                        },
                        {
                            "id": "HSTS",
                            "severity": "WARN",
                            "finding": "No HSTS header",
                        },
                        {
                            "id": "cert_chain_of_trust",
                            "severity": "INFO",
                            "finding": "certificate chain is trusted",
                        },
                        {
                            "id": "TLS1_3",
                            "severity": "OK",
                            "finding": "TLS 1.3 offered",
                        },
                    ],
                    f,
                )

            class FakeResult:
                returncode = 0
                stdout = ""
                stderr = ""

            return FakeResult()

        module_test.monkeypatch.setattr(module_test.module, "run_process", fake_run_process)

    def check(self, module_test, events):
        vulnerabilities = [e for e in events if e.type == "VULNERABILITY" and str(e.module) == "testssl"]
        findings = [e for e in events if e.type == "FINDING" and str(e.module) == "testssl"]

        assert len(self.commands) == 1
        assert "blacklanternsecurity.com:443" in self.commands[0]
        assert any(e.data.get("title") == "TLS: TLS1 (CWE-326)" for e in vulnerabilities)
        assert any(e.data.get("severity") == "MEDIUM" for e in vulnerabilities)
        assert any(e.data.get("testssl_id") == "HSTS" for e in findings)
        assert not any(e.data.get("testssl_id") == "cert_chain_of_trust" for e in findings + vulnerabilities)
        assert not any(e.data.get("testssl_id") == "TLS1_3" for e in findings + vulnerabilities)
