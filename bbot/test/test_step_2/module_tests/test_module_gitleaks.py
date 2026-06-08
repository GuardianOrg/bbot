import json
from pathlib import Path

import pytest

from .base import ModuleTestBase


@pytest.fixture
def mock_gitleaks(monkeypatch, tmp_path):
    async def fake_run_process(self, cmd, *args, **kwargs):
        if cmd[:2] == ["git", "clone"]:
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)

            class FakeGitResult:
                returncode = 0
                stdout = ""
                stderr = ""

            return FakeGitResult()

        if cmd[:2] == ["git", "-C"] and cmd[3:] == ["rev-parse", "HEAD"]:
            class FakeGitRevParseResult:
                returncode = 0
                stdout = "abcdef1234567890abcdef1234567890abcdef12\n"
                stderr = ""

            return FakeGitRevParseResult()

        scan_path = Path(cmd[2])
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "File": str(scan_path / "test/vesting/Vesting.spec.ts"),
                        "StartLine": 20,
                        "Secret": "ghp_fullSecretValue1234567890",
                        "Match": "ghp_fullSecretValue1234567890",
                        "Commit": "abcdef1234567890abcdef1234567890abcdef12",
                        "Fingerprint": "abcdef1234567890abcdef1234567890abcdef12:test/vesting/Vesting.spec.ts:generic-api-key:20",
                    }
                ]
            ),
            encoding="utf-8",
        )

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    async def fake_install_core_deps(self):
        return None

    from bbot.modules.base import BaseModule
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
    monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)


@pytest.mark.usefixtures("mock_gitleaks")
class TestGitleaks(ModuleTestBase):
    targets = ["https://github.com/layer-3-smart"]
    config_overrides = {"deps": {"behavior": "disable"}, "modules": {"gitleaks": {"disabled_rules": []}}}

    async def setup_after_prep(self, module_test):
        repo_event = module_test.scan.make_event(
            {"url": "https://github.com/layer-3-smart/test.git"},
            "CODE_REPOSITORY",
            tags=["git", "target"],
            parent=module_test.scan.root_event,
        )
        await module_test.module.emit_event(repo_event)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]

        assert len(findings) == 1
        finding = findings[0]
        assert finding.data["tool"] == "gitleaks"
        assert finding.data["rule"] == "generic-api-key"
        assert finding.data["url"] == (
            "https://github.com/layer-3-smart/test/blob/"
            "abcdef1234567890abcdef1234567890abcdef12/test/vesting/Vesting.spec.ts#L20"
        )
        assert finding.data["location"] == finding.data["url"]
        assert finding.data["commit_url"] == (
            "https://github.com/layer-3-smart/test/commit/abcdef1234567890abcdef1234567890abcdef12"
        )
        assert finding.data["file_url"] == finding.data["url"]
        assert "Leaked value: ghp_fullSecretValue1234567890." in finding.data["description"]
        assert "one confirmed exposure is sufficient to treat the credential as compromised" in finding.data["description"]
        assert "leak" not in finding.data
        assert "github_url" not in finding.data
        assert "dedupe_key" not in finding.data


@pytest.mark.usefixtures("mock_gitleaks")
class TestGitleaksSkipsGenericApiKey(ModuleTestBase):
    module_name = "gitleaks"
    targets = ["https://github.com/layer-3-smart"]
    config_overrides = {"deps": {"behavior": "disable"}}

    async def setup_after_prep(self, module_test):
        repo_event = module_test.scan.make_event(
            {"url": "https://github.com/layer-3-smart/test.git"},
            "CODE_REPOSITORY",
            tags=["git", "target"],
            parent=module_test.scan.root_event,
        )
        await module_test.module.emit_event(repo_event)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert findings == []
