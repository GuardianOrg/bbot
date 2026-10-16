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

        if cmd[:2] == ["git", "-C"] and cmd[3:] == ["rev-list", "--count", "--all"]:
            from types import SimpleNamespace

            count = 201 if "many" in cmd[2] else 101 if "kill" in cmd[2] else 1
            return SimpleNamespace(returncode=0, stdout=f"{count}\n", stderr="")

        if cmd[:2] == ["git", "-C"] and cmd[3:] == ["rev-parse", "HEAD"]:

            class FakeGitRevParseResult:
                returncode = 0
                stdout = "abcdef1234567890abcdef1234567890abcdef12\n"
                stderr = ""

            return FakeGitRevParseResult()

        if cmd[:2] == ["git", "-C"] and cmd[3:6] == ["show", "-s", "--format=%cI"]:
            from types import SimpleNamespace

            return SimpleNamespace(returncode=0, stdout="2024-06-01T00:00:00Z\n", stderr="")

        self._gitleaks_commands = getattr(self, "_gitleaks_commands", []) + [cmd]
        if "kill" in cmd[2] and "--max-count=100" in cmd[cmd.index("--log-opts") + 1]:
            from types import SimpleNamespace

            return SimpleNamespace(returncode=-9, stdout="", stderr="")
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
        # Descriptions are normalized for display; structured evidence stays exact.
        assert finding.data["secretValue"] == "ghp_fullSecretValue1234567890"
        assert finding.data["secret_latest_commit_at"] == "2024-06-01T00:00:00Z"
        assert (
            "one confirmed exposure is sufficient to treat the credential as compromised"
            in finding.data["description"]
        )
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


@pytest.mark.usefixtures("mock_gitleaks")
class TestGitleaksBatchesAllHistory(ModuleTestBase):
    module_name = "gitleaks"
    targets = ["https://github.com/layer-3-smart"]
    config_overrides = {"deps": {"behavior": "disable"}}

    async def setup_after_prep(self, module_test):
        repo_event = module_test.scan.make_event(
            {"url": "https://github.com/layer-3-smart/many.git"},
            "CODE_REPOSITORY",
            tags=["git", "target"],
            parent=module_test.scan.root_event,
        )
        await module_test.module.emit_event(repo_event)

    def check(self, module_test, events):
        options = [command[command.index("--log-opts") + 1] for command in module_test.module._gitleaks_commands]
        assert options == [
            "--full-history --all --diff-filter=tuxdb --max-count=100 --skip=0",
            "--full-history --all --diff-filter=tuxdb --max-count=100 --skip=100",
            "--full-history --all --diff-filter=tuxdb --max-count=1 --skip=200",
        ]


@pytest.mark.usefixtures("mock_gitleaks")
class TestGitleaksRetriesKilledBatch(ModuleTestBase):
    module_name = "gitleaks"
    targets = ["https://github.com/layer-3-smart"]
    config_overrides = {"deps": {"behavior": "disable"}}

    async def setup_after_prep(self, module_test):
        repo_event = module_test.scan.make_event(
            {"url": "https://github.com/layer-3-smart/kill.git"},
            "CODE_REPOSITORY",
            tags=["git", "target"],
            parent=module_test.scan.root_event,
        )
        await module_test.module.emit_event(repo_event)

    def check(self, module_test, events):
        options = [command[command.index("--log-opts") + 1] for command in module_test.module._gitleaks_commands]
        assert options == [
            "--full-history --all --diff-filter=tuxdb --max-count=100 --skip=0",
            "--full-history --all --diff-filter=tuxdb --max-count=50 --skip=0",
            "--full-history --all --diff-filter=tuxdb --max-count=50 --skip=50",
            "--full-history --all --diff-filter=tuxdb --max-count=1 --skip=100",
        ]
