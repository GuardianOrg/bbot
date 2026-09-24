import json

import pytest

from .base import ModuleTestBase


kingfisher_calls = []


@pytest.fixture
def mock_kingfisher(monkeypatch):
    kingfisher_calls.clear()

    async def fake_run_process(self, cmd, *args, **kwargs):
        if cmd[:2] == ["git", "clone"]:
            class FakeGitCloneResult:
                returncode = 0
                stdout = ""
                stderr = ""

            return FakeGitCloneResult()

        if cmd[:3] == ["git", "-C", cmd[2]] and cmd[3:] == ["rev-parse", "HEAD"]:
            class FakeGitRevParseResult:
                returncode = 0
                stdout = "abcdef1234567890abcdef1234567890abcdef12\n"
                stderr = ""

            return FakeGitRevParseResult()

        if cmd[0] != "kingfisher":
            class FakeGitResult:
                returncode = 0
                stdout = ""
                stderr = ""

            return FakeGitResult()

        assert cmd[1] == "scan"
        assert cmd[3:] == ["--format", "json", "--quiet", "--no-update-check", "--jobs", "1"]
        kingfisher_calls.append(cmd)
        scan_path = cmd[2]
        class FakeResult:
            # Kingfisher exits 200 when it reports findings.
            returncode = 200
            stdout = json.dumps(
                {
                    "findings": [
                        {
                            "rule": {"name": "GitHub Token", "id": "github-token"},
                            "finding": {
                                "snippet": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                                "fingerprint": "abcd",
                                "line": 12,
                                "path": f"{scan_path}/app/.env",
                                "validation": {"status": "unknown", "response": ""},
                                "git_metadata": {"commit": "abcdef1234567890abcdef1234567890abcdef12"},
                            },
                        }
                    ]
                }
            )
            stderr = ""

        return FakeResult()

    from bbot.modules.base import BaseModule
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    async def fake_install_core_deps(self):
        return None

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
    monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)


@pytest.mark.usefixtures("mock_kingfisher")
class TestKingfisher(ModuleTestBase):
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

        assert len(findings) == 1
        assert len(kingfisher_calls) == 1
        finding = findings[0]
        assert finding.data["url"] == (
            "https://github.com/layer-3-smart/test/blob/"
            "abcdef1234567890abcdef1234567890abcdef12/app/.env#L12"
        )
        assert finding.data["location"] == finding.data["url"]
        assert finding.data["commit_url"] == (
            "https://github.com/layer-3-smart/test/commit/abcdef1234567890abcdef1234567890abcdef12"
        )
        assert finding.data["file_url"] == finding.data["url"]
        assert finding.data["tool"] == "kingfisher"
        assert finding.data["rule"] == "GitHub Token"
        assert "Leaked value: ghp_1234567890abcdefghijklmnopqrstuvwxyz." in finding.data["description"]
        assert "one confirmed exposure is sufficient to treat the credential as compromised" in finding.data["description"]
        assert "leak" not in finding.data
        assert "github_url" not in finding.data
        assert "dedupe_key" not in finding.data
