import json
from pathlib import Path

import pytest

from .base import ModuleTestBase


@pytest.fixture
def mock_noseyparker(monkeypatch):
    async def fake_run_process(self, cmd, *args, **kwargs):
        if cmd[:2] == ["git", "clone"]:
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)

            class FakeGitCloneResult:
                returncode = 0
                stdout = ""
                stderr = ""

            return FakeGitCloneResult()

        if cmd[:2] == ["git", "-C"] and cmd[3:] == ["rev-parse", "HEAD"]:
            class FakeGitRevParseResult:
                returncode = 0
                stdout = "ffffffffffffffffffffffffffffffffffffffff\n"
                stderr = ""

            return FakeGitRevParseResult()

        if cmd[:3] == ["noseyparker", "datastore", "init"] or cmd[:2] == ["noseyparker", "scan"]:
            class FakeNoseyParkerResult:
                returncode = 0
                stdout = ""
                stderr = ""

            return FakeNoseyParkerResult()

        class FakeReportResult:
            returncode = 0
            stdout = json.dumps(
                {
                    "findings": [
                        {
                            "rule_name": "Generic API Key",
                            "matches": [
                                {
                                    "snippet": "api_key = gpa_1234567890abcdef",
                                    "provenance": [
                                        {
                                            "kind": "git_repo",
                                            "first_commit": {
                                                "commit_id": "abcdef1234567890abcdef1234567890abcdef12",
                                                "blob_path": "README.md",
                                            },
                                        }
                                    ],
                                    "location": {"source_span": {"start": {"line": 625}}},
                                }
                            ],
                        }
                    ]
                }
            )
            stderr = ""

        return FakeReportResult()

    async def fake_install_core_deps(self):
        return None

    from bbot.modules.base import BaseModule
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
    monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)


@pytest.mark.usefixtures("mock_noseyparker")
class TestNoseyParker(ModuleTestBase):
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
        finding = findings[0]
        assert finding.data["tool"] == "noseyparker"
        assert finding.data["rule"] == "Generic API Key"
        assert finding.data["url"] == (
            "https://github.com/layer-3-smart/test/blob/"
            "abcdef1234567890abcdef1234567890abcdef12/README.md#L625"
        )
        assert finding.data["location"] == finding.data["url"]
        assert finding.data["commit_url"] == (
            "https://github.com/layer-3-smart/test/commit/abcdef1234567890abcdef1234567890abcdef12"
        )
        assert finding.data["file_url"] == finding.data["url"]
        assert "Leaked value: api_key = gpa_1234567890abcdef." in finding.data["description"]
        assert "one confirmed exposure is sufficient to treat the credential as compromised" in finding.data["description"]
        assert "dedupe_key" not in finding.data
