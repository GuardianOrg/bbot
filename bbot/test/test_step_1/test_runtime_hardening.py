"""Focused regressions for upstream runtime hardening backports."""

from pathlib import Path

import pytest

from bbot.core.helpers.git import sanitize_git_repo
from bbot.modules.apkpure import apkpure
from bbot.modules.leakix import leakix
from bbot.modules.nuclei import nuclei


def test_nuclei_environment_does_not_inherit_credentials(monkeypatch, tmp_path):
    module = nuclei.__new__(nuclei)
    module.nuclei_home = tmp_path / "nuclei-home"
    module.nuclei_config_dir = module.nuclei_home / ".config" / "nuclei"
    leaked = {
        "PDCP_API_KEY": "pdcp-secret",
        "GITHUB_TOKEN": "github-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "AZURE_CLIENT_SECRET": "azure-secret",
        "XDG_CONFIG_HOME": "/tmp/host-nuclei-config",
    }
    for key, value in leaked.items():
        monkeypatch.setenv(key, value)

    env = module._nuclei_env()

    assert leaked.keys().isdisjoint(env)
    assert env["HOME"] == str(module.nuclei_home)
    assert env["NUCLEI_CONFIG_DIR"].startswith(str(module.nuclei_home))


@pytest.mark.parametrize("module_class", [apkpure, nuclei])
def test_mobile_downloaders_reject_unsafe_app_ids(module_class):
    assert module_class._is_safe_app_id("com.example.safe-app")
    assert not module_class._is_safe_app_id("../escape")
    assert not module_class._is_safe_app_id("com.example/escape")
    assert not module_class._is_safe_app_id("")


@pytest.mark.asyncio
async def test_leakix_ignores_non_list_error_responses():
    class Response:
        @staticmethod
        def json():
            return {"error": "rate limited"}

    module = leakix.__new__(leakix)
    assert await module.parse_results(Response()) == set()


def test_sanitize_git_repo_preserves_originals_and_writes_safe_config(tmp_path):
    git_dir = tmp_path / ".git"
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    (git_dir / "config").write_text("[core]\nsshCommand = malicious\n")
    (git_dir / "index").write_bytes(b"attacker-controlled-index")
    (hooks_dir / "post-checkout").write_text("#!/bin/sh\nmalicious\n")

    sanitize_git_repo(tmp_path)

    safe_config = (git_dir / "config").read_text()
    assert "sshCommand = echo" in safe_config
    assert "fsmonitor = false" in safe_config
    assert (tmp_path / "git_config_original").is_file()
    assert (tmp_path / "git_index_original").is_file()
    assert (tmp_path / "git_hooks_original").is_dir()
    assert not (git_dir / "index").exists()
    assert not Path(hooks_dir).exists()
