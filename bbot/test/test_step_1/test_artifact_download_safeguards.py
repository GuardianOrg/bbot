"""Regression tests for filesystem and authentication boundaries in download modules."""

from types import SimpleNamespace

import pytest

from ..bbot_fixtures import *  # noqa: F401, F403


@pytest.mark.asyncio
async def test_github_workflows_rejects_spoofed_hosts_and_escaping_paths(bbot_scanner, tmp_path):
    scan = bbot_scanner("evilcorp.com", modules=["github_workflows"])
    await scan._prep()
    try:
        module = scan.modules["github_workflows"]
        module.output_dir = tmp_path / "workflow_logs"
        module.output_dir.mkdir()

        spoofed = SimpleNamespace(tags={"git"}, host="evil.example", data={"url": "https://evil.example/github.com/x"})
        legitimate = SimpleNamespace(tags={"git"}, host="github.com", data={"url": "https://github.com/org/repo"})

        assert (await module.filter_event(spoofed))[0] is False
        assert await module.filter_event(legitimate) is True
        assert module._check_output_path(module.output_dir / "org" / "repo")
        assert not module._check_output_path(module.output_dir / ".." / "outside")
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_github_workflows_sanitizes_artifact_names(bbot_scanner, tmp_path, monkeypatch):
    scan = bbot_scanner("evilcorp.com", modules=["github_workflows"])
    await scan._prep()
    try:
        module = scan.modules["github_workflows"]
        module.output_dir = tmp_path / "workflow_logs"
        module.output_dir.mkdir()
        destinations = []

        async def fake_download(url, **kwargs):
            destinations.append(kwargs["filename"])

        monkeypatch.setattr(module, "api_download", fake_download)

        result = await module.download_run_artifacts("owner", "repo", 991, "..")
        assert result.name == "artifact_991"
        assert result.resolve().is_relative_to(module.output_dir.resolve())
        assert destinations == [result]
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_docker_pull_validates_auth_realm_and_output_path(bbot_scanner, tmp_path):
    scan = bbot_scanner("evilcorp.com", modules=["docker_pull"])
    await scan._prep()
    try:
        module = scan.modules["docker_pull"]
        module.output_dir = tmp_path / "docker_images"
        module.output_dir.mkdir()

        realm, service, scope = module._parse_www_authenticate(
            'Bearer service="registry.docker.io", realm="https://auth.docker.io/token", '
            'scope="repository:library/nginx:pull"'
        )
        assert (realm, service, scope) == (
            "https://auth.docker.io/token",
            "registry.docker.io",
            "repository:library/nginx:pull",
        )
        assert module._validate_realm("https://registry-1.docker.io/v2/foo", realm)
        assert not module._validate_realm(
            "https://registry-1.docker.io/v2/foo",
            "http://169.254.169.254/latest/meta-data",
        )

        result = await module.download_and_write_to_tar(
            "https://registry-1.docker.io",
            "library/nginx",
            "../../../outside",
        )
        assert result is None
        assert not (tmp_path / "outside.tar").exists()
    finally:
        await scan._cleanup()
