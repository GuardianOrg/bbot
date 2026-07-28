"""Regression tests for compatible security fixes from BBOT's final 2.x releases."""

import io
import pickle
import zipfile
from types import SimpleNamespace

import pytest

from ..bbot_fixtures import *  # noqa: F401, F403
from bbot.core.modules import _SafeUnpickler
from bbot.modules.ffuf_shortnames import _ShortnameModelUnpickler
from bbot.modules.git_clone import git_clone
from bbot.modules.postman_download import postman_download


class _UnsafePayload:
    def __reduce__(self):
        return eval, ("40 + 2",)


def test_preload_cache_unpickler_rejects_class_loading():
    payload = pickle.dumps(_UnsafePayload())
    with pytest.raises(pickle.UnpicklingError):
        _SafeUnpickler(io.BytesIO(payload)).load()

    expected = {"module": {"watched_events": ["URL"], "enabled": True}}
    assert _SafeUnpickler(io.BytesIO(pickle.dumps(expected))).load() == expected


def test_shortname_model_unpickler_rejects_unexpected_classes():
    payload = pickle.dumps(_UnsafePayload())
    with pytest.raises(pickle.UnpicklingError):
        _ShortnameModelUnpickler(io.BytesIO(payload)).load()


def test_postman_download_sanitizes_paths_and_zip_members(bbot_scanner, tmp_path):
    module = postman_download(bbot_scanner("evilcorp.com"))
    module.output_dir = tmp_path / "postman"
    module.output_dir.mkdir()

    zip_path = module.save_workspace(
        {"name": "../../outside", "id": "../workspace"},
        [{"id": "../../environment"}],
        [{"info": {"name": "../../collection"}}],
    )

    assert zip_path.resolve().is_relative_to(module.output_dir.resolve())
    assert not (tmp_path / "outside").exists()
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
    assert len(names) == 3
    assert all("/" not in name and "\\" not in name and ".." not in name for name in names)


@pytest.mark.asyncio
async def test_git_clone_uses_safe_flags_and_output_path(bbot_scanner, tmp_path, monkeypatch):
    module = git_clone(bbot_scanner("evilcorp.com"))
    module.output_dir = tmp_path / "git"
    module.output_dir.mkdir()
    module.api_key = ""
    commands = []

    async def fake_run_process(command, **kwargs):
        commands.append(command)
        repo = module.output_dir / "owner" / "repo"
        (repo / ".git" / "hooks").mkdir(parents=True)
        (repo / ".git" / "config").write_text("[core]\n")
        return SimpleNamespace(stderr="Cloning into 'repo'...\n")

    monkeypatch.setattr(module, "run_process", fake_run_process)
    result = await module.clone_git_repository("https://github.com/owner/repo")

    assert result == module.output_dir / "owner" / "repo"
    command = commands[0]
    assert "core.fsmonitor=false" in command
    assert "core.sshCommand=echo" in command
    assert "core.symlinks=false" in command
    assert "transfer.fsckObjects=true" in command
    assert command[-2:] == ["--", "https://github.com/owner/repo"]
    assert await module.clone_git_repository("https://github.com/../repo") is None


@pytest.mark.asyncio
async def test_unarchive_rejects_traversal_links_and_oversized_archives(bbot_scanner, tmp_path, monkeypatch):
    scan = bbot_scanner("evilcorp.com", modules=[])
    await scan._prep()
    try:
        module = scan.modules["unarchive"]

        async def traversal_listing(command, **kwargs):
            return SimpleNamespace(stdout="Path = archive.zip\nPath = ../../outside\nSize = 1\n")

        monkeypatch.setattr(module, "run_process", traversal_listing)
        assert not await module._check_archive_safe(tmp_path / "archive.zip", "zip", [100])

        async def link_listing(command, **kwargs):
            return SimpleNamespace(stdout="Path = archive.zip\nPath = link\nAttributes = l\nSize = 1\n")

        monkeypatch.setattr(module, "run_process", link_listing)
        assert not await module._check_archive_safe(tmp_path / "archive.zip", "zip", [100])

        async def oversized_listing(command, **kwargs):
            return SimpleNamespace(stdout="Path = archive.zip\nPath = large.bin\nSize = 101\n")

        monkeypatch.setattr(module, "run_process", oversized_listing)
        assert not await module._check_archive_safe(tmp_path / "archive.zip", "zip", [100])

        async def safe_listing(command, **kwargs):
            return SimpleNamespace(stdout="Path = archive.zip\nPath = folder/file.txt\nSize = 10\n")

        monkeypatch.setattr(module, "run_process", safe_listing)
        assert await module._check_archive_safe(tmp_path / "archive.zip", "zip", [100])
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_docker_pull_handles_missing_registry_response(bbot_scanner, monkeypatch):
    scan = bbot_scanner("evilcorp.com", modules=["docker_pull"])
    await scan._prep()
    try:
        module = scan.modules["docker_pull"]

        async def failed_request(*args, **kwargs):
            return None

        monkeypatch.setattr(module.helpers, "request", failed_request)
        assert await module.docker_api_request("https://registry-1.docker.io/v2/missing/tags/list") is None
        assert await module.get_tags("https://registry-1.docker.io", "missing") == ["latest"]
        assert await module.get_manifest("https://registry-1.docker.io", "missing", "latest") == {}
        assert await module.download_blob("https://registry-1.docker.io", "missing", "sha256:deadbeef") is None
    finally:
        await scan._cleanup()
