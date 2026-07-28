"""Regression tests for malicious or pathological leaked git repositories."""

import hashlib
import struct

import pytest

from ..bbot_fixtures import *  # noqa: F401, F403
from bbot.modules.gitdumper import gitdumper


@pytest.mark.asyncio
async def test_regex_files_does_not_walk_cwd(bbot_scanner, tmp_path, monkeypatch):
    target = tmp_path / "head"
    target.write_text("ref: refs/heads/main\n")
    decoy_cwd = tmp_path / "cwd"
    decoy_cwd.mkdir()
    (decoy_cwd / "decoy.txt").write_text("ref: refs/heads/should_not_match\n")
    monkeypatch.chdir(decoy_cwd)

    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        module = scan.modules["gitdumper"]
        regex = module.helpers.re.compile(r"ref: refs/heads/([a-zA-Z\d_-]+)")
        results = await module.regex_files(regex, file=target)
        assert "main" in results
        assert "should_not_match" not in results
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_download_files_caps_size_and_rejects_traversal(bbot_scanner, tmp_path, monkeypatch):
    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        module = scan.modules["gitdumper"]
        calls = []

        async def traced_download(url, **kwargs):
            calls.append((url, kwargs))

        monkeypatch.setattr(module.helpers, "download", traced_download)
        safe_url = module.helpers.urlparse("http://example.com/.git/HEAD")
        traversal_url = module.helpers.urlparse("http://example.com/.git/../../outside")
        await module.download_files([safe_url, traversal_url], tmp_path)

        assert len(calls) == 1
        assert calls[0][1]["max_size"] == module._download_max_size
        assert calls[0][1]["filename"].is_relative_to(tmp_path.resolve())
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_download_object_bounds_depth_and_detects_cycles(bbot_scanner, tmp_path, monkeypatch):
    scan = bbot_scanner("evilcorp.com", modules=["gitdumper"])
    await scan._prep()
    try:
        module = scan.modules["gitdumper"]

        async def nop_download_files(urls, folder):
            return True

        monkeypatch.setattr(module, "download_files", nop_download_files)
        hash_a = "a" * 40
        hash_b = "b" * 40
        calls = []

        async def cyclic_catfile(hash_, option="-t", folder=None):
            calls.append(hash_)
            return f"references {hash_b if hash_ == hash_a else hash_a}"

        monkeypatch.setattr(module, "git_catfile", cyclic_catfile)
        await module.download_object(hash_a, "http://example.com", tmp_path)
        assert calls == [hash_a, hash_b]

        counter = [0]

        async def unbounded_catfile(hash_, option="-t", folder=None):
            counter[0] += 1
            return f"{counter[0]:040x}"

        monkeypatch.setattr(module, "git_catfile", unbounded_catfile)
        await module.download_object("0" * 40, "http://example.com", tmp_path)
        assert counter[0] <= module._download_object_max_depth
    finally:
        await scan._cleanup()


def test_write_empty_index_replaces_attacker_controlled_index(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    index_path = git_dir / "index"
    index_path.write_bytes(b"attacker-controlled")

    gitdumper._write_empty_index(tmp_path)

    data = index_path.read_bytes()
    assert data[:4] == b"DIRC"
    version, num_entries = struct.unpack(">II", data[4:12])
    assert version == 2
    assert num_entries == 0
    assert data[12:] == hashlib.sha1(data[:12]).digest()
