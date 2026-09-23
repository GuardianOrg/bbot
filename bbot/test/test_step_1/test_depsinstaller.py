import json

from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_depsinstaller(monkeypatch, bbot_scanner):
    scan = bbot_scanner(
        "127.0.0.1",
    )

    # test shell
    test_file = Path("/tmp/test_file")
    test_file.unlink(missing_ok=True)
    scan.helpers.depsinstaller.shell(module="plumbus", commands=[f"touch {test_file}"])
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)

    # test tasks
    scan.helpers.depsinstaller.tasks(
        module="plumbus",
        tasks=[{"name": "test task execution", "ansible.builtin.shell": {"cmd": f"touch {test_file}"}}],
    )
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)

    await scan._cleanup()


@pytest.mark.asyncio
async def test_depsinstaller_concurrent_scratch_dirs(bbot_scanner):
    """
    Two installers sharing one BBOT home must not share an ansible private_data_dir.

    The shared directory used to be deleted at the start of every run, so a second scan
    starting while the first was mid-playbook took artifacts/<uuid>/ out from under it and
    ansible-runner died with FileNotFoundError on artifacts/<uuid>/status.
    """
    scan = bbot_scanner("127.0.0.1")
    depsinstaller = scan.helpers.depsinstaller

    # same inputs, different scratch directories
    first = depsinstaller.ansible_data_dir(module="plumbus")
    second = depsinstaller.ansible_data_dir(module="plumbus")
    assert first != second
    assert depsinstaller.ansible_data_dir(playbook_hash="abc123") != depsinstaller.ansible_data_dir(
        playbook_hash="abc123"
    )

    # a run must not touch a sibling's directory, including the legacy shared path
    sibling = depsinstaller.data_dir / "plumbus"
    sibling_artifact = sibling / "artifacts" / "in-flight" / "status"
    sibling_artifact.parent.mkdir(parents=True, exist_ok=True)
    sibling_artifact.touch()

    test_file = Path("/tmp/test_file_concurrent")
    test_file.unlink(missing_ok=True)
    depsinstaller.tasks(
        module="plumbus",
        tasks=[{"name": "test task execution", "ansible.builtin.shell": {"cmd": f"touch {test_file}"}}],
    )
    assert test_file.is_file()
    test_file.unlink(missing_ok=True)

    assert sibling_artifact.is_file(), "ansible_run deleted a directory belonging to another installer"
    shutil.rmtree(sibling, ignore_errors=True)

    await scan._cleanup()


@pytest.mark.asyncio
async def test_depsinstaller_setup_status_merge(bbot_scanner):
    """A run writes its own results without dropping ones another run recorded meanwhile."""
    scan = bbot_scanner("127.0.0.1")
    depsinstaller = scan.helpers.depsinstaller

    depsinstaller.setup_status = {}
    depsinstaller.setup_status_writes = {}
    depsinstaller.record_setup_status("module:ours", True)

    # another process installs something and writes the cache while we are still running
    with open(depsinstaller.setup_status_cache, "w") as f:
        json.dump({"module:theirs": True, "module:ours": False}, f)

    depsinstaller.write_setup_status()

    with open(depsinstaller.setup_status_cache) as f:
        written = json.load(f)
    assert written["module:theirs"] is True, "clobbered a concurrent installer's result"
    assert written["module:ours"] is True, "dropped this run's own result"

    await scan._cleanup()
