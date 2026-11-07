"""Secret scanners see only a fork's own commits after its last sync with upstream, never inherited history."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

from bbot.modules.github_org import github_org
from bbot.modules.gitleaks import gitleaks
from bbot.modules.kingfisher import kingfisher
from bbot.modules.noseyparker import noseyparker
from bbot.modules.trufflehog import trufflehog

API = "https://api.github.com"
COMPARE = f"{API}/repos/up/tool/compare/master...acme:tool:main"
BASE = "b" * 40


def sha(name):
    return (name.encode().hex() + "0" * 40)[:40]


def fake_github(history, head, ahead=None, pages=None):
    """A github_org whose API serves a fork of up/tool; `history` maps each fork-only commit to its parents,
    oldest first, as GitHub's compare endpoint lists them."""
    class Org(github_org):
        helpers = SimpleNamespace(quote=lambda value: quote(value, safe=""))

    module = object.__new__(Org)
    module.base_url = API
    module._fork_info = {}
    module.include_forks = True
    commits = [{"sha": sha(c), "parents": [{"sha": sha(p)} for p in parents]} for c, parents in history.items()]
    ahead = len(commits) if ahead is None else ahead
    module.requested = []

    async def api_request(url):
        module.requested.append(url)
        if url == f"{API}/repos/acme/tool":
            body = {"default_branch": "main", "parent": {"full_name": "up/tool", "default_branch": "master"}}
        else:
            page = int(url.rsplit("page=", 1)[1])
            served = (pages or {}).get(page, commits[(page - 1) * 100 : page * 100])
            body = {
                "ahead_by": ahead,
                "merge_base_commit": {"sha": BASE},
                "permalink_url": f"https://github.com/up/tool/compare/up:{BASE}...acme:{sha(head)}",
                "commits": served,
            }
        return SimpleNamespace(status_code=200, json=lambda: body)

    module.api_request = api_request
    return module


def details(module):
    return asyncio.run(module.fork_details({"full_name": "acme/tool", "html_url": "https://github.com/acme/tool"}))


def test_merge_sync_leaves_out_the_commits_made_before_it():
    # forked at u1, own1..own3, synced by merging upstream u2, then own4 and own5
    history = {"own1": ["u1"], "own2": ["own1"], "own3": ["own2"], "sync": ["own3", "u2"], "own4": ["sync"], "own5": ["own4"]}
    assert details(fake_github(history, "own5")) == {"branch": "main", "ahead": 6, "since": sha("sync")}


def test_without_a_sync_every_commit_since_the_fork_point_is_the_owners():
    history = {"own1": ["u1"], "own2": ["own1"]}
    assert details(fake_github(history, "own2"))["since"] == sha("u1")


def test_fast_forward_sync_starts_after_the_upstream_commit_it_moved_to():
    # own1 was upstreamed, the fork fast-forwarded to u9, then own2 and own3 followed
    history = {"own2": ["u9"], "own3": ["own2"]}
    assert details(fake_github(history, "own3"))["since"] == sha("u9")


def test_merging_its_own_branch_is_not_a_sync():
    history = {
        "own1": ["u1"],
        "sync": ["own1", "u2"],
        "feature": ["sync"],
        "own2": ["sync"],
        "merge-feature": ["own2", "feature"],
    }
    assert details(fake_github(history, "merge-feature"))["since"] == sha("sync")


def test_a_fork_without_commits_of_its_own_is_unmodified():
    module = fake_github({}, "u1", ahead=0)
    found = details(module)
    assert found["ahead"] == 0
    module._fork_info["https://github.com/acme/tool"] = found
    assert module.fork_event_fields("https://github.com/acme/tool") == (
        {"fork_branch": "main"},
        ["fork", "fork-unmodified"],
    )


def test_unrelated_history_is_scanned_whole():
    module = fake_github({"root": [], "own1": ["root"]}, "own1")
    module._fork_info["https://github.com/acme/tool"] = details(module)
    assert module.fork_event_fields("https://github.com/acme/tool") == ({}, [])


def test_long_forks_read_the_newest_pages_and_fall_back_to_the_merge_base():
    history = {f"own{i}": [f"own{i - 1}" if i else "u1"] for i in range(250)}
    module = fake_github(history, "own249", pages={1: [], 2: []})
    # pages 1 and 2 are empty here, so the walk runs out of fetched commits before finding a sync
    assert details(module)["since"] == BASE
    assert [u.rsplit("page=", 1)[1] for u in module.requested if "compare" in u] == ["1", "3", "2"]


def test_long_forks_do_not_mistake_an_unfetched_own_commit_for_upstream():
    # own10 (an older page that is not fetched) is merged back near the head: not a sync
    history = {f"own{i}": [f"own{i - 1}" if i else "u1"] for i in range(250)}
    history["own249"] = ["own248", "own10"]
    module = fake_github(history, "own249", pages={1: [], 2: []})
    assert details(module)["since"] == BASE


def test_fork_fields_reach_the_event():
    module = fake_github({"own1": ["u1"], "own2": ["own1"]}, "own2")
    module._fork_info["https://github.com/acme/tool"] = details(module)
    data, tags = module.fork_event_fields("https://github.com/acme/tool")
    assert data == {"fork_branch": "main", "fork_since_commit": sha("u1")} and tags == ["fork"]
    assert module.fork_event_fields("https://github.com/acme/other") == ({}, [])
    # GitHub did not answer: tagged, so scanners skip rather than scan the inherited history
    module._fork_info["https://github.com/acme/broken"] = None
    assert module.fork_event_fields("https://github.com/acme/broken") == ({}, ["fork"])


def repo_event(data=None, tags=()):
    return SimpleNamespace(
        type="CODE_REPOSITORY",
        data={"url": "https://github.com/acme/tool", **(data or {})},
        tags={"git", "github", *tags},
    )


FORK = {"fork_branch": "main", "fork_since_commit": "c" * 40}


def test_scan_range_only_for_forks():
    assert gitleaks.fork_scan_range(repo_event()) is None
    assert gitleaks.fork_scan_range(repo_event(FORK, ["fork"])) == "c" * 40
    assert gitleaks.fork_scan_range(repo_event({"fork_branch": "main"}, ["fork", "fork-unmodified"])) == ""
    assert gitleaks.fork_scan_range(repo_event({}, ["fork"])) == ""


def run_handle_event(module_class, event):
    module = object.__new__(module_class)
    module.verbose = lambda message: None
    prepared = []

    async def prepare_scan_path(event):
        prepared.append(event)
        return None, False

    module.prepare_scan_path = prepare_scan_path
    asyncio.run(module.handle_event(event))
    return prepared


def test_scanners_skip_forks_they_cannot_limit():
    assert run_handle_event(gitleaks, repo_event(FORK, ["fork"]))
    assert run_handle_event(gitleaks, repo_event())
    assert not run_handle_event(gitleaks, repo_event({"fork_branch": "main"}, ["fork", "fork-unmodified"]))
    assert not run_handle_event(gitleaks, repo_event({}, ["fork"]))
    # Nosey Parker cannot scan a commit range, so a fork's inherited history must not reach it
    assert not run_handle_event(noseyparker, repo_event(FORK, ["fork"]))
    assert run_handle_event(noseyparker, repo_event())


def test_gitleaks_walks_only_commits_after_the_sync():
    class Gitleaks(gitleaks):
        config = {"git_commits_per_batch": 100}

    module = object.__new__(Gitleaks)
    counted, scanned = [], []

    async def run_process(command, **kwargs):
        counted.append(command[4:])
        return SimpleNamespace(returncode=0, stdout="3\n")

    async def scan_batch(scan_path, event, offset=None, size=None, revisions="--all"):
        scanned.append(revisions)
        return
        yield

    module.run_process = run_process
    module.scan_batch = scan_batch

    async def collect(event):
        return [f async for f in module.iter_findings("/repo", event)]

    asyncio.run(collect(repo_event(FORK, ["fork"])))
    asyncio.run(collect(repo_event()))
    assert counted == [["--count", f"{'c' * 40}..HEAD"], ["--count", "--all"]]
    assert scanned == [f"{'c' * 40}..HEAD", "--all"]


def test_kingfisher_diffs_from_the_sync():
    module = object.__new__(kingfisher)
    calls = []

    async def run_kingfisher(paths, extra_args=()):
        calls.append(list(extra_args))
        return []

    module.run_kingfisher = run_kingfisher

    async def collect(event):
        return [f async for f in module.iter_findings("/repo", event)]

    asyncio.run(collect(repo_event(FORK, ["fork"])))
    asyncio.run(collect(repo_event()))
    assert calls == [["--since-commit", "c" * 40, "--branch", "HEAD"], []]


def test_trufflehog_passes_the_range_to_its_git_scan():
    class Trufflehog(trufflehog):
        helpers = SimpleNamespace(tools_dir=Path("/tools"))
        scan = SimpleNamespace(home="/home")

    module = object.__new__(Trufflehog)
    module.verified = False
    module.config_file = ""
    module.concurrency = 1
    module.debug = lambda message: None
    commands = []

    async def run_process(command, **kwargs):
        commands.append(command[2])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    module.run_process = run_process

    async def collect(**kwargs):
        return [r async for r in module.execute_trufflehog("git", "https://github.com/acme/tool", **kwargs)]

    asyncio.run(collect(since_commit="c" * 40, branch="main"))
    asyncio.run(collect())
    assert commands[0].endswith(f"git https://github.com/acme/tool --since-commit={'c' * 40} --branch=main")
    assert commands[1].endswith("git https://github.com/acme/tool")


def clone_event(repository, tags=("git",)):
    """What git_clone emits for a repository it cloned (private repositories of a seeded owner)."""
    return SimpleNamespace(
        type="FILESYSTEM", data={"path": "/clones/acme-tool"}, tags=set(tags), get_parent=lambda: repository
    )


def test_a_cloned_fork_keeps_the_range_of_the_repository_it_was_cloned_from():
    assert gitleaks.fork_scan_range(clone_event(repo_event(FORK, ["fork"]))) == "c" * 40
    assert gitleaks.fork_branch(clone_event(repo_event(FORK, ["fork"]))) == "main"
    assert gitleaks.fork_scan_range(clone_event(repo_event({"fork_branch": "main"}, ["fork", "fork-unmodified"]))) == ""
    assert gitleaks.fork_scan_range(clone_event(repo_event())) is None
    # Not a Git clone (an unpacked APK, a docker image): no fork range applies
    assert gitleaks.fork_scan_range(clone_event(repo_event(FORK, ["fork"]), tags=("apk",))) is None


def test_scanners_skip_cloned_forks_they_cannot_limit():
    assert run_handle_event(gitleaks, clone_event(repo_event(FORK, ["fork"])))
    assert not run_handle_event(gitleaks, clone_event(repo_event({}, ["fork"])))
    assert not run_handle_event(noseyparker, clone_event(repo_event(FORK, ["fork"])))
    assert run_handle_event(noseyparker, clone_event(repo_event()))


def test_gitleaks_walks_only_the_own_commits_of_a_cloned_fork():
    class Gitleaks(gitleaks):
        config = {"git_commits_per_batch": 100}

    module = object.__new__(Gitleaks)
    counted, scanned = [], []

    async def run_process(command, **kwargs):
        counted.append(command[4:])
        return SimpleNamespace(returncode=0, stdout="2\n")

    async def scan_batch(scan_path, event, offset=None, size=None, revisions="--all"):
        scanned.append(revisions)
        return
        yield

    module.run_process = run_process
    module.scan_batch = scan_batch

    async def collect(event):
        return [f async for f in module.iter_findings("/clones/acme-tool", event)]

    asyncio.run(collect(clone_event(repo_event(FORK, ["fork"]))))
    assert counted == [["--count", f"{'c' * 40}..HEAD"]]
    assert scanned == [f"{'c' * 40}..HEAD"]
    assert module.scans_git_history(clone_event(repo_event(FORK, ["fork"])))
    assert not module.scans_git_history(clone_event(repo_event()))


def test_trufflehog_limits_a_cloned_fork_to_its_own_commits():
    module = object.__new__(trufflehog)
    module.verbose = lambda message: None
    module.deleted_forks = False
    calls = []

    async def execute_trufflehog(scanner, path=None, string=None, since_commit=None, branch=None):
        calls.append((scanner, path, since_commit, branch))
        return
        yield

    module.execute_trufflehog = execute_trufflehog
    fork = clone_event(repo_event(FORK, ["fork"]))
    fork.parent = SimpleNamespace(host="github.com")
    asyncio.run(module.handle_event(fork))
    unmodified = clone_event(repo_event({"fork_branch": "main"}, ["fork", "fork-unmodified"]))
    unmodified.parent = fork.parent
    asyncio.run(module.handle_event(unmodified))
    assert calls == [("git", "/clones/acme-tool", "c" * 40, "main")]
