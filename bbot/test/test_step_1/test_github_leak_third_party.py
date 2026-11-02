import asyncio
from types import SimpleNamespace

from bbot.modules.templates.github_leak_formatter import github_leak_formatter


class Formatter(github_leak_formatter):
    name = "kingfisher"

    def debug(self, *args, **kwargs):
        pass

    async def run_process(self, *args, **kwargs):
        return SimpleNamespace(stdout="")


def checkout(tmp_path):
    # A Foundry project inside the repo with its dependencies declared as submodules (as in a CTF repo).
    project = tmp_path / "HalbornCTF_Solidity_Ethereum"
    project.mkdir()
    (project / ".gitmodules").write_text(
        '[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://github.com/foundry-rs/forge-std\n'
        '[submodule "oz"]\n  path = lib/openzeppelin-contracts/\n  url = https://github.com/OpenZeppelin/openzeppelin-contracts\n'
    )
    return tmp_path


def test_secrets_in_other_projects_code_are_third_party(tmp_path):
    root = checkout(tmp_path)
    f = Formatter()
    third_party = [
        "HalbornCTF_Solidity_Ethereum/lib/forge-std/src/StdChains.sol",
        "HalbornCTF_Solidity_Ethereum/lib/openzeppelin-contracts/lib/forge-std/foundry.toml",
        "web/node_modules/aws-sdk/test/config.js",
        "/app/Vendor/firebase/GoogleService-Info.plist",
        "jython-standalone-2.7.2.jar!org/python/netty/handler/ssl/OpenSsl.class",
        "libs/bcprov-jdk15on-1.70.jar!org/bouncycastle/test.key",
        "/HalbornCTF_Solidity_Ethereum/lib/forge-std/src/Vm.sol",
    ]
    for path in third_party:
        assert f.is_third_party_path(root, path), path


def test_the_organizations_own_code_is_not_third_party(tmp_path):
    root = checkout(tmp_path)
    f = Formatter()
    own = [
        "HalbornCTF_Solidity_Ethereum/src/Exploit.sol",
        "HalbornCTF_Solidity_Ethereum/lib/forge-std-fork/src/Config.sol",  # same prefix, not the submodule
        "HalbornCTF_Solidity_Ethereum/lib/forge-std",  # the submodule pointer itself
        "libs/internal-auth/config.js",  # a monorepo's own library
        "src/vendor.js",  # a file named like a dependency folder
        "bin/vendor",  # a script named like a dependency folder
        "release/app-release.jar!config.properties",
        "release/app-7.jar!config.properties",  # a build number, not a library release  # an unversioned build of their own
        "mobile/acme-2.1.0.apk!res/values/strings.xml",  # the organization's own app
        "",
    ]
    for path in own:
        assert not f.is_third_party_path(root, path), path


def test_a_leak_in_third_party_code_is_not_reported_but_one_in_own_code_is(tmp_path):
    root = checkout(tmp_path)
    f = Formatter()
    event = SimpleNamespace(data={"url": "https://github.com/HalbornSecurity/CTFs"})

    def leak(path):
        return asyncio.run(
            f.format_github_leak(
                event,
                root,
                "b1d3925804e74152b316ca7da97060d3",
                detector="Infura",
                file_path=path,
                line=6,
                commit="14e1d668ac0b7d4302ad00b26c7bdd62e42d9c0b",
                verified=True,
            )
        )

    assert leak(str(root / "HalbornCTF_Solidity_Ethereum/lib/forge-std/foundry.toml")) is None
    own = leak(str(root / "HalbornCTF_Solidity_Ethereum/foundry.toml"))
    assert own["file_url"].endswith("/HalbornCTF_Solidity_Ethereum/foundry.toml#L6")
    assert own["severity"] == "High"


class GitFormatter(Formatter):
    async def run_process(self, command, env=None, **kwargs):
        import subprocess

        self.commands = getattr(self, "commands", []) + [command]
        return subprocess.run(command, capture_output=True, text=True, env=env)


def remote_repo(tmp_path):
    """A repository only reachable by URL whose nested Foundry project declares lib/forge-std as a submodule
    in the first commit and drops that declaration in the second one."""
    import subprocess

    repo = tmp_path / "remote"
    project = repo / "HalbornCTF_Solidity_Ethereum"
    (project / "lib/forge-std/src").mkdir(parents=True)
    (repo / ".gitmodules").write_text('[submodule "tools"]\n\tpath = tools/solc\n\turl = https://example.com/solc\n')
    (project / ".gitmodules").write_text(
        '[submodule "lib/forge-std"]\n\tpath = lib/forge-std\n\turl = https://example.com/f\n'
    )
    (project / "lib/forge-std/src/StdChains.sol").write_text("infura b1d3925804e74152b316ca7da97060d3\n")
    (project / "foundry.toml").write_text("rpc = 'b1d3925804e74152b316ca7da97060d3'\n")

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout

    git("init", "-q")
    git("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "with submodules")
    first = git("rev-parse", "HEAD").strip()
    (project / ".gitmodules").unlink()
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "vendored now")
    second = git("rev-parse", "HEAD").strip()
    return repo.as_uri(), first, second


def test_a_repository_scanned_by_url_reads_the_submodules_declared_at_the_leaks_commit(tmp_path):
    url, first, second = remote_repo(tmp_path)
    f = GitFormatter()
    vendored = "HalbornCTF_Solidity_Ethereum/lib/forge-std/src/StdChains.sol"
    own = "HalbornCTF_Solidity_Ethereum/foundry.toml"
    try:
        at_first = asyncio.run(f.remote_submodule_paths(url, first, vendored))
        assert at_first == {"HalbornCTF_Solidity_Ethereum/lib/forge-std", "tools/solc"}
        assert f.is_third_party_path(url, vendored, at_first)
        assert f.is_third_party_path(
            url, "tools/solc/keys.txt", asyncio.run(f.remote_submodule_paths(url, first, "tools/solc/keys.txt"))
        )
        assert not f.is_third_party_path(url, own, asyncio.run(f.remote_submodule_paths(url, first, own)))
        # Once the project stopped declaring the submodule, the committed copy is the organization's code.
        at_second = asyncio.run(f.remote_submodule_paths(url, second, vendored))
        assert at_second == {"tools/solc"}
        assert not f.is_third_party_path(url, vendored, at_second)
        # One clone per repository, reused for every finding.
        assert sum(command[1] == "clone" for command in f.commands) == 1
        clone = f._remote_clones[url]
        assert clone.is_dir()
    finally:
        f.cleanup_remote_clones()
    assert not clone.exists()


def test_an_unreachable_repository_or_missing_commit_means_no_submodules(tmp_path):
    f = GitFormatter()
    missing = (tmp_path / "nowhere").as_uri()
    assert asyncio.run(f.remote_submodule_paths(missing, "14e1d668", "a/lib/x.sol")) == set()
    url, first, _ = remote_repo(tmp_path)
    assert asyncio.run(f.remote_submodule_paths(url, "", "HalbornCTF_Solidity_Ethereum/lib/forge-std/a.sol")) == set()
    assert (
        asyncio.run(f.remote_submodule_paths(url, "0" * 40, "HalbornCTF_Solidity_Ethereum/lib/forge-std/a.sol"))
        == set()
    )
    f.cleanup_remote_clones()
