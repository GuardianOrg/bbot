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
                event, root, "b1d3925804e74152b316ca7da97060d3", detector="Infura", file_path=path, line=6,
                commit="14e1d668ac0b7d4302ad00b26c7bdd62e42d9c0b", verified=True,
            )
        )

    assert leak(str(root / "HalbornCTF_Solidity_Ethereum/lib/forge-std/foundry.toml")) is None
    own = leak(str(root / "HalbornCTF_Solidity_Ethereum/foundry.toml"))
    assert own["file_url"].endswith("/HalbornCTF_Solidity_Ethereum/foundry.toml#L6")
    assert own["severity"] == "High"
