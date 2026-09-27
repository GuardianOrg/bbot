import json
import base64
from types import SimpleNamespace

import pytest

from .base import ModuleTestBase
from bbot.modules.templates.github_leak_formatter import github_leak_formatter


kingfisher_calls = []
# What the fake Kingfisher run returns; a test may change it in setup_after_prep.
kingfisher_outcome = {}


def test_public_recaptcha_site_key_is_not_reported_as_a_secret(tmp_path):
    class Formatter(github_leak_formatter):
        name = "kingfisher"

    key = "6LsyntheticSiteKeyForRegressionTest1234567890"
    artifact = tmp_path / "manifest.json"
    artifact.write_text(f'<div class="g-recaptcha" data-sitekey="{key}"></div>\n')
    root = SimpleNamespace(type="SCAN", data=None, parent=None)
    url = SimpleNamespace(type="URL_UNVERIFIED", data="https://accounts.example.com/manifest.json", parent=root)
    event = SimpleNamespace(type="FILESYSTEM", data={"path": str(artifact)}, parent=url)
    formatter = Formatter()

    assert formatter.format_artifact_leak(
        event, artifact, key, detector="reCAPTCHA API Key", file_path=str(artifact), line=1,
    ) is None
    assert formatter.format_artifact_leak(
        event, artifact, key, detector="reCAPTCHA API Key", file_path=str(artifact), line=1, verified=True,
    )["severity"] == "High"

    artifact.write_text(f'<script>const recaptchaSecretKey = "{key}";</script>\n')
    assert formatter.format_artifact_leak(
        event, artifact, key, detector="reCAPTCHA API Key", file_path=str(artifact), line=1,
    )["category"] == "secret"


def test_public_amplitude_project_api_key_is_not_a_secret_key(tmp_path):
    class Formatter(github_leak_formatter):
        name = "kingfisher"

    key = "0123456789abcdef0123456789abcdef"
    artifact = tmp_path / "page.html"
    artifact.write_text(f'<script>\\"integrations\\":{{\\"amplitude\\":{{\\"apiKey\\":\\"{key}\\"}}}}</script>\n')
    root = SimpleNamespace(type="SCAN", data=None, parent=None)
    url = SimpleNamespace(type="URL_UNVERIFIED", data="https://docs.example.com/page.html", parent=root)
    event = SimpleNamespace(type="FILESYSTEM", data={"path": str(artifact)}, parent=url)
    formatter = Formatter()

    assert formatter.format_artifact_leak(
        event, artifact, key, detector="Amplitude Secret Key", file_path=str(artifact), line=1, verified=True,
    ) is None

    artifact.write_text(f'<script>const amplitudeSecretKey = "{key}";</script>\n')
    assert formatter.format_artifact_leak(
        event, artifact, key, detector="Amplitude Secret Key", file_path=str(artifact), line=1, verified=True,
    )["category"] == "secret"


def test_documentation_placeholders_are_not_reported_as_secrets(tmp_path):
    class Formatter(github_leak_formatter):
        name = "kingfisher"

    artifact = tmp_path / "api-docs.md"
    artifact.write_text("Authorization: Bearer YOUR_ACCESS_TOKEN\nSECRET=\"XXXXXXXXXXXXXX\"\n")
    root = SimpleNamespace(type="SCAN", data=None, parent=None)
    url = SimpleNamespace(type="URL_UNVERIFIED", data="https://docs.example.com/api-docs.md", parent=root)
    event = SimpleNamespace(type="FILESYSTEM", data={"path": str(artifact)}, parent=url)
    formatter = Formatter()

    for value, detector in (
        ("Authorization: Bearer YOUR_ACCESS_TOKEN", "HTTP Bearer Token"),
        ('SECRET="XXXXXXXXXXXXXX', "Generic Secret"),
        (
            r"-----BEGIN EC PRIVATE KEY-----\nYOUR PRIVATE KEY\n-----END EC PRIVATE KEY-----\n"
            '"\n\nclient = RESTClient(api_key=api_key, api_secret=api_secret)',
            "private-key",
        ),
    ):
        assert formatter.format_artifact_leak(event, artifact, value, detector=detector) is None
        assert formatter.format_artifact_leak(event, artifact, value, detector=detector, verified=True)[
            "severity"
        ] == "High"

    assert formatter.format_artifact_leak(
        event, artifact, "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature", detector="HTTP Bearer Token"
    )["category"] == "secret"
    assert formatter.format_artifact_leak(
        event, artifact, "-----BEGIN EC PRIVATE KEY-----\nMIIExampleKeyMaterial\n-----END EC PRIVATE KEY-----",
        detector="private-key",
    )["category"] == "secret"


def test_expired_jwt_artifacts_are_not_reported_as_secrets(tmp_path):
    class Formatter(github_leak_formatter):
        name = "kingfisher"

    def token(expires_at):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        claims = base64.urlsafe_b64encode(json.dumps({"sub": "fixture", "exp": expires_at}).encode()).decode().rstrip("=")
        return f"{header}.{claims}.fixturesignature"

    expired = token(1701980000)
    future = token(4102444800)
    artifact = tmp_path / "api-docs.yaml"
    artifact.write_text(f"jwt: {expired}\n")
    root = SimpleNamespace(type="SCAN", data=None, parent=None)
    url = SimpleNamespace(type="URL_UNVERIFIED", data="https://docs.example.com/api-docs.yaml", parent=root)
    event = SimpleNamespace(type="FILESYSTEM", data={"path": str(artifact)}, parent=url)
    formatter = Formatter()

    for detector in ("jwt", "JSON Web Token (base64url-encoded)"):
        assert formatter.format_artifact_leak(event, artifact, expired, detector=detector) is None
        assert formatter.format_artifact_leak(event, artifact, expired, detector=detector, verified=True)[
            "category"
        ] == "secret"
        assert formatter.format_artifact_leak(event, artifact, future, detector=detector)["category"] == "secret"


@pytest.fixture
def mock_kingfisher(monkeypatch):
    kingfisher_calls.clear()
    kingfisher_outcome.update(returncode=200, status="Not Attempted")

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
        assert cmd[3:] == ["--format", "json", "--quiet", "--no-update-check", "--no-dedup", "--jobs", "1"]
        kingfisher_calls.append(cmd)
        scan_path = cmd[2]
        class FakeResult:
            # Kingfisher exits 200 when it reports findings, 205 when one was validated as live.
            returncode = kingfisher_outcome["returncode"]
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
                                "validation": {"status": kingfisher_outcome["status"], "response": ""},
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


class TestKingfisherValidatedSecret(TestKingfisher):
    module_name = "kingfisher"

    async def setup_after_prep(self, module_test):
        kingfisher_outcome.update(returncode=205, status="Active Credential")
        await super().setup_after_prep(module_test)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]

        assert len(findings) == 1
        assert findings[0].data["severity"] == "High"
        assert findings[0].data["validation_status"] == "active credential"


batch_calls = []
# A multi-file Kingfisher run fails as a whole (rc 1) when any one of its paths cannot be read.
batch_outcome = {}


@pytest.fixture
def mock_kingfisher_batch(monkeypatch):
    batch_calls.clear()
    batch_outcome.update(fail_multi_file=False)

    async def fake_run_process(self, cmd, *args, **kwargs):
        if cmd[0] != "kingfisher":
            class FakeGitResult:
                # Downloaded files are not Git checkouts: no remote, no HEAD.
                returncode = 128
                stdout = ""
                stderr = "fatal: not a git repository"

            return FakeGitResult()

        paths = cmd[2 : cmd.index("--format")]
        batch_calls.append(paths)
        if batch_outcome["fail_multi_file"] and len(paths) > 1:
            class FailedResult:
                returncode = 1
                stdout = ""
                stderr = "Error: No such file or directory"

            return FailedResult()
        findings = []
        for path in paths:
            # Archives are reported per member as "<archive>!<member>".
            reported = f"{path}!config/prod.env" if path.endswith(".zip") else path
            findings.append(
                {
                    "rule": {"name": "AWS Secret Access Key", "id": "aws"},
                    "finding": {
                        "snippet": f"secret-for-{path.rsplit('/', 1)[-1]}",
                        "fingerprint": path,
                        "line": 3,
                        "path": reported,
                        "validation": {"status": "unknown"},
                    },
                }
            )

        class FakeResult:
            returncode = 200
            stdout = json.dumps({"findings": findings})
            stderr = ""

        return FakeResult()

    from bbot.modules.base import BaseModule
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    async def fake_install_core_deps(self):
        return None

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
    monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)


@pytest.mark.usefixtures("mock_kingfisher_batch")
class TestKingfisherDownloadedFiles(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    module_name = "kingfisher"
    config_overrides = {"deps": {"behavior": "disable"}}
    downloads = {"app.js": "/static/app.js", "config.json": "/config.json", "bundle.zip": "/bundle.zip"}

    async def setup_after_prep(self, module_test):
        # Queue every download before the module starts handling them, as filedownload does in bulk.
        for name, url_path in self.downloads.items():
            file_path = module_test.scan.temp_dir / name
            file_path.write_text("placeholder")
            url_event = module_test.scan.make_event(
                f"http://127.0.0.1:8888{url_path}", "URL_UNVERIFIED", parent=module_test.scan.root_event
            )
            file_event = module_test.scan.make_event(
                {"path": str(file_path)}, "FILESYSTEM", tags=["filedownload", "file"], parent=url_event
            )
            await module_test.module.queue_event(file_event)

    def check(self, module_test, events):
        findings = {e.data["url"]: e for e in events if e.type == "FINDING"}

        assert set(findings) == {f"http://127.0.0.1:8888{url_path}" for url_path in self.downloads.values()}
        scanned = [path for call in batch_calls for path in call]
        assert sorted(p.rsplit("/", 1)[-1] for p in scanned) == sorted(self.downloads)
        assert len(batch_calls) < len(self.downloads), "downloaded files were not scanned together"
        for name, url_path in self.downloads.items():
            finding = findings[f"http://127.0.0.1:8888{url_path}"]
            assert finding.data["location"] == finding.data["url"]
            assert finding.data["secret_value"] == f"secret-for-{name}"
            assert finding.data["title"] == "Leak of AWS Secret Access Key detected in a public artifact"
            assert "repository_url" not in finding.data
        archive = findings["http://127.0.0.1:8888/bundle.zip"]
        assert archive.data["path"] == "bundle.zip!config/prod.env"
        assert "bundle.zip!config/prod.env:line 3" in archive.data["description"]


@pytest.mark.usefixtures("mock_kingfisher_batch")
class TestKingfisherFailedBatchRescansFiles(TestKingfisherDownloadedFiles):
    async def setup_after_prep(self, module_test):
        batch_outcome.update(fail_multi_file=True)
        await super().setup_after_prep(module_test)

    def check(self, module_test, events):
        findings = {e.data["url"] for e in events if e.type == "FINDING"}

        assert findings == {f"http://127.0.0.1:8888{url_path}" for url_path in self.downloads.values()}
        assert sorted(len(call) for call in batch_calls) == [1, 1, 1, 3]


def test_batch_source_key_handles_bang_in_file_names():
    from bbot.modules.templates.code_secret_scanner import code_secret_scanner

    lookup = {"/tmp/scan/a!b.zip": "/tmp/scan/a!b.zip", "/tmp/scan/app.js": "/tmp/scan/app.js"}

    assert code_secret_scanner.batch_source_key("/tmp/scan/a!b.zip!config/prod.env", lookup) == "/tmp/scan/a!b.zip"
    assert code_secret_scanner.batch_source_key("/tmp/scan/app.js", lookup) == "/tmp/scan/app.js"
    assert code_secret_scanner.batch_source_key("/tmp/scan/other.js", lookup) is None
