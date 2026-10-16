from bbot.core.event.base import FINDING
from bbot.modules.templates.github_leak_formatter import github_leak_formatter


def test_github_leak_dedupe_key_controls_finding_identity():
    finding_1 = FINDING(
        {
            "host": "github.com",
            "url": "https://github.com/org/repo/blob/abc/file#L1",
            "tool": "gitleaks",
            "rule": "generic-api-key",
        },
        "FINDING",
        _dummy=True,
    )
    finding_1._dedupe_key = github_leak_formatter.secret_dedupe_key(
        "https://github.com/Org/Repo", "secret-fingerprint"
    )
    finding_2 = FINDING(
        {
            "host": "github.com",
            "url": "https://github.com/org/repo/blob/def/file#L9",
            "tool": "trufflehog",
            "rule": "github-token",
        },
        "FINDING",
        _dummy=True,
    )
    finding_2._dedupe_key = github_leak_formatter.secret_dedupe_key(
        "https://github.com/org/repo/", "secret-fingerprint"
    )

    assert finding_1.id == finding_2.id

    other_repository = FINDING(dict(finding_2.data), "FINDING", _dummy=True)
    other_repository._dedupe_key = github_leak_formatter.secret_dedupe_key(
        "https://github.com/org/another-repo", "secret-fingerprint"
    )
    another_secret = FINDING(dict(finding_2.data), "FINDING", _dummy=True)
    another_secret._dedupe_key = github_leak_formatter.secret_dedupe_key(
        "https://github.com/org/repo", "different-fingerprint"
    )
    assert finding_1.id != other_repository.id
    assert finding_1.id != another_secret.id
