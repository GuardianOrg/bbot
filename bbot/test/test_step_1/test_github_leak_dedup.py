from bbot.core.event.base import FINDING


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
    finding_1._dedupe_key = "github-leak:https://github.com/org/repo:secret"
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
    finding_2._dedupe_key = "github-leak:https://github.com/org/repo:secret"

    assert finding_1.id == finding_2.id
