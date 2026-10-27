import asyncio

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


def test_caa_lookup_failure_does_not_report_missing_policy():
    audit = object.__new__(domain_config_dns_audit)

    async def query_dns(_domain, _rdtype):
        return False, []

    audit.query_dns = query_dns
    findings = []
    asyncio.run(audit.check_caa("example.com", {}, findings))
    assert findings == []


def test_empty_successful_caa_answer_still_reports_missing_policy():
    audit = object.__new__(domain_config_dns_audit)

    async def query_dns(_domain, _rdtype):
        return True, []

    audit.query_dns = query_dns
    findings = []
    asyncio.run(audit.check_caa("example.com", {}, findings))
    assert [finding.title for finding in findings] == ["Missing CAA Records"]


def test_wildcard_issuer_is_malformed_not_broad_authorization():
    audit = object.__new__(domain_config_dns_audit)
    findings = []
    asyncio.run(audit.check_caa_policy_quality(
        "example.com", {"CAA": ['0 issuewild "*"']}, findings
    ))
    assert [(finding.title, finding.severity) for finding in findings] == [
        ("CAA Issuer Value Is Malformed", "INFO")
    ]


def test_ordinary_caa_issuer_remains_visible():
    audit = object.__new__(domain_config_dns_audit)
    findings = []
    asyncio.run(audit.check_caa_policy_quality(
        "example.com", {"CAA": ['0 issue "letsencrypt.org"']}, findings
    ))
    assert [finding.title for finding in findings] == ["CAA Uses issue Policy for Wildcards"]
    assert "issue values also govern" in findings[0].description
