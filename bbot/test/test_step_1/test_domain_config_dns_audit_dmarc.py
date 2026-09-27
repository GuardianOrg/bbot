import asyncio

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


def findings_for_dmarc(record):
    audit = object.__new__(domain_config_dns_audit)

    async def query_dns(name, rdtype):
        assert (name, rdtype) == ("_dmarc.example.com", "TXT")
        return True, [record]

    audit.query_dns = query_dns
    findings = []
    asyncio.run(audit.check_dmarc("example.com", {"MX": ["10 mail.example.com"]}, findings))
    return findings


def test_reject_without_sp_protects_subdomains_by_inheritance():
    findings = findings_for_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")

    assert not any(finding.title == "DMARC Missing Subdomain Policy" for finding in findings)
    assert not any(finding.title == "DMARC Subdomain Policy Weaker Than Parent" for finding in findings)


def test_quarantine_without_sp_also_inherits_the_parent_policy():
    findings = findings_for_dmarc("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com")

    assert not any(finding.title == "DMARC Missing Subdomain Policy" for finding in findings)
    assert not any(finding.title == "DMARC Subdomain Policy Weaker Than Parent" for finding in findings)


def test_none_without_sp_does_not_create_a_second_weak_policy_finding():
    findings = findings_for_dmarc("v=DMARC1; p=none; rua=mailto:dmarc@example.com")

    assert any(finding.title == "DMARC Policy Set to None" for finding in findings)
    assert not any(finding.title == "DMARC Missing Subdomain Policy" for finding in findings)
    assert not any(finding.title == "DMARC Subdomain Policy Weaker Than Parent" for finding in findings)


def test_explicit_none_subdomain_policy_weakens_parent_reject():
    findings = findings_for_dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com")

    assert any(
        finding.title == "DMARC Subdomain Policy Weaker Than Parent" and finding.severity == "MEDIUM"
        for finding in findings
    )


def test_explicit_quarantine_subdomain_policy_weakens_parent_reject():
    findings = findings_for_dmarc("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com")

    assert any(
        finding.title == "DMARC Subdomain Policy Weaker Than Parent" and finding.severity == "LOW"
        for finding in findings
    )


def test_equal_explicit_subdomain_policy_is_not_marked_weak():
    findings = findings_for_dmarc("v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com")

    assert not any(finding.title == "DMARC Subdomain Policy Weaker Than Parent" for finding in findings)
