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


def test_forensic_report_destination_does_not_require_optional_fo_tag():
    findings = findings_for_dmarc("v=DMARC1; p=reject; rua=mailto:aggregate@example.com; ruf=mailto:forensic@example.com")
    assert not any(finding.title == "DMARC Forensic Reporting Not Configured" for finding in findings)


def test_missing_optional_forensic_reporting_is_not_a_vulnerability():
    findings = findings_for_dmarc("v=DMARC1; p=reject; rua=mailto:aggregate@example.com")
    assert not any(finding.title == "DMARC Forensic Reporting Not Configured" for finding in findings)


def spoofing_findings(dmarc_answer, spf="v=spf1 include:_spf.google.com -all", lookup_ok=True, mx=("10 mail.example.com",)):
    audit = object.__new__(domain_config_dns_audit)

    async def query_dns(name, rdtype):
        return lookup_ok, ([dmarc_answer] if dmarc_answer else []) if lookup_ok else ["timeout"]

    audit.query_dns = query_dns
    records = {"NS": ["ns1.example.net"], "MX": list(mx)}
    if spf:
        records["SPF"] = spf
    findings = []
    asyncio.run(audit.check_dmarc("example.com", records, findings))
    asyncio.run(audit.check_email_spoofing("example.com", records, findings))
    return [finding for finding in findings if finding.title == "Email Spoofing Possible"]


def test_missing_dmarc_makes_the_domain_spoofable_even_with_spf_hard_fail():
    (finding,) = spoofing_findings(None)

    assert finding.severity == "HIGH"
    assert finding.category == "Email-Spoofing"
    assert finding.details["spf"] == "v=spf1 include:_spf.google.com -all"
    assert finding.details["dmarc"] == "none"
    assert "publishes no DMARC record" in finding.details["spoofing_reason"]
    assert "SPF only checks the envelope sender" in finding.details["spoofing_reason"]


def test_monitoring_only_or_invalid_dmarc_is_spoofable():
    (none,) = spoofing_findings("v=DMARC1; p=none; rua=mailto:d@example.com", spf=None)
    assert "p=none, which only monitors" in none.details["spoofing_reason"]
    assert "no SPF record" in none.details["spoofing_reason"]
    (invalid,) = spoofing_findings("v=DMARC1; rua=mailto:d@example.com", spf="v=spf1 ~all")
    assert "no valid p= policy" in invalid.details["spoofing_reason"]
    assert "SPF ends in ~all" in invalid.details["spoofing_reason"]


def test_subdomains_left_at_none_are_spoofable():
    (finding,) = spoofing_findings("v=DMARC1; p=reject; sp=none")
    assert "sets sp=none" in finding.details["spoofing_reason"]


def test_enforced_dmarc_or_an_unknown_answer_is_not_reported_as_spoofable():
    assert spoofing_findings("v=DMARC1; p=reject") == []
    assert spoofing_findings("v=DMARC1; p=quarantine; sp=reject") == []
    assert spoofing_findings(None, lookup_ok=False) == []


def test_a_domain_that_receives_no_mail_is_not_reported_as_spoofable():
    assert spoofing_findings(None, spf=None, mx=()) == []
    # A null MX (RFC 7505) says the domain accepts no mail.
    assert spoofing_findings(None, spf=None, mx=("0 .",)) == []
    assert len(spoofing_findings(None, spf=None, mx=("0 .", "10 mail.example.com"))) == 1
