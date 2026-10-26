import asyncio
from types import SimpleNamespace

import dns.rcode
import dns.rdatatype

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


def audit_with_dns_answers(answers):
    audit = object.__new__(domain_config_dns_audit)
    audit.is_apex_domain = lambda _domain: True
    audit.get_tld = lambda _domain: "com"

    async def query_dns(name, rdtype, nameserver=None):
        return answers.get((name, rdtype, nameserver), answers.get((name, rdtype), (False, [])))

    async def skip_other_check(*_args):
        return None

    audit.query_dns = query_dns
    audit.check_rrsig_expiration = skip_other_check
    audit.check_nsec_records = skip_other_check
    audit.check_dnssec_validation = skip_other_check
    return audit


def test_dnskey_lookup_failure_does_not_claim_dnssec_is_disabled():
    audit = audit_with_dns_answers({("example.com", "DNSKEY"): (False, [])})
    findings = []

    asyncio.run(audit.check_dnssec("example.com", {}, findings))

    assert findings == []


def test_successful_empty_dnskey_answer_reports_absence():
    audit = audit_with_dns_answers({("example.com", "DNSKEY"): (True, [])})
    findings = []

    asyncio.run(audit.check_dnssec("example.com", {}, findings))

    assert [finding.title for finding in findings] == ["DNSSEC Not Enabled"]


def test_dnskey_lookup_recovers_real_absence_from_alternate_resolver():
    audit = audit_with_dns_answers({
        ("example.com", "DNSKEY", "1.1.1.1"): (True, []),
    })
    findings = []

    asyncio.run(audit.check_dnssec("example.com", {}, findings))

    assert [finding.title for finding in findings] == ["DNSSEC Not Enabled"]


def test_existing_dnskey_overrides_empty_local_answer():
    audit = audit_with_dns_answers({
        ("example.com", "DNSKEY"): (True, []),
        ("example.com", "DNSKEY", "1.1.1.1"): (True, ["257 3 13 AAAA"]),
        ("example.com", "DS"): (True, ["12345 13 2 ABCD"]),
    })
    records = {}
    findings = []

    asyncio.run(audit.check_dnssec("example.com", records, findings))

    assert records["DNSKEY"] == ["257 3 13 AAAA"]
    assert not any(finding.title == "DNSSEC Not Enabled" for finding in findings)


def test_ds_lookup_failure_does_not_claim_parent_ds_is_missing():
    audit = audit_with_dns_answers({("example.com", "DNSKEY"): (True, ["257 3 13 AAAA"])})
    findings = []

    asyncio.run(audit.check_dnssec("example.com", {}, findings))

    assert findings == []


def test_ds_lookup_recovers_real_absence_from_alternate_resolver():
    audit = audit_with_dns_answers({
        ("example.com", "DNSKEY"): (True, ["257 3 13 AAAA"]),
        ("example.com", "DS", "1.1.1.1"): (True, []),
    })
    findings = []

    asyncio.run(audit.check_dnssec("example.com", {}, findings))

    assert [finding.title for finding in findings] == ["Missing DS Record at Parent"]


def test_ds_lookup_recovers_existing_parent_ds_from_alternate_resolver():
    audit = audit_with_dns_answers({
        ("example.com", "DNSKEY"): (True, ["257 3 13 AAAA"]),
        ("example.com", "DS", "1.1.1.1"): (True, ["12345 13 2 ABCD"]),
    })
    records = {}
    findings = []

    asyncio.run(audit.check_dnssec("example.com", records, findings))

    assert records["DS"] == ["12345 13 2 ABCD"]
    assert not any(finding.title == "Missing DS Record at Parent" for finding in findings)


def test_existing_ds_overrides_empty_local_answer():
    audit = audit_with_dns_answers({
        ("example.com", "DNSKEY"): (True, ["257 3 13 AAAA"]),
        ("example.com", "DS"): (True, []),
        ("example.com", "DS", "1.1.1.1"): (True, ["12345 13 2 ABCD"]),
    })
    records = {}
    findings = []

    asyncio.run(audit.check_dnssec("example.com", records, findings))

    assert records["DS"] == ["12345 13 2 ABCD"]
    assert not any(finding.title == "Missing DS Record at Parent" for finding in findings)


def test_successful_empty_ds_answer_reports_missing_parent_ds_once():
    audit = audit_with_dns_answers({
        ("example.com", "DNSKEY"): (True, ["257 3 13 AAAA"]),
        ("example.com", "DS"): (True, []),
    })
    findings = []

    asyncio.run(audit.check_dnssec("example.com", {}, findings))

    assert [finding.title for finding in findings] == ["Missing DS Record at Parent"]


def test_missing_ds_suppresses_ad_flag_and_negative_validation_reports(monkeypatch):
    audit = object.__new__(domain_config_dns_audit)
    audit.is_apex_domain = lambda _domain: True
    queries = []

    async def response_must_not_be_queried(*_args, **_kwargs):
        raise AssertionError("A missing parent DS cannot yield an authenticated answer")

    audit.query_dns_full = response_must_not_be_queried
    monkeypatch.setattr("dns.query.udp", lambda *_args, **_kwargs: queries.append(True))
    records = {"DNSKEY": ["257 3 13 AAAA"]}
    findings = []

    asyncio.run(audit.check_dnssec_validation("example.com", records, findings))
    asyncio.run(audit.check_dnssec_negative_validation("example.com", records, findings))

    assert findings == []
    assert queries == []


def test_ad_flag_check_still_runs_when_parent_ds_exists():
    audit = object.__new__(domain_config_dns_audit)

    async def unsigned_response(*_args, **_kwargs):
        return True, SimpleNamespace(flags=0)

    audit.query_dns_full = unsigned_response
    findings = []

    asyncio.run(audit.check_dnssec_validation(
        "example.com", {"DNSKEY": ["257 3 13 AAAA"], "DS": ["12345 13 2 ABCD"]}, findings
    ))

    assert [finding.title for finding in findings] == ["DNSSEC Validation Failing"]


def test_unauthenticated_negative_answer_still_reports_when_parent_ds_exists(monkeypatch):
    audit = object.__new__(domain_config_dns_audit)
    audit.is_apex_domain = lambda _domain: True
    audit.dns_timeout = 1
    response = SimpleNamespace(
        flags=0,
        rcode=lambda: dns.rcode.NXDOMAIN,
        authority=[SimpleNamespace(rdtype=dns.rdatatype.NSEC)],
    )
    monkeypatch.setattr("dns.query.udp", lambda *_args, **_kwargs: response)
    findings = []

    asyncio.run(audit.check_dnssec_negative_validation(
        "example.com", {"DNSKEY": ["257 3 13 AAAA"], "DS": ["12345 13 2 ABCD"]}, findings
    ))

    assert [finding.title for finding in findings] == ["DNSSEC Negative Response Not Validated"]
