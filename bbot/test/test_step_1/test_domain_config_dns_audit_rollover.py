import asyncio

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


def audit_with_lifecycle_records(records):
    audit = object.__new__(domain_config_dns_audit)
    audit.is_apex_domain = lambda _domain: True

    async def query_dns(name, rdtype):
        return True, records.get((name, rdtype), [])

    audit.query_dns = query_dns
    return audit


def test_matching_cds_without_cdnskey_is_not_an_incomplete_rollover():
    # multicoin.capital publishes CDS for a parent that already holds the matching DS.
    digest = "75A65C598E9320CBDDE7DEDC02EEDBCD5EC181ACF8FDEBE498F254F45AA24651"
    ds = f"3614 8 2 {digest}"
    audit = audit_with_lifecycle_records({
        ("multicoin.capital", "DS"): [ds],
        ("multicoin.capital", "CDS"): [ds],
    })
    findings = []

    asyncio.run(audit.check_dnssec_lifecycle("multicoin.capital", {"DNSKEY": ["signed"]}, findings))

    assert not any("Rollover Signal Incomplete" in finding.title for finding in findings)


def test_cdnskey_without_cds_is_not_an_incomplete_rollover():
    audit = audit_with_lifecycle_records({
        ("example.com", "CDNSKEY"): ["3614 257 3 8 AwEAAa"],
    })
    findings = []

    asyncio.run(audit.check_dnssec_lifecycle("example.com", {"DNSKEY": ["signed"]}, findings))

    assert not any("Rollover Signal Incomplete" in finding.title for finding in findings)


def test_parent_child_key_tag_mismatch_remains_actionable():
    audit = audit_with_lifecycle_records({
        ("example.com", "DS"): ["1111 8 2 ABCDEF"],
        ("example.com", "CDS"): ["2222 8 2 ABCDEF"],
    })
    findings = []

    asyncio.run(audit.check_dnssec_lifecycle("example.com", {"DNSKEY": ["signed"]}, findings))

    assert any(finding.title == "DNSSEC Parent/Child Key Tag Mismatch" and finding.severity == "HIGH" for finding in findings)
