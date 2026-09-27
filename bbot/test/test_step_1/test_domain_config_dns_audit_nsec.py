import asyncio

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


def audit_with_nsec_records(records):
    audit = object.__new__(domain_config_dns_audit)

    async def query_dns(name, rdtype):
        return True, records.get((name, rdtype), [])

    audit.query_dns = query_dns
    return audit


def test_online_signed_minimally_covering_nsec_is_not_zone_walking():
    # Cloudflare returned this exact next-name shape for eight QA domains.
    audit = audit_with_nsec_records({
        ("example.com", "NSEC"): [r"\000.example.com. A NS SOA MX TXT RRSIG NSEC DNSKEY"],
    })
    findings = []

    asyncio.run(audit.check_nsec_records("example.com", findings))

    assert not any(finding.title == "NSEC Allows Zone Walking" for finding in findings)


def test_static_nsec_chain_still_reports_zone_walking():
    audit = audit_with_nsec_records({
        ("example.com", "NSEC"): ["www.example.com. NS SOA RRSIG NSEC"],
        ("www.example.com", "NSEC"): ["example.com. A RRSIG NSEC"],
    })
    findings = []

    asyncio.run(audit.check_nsec_records("example.com", findings))

    assert any(finding.title == "NSEC Allows Zone Walking" for finding in findings)
