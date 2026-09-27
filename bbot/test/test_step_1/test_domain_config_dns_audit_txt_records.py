import asyncio
import base64

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from Crypto.PublicKey import RSA

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


class FakeResolver:
    def __init__(self, records):
        self.records = records

    def resolve(self, domain, rdtype):
        if (domain, rdtype) not in self.records:
            raise dns.resolver.NoAnswer
        return self.records[domain, rdtype]


def txt_record(*pieces):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, " ".join(f'"{piece}"' for piece in pieces))


def audit_with_records(records):
    audit = object.__new__(domain_config_dns_audit)
    audit.dns_cache = {}
    audit.get_resolver = lambda nameserver=None: FakeResolver(records)
    return audit


def test_multistring_dkim_txt_is_one_2048_bit_key():
    public_der = RSA.generate(2048).public_key().export_key(format="DER")
    public_key = base64.b64encode(public_der).decode()
    record = txt_record("v=DKIM1; k=rsa; p=" + public_key[:110], public_key[110:260], public_key[260:])
    audit = audit_with_records({("google._domainkey.example.com", "TXT"): [record]})
    audit.dkim_selectors = ["google"]
    records = {}
    findings = []

    asyncio.run(audit.check_dkim("example.com", records, findings))

    assert records["DKIM_selectors"] == ["google"]
    assert not any(finding.title == "Weak DKIM Key Size" for finding in findings)


def test_tls_rpt_destination_does_not_include_txt_presentation_quotes():
    report_domain = "tls.reports.example.com"
    audit = audit_with_records({
        ("_smtp._tls.example.com", "TXT"): [txt_record(f"v=TLSRPTv1; rua=mailto:reports@{report_domain}")],
        (report_domain, "MX"): [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, "10 mx.example.com.")],
    })
    records = {"MX": ["10 mx.example.com"]}
    findings = []

    async def check():
        await audit.check_tls_rpt("example.com", records, findings)
        await audit.check_tls_rpt_destinations("example.com", records, findings)

    asyncio.run(check())

    assert not any(finding.title == "Potentially Undeliverable TLS-RPT Destination" for finding in findings)
