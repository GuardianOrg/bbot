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


def test_weak_dkim_uses_rsa_modulus_bits_instead_of_encoded_length():
    # DER structure overhead makes a 896-bit modulus look larger than 1024 bits
    # when the detector estimates key size from Base64 character count.
    public_key = RSA.construct(((1 << 895) | 65537, 65537), consistency_check=False)
    encoded = base64.b64encode(public_key.export_key(format="DER")).decode()
    audit = audit_with_records({("google._domainkey.example.com", "TXT"): [
        txt_record("v=DKIM1; k=rsa; p=" + encoded[:100], encoded[100:250], encoded[250:])
    ]})
    audit.dkim_selectors = ["google"]
    findings = []

    asyncio.run(audit.check_dkim("example.com", {}, findings))

    assert any(finding.title == "Weak DKIM Key Size" and "896 bits" in finding.evidence for finding in findings)


def test_malformed_dkim_public_key_is_reported():
    audit = audit_with_records({("google._domainkey.example.com", "TXT"): [txt_record("v=DKIM1; k=rsa; p=not_base64!")]})
    audit.dkim_selectors = ["google"]
    findings = []

    asyncio.run(audit.check_dkim("example.com", {}, findings))

    assert any(finding.title == "Invalid DKIM Public Key" for finding in findings)


def test_unpadded_dkim_base64_is_not_marked_invalid():
    # RFC 6376 allows p= base64 without trailing padding.
    public_key = RSA.construct(((1 << 1535) | 65537, 65537), consistency_check=False)
    encoded = base64.b64encode(public_key.export_key(format="DER")).decode().rstrip("=")
    audit = audit_with_records({("google._domainkey.example.com", "TXT"): [
        txt_record("v=DKIM1; k=rsa; p=" + encoded[:100], encoded[100:250], encoded[250:])
    ]})
    audit.dkim_selectors = ["google"]
    findings = []

    asyncio.run(audit.check_dkim("example.com", {}, findings))

    assert not any(finding.title == "Invalid DKIM Public Key" for finding in findings)


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
