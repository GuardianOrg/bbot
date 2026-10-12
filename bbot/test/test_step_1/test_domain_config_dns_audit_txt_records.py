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


def spf_findings(*txt):
    findings = []
    asyncio.run(audit_with_records({}).check_spf('example.com', {'TXT': list(txt), 'MX': ['10 mx.example.com.']}, findings))
    return {finding.title for finding in findings}


def test_spf_does_not_treat_ptr_in_a_provider_name_as_a_mechanism():
    titles = spf_findings('v=spf1 include:ptr.mail.example.com -all')
    assert 'SPF Uses Deprecated PTR Mechanism' not in titles


def test_spf_keeps_real_ptr_mechanisms():
    for mechanism in ('ptr', 'ptr:example.com', '+ptr', '~ptr:example.com'):
        assert 'SPF Uses Deprecated PTR Mechanism' in spf_findings(f'v=spf1 {mechanism} -all')


def test_spf_ignores_unrelated_txt_containing_version_text():
    titles = spf_findings('v=spf1 -all', 'verification=some-v=spf1-token')
    assert 'Multiple SPF Records' not in titles
    assert 'Missing SPF Record' in spf_findings('verification=v=spf1')


def test_spf_detects_allow_all_before_modifiers_and_with_implicit_plus():
    for record in ('v=spf1 all', 'v=spf1 +all exp=explain.example.com', 'v=spf1 +all -all'):
        assert 'SPF Allows All Senders' in spf_findings(record)


def test_spf_uses_first_all_mechanism():
    titles = spf_findings('v=spf1 -all +all')
    assert 'SPF Allows All Senders' not in titles


def test_spf_retains_multiple_real_records():
    assert 'Multiple SPF Records' in spf_findings('v=spf1 -all', 'v=spf1 +all')


def mx_findings(*mx):
    audit = audit_with_records({})
    audit.managed_mx_suffixes = []

    async def query_dns(host, kind):
        return True, [] if host == 'missing.example.com' else ['203.0.113.1']

    audit.query_dns = query_dns
    findings = []
    records = {'MX': list(mx)}
    asyncio.run(audit.check_mx_security('example.com', records, findings))
    assert records['MX'] == list(mx)
    return {finding.title for finding in findings}


def test_equal_mx_priorities_are_valid_for_self_hosted_load_balancing():
    assert 'Duplicate MX Priorities' not in mx_findings('10 mx1.example.com.', '10 mx2.example.com.')


def test_equal_mx_priorities_do_not_hide_broken_exchange_hosts():
    titles = mx_findings('10 mx1.example.com.', '10 missing.example.com.', '10 localhost.', '10 192.0.2.1')
    assert {'MX Does Not Resolve', 'MX Points to Localhost/Internal', 'MX Points to IP Address'} <= titles


def test_null_mx_conflicts_stay_detected_with_equal_priorities():
    assert 'Null MX Mixed With Other MX Records' in mx_findings('0 .', '0 mx.example.com.')


def test_spf_detects_bare_lookup_mechanisms_over_the_limit():
    policy = 'v=spf1 ' + ' '.join(['a', 'mx'] * 6) + ' -all'
    assert 'SPF Exceeds DNS Lookup Limit' in spf_findings(policy)


def test_spf_does_not_count_mechanism_text_inside_unknown_modifiers():
    policy = 'v=spf1 vendor=' + 'include:' * 12 + ' -all'
    assert 'SPF Exceeds DNS Lookup Limit' not in spf_findings(policy)


def test_spf_does_not_report_unevaluated_mechanisms_after_all():
    policy = 'v=spf1 -all ptr ' + ' '.join(f'include:mail{i}.example.com' for i in range(12))
    titles = spf_findings(policy)
    assert 'SPF Exceeds DNS Lookup Limit' not in titles
    assert 'SPF Uses Deprecated PTR Mechanism' not in titles


def test_spf_ignored_redirect_does_not_increase_lookup_count():
    policy = 'v=spf1 ' + ' '.join(f'include:mail{i}.example.com' for i in range(10)) + ' -all redirect=other.example.com'
    assert 'SPF Exceeds DNS Lookup Limit' not in spf_findings(policy)


def test_spf_keeps_explicit_lookup_limit_findings():
    policy = 'v=spf1 ' + ' '.join(f'include:mail{i}.example.com' for i in range(11)) + ' -all'
    assert 'SPF Exceeds DNS Lookup Limit' in spf_findings(policy)


def test_spf_include_depth_does_not_query_ignored_terms():
    audit = audit_with_records({})
    queries = []

    async def query_dns(host, kind):
        queries.append((host, kind))
        return True, ['v=spf1 -all']

    audit.query_dns = query_dns
    policies = [
        'v=spf1 -all ' + ' '.join(f'include:mail{i}.example.com' for i in range(12)),
        'v=spf1 -all redirect=other.example.com',
        'v=spf1 redirect=other.example.com -all',
    ]
    for policy in policies:
        findings = []
        asyncio.run(audit.check_spf_include_depth('example.com', {'SPF': policy}, findings))
        assert not findings
    assert not queries


def test_spf_nested_lookup_counter_ignores_non_spf_txt_and_keeps_bare_mechanisms():
    audit = audit_with_records({})
    nested_records = []

    async def query_dns(host, kind):
        return True, nested_records

    audit.query_dns = query_dns
    records = {'SPF': 'v=spf1 include:mail.example.com -all'}
    nested_records[:] = ['v=spf1 -all', 'vendor=v=spf1 ' + 'include:' * 12]
    findings = []
    asyncio.run(audit.check_spf_include_depth('example.com', records, findings))
    assert not findings

    nested_records[:] = ['v=spf1 ' + ' '.join(['a', 'mx'] * 5) + ' -all']
    findings = []
    asyncio.run(audit.check_spf_include_depth('example.com', records, findings))
    assert any(f.title == 'SPF Approaching Lookup Limit' for f in findings)
