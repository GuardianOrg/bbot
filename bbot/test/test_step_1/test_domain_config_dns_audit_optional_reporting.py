import asyncio

from bbot.modules.domain_config_dns_audit import domain_config_dns_audit


def test_missing_optional_telemetry_is_not_emitted_as_a_finding():
    module = object.__new__(domain_config_dns_audit)

    async def query_dns(name, rdtype):
        if name == "_smtp._tls.example.com":
            return True, []
        if name == "example.com" and rdtype == "CAA":
            return True, ['0 issue "letsencrypt.org"']
        raise AssertionError((name, rdtype))

    module.query_dns = query_dns
    records = {"MX": ["10 mail.example.com"]}
    findings = []
    asyncio.run(module.check_tls_rpt("example.com", records, findings))
    asyncio.run(module.check_caa("example.com", records, findings))
    assert records["CAA"]
    assert not findings
