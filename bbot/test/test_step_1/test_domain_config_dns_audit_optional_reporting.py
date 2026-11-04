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


def test_service_binding_records_remain_inventory_without_absence_finding():
    module = object.__new__(domain_config_dns_audit)

    async def query_dns(name, rdtype):
        if name == "example.com" and rdtype == "HTTPS":
            return True, ['1 . alpn="h2"']
        return True, []

    module.query_dns = query_dns
    records = {"A": ["192.0.2.1"]}
    findings = []
    asyncio.run(module.check_https_svcb_records("example.com", records, findings))
    assert records["HTTPS"] == ['example.com: 1 . alpn="h2"']
    assert not findings

    records = {"A": ["192.0.2.1"]}
    async def no_records(_name, _rdtype):
        return True, []
    module.query_dns = no_records
    asyncio.run(module.check_https_svcb_records("example.com", records, findings))
    assert not findings
