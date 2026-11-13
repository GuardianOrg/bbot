import asyncio
from types import SimpleNamespace

from .base import ModuleTestBase


def test_initial_dns_preserves_absence_but_not_failed_or_conflicting_answers():
    from bbot.modules.monitoring_dns import monitoring_dns
    from bbot.core.event import make_event

    module = object.__new__(monitoring_dns)
    captured = []

    async def query(host, kind, provider):
        if kind == "AAAA":
            return True, ["2606:4700:4700::1111"] if provider == "1.1.1.1" else []
        if kind == "SRV":
            return False, []
        if kind == "MX":
            return True, ["10 mx.one.example" if provider == "1.1.1.1" else "10 mx.two.example"]
        if kind == "TXT":
            return True, ["v=spf1 include:mail.example ~all"]
        if kind == "SOA":
            return True, [
                "ns.example hostmaster.example 10 60 60 86400 60"
                if provider == "1.1.1.1"
                else "ns.example hostmaster.example 11 60 60 86400 60"
            ]
        return True, []

    async def emit(payload, kind, **kwargs):
        event = make_event(payload, kind, dummy=True)
        captured.append(event)
        return event

    module.query_record = query
    module.emit_event = emit
    asyncio.run(module.handle_event(SimpleNamespace(host="example.com")))
    assert len(captured) == 1
    data = captured[0].data
    assert data["monitoring_records"]["A"] == []
    assert data["monitoring_records"]["TXT"] == ["v=spf1 include:mail.example ~all"]
    assert "SOA" in data["monitoring_records"]
    assert "MX" not in data["monitoring_records"]
    assert "AAAA" not in data["monitoring_records"]
    assert "SRV" not in data["monitoring_records"]
    assert data["monitoring_errors"] == {
        "AAAA": "resolvers-disagree",
        "MX": "resolvers-disagree",
        "SRV": "lookup-unavailable",
    }


def test_initial_dangling_cname_requires_repeated_corroboration_and_emits_matching_finding():
    from bbot.modules.monitoring_dns import monitoring_dns
    module = object.__new__(monitoring_dns)
    captured = []
    current = {'target': 'deleted.example.net', 'missing': True}

    async def query(host, kind, provider):
        return True, [current['target']] if kind == 'CNAME' else []

    async def missing(target, provider):
        return current['missing']

    async def emit(payload, kind, **kwargs):
        captured.append((kind, payload))
        return SimpleNamespace(data=payload)

    module.query_record, module.target_nxdomain, module.emit_event = query, missing, emit
    event = SimpleNamespace(host='app.example.com')
    asyncio.run(module.handle_event(event))
    assert not [row for row in captured if row[0] == 'FINDING']
    asyncio.run(module.finish())
    findings = [row[1] for row in captured if row[0] == 'FINDING']
    assert len(findings) == 1
    assert findings[0]['severity'] == 'HIGH'
    assert findings[0]['monitor_targets'] == ['deleted.example.net']
    asyncio.run(module.finish())
    assert len([row for row in captured if row[0] == 'FINDING']) == 1
    # A candidate that recovers before confirmation cannot become a finding.
    current['target'] = 'recovered.example.net'
    asyncio.run(module.handle_event(event))
    current['missing'] = False
    asyncio.run(module.finish())
    assert len([row for row in captured if row[0] == 'FINDING']) == 1


def test_target_existence_distinguishes_nxdomain_nodata_and_unavailable(monkeypatch):
    import dns.resolver
    import dns.exception
    import bbot.modules.monitoring_dns as source
    module = object.__new__(source.monitoring_dns)
    outcome = {'error': None}
    class Resolver:
        async def resolve(self, *args, **kwargs):
            if outcome['error']:
                raise outcome['error']
            return []
    monkeypatch.setattr(source.dns.asyncresolver, 'Resolver', lambda **kwargs: Resolver())
    for error, expected in [(None, False), (dns.resolver.NXDOMAIN(), True),
                            (dns.resolver.NoAnswer(), False), (dns.exception.Timeout(), None)]:
        outcome['error'] = error
        assert asyncio.run(module.target_nxdomain('target.example.net', '1.1.1.1')) is expected



class TestMonitoringDnsBrokenAlias(ModuleTestBase):
    module_name = 'monitoring_dns'
    targets = ['app.example.com']
    config_overrides = {'deps': {'behavior': 'disable'}, 'dns': {'emit_unresolved': False},
                        'omit_event_types': ['DNS_NAME_UNRESOLVED']}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller
        async def fake_install_core_deps(self):
            return None
        module_test.monkeypatch.setattr(DepsInstaller, 'install_core_deps', fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({'app.example.com': {'CNAME': ['gone.example.net']}})
        async def query(host, kind, provider):
            return True, ['gone.example.net'] if kind == 'CNAME' else []
        async def missing(target, provider):
            return True
        module_test.monkeypatch.setattr(module_test.module, 'query_record', query)
        module_test.monkeypatch.setattr(module_test.module, 'target_nxdomain', missing)

    def check(self, module_test, events):
        findings = [event for event in events if event.type == 'FINDING'
                    and event.data.get('title') == 'Dangling CNAME for app.example.com']
        assert len(findings) == 1
        assert findings[0].data['severity'] == 'HIGH'
        assert findings[0].data['monitor_targets'] == ['gone.example.net']
        assert any(event.type == 'DOMAIN_DNS_CONFIG' for event in events)
