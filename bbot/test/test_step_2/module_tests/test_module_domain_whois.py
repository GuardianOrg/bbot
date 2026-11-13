from datetime import date, datetime

from .base import ModuleTestBase


class TestDomainWhois(ModuleTestBase):
    module_name = "domain_whois"
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"deps": {"behavior": "disable"}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        module_test.monkeypatch.setattr(
            module_test.module,
            "lookup_whois",
            lambda domain: {
                "registrar": "MarkMonitor Inc.",
                "creation_date": datetime(2020, 1, 2, 3, 4, 5),
                "expiration_date": date(2030, 1, 2),
                "updated_date": "2025-04-01T02:03:04Z",
                "name": "Example Admin",
                "emails": ["dns-admin@blacklanternsecurity.com"],
                "registrant_email": "dns-admin@blacklanternsecurity.com",
                "org": "Black Lantern Security",
                "country": "US",
                "dnssec": "signed",
                "status": ["clientTransferProhibited", "clientUpdateProhibited"],
            },
        )

    def check(self, module_test, events):
        whois_events = [e for e in events if e.type == "DOMAIN_WHOIS"]
        assert len(whois_events) == 1

        event = whois_events[0]
        assert event.data["host"] == "blacklanternsecurity.com"
        assert event.data["registrar"] == "MarkMonitor Inc."
        assert event.data["registration_date"] == "2020-01-02T03:04:05"
        assert event.data["expiration_date"] == "2030-01-02T00:00:00"
        assert event.data["updated_date"] == "2025-04-01T02:03:04Z"
        assert event.data["registrant_name"] == "Example Admin"
        assert event.data["registrant_email"] == "dns-admin@blacklanternsecurity.com"
        assert event.data["registrant_org"] == "Black Lantern Security"
        assert event.data["registrant_country"] == "US"
        assert event.data["dnssec"] is True
        assert event.data["whois_status"] == ["clientTransferProhibited", "clientUpdateProhibited"]


class TestDomainWhoisRdapFallback(TestDomainWhois):
    targets = ["polychain.capital"]

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        await module_test.mock_dns({"polychain.capital": {"A": ["127.0.0.88"]}})

    async def setup_after_prep(self, module_test):
        def failed_whois(_domain):
            raise RuntimeError("Whois command returned no output")

        async def rdap(_domain):
            return {
                "registrar": "Example Registrar",
                "creation_date": "2016-07-24T00:36:56.017Z",
                "status": ["client transfer prohibited"],
            }

        module_test.monkeypatch.setattr(module_test.module, "lookup_whois", failed_whois)
        module_test.monkeypatch.setattr(module_test.module, "lookup_rdap", rdap, raising=False)
        module_test.monkeypatch.setattr(module_test.module, "WHOIS_RETRY_DELAYS", (0, 0), raising=False)

    def check(self, module_test, events):
        whois_events = [e for e in events if e.type == "DOMAIN_WHOIS"]
        assert len(whois_events) == 1
        assert whois_events[0].data["host"] == "polychain.capital"
        assert whois_events[0].data["whois_status"] == ["client transfer prohibited"]
        assert module_test.scan.finish_event().data["status"] == "FINISHED"


class TestDomainWhoisBothSourcesFailed(TestDomainWhoisRdapFallback):
    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)

        async def failed_rdap(_domain):
            raise RuntimeError("RDAP returned an invalid domain response")

        module_test.monkeypatch.setattr(module_test.module, "lookup_rdap", failed_rdap, raising=False)

    def check(self, module_test, events):
        assert module_test.scan.finish_event().data["status"] == "FAILED"
        assert not any(e.type == "DOMAIN_WHOIS" for e in events)


class TestDomainWhoisRetriesWhoisWithoutRdap(TestDomainWhoisRdapFallback):
    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)
        self.whois_calls = []

        def flaky_whois(domain):
            self.whois_calls.append(domain)
            if len(self.whois_calls) < 3:
                raise RuntimeError("Whois command returned no output")
            return {"registrar": "Example Registrar", "status": ["clientTransferProhibited"]}

        async def no_rdap(domain):
            raise ValueError(f"No authoritative RDAP service found for {domain}")

        module_test.monkeypatch.setattr(module_test.module, "lookup_whois", flaky_whois)
        module_test.monkeypatch.setattr(module_test.module, "lookup_rdap", no_rdap, raising=False)

    def check(self, module_test, events):
        whois_events = [e for e in events if e.type == "DOMAIN_WHOIS"]
        assert len(whois_events) == 1
        assert whois_events[0].data["whois_status"] == ["clientTransferProhibited"]
        assert self.whois_calls == ["polychain.capital"] * 3
        assert module_test.scan.finish_event().data["status"] == "FINISHED"


def test_domain_whois_gives_up_after_the_last_whois_retry():
    import asyncio
    from types import SimpleNamespace

    import pytest

    from bbot.modules.domain_whois import domain_whois

    mod = object.__new__(domain_whois)
    calls = {"whois": 0, "rdap": 0}

    def failed_whois(_domain):
        calls["whois"] += 1
        raise RuntimeError("timed out")

    async def failed_rdap(domain):
        calls["rdap"] += 1
        raise ValueError(f"No authoritative RDAP service found for {domain}")

    mod.lookup_whois, mod.lookup_rdap, mod.WHOIS_RETRY_DELAYS = failed_whois, failed_rdap, (0, 0)
    mod.scan = SimpleNamespace(helpers=SimpleNamespace(split_domain=lambda host: ("", host)))
    mod.debug = lambda *_: None

    with pytest.raises(RuntimeError, match="3 attempts"):
        asyncio.run(mod.handle_event(SimpleNamespace(data="gyzer.io")))
    assert calls == {"whois": 3, "rdap": 1}


def test_domain_whois_rdap_bootstrap_preserves_registration_status():
    import asyncio
    from types import SimpleNamespace

    from bbot.modules.domain_whois import domain_whois

    mod = object.__new__(domain_whois)
    responses = {
        "https://data.iana.org/rdap/dns.json": {
            "services": [[["capital"], ["https://rdap.identitydigital.services/rdap/"]]],
        },
        "https://rdap.identitydigital.services/rdap/domain/polychain.capital": {
            "objectClassName": "domain",
            "ldhName": "polychain.capital",
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "registration", "eventDate": "2016-07-24T00:36:56.017Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
        },
    }

    async def request(url, **_kwargs):
        return SimpleNamespace(status_code=200, json=lambda: responses[url])

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))
    result = asyncio.run(mod.lookup_rdap("polychain.capital"))

    assert result["status"] == ["client transfer prohibited"]
    assert result["creation_date"] == "2016-07-24T00:36:56.017Z"
    assert result["registrar"] == "Example Registrar"


def test_initial_whois_risk_is_reported_in_addition_to_baseline_metadata():
    import asyncio
    from types import SimpleNamespace
    from bbot.modules.domain_whois import domain_whois
    mod = object.__new__(domain_whois)
    mod.scan = SimpleNamespace(helpers=SimpleNamespace(split_domain=lambda _: ('', 'example.com')))
    mod.lookup_whois = lambda _: {'registrar': 'Example Registrar', 'status': ['pendingDelete']}
    emitted = []
    async def emit(data, kind, **kwargs):
        emitted.append((kind, data))
        return object()
    mod.emit_event = emit
    asyncio.run(mod.handle_event(SimpleNamespace(data='example.com')))
    assert any(kind == 'DOMAIN_WHOIS' for kind, _ in emitted)
    assert any(kind == 'FINDING' and data['severity'] == 'CRITICAL' and 'lifecycle' in data['title'] for kind, data in emitted)


def test_initial_registration_findings_preserve_expiry_lifecycle_and_registry_visibility():
    from datetime import timezone, timedelta
    from bbot.core.helpers.registration_findings import initial_registration_findings
    now = datetime(2026, 11, 13, tzinfo=timezone.utc)
    secure = ['clientTransferProhibited', 'clientDeleteProhibited', 'clientUpdateProhibited']
    for days, severity, window in [(20, 'HIGH', 30), (5, 'CRITICAL', 7), (-1, 'CRITICAL', 0)]:
        findings = initial_registration_findings({'host': 'example.com', 'whois_status': secure,
            'expiration_date': (now + timedelta(days=days)).isoformat()}, now=now)
        assert len(findings) == 1 and findings[0]['severity'] == severity
        assert findings[0]['monitor_value'] == f'expiry:{window}'
    assert initial_registration_findings({'host': 'example.com', 'whois_status': []}, now=now) == []
    assert initial_registration_findings({'host': 'example.ch', 'whois_status': ['active']}, now=now) == []
    findings = initial_registration_findings({'host': 'example.ch', 'whois_status': ['pendingDelete'],
                                             'lock_statuses_published': False}, now=now)
    assert len(findings) == 1 and findings[0]['severity'] == 'CRITICAL'


def test_free_form_registry_text_cannot_prove_a_missing_transfer_lock():
    from bbot.core.helpers.registration_findings import initial_registration_findings
    assert initial_registration_findings({'host': 'example.uk', 'whois_status': ['Registered until expiry date.']}) == []
    findings = initial_registration_findings({'host': 'example.uk', 'whois_status': ['pendingDelete']})
    assert any(row['severity'] == 'CRITICAL' for row in findings)
    assert any(row['monitor_value'] == 'lock:missing' for row in findings)


def test_registration_lock_publication_provenance_survives_the_event_schema():
    from bbot.core.event import make_event
    event = make_event({'host': 'example.ch', 'whois_status': ['active'],
                        'lock_statuses_published': False}, 'DOMAIN_WHOIS', dummy=True)
    assert event.data.get('lock_statuses_published') is False
