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
