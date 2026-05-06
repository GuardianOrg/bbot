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
