import json
from datetime import datetime

from .base import ModuleTestBase


class TestDomainPhishing(ModuleTestBase):
    module_name = "domain_phishing"
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {
            "domain_phishing": {
                "binary": "/bin/echo",
                "young_domain_days": 45,
                "min_score": 3,
            }
        },
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        from bbot.modules.base import BaseModule

        async def fake_run_process(self_module, cmd, *args, **kwargs):
            class FakeResult:
                returncode = 0
                stdout = json.dumps(
                    [
                        {
                            "domain": "blacklanternsecur1ty.com",
                            "fuzzer": "replacement",
                            "dns-a": ["1.2.3.4"],
                            "dns-mx": ["mx1.example.com"],
                            "dns-ns": ["ns1.example.com"],
                            "created": "2026-05-01",
                        },
                        {
                            "domain": "blacklanternsecurity.com",
                            "fuzzer": "replacement",
                        },
                    ]
                )
                stderr = ""

            return FakeResult()

        module_test.monkeypatch.setattr(BaseModule, "run_process", fake_run_process)

        module_test.monkeypatch.setattr(
            module_test.module,
            "_whois_lookup",
            lambda domain: {
                "registrar": "NameCheap, Inc.",
                "creation_date": datetime(2026, 4, 15, 10, 0, 0),
                "org": "Shady Buyer LLC",
                "emails": ["abuse@evil.example"],
                "name": "John Phisher",
                "country": "PA",
            },
        )

    def check(self, module_test, events):
        phishing_events = [
            e
            for e in events
            if e.type in ("FINDING", "VULNERABILITY") and e.data.get("category") == "phishing-lookalike-domain"
        ]
        assert len(phishing_events) == 1

        event = phishing_events[0]
        assert event.type == "VULNERABILITY"
        assert event.data["host"] == "blacklanternsecur1ty.com"
        assert event.data["category"] == "phishing-lookalike-domain"
        assert event.data["source-domain"] == "blacklanternsecurity.com"
        assert event.data["probability"] == event.data["score"]
        assert event.data["probability"] >= 4
        assert event.data["title"] == "Potential phishing look-alike domain: blacklanternsecur1ty.com"
        assert "Candidate domain: blacklanternsecur1ty.com" in event.data["evidence"]

        # WHOIS ownership fingerprint is attached for downstream de-duplication.
        assert event.data["registrar"] == "NameCheap, Inc."
        assert event.data["registration_date"] == "2026-04-15T10:00:00"
        assert event.data["registrant_org"] == "Shady Buyer LLC"
        assert event.data["registrant_email"] == "abuse@evil.example"
        assert event.data["registrant_name"] == "John Phisher"
        assert event.data["registrant_country"] == "PA"


def test_domain_phishing_change_key_suppression():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.history_file = "/tmp/domain_phishing_state.json"
    mod.known = {}

    key = mod._candidate_change_key(
        {"domain": "x.com", "whois_created": "2026-04-15T10:00:00", "whois_registrar": "MarkMonitor, Inc."}
    )
    assert key == {"created": "2026-04-15", "registrar": "markmonitor inc"}
    assert mod._is_known_unchanged("x.com", key) is False

    mod._remember_candidate("x.com", key)
    assert mod._is_known_unchanged("x.com", key) is True

    # RDAP-style UTC date + differently-punctuated registrar for the same owner still match.
    key_same_owner = mod._candidate_change_key(
        {"domain": "x.com", "whois_created": "2026-04-15T10:00:00.000Z", "whois_registrar": "MarkMonitor Inc"}
    )
    assert mod._is_known_unchanged("x.com", key_same_owner) is True

    # A genuine registration-date change is not suppressed.
    key_changed = mod._candidate_change_key(
        {"domain": "x.com", "whois_created": "2027-01-01", "whois_registrar": "MarkMonitor, Inc."}
    )
    assert mod._is_known_unchanged("x.com", key_changed) is False


def test_domain_phishing_suppression_disabled_without_history_file():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.history_file = ""
    mod.known = {}
    key = mod._candidate_change_key({"domain": "x.com", "whois_created": "2026-04-15", "whois_registrar": "R"})
    mod._remember_candidate("x.com", key)
    # With no history_file configured, nothing is remembered and nothing is suppressed.
    assert mod.known == {}
    assert mod._is_known_unchanged("x.com", key) is False
