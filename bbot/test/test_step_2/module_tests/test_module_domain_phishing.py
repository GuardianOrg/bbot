import asyncio
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

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
            assert "--tld" in cmd
            tlds = Path(cmd[cmd.index("--tld") + 1]).read_text().splitlines()
            assert {"com", "net", "io", "co", "xyz", "finance", "money"}.issubset(set(tlds))
            assert "vowel-swap" in cmd[cmd.index("--fuzzers") + 1].split(",")

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
                            "domain": "black-lanternsecurity.com",
                            "fuzzer": "hyphenation",
                            "dns-a": ["1.2.3.5"],
                            "dns-mx": ["mx2.example.com"],
                            "dns-ns": ["ns2.example.com"],
                            "created": "2026-05-01",
                        },
                        {
                            "domain": "blacklanternsecuritys.com",
                            "fuzzer": "addition",
                            "dns-mx": ["mx3.example.com"],
                            "dns-ns": ["ns3.example.com"],
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
            "_monitor_extra_candidates",
            lambda _root, _rows: asyncio.sleep(0, result=[]),
        )

        async def fake_request(url, **_kwargs):
            if "black-lanternsecurity.com" in url:
                return SimpleNamespace(
                    url=url,
                    status_code=301,
                    headers={"location": "https://blacklanternsecurity.com/"},
                )
            return SimpleNamespace(url=url, status_code=200, headers={})

        module_test.monkeypatch.setattr(module_test.module.helpers, "request", fake_request)

        module_test.monkeypatch.setattr(
            module_test.module,
            "_whois_lookup",
            lambda domain: {
                "registrar": "NameCheap, Inc.",
                "creation_date": datetime(2026, 4, 15, 10, 0, 0),
                "org": "Shady Buyer LLC",
                "emails": ["abuse@evil.example"],
                "registrant_email": "abuse@evil.example",
                "name": "John Phisher",
                "country": "PA",
            },
        )

    def check(self, module_test, events):
        assert module_test.scan.finish_event().data["status"] == "FINISHED"
        phishing_events = [
            e
            for e in events
            if e.type in ("FINDING", "VULNERABILITY") and e.data.get("category") == "phishing-lookalike-domain"
        ]
        assert len(phishing_events) == 2

        event = next(e for e in phishing_events if e.data["host"] == "blacklanternsecur1ty.com")
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

        low = next(e for e in phishing_events if e.data["host"] == "blacklanternsecuritys.com")
        assert low.type == "FINDING"
        assert low.data["severity"] == "LOW"


class TestDomainPhishingFailedProcess(ModuleTestBase):
    module_name = "domain_phishing"
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {"domain_phishing": {"binary": "/bin/echo", "fuzzers": ["omission"]}},
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        from bbot.modules.base import BaseModule

        async def failed_run_process(self_module, cmd, *args, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="dnstwist failed")

        module_test.monkeypatch.setattr(BaseModule, "run_process", failed_run_process)

    def check(self, module_test, events):
        assert module_test.scan.finish_event().data["status"] == "FAILED"
        assert not any(e.type in ("FINDING", "VULNERABILITY") for e in events)


class TestDomainPhishingRegisteredWithoutAddress(ModuleTestBase):
    module_name = "domain_phishing"
    targets = ["coinbase.com"]
    config_overrides = {
        "deps": {"behavior": "disable"},
        "dns": {"emit_unresolved": False, "max_unresolved_subdomains_per_module": 1},
        "modules": {"domain_phishing": {"binary": "/bin/echo", "fuzzers": ["addition"], "min_score": 3}},
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)
        await module_test.mock_dns({"coinbase.com": {"A": ["127.0.0.88"]}})

    async def setup_after_prep(self, module_test):
        from bbot.modules.base import BaseModule

        async def fake_run_process(self_module, cmd, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                {
                    "domain": "coinbasef.com", "fuzzer": "addition",
                    "dns_ns": ["jerome.ns.cloudflare.com"],
                    "whois_created": datetime.now().date().isoformat(),
                },
                {
                    "domain": "coinbases.com", "fuzzer": "addition",
                    "dns_mx": ["route1.mx.cloudflare.net"], "dns_ns": ["damon.ns.cloudflare.com"],
                },
            ]), stderr="")

        module_test.monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
        module_test.monkeypatch.setattr(
            module_test.module, "_monitor_extra_candidates", lambda _root, _rows: asyncio.sleep(0, result=[])
        )
        module_test.monkeypatch.setattr(
            module_test.module,
            "_lookup_ownership_fingerprint",
            lambda _domain: asyncio.sleep(0, result=module_test.module._empty_fingerprint()),
        )

    def check(self, module_test, events):
        phishing_events = [
            event for event in events
            if event.type in ("FINDING", "VULNERABILITY")
            and event.data.get("category") == "phishing-lookalike-domain"
        ]
        assert module_test.scan.finish_event().data["status"] == "FINISHED"
        assert {event.data["host"] for event in phishing_events} == {"coinbasef.com", "coinbases.com"}
        assert not any(event.type == "DNS_NAME_UNRESOLVED" for event in events)


class TestDomainPhishingCancelledProcess(TestDomainPhishingFailedProcess):
    async def setup_after_prep(self, module_test):
        from bbot.modules.base import BaseModule

        async def cancelled_run_process(self_module, cmd, *args, **kwargs):
            raise asyncio.CancelledError

        module_test.monkeypatch.setattr(BaseModule, "run_process", cancelled_run_process)


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


def test_domain_phishing_does_not_score_dnstwist_dns_errors_as_live_records():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.young_domain_days = 45
    mod.lsh_threshold = 70
    candidate = {
        "domain": "coindase.com",
        "fuzzer": "homoglyph",
        "dns_a": ["!ServFail"],
        "dns_aaaa": ["!ServFail"],
        "dns_ns": ["!ServFail"],
        "whois_created": "2017-06-21",
    }

    score, severity, reasons = mod._score_candidate(candidate)

    assert score == 2
    assert severity == "LOW"
    assert reasons == ["visually deceptive permutation (homoglyph)"]
    assert "!ServFail" not in mod._build_evidence(candidate, "homoglyph", score, reasons)


@pytest.mark.parametrize("null_mx", ["0 .", "0.", "0 ", "."])
def test_domain_phishing_null_mx_does_not_score_mail_service(null_mx):
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.young_domain_days = 45
    mod.lsh_threshold = 70
    candidate = {
        "domain": "4r.ca",
        "fuzzer": "homoglyph",
        "dns-a": ["192.0.2.10"],
        "dns-mx": [null_mx],
        "dns-ns": ["ns1.example.net"],
        "whois-created": "2005-01-20",
    }

    score, severity, reasons = mod._score_candidate(candidate)

    assert score == 4
    assert severity == "MEDIUM"
    assert not any("MX" in reason or "mail" in reason for reason in reasons)


def test_domain_phishing_supplies_tld_dictionary_for_tld_swap(tmp_path):
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.binary = "/bin/echo"
    mod.registered_only = True
    mod.enable_lsh = False
    mod.threads = 1
    mod.fuzzers = domain_phishing.options["fuzzers"]
    mod.tld_swap_tlds = domain_phishing.options["tld_swap_tlds"]
    mod.nameservers = []
    mod.tld_file = None
    mod.max_candidates = domain_phishing.options["max_candidates"]
    mod.debug = lambda *_args: None
    command = []

    def tempfile(contents, pipe=False):
        path = tmp_path / "tlds.txt"
        path.write_text("\n".join(contents))
        return path

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(
        split_domain=lambda _domain: ("", "bitpay.com"), is_domain=lambda _domain: True, tempfile=tempfile
    ))

    async def run_process(cmd, **_kwargs):
        command.extend(cmd)
        return SimpleNamespace(stdout="[]")

    mod.run_process = run_process
    mod._monitor_extra_candidates = lambda _root, _rows: asyncio.sleep(0, result=[])
    asyncio.run(mod.handle_event(SimpleNamespace(data="bitpay.com")))

    assert "--tld" in command
    assert {"com", "net", "io", "co", "xyz", "finance", "money"}.issubset(
        set(Path(command[command.index("--tld") + 1]).read_text().splitlines())
    )
    assert "vowel-swap" in command[command.index("--fuzzers") + 1].split(",")
    assert "repetition" in command[command.index("--fuzzers") + 1].split(",")


def test_domain_phishing_keeps_monitor_only_homoglyph_and_final_insertion():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.binary = "/bin/echo"
    mod.registered_only = True
    mod.enable_lsh = False
    mod.threads = 1
    mod.fuzzers = domain_phishing.options["fuzzers"]
    mod.tld_swap_tlds = domain_phishing.options["tld_swap_tlds"]
    mod.nameservers = []
    mod.tld_file = None
    mod.max_candidates = 2000
    mod.min_score = 3
    mod.young_domain_days = 45
    mod.lsh_threshold = 70
    mod.history_file = ""
    mod.known = {}
    mod.scan = SimpleNamespace(helpers=SimpleNamespace(
        split_domain=lambda _domain: ("", "coinbase.com"),
        is_domain=lambda _domain: True,
        tempfile=lambda _contents, pipe=False: Path("/tmp/tlds.txt"),
    ))
    mod.run_process = lambda *_args, **_kwargs: asyncio.sleep(0, result=SimpleNamespace(stdout="[]"))
    mod._redirects_to_protected_domain = lambda *_args: asyncio.sleep(0, result=False)
    mod.info = lambda *_args: None
    mod.debug = lambda *_args: None
    emitted = []

    async def resolve_extra(domain, fuzzer):
        if domain not in {"coinba5e.com", "coinbasre.com"}:
            return None
        return {
            "domain": domain,
            "fuzzer": fuzzer,
            "dns-a": ["1.2.3.4"],
            "dns-ns": ["ns.example.com"],
            "_monitor_fingerprint": mod._empty_fingerprint(),
        }

    async def emit_event(payload, event_type, **_kwargs):
        emitted.append((payload["host"], event_type, payload.get("severity")))
        return payload

    mod._resolve_monitor_extra_candidate = resolve_extra
    mod.emit_event = emit_event
    asyncio.run(mod.handle_event(SimpleNamespace(data="coinbase.com")))

    assert set(emitted) == {
        ("coinba5e.com", "VULNERABILITY", "MEDIUM"),
        ("coinbasre.com", "FINDING", "LOW"),
    }


def test_domain_phishing_resolves_only_missing_monitor_permutations(monkeypatch):
    import dns.asyncresolver
    import dns.resolver

    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.fuzzers = ["homoglyph", "insertion"]
    looked_up = []

    async def resolve(domain, record_type, lifetime):
        looked_up.append((domain, record_type))
        if domain != "coinbasre.com":
            raise dns.resolver.NXDOMAIN()
        return {"A": ["1.2.3.4"], "AAAA": [], "MX": ["10 mx.example.com."], "NS": ["ns.example.com."]}[record_type]

    async def fingerprint(_domain):
        return {"registrar": "Example Registrar", "registration_date": "2026-09-01"}

    monkeypatch.setattr(dns.asyncresolver, "resolve", resolve)
    mod._lookup_ownership_fingerprint = fingerprint
    rows = asyncio.run(mod._monitor_extra_candidates("coinbase.com", [{"domain": "coinba5e.com"}]))

    assert len(rows) == 1
    assert rows[0]["domain"] == "coinbasre.com"
    assert rows[0]["dns-a"] == ["1.2.3.4"]
    assert rows[0]["dns-ns"] == ["ns.example.com"]
    assert rows[0]["whois-created"] == "2026-09-01"
    assert not any(domain == "coinba5e.com" for domain, _record_type in looked_up)


def test_domain_phishing_extra_candidates_do_not_displace_dnstwist_results(tmp_path):
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.binary = "/bin/echo"
    mod.registered_only = False
    mod.enable_lsh = False
    mod.threads = 1
    mod.fuzzers = []
    mod.nameservers = []
    mod.max_candidates = 1
    mod.min_score = 3
    mod.young_domain_days = 45
    mod.lsh_threshold = 70
    mod.history_file = str(tmp_path / "phishing-history.json")
    mod.known = {}
    mod._state_lock = asyncio.Lock()
    mod.scan = SimpleNamespace(helpers=SimpleNamespace(
        split_domain=lambda _domain: ("", "coinbase.com"), is_domain=lambda _domain: True,
    ))
    row = {"domain": "coinbases.com", "fuzzer": "addition", "dns-mx": ["mx.example.com"], "dns-ns": ["ns.example.com"]}
    extra = {"domain": "coinba5e.com", "fuzzer": "homoglyph", "dns-mx": ["mx.example.com"], "dns-ns": ["ns.example.com"]}
    mod.run_process = lambda *_args, **_kwargs: asyncio.sleep(0, result=SimpleNamespace(stdout=json.dumps([row])))
    mod._monitor_extra_candidates = lambda _root, _rows: asyncio.sleep(0, result=[extra])
    mod._redirects_to_protected_domain = lambda *_args: asyncio.sleep(0, result=False)
    mod._lookup_ownership_fingerprint = lambda _domain: asyncio.sleep(0, result=mod._empty_fingerprint())
    emitted = []

    async def emit_event(payload, *_args, **_kwargs):
        emitted.append(payload["host"])
        return payload

    mod.emit_event = emit_event
    mod.info = lambda *_args: None

    asyncio.run(mod.handle_event(SimpleNamespace(data="coinbase.com")))

    assert set(emitted) == {"coinbases.com", "coinba5e.com"}


def test_domain_phishing_does_not_remember_an_event_that_failed_to_emit(tmp_path):
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.binary = "/bin/echo"
    mod.registered_only = False
    mod.enable_lsh = False
    mod.threads = 1
    mod.fuzzers = []
    mod.nameservers = []
    mod.max_candidates = 2000
    mod.min_score = 3
    mod.young_domain_days = 45
    mod.lsh_threshold = 70
    mod.history_file = str(tmp_path / "phishing-history.json")
    mod.known = {}
    mod._state_lock = asyncio.Lock()
    mod.scan = SimpleNamespace(helpers=SimpleNamespace(
        split_domain=lambda _domain: ("", "coinbase.com"), is_domain=lambda _domain: True,
    ))
    row = {"domain": "coinbases.com", "fuzzer": "addition", "dns-mx": ["mx.example.com"], "dns-ns": ["ns.example.com"]}
    mod.run_process = lambda *_args, **_kwargs: asyncio.sleep(0, result=SimpleNamespace(stdout=json.dumps([row])))
    mod._monitor_extra_candidates = lambda _root, _rows: asyncio.sleep(0, result=[])
    mod._redirects_to_protected_domain = lambda *_args: asyncio.sleep(0, result=False)
    mod._lookup_ownership_fingerprint = lambda _domain: asyncio.sleep(0, result=mod._empty_fingerprint())
    mod.emit_event = lambda *_args, **_kwargs: asyncio.sleep(0, result=None)
    mod.info = lambda *_args: None

    with pytest.raises(RuntimeError, match="could not emit"):
        asyncio.run(mod.handle_event(SimpleNamespace(data="coinbase.com")))

    assert mod.known == {}
    assert not Path(mod.history_file).exists()


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected_error"),
    [
        (1, "[]", "dnstwist exited with code 1"),
        (0, "not JSON", "invalid dnstwist JSON"),
        (0, "", "invalid dnstwist JSON"),
    ],
)
def test_domain_phishing_fails_when_dnstwist_output_is_unusable(returncode, stdout, expected_error):
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    mod.binary = "/bin/echo"
    mod.registered_only = False
    mod.enable_lsh = False
    mod.threads = 1
    mod.fuzzers = []
    mod.nameservers = []
    mod.scan = SimpleNamespace(helpers=SimpleNamespace(
        split_domain=lambda _domain: ("", "coinbase.com"), is_domain=lambda _domain: True,
    ))
    mod.run_process = lambda *_args, **_kwargs: asyncio.sleep(
        0, result=SimpleNamespace(returncode=returncode, stdout=stdout, stderr="dnstwist failed")
    )
    mod._monitor_extra_candidates = lambda _root, _rows: asyncio.sleep(0, result=[])
    mod.debug = lambda *_args: None

    with pytest.raises(RuntimeError, match=expected_error):
        asyncio.run(mod.handle_event(SimpleNamespace(data="coinbase.com")))


def test_domain_phishing_missing_binary_is_a_hard_setup_failure(tmp_path):
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    binary = str(tmp_path / "missing-dnstwist")
    mod._name = "domain_phishing"
    mod.scan = SimpleNamespace(config={"modules": {"domain_phishing": {"binary": binary, "fuzzers": ["omission"]}}})
    status, message = asyncio.run(mod.setup())

    assert status is False
    assert binary in message


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


def test_domain_phishing_suppresses_redirects_to_protected_domain():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)

    async def request(_url, **_kwargs):
        return SimpleNamespace(
            url=_url,
            status_code=301,
            headers={"location": "https://www.guardianaudits.com/welcome"},
        )

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))
    candidate = {"dns-a": ["1.2.3.4"]}
    assert (
        asyncio.run(mod._redirects_to_protected_domain("guardian-audits.com", "guardianaudits.com", candidate)) is True
    )


def test_domain_phishing_does_not_trust_deceptive_redirect_suffix():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)

    async def request(_url, **_kwargs):
        return SimpleNamespace(
            url=_url,
            status_code=302,
            headers={"location": "https://guardianaudits.com.evil.test/login"},
        )

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))
    candidate = {"dns-a": ["1.2.3.4"]}
    assert (
        asyncio.run(mod._redirects_to_protected_domain("guardian-audits.com", "guardianaudits.com", candidate))
        is False
    )


def test_domain_phishing_does_not_follow_redirects_to_private_addresses():
    from bbot.modules.domain_phishing import domain_phishing

    mod = object.__new__(domain_phishing)
    requested_urls = []

    async def request(url, **_kwargs):
        requested_urls.append(url)
        return SimpleNamespace(
            url=url,
            status_code=302,
            headers={"location": "https://internal.guardian-audits.com/admin"},
        )

    async def resolve(hostname, **kwargs):
        assert hostname == "internal.guardian-audits.com"
        assert kwargs == {"use_cache": False}
        return {"127.0.0.1"}

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(request=request, resolve=resolve))
    candidate = {"dns-a": ["1.2.3.4"]}

    assert (
        asyncio.run(mod._redirects_to_protected_domain("guardian-audits.com", "guardianaudits.com", candidate))
        is False
    )
    assert requested_urls == ["https://guardian-audits.com/"]
