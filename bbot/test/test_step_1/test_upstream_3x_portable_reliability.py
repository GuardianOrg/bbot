"""Regressions for portable reliability fixes reviewed from BBOT 3.x."""

import asyncio
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from ..bbot_fixtures import *  # noqa: F401, F403
from bbot.core.helpers.async_helpers import async_to_sync_gen
from bbot.core.helpers.depsinstaller import sudo_askpass
from bbot.core.helpers.dns.brute import DNSBrute
from bbot.core.helpers.dns.engine import DNSEngine
from bbot.core.helpers.helper import _pool_worker_init
from bbot.logger import colorize
from bbot.modules.internal.excavate import excavate
from bbot.modules.lightfuzz.submodules.base import BaseLightfuzz
from bbot.modules.lightfuzz.submodules.crypto import crypto
from bbot.scanner.scanner import Scanner
from bbot.scanner.target import ScanBlacklist


def _noop(*args, **kwargs):
    return None


def _lightfuzz_stub():
    helpers = SimpleNamespace(truncate_string=lambda value, length: value[:length])
    return SimpleNamespace(debug=_noop, verbose=_noop, helpers=helpers)


def test_lightfuzz_non_ascii_base64_is_not_a_crash():
    assert BaseLightfuzz.is_base64("é") is False


def test_lightfuzz_normalizes_none_at_request_boundary():
    event = SimpleNamespace(data={"name": "token", "url": "https://example.com/"})
    module = BaseLightfuzz(_lightfuzz_stub(), event)

    request = module.prepare_request("POSTPARAM", None, {}, {"peer": None})

    assert request["data"] == {"token": "", "peer": ""}


@pytest.mark.asyncio
async def test_crypto_aborts_when_a_probe_has_no_response(monkeypatch):
    original_value = "00" * 32
    event = SimpleNamespace(
        data={
            "name": "token",
            "type": "GETPARAM",
            "url": "https://example.com/",
            "original_value": original_value,
        },
        envelopes=SimpleNamespace(get_subparam=lambda: original_value),
    )
    module = crypto(_lightfuzz_stub(), event)

    async def baseline_probe(cookies):
        return SimpleNamespace(text="baseline")

    async def compare_probe(*args, **kwargs):
        return False, ["body"], None, None

    monkeypatch.setattr(module, "baseline_probe", baseline_probe)
    monkeypatch.setattr(module, "cryptanalysis", lambda value: (True, False))
    monkeypatch.setattr(module, "compare_baseline", lambda *args, **kwargs: SimpleNamespace(compare_body=_noop))
    monkeypatch.setattr(module, "compare_probe", compare_probe)

    await module.fuzz()

    assert module.results == []


@pytest.mark.asyncio
async def test_crypto_skips_none_linked_parameters(monkeypatch):
    original_value = "00" * 32
    event = SimpleNamespace(
        data={
            "name": "token",
            "type": "GETPARAM",
            "url": "https://example.com/",
            "original_value": original_value,
            "additional_params": {"peer": None},
        },
        envelopes=SimpleNamespace(get_subparam=lambda: original_value),
    )
    module = crypto(_lightfuzz_stub(), event)
    response = SimpleNamespace(text="changed")
    compare_calls = 0

    async def baseline_probe(cookies):
        return SimpleNamespace(text="baseline")

    async def compare_probe(*args, **kwargs):
        nonlocal compare_calls
        compare_calls += 1
        return False, ["body"], None, response

    async def error_string_search(*args, **kwargs):
        return None

    monkeypatch.setattr(module, "baseline_probe", baseline_probe)
    monkeypatch.setattr(module, "cryptanalysis", lambda value: (True, False))
    monkeypatch.setattr(
        module,
        "compare_baseline",
        lambda *args, **kwargs: SimpleNamespace(compare_body=lambda *args: False),
    )
    monkeypatch.setattr(module, "compare_probe", compare_probe)
    monkeypatch.setattr(module, "error_string_search", error_string_search)

    await module.fuzz()

    assert compare_calls == 3


@pytest.mark.asyncio
async def test_excavate_skips_invalid_jquery_parameter_json():
    class AsyncRegex:
        @staticmethod
        async def findall(*args, **kwargs):
            return [("/search", "{broken}")]

        @staticmethod
        async def sub(pattern, replacement, value):
            return pattern.sub(replacement, value)

    parent = SimpleNamespace(helpers=SimpleNamespace(re=AsyncRegex()), debug=_noop)
    rule = excavate.ParameterExtractor.GetJquery(parent, "$.get('/search', {broken})")

    assert [result async for result in rule.extract()] == []


def test_blacklist_invalid_host_does_not_crash():
    assert ScanBlacklist().get("not a valid target !!!") is None


def test_scanner_drain_queues_handles_disabled_queues():
    populated_queue = asyncio.Queue()
    populated_queue.put_nowait("event")
    scanner = SimpleNamespace(
        modules={
            "disabled": SimpleNamespace(incoming_event_queue=None, outgoing_event_queue=False),
            "active": SimpleNamespace(incoming_event_queue=populated_queue, outgoing_event_queue=asyncio.Queue()),
        },
        debug=_noop,
    )

    Scanner._drain_queues(scanner)

    assert populated_queue.empty()


def test_async_to_sync_generator_closes_its_source():
    state = {"closed": False}

    async def source():
        try:
            yield "event"
            await asyncio.sleep(60)
        finally:
            state["closed"] = True

    sync_generator = async_to_sync_gen(source())
    assert next(sync_generator) == "event"
    sync_generator.close()

    assert state["closed"] is True


def test_sudo_askpass_does_not_log_ciphertext(monkeypatch, tmp_path, capsys):
    encrypted_password = "sensitive-encrypted-password-blob"
    key_path = tmp_path / "sudo.key"
    key_path.write_bytes(b"invalid-key")
    monkeypatch.setenv(sudo_askpass.ENV_VAR_NAME, encrypted_password)
    monkeypatch.setenv(sudo_askpass.KEY_ENV_VAR_PATH, str(key_path))
    monkeypatch.setattr(sudo_askpass, "decrypt_password", lambda *args: (_ for _ in ()).throw(ValueError("bad")))

    with pytest.raises(SystemExit):
        sudo_askpass.main()

    stderr = capsys.readouterr().err
    assert encrypted_password not in stderr
    assert "Error decrypting sudo password" in stderr


def test_gowitness_correlation_tolerates_scheme_and_default_port_changes():
    pytest.importorskip("aiosqlite")
    from bbot.modules.gowitness import gowitness

    assert gowitness._url_key(urlparse("http://example.com/path")) == gowitness._url_key(
        urlparse("https://example.com:443/path")
    )
    assert gowitness._url_key(urlparse("https://example.com/other")) != gowitness._url_key(
        urlparse("https://example.com/path")
    )


def test_no_color_environment_disables_ansi(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert colorize("plain") == "plain"


def test_process_pool_worker_initializer_is_portable():
    _pool_worker_init()


@pytest.mark.asyncio
async def test_dnsbrute_canaries_are_detected_after_generation():
    class DNS:
        @staticmethod
        async def is_wildcard_domain(*args, **kwargs):
            return {}

    parent = SimpleNamespace(
        config={"dns": {}},
        dns=DNS(),
        word_cloud=SimpleNamespace(devops_mutations=[]),
        re=SimpleNamespace(compile=lambda *args, **kwargs: None),
    )
    brute = DNSBrute(parent)
    brute.num_canaries = 10
    canaries = [f"canary{i}" for i in range(brute.num_canaries)]
    brute.gen_random_subdomains = lambda count: iter(canaries)

    async def massdns(module, domain, subdomains, rdtype):
        for subdomain in subdomains:
            yield f"{subdomain}.{domain}", "192.0.2.1", rdtype

    brute._massdns = massdns

    assert await brute.dnsbrute(SimpleNamespace(), "example.com", ["www"]) == []


def test_dns_engine_growth_caches_are_bounded():
    engine = DNSEngine(None, config={})

    assert engine._wildcard_cache.maxsize == 10000
    assert engine._dns_warnings.maxsize == 10000
    assert engine._errors.maxsize == 10000
    assert engine._dns_cache.maxsize == 10000
