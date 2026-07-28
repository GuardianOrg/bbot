"""Regression tests for compatible reliability fixes from BBOT 2.8.3+."""

import base64
import json
from types import SimpleNamespace

import pytest
import asyncpg
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from ..bbot_fixtures import *  # noqa: F401, F403
from bbot.core.helpers.interactsh import Interactsh
from bbot.core.helpers.misc import make_printable
from bbot.core.helpers.web.envelopes import BaseEnvelope
from bbot.errors import InteractshError
from bbot.modules.badsecrets import badsecrets
from bbot.modules.crt_db import crt_db
from bbot.modules.fingerprintx import fingerprintx
from bbot.modules.lightfuzz.lightfuzz import lightfuzz
from bbot.modules.lightfuzz.submodules.base import BaseLightfuzz
from bbot.modules.lightfuzz.submodules.crypto import crypto


def test_interactsh_decrypts_aes_ctr_payload():
    client = Interactsh(SimpleNamespace(config={}))
    rsa_key = RSA.generate(1024)
    client.private_key = rsa_key.export_key()

    aes_key = b"0123456789abcdef"
    iv = b"fedcba9876543210"
    expected = {"protocol": "dns", "full-id": "example.oast.pro"}
    plaintext = json.dumps(expected).encode()
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=iv)
    encrypted_data = base64.b64encode(iv + cipher.encrypt(plaintext)).decode()
    encrypted_key = base64.b64encode(PKCS1_OAEP.new(rsa_key.public_key(), hashAlgo=SHA256).encrypt(aes_key)).decode()

    assert client._decrypt(encrypted_key, encrypted_data) == expected


@pytest.mark.asyncio
async def test_interactsh_poll_loop_stops_after_repeated_failures():
    parent = SimpleNamespace(config={}, scan=SimpleNamespace(stopping=False))
    client = Interactsh(parent)
    client.poll_interval = 0
    attempts = 0

    async def failed_poll():
        nonlocal attempts
        attempts += 1
        raise InteractshError("temporary failure")

    client.poll = failed_poll
    await client._poll_loop(lambda data: None)

    assert attempts == 5


def test_crypto_rejects_narrow_alphabet_base64_false_positives():
    narrow_value = "ABCDEFGHIJKLMNOP"
    binary_value = base64.b64encode(bytes(range(32))).decode()

    assert crypto.format_agnostic_decode(narrow_value)[1] == "unknown"
    assert crypto.format_agnostic_decode(binary_value)[1] == "base64"


def test_console_output_escapes_terminal_control_characters():
    assert make_printable("safe\tline\nraw\x00\x0e") == "safe\tline\nraw\\x00\\x0e"
    assert make_printable(b"bytes\x1f") == "bytes\\x1f"


@pytest.mark.asyncio
async def test_fingerprintx_emits_ipv6_web_url(bbot_scanner, monkeypatch):
    module = fingerprintx(bbot_scanner("2001:db8::1"))
    module.timeout_ms = 2000
    module.fast = False
    parent_event = SimpleNamespace(data="[2001:db8::1]:443")
    emitted = []

    async def fake_process(*args, **kwargs):
        yield json.dumps(
            {
                "ip": "2001:db8::1",
                "host": "2001:db8::1",
                "port": 443,
                "protocol": "HTTPS",
                "metadata": {},
            }
        )

    async def record_event(data, event_type, **kwargs):
        emitted.append((event_type, data, kwargs))

    monkeypatch.setattr(module, "run_process_live", fake_process)
    monkeypatch.setattr(module, "emit_event", record_event)

    await module.handle_batch(parent_event)

    assert any(event_type == "PROTOCOL" and data["protocol"] == "HTTPS" for event_type, data, _ in emitted)
    assert any(
        event_type == "URL_UNVERIFIED" and data == "https://[2001:db8::1]" and kwargs["parent"] is parent_event
        for event_type, data, kwargs in emitted
    )


@pytest.mark.asyncio
async def test_crt_db_stops_after_upstream_out_of_memory(bbot_scanner, monkeypatch):
    module = crt_db(bbot_scanner("example.com"))
    errors = []

    class FailedConnection:
        @staticmethod
        def is_closed():
            return False

        @staticmethod
        async def fetch(*args, **kwargs):
            raise asyncpg.OutOfMemoryError("shared memory exhausted")

    module.db_conn = FailedConnection()
    monkeypatch.setattr(module, "set_error_state", errors.append)

    assert await module.request_url("example.com") == []
    assert errors == ["crt.sh Postgres reported out-of-memory: shared memory exhausted"]


def test_lightfuzz_envelope_packing_does_not_mutate_shared_state():
    envelope = BaseEnvelope.detect("706172616d")
    event = SimpleNamespace(data={"name": "value"}, envelopes=envelope)
    module = BaseLightfuzz(SimpleNamespace(debug=lambda *args, **kwargs: None), event)

    assert module.outgoing_probe_value("first") == "6669727374"
    assert module.outgoing_probe_value("second") == "7365636f6e64"
    assert envelope.get_subparam() == "param"
    assert envelope.pack() == "706172616d"


@pytest.mark.asyncio
async def test_lightfuzz_conversion_restores_shared_event(bbot_scanner, monkeypatch):
    module = lightfuzz(bbot_scanner("evilcorp.com"))
    module.disable_post = True
    module.try_post_as_get = True
    module.try_get_as_post = False
    module.submodules = {"probe": object}
    observed = []

    async def connected(*args, **kwargs):
        return SimpleNamespace(status_code=200)

    async def record_submodule(submodule, event):
        observed.append(dict(event.data))

    monkeypatch.setattr(module.helpers, "request", connected)
    monkeypatch.setattr(module, "run_submodule", record_submodule)
    event = SimpleNamespace(
        type="WEB_PARAMETER",
        tags=set(),
        data={
            "url": "https://example.com/",
            "type": "POSTPARAM",
            "name": "search",
            "original_value": "",
        },
    )

    await module.handle_event(event)

    assert len(observed) == 1
    assert observed[0]["type"] == "GETPARAM"
    assert observed[0]["converted_from_post"] is True
    assert event.data["type"] == "POSTPARAM"
    assert "converted_from_post" not in event.data


@pytest.mark.asyncio
async def test_lightfuzz_avoids_confirmed_wafs(bbot_scanner):
    module = lightfuzz(bbot_scanner("evilcorp.com"))
    module.avoid_wafs = True
    event = SimpleNamespace(type="WEB_PARAMETER", tags={"waf"}, parsed_url=None)
    assert await module.filter_event(event) is False


@pytest.mark.asyncio
async def test_badsecrets_suppresses_jwt_identification_and_classifies_aspnet(bbot_scanner, monkeypatch):
    module = badsecrets(bbot_scanner("evilcorp.com"))
    module.custom_secrets = None
    emitted = []

    async def fake_executor(*args, **kwargs):
        return (
            [
                {
                    "type": "IdentifyOnly",
                    "detecting_module": "Generic_JWT",
                    "description": {"product": "JWT"},
                    "product": "JWT",
                },
                {
                    "type": "IdentifyOnly",
                    "detecting_module": "ASPNET_Resource",
                    "description": {"product": "ASP.NET"},
                    "product": "ASP.NET",
                },
            ],
            [],
        )

    async def record_event(data, event_type, *args, **kwargs):
        emitted.append((event_type, data))

    monkeypatch.setattr(module.helpers, "run_in_executor_mp", fake_executor)
    monkeypatch.setattr(module, "emit_event", record_event)
    event = SimpleNamespace(
        host="example.com",
        data={
            "body": "body",
            "header": {},
            "url": "https://example.com/",
        },
    )

    await module.handle_event(event)

    assert emitted == [
        (
            "TECHNOLOGY",
            {
                "technology": "microsoft asp.net",
                "url": "https://example.com/",
                "host": "example.com",
            },
        )
    ]
