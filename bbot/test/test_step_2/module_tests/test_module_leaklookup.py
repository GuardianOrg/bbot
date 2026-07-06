import hashlib

from .base import ModuleTestBase


class TestLeaklookupPrivate(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={
                "error": "false",
                "message": {
                    "LinkedIn": [
                        {"email_address": "bob@blacklanternsecurity.com", "username": "bob", "password": "hunter2"}
                    ]
                },
            },
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.type == "EMAIL_ADDRESS" and e.data == "bob@blacklanternsecurity.com"])
        assert 1 == len([e for e in events if e.type == "PASSWORD" and e.data == "bob@blacklanternsecurity.com:hunter2"])
        assert 1 == len([e for e in events if e.type == "USERNAME" and e.data == "bob@blacklanternsecurity.com:bob"])


class TestLeaklookupPublic(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"public_api_key": "pub"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"LinkedIn": [], "Adobe": []}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "credential-exposure"]
        # Public key has no records, so we alert on the breach-name hit — one FINDING per breach.
        assert 2 == len(findings)
        assert any("LinkedIn" in e.data.get("title", "") for e in findings)
        assert any("Adobe" in e.data.get("title", "") for e in findings)
        # No leaked credential events without the paid key.
        assert 0 == len([e for e in events if e.type in ("PASSWORD", "HASHED_PASSWORD")])


class TestLeaklookupEscalation(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"public_api_key": "pub", "private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        # 1st call (public detection) → breach names only.
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"LinkedIn": []}},
        )
        # 2nd call (paid escalation) → the actual records.
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"LinkedIn": [{"email": "bob@blacklanternsecurity.com", "password": "hunter2"}]}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        # Public detected the breach → escalated to the paid key → emitted the record.
        assert 1 == len([e for e in events if e.type == "PASSWORD" and e.data == "bob@blacklanternsecurity.com:hunter2"])


def test_leak_history_fingerprint_and_store(tmp_path):
    from bbot.core.helpers.leak_history import LeakHistory, leak_fingerprint, secret_hash

    # Cleartext is hashed; an existing hash is kept as-is.
    assert secret_hash("hunter2") == hashlib.sha256(b"hunter2").hexdigest()
    assert secret_hash("a" * 64) == "a" * 64

    # Fingerprint is canonicalized (case/space) and source-scoped.
    fp = leak_fingerprint("leaklookup", "LinkedIn", "bob@x.com", "hunter2")
    assert fp == leak_fingerprint("leaklookup", " LinkedIn ", "BOB@X.COM", "hunter2")
    assert fp != leak_fingerprint("dehashed", "LinkedIn", "bob@x.com", "hunter2")

    # Store round-trips through disk.
    path = tmp_path / "leaks.json"
    store = LeakHistory(str(path))
    assert not store.contains(fp)
    store.add(fp)
    store.save()
    assert LeakHistory(str(path)).contains(fp)

    # Disabled (no path) never suppresses.
    disabled = LeakHistory("")
    disabled.add(fp)
    assert not disabled.contains(fp)
