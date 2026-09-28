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
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "breach-dataset-match"]
        # Public key has no records, so we alert on the breach-name hit — one FINDING per breach.
        assert 2 == len(findings)
        assert all(e.data.get("severity") == "INFO" for e in findings)
        assert any("LinkedIn" in e.data.get("title", "") for e in findings)
        assert any("Adobe" in e.data.get("title", "") for e in findings)
        # No leaked credential events without the paid key.
        assert 0 == len([e for e in events if e.type in ("PASSWORD", "HASHED_PASSWORD")])


class TestLeaklookupAccountOnly(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"Example": [{"email_address": "alice@blacklanternsecurity.com"}]}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "breach-account-exposure"]
        assert len(findings) == 1
        assert findings[0].data["account"] == "alice@blacklanternsecurity.com"
        assert findings[0].data["severity"] == "MEDIUM"
        assert not any(e.type in ("PASSWORD", "HASHED_PASSWORD") for e in events)


class TestLeaklookupUsernamePassword(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"Example": [{"username": "alice", "password": "hunter2"}]}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "credential-exposure"]
        assert len(findings) == 1
        assert findings[0].data["account"] == "alice"
        assert findings[0].data["secret_hash"] == hashlib.sha256(b"hunter2").hexdigest()
        assert findings[0].data["severity"] == "HIGH"
        assert "hunter2" not in str(findings[0].data)


class TestLeaklookupHexPasswordWithoutEmail(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"Example": [{"username": "alice", "password": "0123456789abcdef"}]}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "credential-exposure"]
        assert len(findings) == 1
        assert findings[0].data["secret_hash"] == hashlib.sha256(b"0123456789abcdef").hexdigest()
        assert "0123456789abcdef" not in str(findings[0].data)


class TestLeaklookupMultiValue(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={
                "error": "false",
                "message": {
                    "Example": [{
                        "email_address": ["alice@blacklanternsecurity.com", "bob@blacklanternsecurity.com"],
                        "password": ["alpha-pass", "beta-pass"],
                    }]
                },
            },
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        passwords = [e for e in events if e.type == "PASSWORD"]
        assert {e.data for e in passwords} == {
            "alice@blacklanternsecurity.com:alpha-pass",
            "alice@blacklanternsecurity.com:beta-pass",
            "bob@blacklanternsecurity.com:alpha-pass",
            "bob@blacklanternsecurity.com:beta-pass",
        }


class TestLeaklookupMetadataOnlyPaid(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"Example": [{"source": "dataset-metadata"}]}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "breach-dataset-match"]
        assert len(findings) == 1
        assert findings[0].data["severity"] == "INFO"
        assert "leaklookup-public-api" not in findings[0].tags


class TestLeaklookupPublicMetadataRows(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"public_api_key": "pub"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"Example": [{"source": "public-index"}]}},
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data.get("category") == "breach-dataset-match"]
        assert len(findings) == 1
        assert "leaklookup-public-api" in findings[0].tags


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


class TestLeaklookupEscalationFromMetadataRows(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"public_api_key": "pub", "private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"Example": [{"source": "public-index"}]}},
        )
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={
                "error": "false",
                "message": {"Example": [{"email_address": "alice@blacklanternsecurity.com", "password": "hunter2"}]},
            },
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        passwords = [e for e in events if e.type == "PASSWORD"]
        assert [e.data for e in passwords] == ["alice@blacklanternsecurity.com:hunter2"]


class TestLeaklookupPaidOnlyBreach(ModuleTestBase):
    module_name = "leaklookup"
    config_overrides = {"modules": {"leaklookup": {"public_api_key": "pub", "private_api_key": "priv"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={"error": "false", "message": {"LinkedIn": []}},
        )
        module_test.httpx_mock.add_response(
            url="https://leak-lookup.com/api/search",
            method="POST",
            json={
                "error": "false",
                "message": {"LinkedIn": [], "Example": [{"email_address": "alice@blacklanternsecurity.com", "password": "hunter2"}]},
            },
        )
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.1"]}})

    def check(self, module_test, events):
        passwords = [e for e in events if e.type == "PASSWORD"]
        assert [e.data for e in passwords] == ["alice@blacklanternsecurity.com:hunter2"]


def test_leak_history_fingerprint_and_store(tmp_path):
    from bbot.core.helpers.leak_history import LeakHistory, leak_fingerprint, secret_hash

    # Cleartext is hashed even if it looks like hex; known hashes are kept as-is.
    assert secret_hash("hunter2") == hashlib.sha256(b"hunter2").hexdigest()
    hex_password = "0123456789abcdef0123456789abcdef"
    assert secret_hash(hex_password) == hashlib.sha256(hex_password.encode()).hexdigest()
    assert secret_hash("a" * 64, already_hashed=True) == "a" * 64

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


def test_leak_breach_fingerprint_is_domain_scoped(tmp_path):
    from bbot.core.helpers.leak_history import LeakHistory, leak_fingerprint

    # The module scopes a public breach hit to the queried domain (see leaklookup._breach_fp).
    # Two domains in the same breach must NOT collide, or the first domain reported would
    # silently suppress every other domain that shares that breach in one history file.
    fp_a = leak_fingerprint("leaklookup", "LinkedIn", None, None, scope="a.com")
    fp_b = leak_fingerprint("leaklookup", "LinkedIn", None, None, scope="b.com")
    assert fp_a != fp_b

    path = tmp_path / "leaks.json"
    store = LeakHistory(str(path))
    store.add(fp_a)
    store.save()

    reloaded = LeakHistory(str(path))
    assert reloaded.contains(fp_a)  # a.com already reported → suppressed on the next scan
    assert not reloaded.contains(fp_b)  # b.com is still reported


def test_record_fingerprint_covers_all_values():
    from bbot.core.helpers.leak_history import record_fingerprint, secret_hash

    # Records that share only their first sorted email are still distinct (no silent loss).
    fp1 = record_fingerprint("dehashed", "X", emails=["a@x.com", "b@x.com"], passwords=["pw"])
    fp2 = record_fingerprint("dehashed", "X", emails=["a@x.com", "c@x.com"], passwords=["pw"])
    assert fp1 != fp2

    # Order / case / surrounding space are canonicalized away.
    assert record_fingerprint("dehashed", "X", emails=["A@X.com", " b@x.com "], passwords=["pw"]) == record_fingerprint(
        "dehashed", "X", emails=["b@x.com", "a@x.com"], passwords=["pw"]
    )

    # A cleartext secret fingerprints the same as its precomputed hash → it is hashed, not
    # fingerprinted in the clear.
    assert record_fingerprint("dehashed", "X", emails=["a@x.com"], passwords=["pw"]) == record_fingerprint(
        "dehashed", "X", emails=["a@x.com"], hashes=[secret_hash("pw")]
    )
