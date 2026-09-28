from .base import ModuleTestBase


def test_sslcert_rechecks_scoped_san_host_with_sni_only_on_its_resolved_ip():
    import asyncio
    from types import SimpleNamespace

    from bbot.modules.sslcert import sslcert

    mod = object.__new__(sslcert)
    resolved = {
        "fix.bakkt.com": ["34.54.2.96"],
        "other.bakkt.com": ["203.0.113.10"],
    }
    mod.scan = SimpleNamespace(
        in_scope=lambda name: name.endswith(".bakkt.com"),
        helpers=SimpleNamespace(
            resolve=lambda name: asyncio.sleep(0, result=resolved.get(name, [])),
            make_netloc=lambda name, port: f"{name}:{port}",
        ),
    )
    visited = []
    emitted = []

    async def visit_host(address, port, server_name=None):
        visited.append((address, port, server_name))
        return [], [], {"certNotAfter": "2025-06-20T15:12:28+00:00", "certSanDomains": ["fix.bakkt.com"]}, (address, port)

    async def emit_event(data, event_type, **kwargs):
        emitted.append((data, event_type, kwargs))

    mod.visit_host = visit_host
    mod.emit_event = emit_event
    parent = SimpleNamespace(host="34.54.2.96")
    asyncio.run(mod.recheck_scoped_san_hosts(
        parent,
        {"certSanDomains": ["fix.bakkt.com", "other.bakkt.com", "external.example", "*.bakkt.com"]},
        "34.54.2.96",
        5556,
    ))

    assert visited == [("34.54.2.96", 5556, "fix.bakkt.com")]
    assert len(emitted) == 1
    data, event_type, kwargs = emitted[0]
    assert event_type == "TLS_CERTIFICATE"
    assert data["host"] == "fix.bakkt.com"
    assert data["url"] == "https://fix.bakkt.com:5556/"
    assert data["certNotAfter"] == "2025-06-20T15:12:28+00:00"
    assert kwargs["parent"] is parent


class TestSSLCert(ModuleTestBase):
    targets = ["127.0.0.1:9999", "bbottest.notreal"]
    config_overrides = {"deps": {"behavior": "disable"}, "scope": {"report_distance": 1}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.data == "www.bbottest.notreal" and str(e.module) == "sslcert" and e.scope_distance == 0
            ]
        ), "Failed to detect subject alternate name (SAN)"
        assert 1 == len(
            [e for e in events if e.data == "test.notreal" and str(e.module) == "sslcert" and e.scope_distance == 1]
        ), "Failed to detect main subject"
        cert_events = [e for e in events if e.type == "TLS_CERTIFICATE" and str(e.module) == "sslcert"]
        assert cert_events, "Failed to emit TLS certificate metadata"
        assert any(e.data.get("certFingerprintSha256") for e in cert_events), "Failed to emit certificate SHA256"
        assert any(e.data.get("certSubjectCn") == "test.notreal" for e in cert_events), "Failed to emit certificate subject CN"
        assert any("www.bbottest.notreal" in e.data.get("certSanDomains", []) for e in cert_events), "Failed to emit SANs"


def test_sslcert_metadata_keeps_wildcard_sans():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from OpenSSL import crypto

    from bbot.modules.sslcert import sslcert

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("*.api.example.com"), x509.DNSName("api.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert = crypto.X509.from_cryptography(certificate)

    metadata = sslcert.get_cert_metadata(cert)

    assert metadata["certSanDomains"] == ["*.api.example.com", "api.example.com"]
    assert metadata["certificate"]["sanDomains"] == ["*.api.example.com", "api.example.com"]
    assert sslcert.get_cert_sans(cert) == ["api.example.com", "api.example.com"]
