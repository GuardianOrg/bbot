from .base import ModuleTestBase


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
