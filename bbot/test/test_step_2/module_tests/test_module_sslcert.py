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
