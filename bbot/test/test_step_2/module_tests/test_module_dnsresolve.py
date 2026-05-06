from .base import ModuleTestBase


class TestDNSREsolve(ModuleTestBase):
    config_overrides = {
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
        "deps": {"behavior": "disable"},
        "url_extension_blacklist": [],
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {
                    "A": ["192.168.0.7"],
                    "AAAA": ["::1"],
                    "CNAME": ["www.blacklanternsecurity.com"],
                    "TXT": ['"v=spf1 include:_spf.google.com ~all"'],
                    "MX": ["1 smtp.google.com."],
                    "CAA": ['0 iodef "mailto:dnsadmin@blacklanternsecurity.com"'],
                },
                "_dmarc.blacklanternsecurity.com": {
                    "TXT": ['"v=DMARC1; rua=mailto:dmarc@blacklanternsecurity.com,https://reports.blacklanternsecurity.com/dmarc"'],
                },
                "_smtp._tls.blacklanternsecurity.com": {
                    "TXT": ['"v=TLSRPTv1; rua=mailto:tlsrpt@blacklanternsecurity.com,https://reports.blacklanternsecurity.com/tls"'],
                },
                "default._bimi.blacklanternsecurity.com": {
                    "TXT": ['"v=BIMI1; l=https://assets.blacklanternsecurity.com/logo.svg; a=https://assets.blacklanternsecurity.com/vmc.pem"'],
                },
                "www.blacklanternsecurity.com": {"A": ["192.168.0.8"]},
            }
        )

    def check(self, module_test, events):
        assert len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "blacklanternsecurity.com"
                and "a-record" in e.tags
                and "aaaa-record" in e.tags
                and "cname-record" in e.tags
                and "mx-record" in e.tags
                and "txt-record" in e.tags
                and "private-ip" in e.tags
                and e.scope_distance == 0
                and "192.168.0.7" in e.resolved_hosts
                and "::1" in e.resolved_hosts
                and "www.blacklanternsecurity.com" in e.resolved_hosts
                and e.dns_children.get("A") == {"192.168.0.7"}
                and e.dns_children.get("AAAA") == {"::1"}
                and e.dns_children.get("CNAME") == {"www.blacklanternsecurity.com"}
            ]
        ) >= 1
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "www.blacklanternsecurity.com"
                and "a-record" in e.tags
                and "private-ip" in e.tags
                and e.scope_distance == 0
                and "192.168.0.8" in e.resolved_hosts
                and e.dns_children == {"A": {"192.168.0.8"}}
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "IP_ADDRESS"
                and e.data == "192.168.0.7"
                and "private-ip" in e.tags
                and e.scope_distance == 1
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "FINDING"
                and e.data.get("category") == "domain-classification"
                and e.data.get("is_google_workspace") is True
                and e.data.get("host") == "blacklanternsecurity.com"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "EMAIL_ADDRESS"
                and e.data == "dnsadmin@blacklanternsecurity.com"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "EMAIL_ADDRESS"
                and e.data == "dmarc@blacklanternsecurity.com"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "EMAIL_ADDRESS"
                and e.data == "tlsrpt@blacklanternsecurity.com"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and e.data == "https://reports.blacklanternsecurity.com/dmarc"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and e.data == "https://reports.blacklanternsecurity.com/tls"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and e.data == "https://assets.blacklanternsecurity.com/logo.svg"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and e.data == "https://assets.blacklanternsecurity.com/vmc.pem"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "RAW_DNS_RECORD"
                and e.data.get("host") == "_dmarc.blacklanternsecurity.com"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "RAW_DNS_RECORD"
                and e.data.get("host") == "_smtp._tls.blacklanternsecurity.com"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "RAW_DNS_RECORD"
                and e.data.get("host") == "default._bimi.blacklanternsecurity.com"
            ]
        )
