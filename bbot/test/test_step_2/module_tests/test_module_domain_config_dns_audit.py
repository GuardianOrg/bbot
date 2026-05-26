from .base import ModuleTestBase


class TestDomainConfigDnsAudit(ModuleTestBase):
    module_name = "domain_config_dns_audit"
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {
            "domain_config_dns_audit": {
                "quick": True,
                "wildcard_nameservers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
            }
        },
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        async def fake_collect_basic_dns(domain):
            return {
                "A": ["1.2.3.4"],
                "AAAA": [],
                "NS": ["ns1.blacklanternsecurity.com"],
                "MX": ["10 mail.blacklanternsecurity.com"],
                "TXT": ["v=spf1 +all"],
                "SOA": "ns1.blacklanternsecurity.com hostmaster.blacklanternsecurity.com 2026050701 3600 600 1209600 300",
            }

        async def fake_query_dns(domain, rdtype, nameserver=None, raise_on_nxdomain=False):
            if domain == "ns1.blacklanternsecurity.com" and rdtype == "A":
                return True, ["192.0.2.53"]
            if domain == "mail.blacklanternsecurity.com" and rdtype == "A":
                return True, ["192.0.2.25"]
            if domain == "blacklanternsecurity.com" and rdtype == "SOA" and nameserver:
                return True, [
                    "ns1.blacklanternsecurity.com hostmaster.blacklanternsecurity.com 2026050701 3600 600 1209600 300"
                ]
            return True, []

        async def fake_query_dns_with_ttl(domain, rdtype, nameserver=None):
            return True, []

        async def fake_query_dns_full(domain, rdtype, nameserver=None):
            return False, None

        async def fake_check_zone_transfer(domain, records):
            return {
                "zone_transfer_possible": False,
                "zone_transfer_nameservers": ["ns1.blacklanternsecurity.com"],
            }

        async def fake_check_wildcard(host):
            return {
                "is_wildcard": True,
                "wildcard_ips": ["1.2.3.4", "2001:db8::1"],
                "wildcard_records": {
                    "A": ["1.2.3.4"],
                    "AAAA": ["2001:db8::1"],
                    "CNAME": ["wildcard.edge.blacklanternsecurity.com"],
                },
            }

        module_test.monkeypatch.setattr(module_test.module, "collect_basic_dns", fake_collect_basic_dns)
        module_test.monkeypatch.setattr(module_test.module, "query_dns", fake_query_dns)
        module_test.monkeypatch.setattr(module_test.module, "query_dns_with_ttl", fake_query_dns_with_ttl)
        module_test.monkeypatch.setattr(module_test.module, "query_dns_full", fake_query_dns_full)
        module_test.monkeypatch.setattr(module_test.module, "check_zone_transfer", fake_check_zone_transfer)
        module_test.monkeypatch.setattr(module_test.module, "check_wildcard", fake_check_wildcard)

    def check(self, module_test, events):
        domain_config_events = [e for e in events if e.type == "DOMAIN_DNS_CONFIG"]
        findings = [e for e in events if e.type == "FINDING"]
        vulnerabilities = [e for e in events if e.type == "VULNERABILITY"]

        assert len(domain_config_events) == 1
        assert domain_config_events[0].data["host"] == "blacklanternsecurity.com"
        assert domain_config_events[0].data["zone_transfer_possible"] is False
        assert domain_config_events[0].data["is_wildcard"] is True
        assert domain_config_events[0].data["wildcard_ips"] == ["1.2.3.4", "2001:db8::1"]
        assert domain_config_events[0].data["wildcard_records"] == {
            "A": ["1.2.3.4"],
            "AAAA": ["2001:db8::1"],
            "CNAME": ["wildcard.edge.blacklanternsecurity.com"],
        }

        finding_titles = {e.data.get("title") for e in findings}
        vulnerability_titles = {e.data.get("title") for e in vulnerabilities}

        assert "No IPv6 (AAAA) Record" in finding_titles
        assert "Insufficient Nameservers" in vulnerability_titles
        assert "SPF Allows All Senders" in vulnerability_titles
        assert "Missing DMARC Record" in vulnerability_titles
        assert "Missing CAA Records" in vulnerability_titles
        assert all("testssl" not in str(e.data).lower() for e in findings + vulnerabilities)


class TestDomainConfigDnsAuditTargetSubdomain(TestDomainConfigDnsAudit):
    targets = ["app.blacklanternsecurity.com"]

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.88"]},
                "app.blacklanternsecurity.com": {"A": ["127.0.0.89"]},
            }
        )

    def check(self, module_test, events):
        domain_config_events = [e for e in events if e.type == "DOMAIN_DNS_CONFIG"]
        domain_config_by_host = {e.data.get("host"): e for e in domain_config_events}

        assert set(domain_config_by_host) == {"blacklanternsecurity.com", "app.blacklanternsecurity.com"}
        assert domain_config_by_host["blacklanternsecurity.com"].data["zone_transfer_possible"] is False
        assert domain_config_by_host["blacklanternsecurity.com"].data["is_wildcard"] is True
        assert domain_config_by_host["app.blacklanternsecurity.com"].data["is_wildcard"] is True
        assert domain_config_by_host["app.blacklanternsecurity.com"].data["wildcard_ips"] == [
            "1.2.3.4",
            "2001:db8::1",
        ]
        assert domain_config_by_host["app.blacklanternsecurity.com"].data["wildcard_records"]["CNAME"] == [
            "wildcard.edge.blacklanternsecurity.com",
        ]


class TestDomainConfigDnsAuditWildcardChildTarget(TestDomainConfigDnsAudit):
    targets = ["fake.blacklanternsecurity.com"]
    config_overrides = {
        **TestDomainConfigDnsAudit.config_overrides,
        "dns": {"wildcard_ignore": []},
    }

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.88"]},
            },
            custom_lookup_fn="""
def custom_lookup(query, rdtype):
    if rdtype == "A" and query.strip(".").endswith("blacklanternsecurity.com"):
        return {"127.0.0.88"}
""",
        )

    def check(self, module_test, events):
        domain_config_events = [e for e in events if e.type == "DOMAIN_DNS_CONFIG"]
        domain_config_hosts = {e.data.get("host") for e in domain_config_events}

        assert "blacklanternsecurity.com" in domain_config_hosts
        assert "fake.blacklanternsecurity.com" not in domain_config_hosts
