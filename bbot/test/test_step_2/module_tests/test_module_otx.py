from .base import ModuleTestBase


class TestOTX(ModuleTestBase):
    config_overrides = {"modules": {"otx": {"api_key": "test"}}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://otx.alienvault.com/api/v1/indicators/domain/blacklanternsecurity.com/passive_dns",
            json={
                "passive_dns": [
                    {
                        "address": "2606:50c0:8000::153",
                        "first": "2021-10-28T20:23:08",
                        "last": "2022-08-24T18:29:49",
                        "hostname": "asdf.blacklanternsecurity.com",
                        "record_type": "AAAA",
                        "indicator_link": "/indicator/hostname/www.blacklanternsecurity.com",
                        "flag_url": "assets/images/flags/us.png",
                        "flag_title": "United States",
                        "asset_type": "hostname",
                        "asn": "AS54113 fastly",
                    }
                ]
            },
            headers={"X-OTX-API-KEY": "test"},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(
            e.type == "DOMAIN_DNS_HISTORY"
            and e.data["host"] == "asdf.blacklanternsecurity.com"
            and e.data["records"][0]["ip"] == "2606:50c0:8000::153"
            for e in events
        ), "Failed to emit passive DNS history"


class TestOTXIPPassiveDNS(ModuleTestBase):
    module_name = "otx"
    targets = ["1.2.3.4"]
    config_overrides = {"modules": {"otx": {"api_key": "test"}}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/passive_dns",
            json={
                "passive_dns": [
                    {
                        "address": "1.2.3.4",
                        "first": "2024-01-01T00:00:00",
                        "last": "2025-01-01T00:00:00",
                        "hostname": "legacy.blacklanternsecurity.com",
                        "record_type": "A",
                        "asset_type": "hostname",
                    }
                ]
            },
            headers={"X-OTX-API-KEY": "test"},
        )
        await module_test.mock_dns({"legacy.blacklanternsecurity.com": {"A": ["1.2.3.4"]}})

    def check(self, module_test, events):
        assert any(e.type == "DNS_NAME" and e.data == "legacy.blacklanternsecurity.com" for e in events), (
            "Failed to emit DNS_NAME from OTX IP passive DNS"
        )
        assert any(
            e.type == "DOMAIN_DNS_HISTORY"
            and e.data["host"] == "legacy.blacklanternsecurity.com"
            and e.data["records"][0]["ip"] == "1.2.3.4"
            for e in events
        ), "Failed to emit passive DNS history from OTX IP lookup"


class TestOTXIPLookupsDisabled(ModuleTestBase):
    module_name = "otx"
    targets = ["1.2.3.4"]
    config_overrides = {"modules": {"otx": {"api_key": "test", "query_ips": False}}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    def check(self, module_test, events):
        assert not any(str(event.module) == "otx" for event in events), "OTX queried an IP despite query_ips=false"


class TestOTXCloudIPFiltering(TestOTXIPPassiveDNS):
    config_overrides = {
        "modules": {"otx": {"api_key": "test", "query_ips": True, "query_cloud_ips": False}}
    }

    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)

        direct_target = module_test.scan.make_event(
            "1.2.3.4", "IP_ADDRESS", parent=module_test.scan.root_event, tags=["target", "cloud-azure"]
        )
        direct_target.scope_distance = 0
        allowed, _reason = await module_test.module.filter_event(direct_target)
        assert allowed is True, "OTX must retain passive DNS checks for explicitly targeted IPs"

        discovered_ip = module_test.scan.make_event(
            "1.2.3.5", "IP_ADDRESS", parent=module_test.scan.root_event
        )
        discovered_ip.scope_distance = 1
        allowed, _reason = await module_test.module.filter_event(discovered_ip)
        assert allowed is True, "OTX must retain passive DNS checks for non-provider discovered IPs"

        cloud_ip = module_test.scan.make_event(
            "1.2.3.6", "IP_ADDRESS", parent=module_test.scan.root_event, tags=["cloud-azure"]
        )
        cloud_ip.scope_distance = 1
        allowed, reason = await module_test.module.filter_event(cloud_ip)
        assert allowed is False, "OTX should skip non-target cloud IP expansion when disabled"
        assert reason == "Non-target cloud and CDN IP lookups are disabled by configuration"
