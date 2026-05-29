import asyncio

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


class TestDNSResolveDropUnresolved(ModuleTestBase):
    modules_overrides = ["speculate"]
    config_overrides = {
        "dns": {"emit_unresolved": False},
        "deps": {"behavior": "disable"},
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["192.168.0.7"]}})

        dnsresolve = module_test.scan.modules["dnsresolve"]
        event = module_test.scan.make_event(
            "missing.blacklanternsecurity.com", "DNS_NAME", parent=module_test.scan.root_event
        )
        event.scope_distance = 0
        result = await dnsresolve.handle_event(event)
        assert result == (False, "unresolved DNS events are disabled")

        cache_key = dnsresolve._host_resolution_cache_key(event.host)
        assert dnsresolve.host_resolution_cache[cache_key]["type"] == "DNS_NAME_UNRESOLVED"

    def check(self, module_test, events):
        assert not any(e.type == "DNS_NAME_UNRESOLVED" and e.data == "missing.blacklanternsecurity.com" for e in events)


class TestDNSResolveUnresolvedSubdomainBudget(ModuleTestBase):
    modules_overrides = ["speculate"]
    config_overrides = {
        "dns": {"emit_unresolved": False, "max_unresolved_subdomains_per_module": 1},
        "deps": {"behavior": "disable"},
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["192.168.0.7"]}})

        dnsresolve = module_test.scan.modules["dnsresolve"]
        tool_a = module_test.scan._make_dummy_module(name="tool_a")
        tool_b = module_test.scan._make_dummy_module(name="tool_b")
        tool_c = module_test.scan._make_dummy_module(name="tool_c")
        tool_d = module_test.scan._make_dummy_module(name="tool_d")

        first_event = module_test.scan.make_event(
            "missing1.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_a,
        )
        first_event.scope_distance = 0
        assert await dnsresolve.handle_event(first_event) == (False, "unresolved DNS events are disabled")

        resolve_calls = []
        original_resolve_event = dnsresolve.resolve_event

        async def count_resolve_event(event, *args, **kwargs):
            resolve_calls.append((str(event.module), event.host))
            return await original_resolve_event(event, *args, **kwargs)

        module_test.monkeypatch.setattr(dnsresolve, "resolve_event", count_resolve_event)

        skipped_by_tool_a = module_test.scan.make_event(
            "missing2.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_a,
        )
        skipped_by_tool_a.scope_distance = 0
        assert await dnsresolve.handle_event(skipped_by_tool_a) == (
            False,
            'unresolved subdomain budget exceeded for module "tool_a"',
        )
        missing2_cache_key = dnsresolve._host_resolution_cache_key(skipped_by_tool_a.host)
        assert missing2_cache_key not in dnsresolve.host_resolution_cache
        assert resolve_calls == []

        skipped_url_by_tool_a = module_test.scan.make_event(
            "https://missing-url.blacklanternsecurity.com/",
            "URL_UNVERIFIED",
            parent=module_test.scan.root_event,
            module=tool_a,
        )
        skipped_url_by_tool_a.scope_distance = 0
        assert await dnsresolve.handle_event(skipped_url_by_tool_a) == (
            False,
            'unresolved subdomain budget exceeded for module "tool_a"',
        )
        missing_url_cache_key = dnsresolve._host_resolution_cache_key(skipped_url_by_tool_a.host)
        assert missing_url_cache_key not in dnsresolve.host_resolution_cache
        assert resolve_calls == []

        pending_by_tool_c = module_test.scan.make_event(
            "pending.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_c,
        )
        pending_allowed, pending_module, pending_host_key = await dnsresolve._reserve_unresolved_subdomain_budget(
            pending_by_tool_c
        )
        assert pending_allowed is True
        assert pending_module == "tool_c"

        blocked_while_tool_c_pending = module_test.scan.make_event(
            "blocked.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_c,
        )
        blocked_while_tool_c_pending.scope_distance = 0
        blocked_task = asyncio.create_task(dnsresolve.handle_event(blocked_while_tool_c_pending))
        await asyncio.sleep(0.1)
        assert not blocked_task.done()
        assert resolve_calls == []

        await dnsresolve._release_unresolved_subdomain_budget(pending_module, pending_host_key, unresolved=True)
        assert await blocked_task == (
            False,
            'unresolved subdomain budget exceeded for module "tool_c"',
        )
        blocked_cache_key = dnsresolve._host_resolution_cache_key(blocked_while_tool_c_pending.host)
        assert blocked_cache_key not in dnsresolve.host_resolution_cache
        assert resolve_calls == []

        checked_by_tool_b = module_test.scan.make_event(
            "missing2.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_b,
        )
        checked_by_tool_b.scope_distance = 0
        assert await dnsresolve.handle_event(checked_by_tool_b) == (False, "unresolved DNS events are disabled")
        assert resolve_calls
        assert all(call == ("tool_b", "missing2.blacklanternsecurity.com") for call in resolve_calls)
        assert dnsresolve.host_resolution_cache[missing2_cache_key]["type"] == "DNS_NAME_UNRESOLVED"

        cached_but_still_skipped_by_tool_a = module_test.scan.make_event(
            "missing2.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_a,
        )
        cached_but_still_skipped_by_tool_a.scope_distance = 0
        assert await dnsresolve.handle_event(cached_but_still_skipped_by_tool_a) == (
            False,
            'unresolved subdomain budget exceeded for module "tool_a"',
        )

        async def fail_resolve_event(*args, **kwargs):
            raise RuntimeError("resolver failed")

        module_test.monkeypatch.setattr(dnsresolve, "resolve_event", fail_resolve_event)
        failing_by_tool_d = module_test.scan.make_event(
            "failure.blacklanternsecurity.com",
            "DNS_NAME",
            parent=module_test.scan.root_event,
            module=tool_d,
        )
        failing_by_tool_d.scope_distance = 0
        try:
            await dnsresolve.handle_event(failing_by_tool_d)
        except RuntimeError as e:
            assert str(e) == "resolver failed"
        else:
            assert False, "expected resolver failure"
        assert not dnsresolve.pending_unresolved_subdomains_by_module.get("tool_d")

    def check(self, module_test, events):
        assert not any(e.type == "DNS_NAME_UNRESOLVED" and e.data.endswith(".blacklanternsecurity.com") for e in events)
