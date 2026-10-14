from .base import ModuleTestBase


class TestDnsgen(ModuleTestBase):
    targets = ["api02.dev.eu.example.co.uk"]
    whitelist = ["example.co.uk"]
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {"dnsgen": {"max_candidates": 1200, "max_candidates_per_seed": 300, "max_rounds": 2}},
    }

    async def setup_after_prep(self, module_test):
        self.queried = []
        self.found = {
            "api03.dev.eu.example.co.uk",
            "api02.prod.eu.example.co.uk",
            "prod-api02.dev.eu.example.co.uk",
            "api02-prod.dev.eu.example.co.uk",
        }

        async def brute(module, domain, prefixes, type=None, timeout=None):
            names = [f"{prefix}.{domain}" for prefix in prefixes]
            self.queried.extend((name, type) for name in names)
            return [name for name in names if name in self.found]

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns.brute, "dnsbrute", brute)
        await module_test.mock_dns({host: {"A": ["127.0.0.88"]} for host in {self.targets[0], *self.found}})

    def check(self, module_test, events):
        discovered = [event.data for event in events if str(event.module) == "dnsgen"]
        assert set(discovered) == self.found
        assert len(discovered) == len(set(discovered))
        assert len(self.queried) == len(set(self.queried))
        assert len(self.queried) <= 2400
        assert all(name != self.targets[0] for name, _ in self.queried)
