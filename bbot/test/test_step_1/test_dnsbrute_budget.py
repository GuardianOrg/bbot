import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ..bbot_fixtures import *


async def test_brute_deduplicates_full_names_between_domains_modules_and_rounds(bbot_scanner):
    scan = bbot_scanner("example.com", config={"dns": {"brute_max_candidates": 3}})
    helper = scan.helpers.dns.brute
    module = scan.helpers
    calls = []

    async def wildcard(*args, **kwargs):
        await asyncio.sleep(0)
        return {}

    async def massdns(module, domain, prefixes, rdtype, timeout=None):
        names = [f"{prefix}.{domain}" for prefix in prefixes if prefix in {"api.dev", "api", "auth", "www", "mail"}]
        calls.extend((name, rdtype) for name in names)
        for name in names:
            yield name, "1.2.3.4", rdtype

    helper.parent_helper.dns.is_wildcard_domain = wildcard
    helper._massdns = massdns
    await asyncio.gather(
        helper(module, "example.com", ["api.dev", "api.dev", "auth"]),
        helper(module, "dev.example.com", ["api", "api"]),
    )
    await helper(module, "example.com", ["auth", "www", "mail"])
    assert calls == [("api.dev.example.com", "A"), ("auth.example.com", "A"), ("www.example.com", "A")]
    assert len(helper.queries_tried) == 3
    assert await helper(module, "example.com", ["another"]) == []


async def test_brute_keeps_ipv6_queries_distinct_and_normalizes_case(bbot_scanner):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    calls = []

    async def wildcard(*args, **kwargs):
        return {}

    async def massdns(module, domain, prefixes, rdtype, timeout=None):
        calls.append((domain, prefixes, rdtype))
        if False:
            yield

    helper.parent_helper.dns.is_wildcard_domain = wildcard
    helper._massdns = massdns
    await helper(scan.helpers, "Example.COM.", ["API", "api"])
    await helper(scan.helpers, "example.com", ["api"], type="AAAA")
    await helper(scan.helpers, "example.com", ["api"])
    assert len(calls) == 2
    assert helper.queries_tried == {("api.example.com", "A"), ("api.example.com", "AAAA")}


async def test_brute_unlimited_budget_deduplicates_without_count_limit(bbot_scanner):
    scan = bbot_scanner("example.com", config={"dns": {"brute_max_candidates": 0}})
    helper = scan.helpers.dns.brute
    assert helper.remaining_candidates(scan.helpers) is None
    for index in range(1000):
        key = (f"host{index}.example.com", "A")
        assert helper.claim(scan.helpers, key)
        assert not helper.claim(scan.helpers, key)
    assert helper.claim(scan.helpers, ("host0.example.com", "AAAA"))
    assert len(helper.queries_tried) == 1001
    assert not helper.reservations


async def test_brute_rejects_negative_budget(bbot_scanner):
    scan = bbot_scanner("example.com", config={"dns": {"brute_max_candidates": -1}})
    with pytest.raises(ValueError, match="brute_max_candidates"):
        scan.helpers.dns.brute


async def test_brute_passes_remaining_budget_to_massdns_subprocess(bbot_scanner):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    helper.resolver_file = AsyncMock(return_value="fixture-resolvers.txt")
    module = SimpleNamespace(run_process=AsyncMock(return_value=SimpleNamespace(stdout="")))
    assert [result async for result in helper._massdns(module, "example.com", ["api"], "A", timeout=0.5)] == []
    assert module.run_process.await_args.kwargs["idle_timeout"] == 0.5
