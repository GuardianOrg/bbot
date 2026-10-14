import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bbot.core.helpers.dns.permutations import iter_dnsgen_candidates
from bbot.modules.dnsgen import dnsgen
from ..bbot_fixtures import *


def test_real_dnsgen_covers_deep_names_short_labels_affixes_and_padded_numbers():
    candidates = set(iter_dnsgen_candidates("api02.dev.eu.example.co.uk", "example.co.uk", ["prod", "auth"]))
    assert {
        "api03.dev.eu.example.co.uk",
        "api01.dev.eu.example.co.uk",
        "api02.prod.eu.example.co.uk",
        "api02.dev.prod.example.co.uk",
        "auth.api02.dev.eu.example.co.uk",
        "api02.auth.dev.eu.example.co.uk",
        "prod-api02.dev.eu.example.co.uk",
        "api02-prod.dev.eu.example.co.uk",
    } <= candidates
    assert all(name.endswith(".example.co.uk") for name in candidates)


def test_dnsgen_wordlists_are_isolated_between_interleaved_scans():
    first = iter_dnsgen_candidates("api.dev.example.com", "example.com", ["firstonly"])
    second = iter_dnsgen_candidates("api.dev.example.net", "example.net", ["secondonly"])
    next(first)
    next(second)
    assert all("secondonly" not in candidate for candidate in first)
    assert all("firstonly" not in candidate for candidate in second)


async def make_module(bbot_scanner, overrides=None, targets=("example.com",)):
    scan = bbot_scanner(
        *targets, modules=["dnsgen"], config={"modules": {"dnsgen": {"incremental": False, **(overrides or {})}}}
    )
    module = dnsgen(scan)
    module._name = "dnsgen"
    await module.setup()
    return module


async def add_seed(module, hostname):
    await module.handle_event(SimpleNamespace(host=hostname, host_original=hostname))


async def test_dnsgen_enforces_scan_domain_seed_and_round_budgets(bbot_scanner):
    module = await make_module(
        bbot_scanner,
        {
            "max_candidates": 9,
            "max_candidates_per_domain": 7,
            "max_candidates_per_seed": 4,
            "max_rounds": 2,
            "max_seeds": 3,
            "dns_batch_size": 3,
        },
    )
    for hostname in ("api.dev.example.com", "auth.dev.example.com", "www.example.com", "extra.example.com"):
        await add_seed(module, hostname)
    assert len(module.seeds) == 3
    queried = []

    async def brute(module, domain, prefixes, type=None, timeout=None):
        queried.extend(f"{prefix}.{domain}" for prefix in prefixes)
        return []

    module.helpers.dns.brute.dnsbrute = brute
    await module.finish()
    await module.finish()
    await module.finish()
    assert len(set(queried)) <= 7
    assert all(name not in module.known_hosts for name in queried)
    assert len(queried) == len(set(queried)) * 2  # A and AAAA are intentional distinct queries.
    assert module.rounds <= 2


async def test_dnsgen_runtime_deadline_cancels_slow_dns(bbot_scanner):
    module = await make_module(bbot_scanner, {"max_runtime": 0.02, "dns_batch_size": 1})
    await add_seed(module, "api.dev.example.com")
    started = asyncio.Event()

    async def brute(*args, **kwargs):
        started.set()
        await asyncio.sleep(10)

    module.helpers.dns.brute.dnsbrute = brute
    await asyncio.wait_for(module.finish(), timeout=1)
    assert started.is_set()
    await module.finish()  # An expired budget cannot restart on the next finish cycle.
    assert module.rounds == 1


async def test_dnsgen_shared_dedup_and_scope_filter(bbot_scanner):
    module = await make_module(bbot_scanner, {"max_candidates_per_seed": 300, "dns_batch_size": 1000})
    await add_seed(module, "api.dev.example.com")
    module.helpers.dns.brute.queries_tried.update(
        {
            ("api.prod.example.com", "A"),
            ("api.prod.example.com", "AAAA"),
        }
    )
    batches = []

    async def brute(module, root, prefixes, type=None, timeout=None):
        names = [f"{prefix}.{root}" for prefix in prefixes]
        batches.extend(names)
        return names[:1]

    module.helpers.dns.brute.dnsbrute = brute
    module.emit_event = AsyncMock()
    await module.finish()
    assert "api.prod.example.com" not in batches
    assert "api.stg.example.com" in batches
    assert all(name.endswith(".example.com") for name in batches)
    assert module.emit_event.await_count == 1


@pytest.mark.parametrize("option", ["max_candidates", "max_seeds", "max_words", "max_rounds", "max_runtime"])
async def test_dnsgen_rejects_unlimited_budgets(bbot_scanner, option):
    with pytest.raises(ValueError, match=option):
        await make_module(bbot_scanner, {option: 0})


async def test_dnsgen_global_budget_is_shared_across_roots_and_new_seed_rounds(bbot_scanner):
    module = await make_module(
        bbot_scanner,
        {"max_candidates": 5, "max_candidates_per_domain": 10, "max_candidates_per_seed": 2},
        targets=("example.com", "example.net"),
    )
    for host in ("api.dev.example.com", "auth.dev.example.com", "api.dev.example.net"):
        await add_seed(module, host)
    queried = []

    async def brute(module, root, prefixes, type=None, timeout=None):
        queried.extend((f"{prefix}.{root}", type) for prefix in prefixes)
        return []

    module.brute.dnsbrute = brute
    await module.finish()
    await add_seed(module, "newseed.example.net")
    await module.finish()
    assert len(module.candidates_tried) == 5
    assert len(queried) == len(set(queried)) == 10
    assert {root for root, count in module.domain_counts.items() if count} == {"example.com", "example.net"}
