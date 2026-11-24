import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from ..bbot_fixtures import *


def _scan(bbot_scanner, targets, words, dnsbrute_config, brute_max_candidates=0):
    scan = bbot_scanner(
        *targets,
        modules=["dnsbrute"],
        config={
            "deps": {"behavior": "disable"},
            "dns": {"brute_max_candidates": brute_max_candidates, "brute_max_runtime": 60},
            "modules": {"dnsbrute": {"wordlist": str(words), "dns_batch_size": 10, **dnsbrute_config}},
        },
    )
    return scan


async def _run(scan, records, found=()):
    await scan.helpers._mock_dns(records)
    helper = scan.helpers.dns.brute
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})
    asked = []

    async def massdns(module, domain, prefixes, rdtype, timeout=None):
        for prefix in prefixes:
            if prefix.startswith("w") and prefix[1:].isdigit():  # not the wildcard canaries
                asked.append((f"{prefix}.{domain}", rdtype))
            if rdtype == "A" and f"{prefix}.{domain}" in found:
                yield f"{prefix}.{domain}", "192.0.2.7", "A"

    helper._massdns = massdns
    events = await asyncio.wait_for(_collect(scan), 20)
    return events, asked


async def _collect(scan):
    return [event async for event in scan.async_start()]


async def test_top_up_continues_each_parent_after_the_words_the_first_run_checked(bbot_scanner, tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("\n".join(f"w{i}" for i in range(30)))
    first_coverage = tmp_path / "first.json"
    # The first run's query budget covers 10 of the 30 words (A and AAAA each).
    first = _scan(bbot_scanner, ["example.com"], words, {"coverage_file": str(first_coverage)}, brute_max_candidates=20)
    _events, first_asked = await _run(first, {"example.com": {"A": ["192.0.2.10"]}})
    coverage = json.loads(first_coverage.read_text())
    assert coverage["parents"] == {"example.com": [10, 30, False]}
    assert coverage["queries"] == 20 and coverage["word_count"] == 30
    assert {host for host, _ in first_asked} == {f"w{i}.example.com" for i in range(10)}

    second_coverage = tmp_path / "second.json"
    second = _scan(bbot_scanner, ["example.com", "other.com"], words, {
        "resume_file": str(first_coverage), "resume_only": True, "coverage_file": str(second_coverage)})
    events, asked = await _run(
        second,
        {"example.com": {"A": ["192.0.2.10"]}, "other.com": {"A": ["192.0.2.11"]},
         "w25.example.com": {"A": ["192.0.2.7"]}},
        found={"w25.example.com"},
    )
    # Only the remaining 20 words, only for the resumed parent; the unnamed target is not brute-forced.
    assert sorted({host for host, _ in asked}) == sorted(f"w{i}.example.com" for i in range(10, 30))
    assert len(asked) == 40
    assert "w25.example.com" in {e.data for e in events if e.type == "DNS_NAME" and str(e.module) == "dnsbrute"}
    final = json.loads(second_coverage.read_text())
    assert final["parents"] == {"example.com": [30, 30, False]}
    assert final["resume_matched"] and final["queries"] == 40
    assert set(final["resolver"]) >= {"servfail", "refused", "transport_failures", "concurrency_cuts"}


async def test_a_changed_wordlist_restarts_resumed_parents_from_the_first_word(bbot_scanner, tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("\n".join(f"w{i}" for i in range(12)))
    resume = tmp_path / "resume.json"
    resume.write_text(json.dumps({"wordlist_sha256": "0" * 64, "parents": {"example.com": [8, 12]}}))
    scan = _scan(bbot_scanner, ["example.com"], words, {"resume_file": str(resume), "resume_only": True})
    _events, asked = await _run(scan, {"example.com": {"A": ["192.0.2.10"]}})
    assert {host for host, _ in asked} == {f"w{i}.example.com" for i in range(12)}


async def test_resolver_refusals_cut_concurrency_and_are_counted(bbot_scanner):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    helper.resolver_file = AsyncMock(return_value="fixture.txt")
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})
    helper.resolver_pool.selected = ["192.0.2.53:53"]
    names = [f"n{i}" for i in range(1000)]
    statuses = ["REFUSED"] * 100 + ["SERVFAIL"] * 3 + ["NXDOMAIN"] * 897
    output = SimpleNamespace(stdout="\n".join(
        json.dumps({"name": f"{name}.example.com.", "status": status, "data": {}})
        for name, status in zip(names, statuses)))

    async def run_process(*command, **_):
        return output

    await helper(massdns_module(run_process), "example.com", names)
    assert helper.per_resolver_threads == 25 and helper.concurrency_cuts == 1
    metrics = helper.resolver_metrics()
    assert (metrics["refused"], metrics["servfail"], metrics["answered"]) == (100, 3, 1000)
