import asyncio
import os
import shutil
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest
import pytest_asyncio

from ..bbot_fixtures import *
from bbot.errors import DNSError
from bbot.core.helpers.dns.resolvers import ResolverPool
from bbot.modules.dnsbrute import dnsbrute
from bbot.modules.dnsgen import dnsgen
from bbot.modules.dnsdepth import dnsdepth


class DNSFixture(asyncio.DatagramProtocol):
    def __init__(self, mode="good", delay=0):
        self.mode, self.delay = mode, delay
        self.pending = []
        self.queries = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        query = dns.message.from_wire(data)
        question = query.question[0]
        host = str(question.name).rstrip(".")
        kind = dns.rdatatype.to_text(question.rdtype)
        self.queries.append((host, kind))
        if self.mode == "timeout":
            return
        response = dns.message.make_response(query)
        records = {name: {} for name, _, _ in ResolverPool.controls}
        for name, record_type, values in ResolverPool.controls:
            records[name][record_type] = sorted(values)
        records.update(
            {
                "both.example.com": {"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]},
                "v6.example.com": {"AAAA": ["2001:db8::2"]},
                "alias.example.com": {"CNAME": ["both.example.com."]},
                "dangling.example.com": {"CNAME": ["missing.example.com."]},
            }
        )
        values = records.get(host, {}).get(kind, [])
        record_kind = kind
        if not values and records.get(host, {}).get("CNAME"):
            values, record_kind = records[host]["CNAME"], "CNAME"
        if self.mode == "bad-aaaa" and kind == "AAAA":
            values = ["2001:db8::bad"]
        if host.endswith(".invalid") and self.mode == "hijack":
            values = ["192.0.2.99"]
        if self.mode == "benchmark" and host.startswith("n") and host.split(".")[0][1:].isdigit():
            index = int(host.split(".")[0][1:])
            if index % 20 == 0 and kind == "A":
                values = ["192.0.2.1"]
            if index % 20 == 1 and kind == "AAAA":
                values = ["2001:db8::1"]
        if host == "wrong-owner.example.com":
            response.answer.append(dns.rrset.from_text("unrelated.example.net.", 60, "IN", kind, "192.0.2.99"))
        elif values:
            response.answer.append(dns.rrset.from_text(host + ".", 60, "IN", record_kind, *values))
        elif host not in records:
            response.set_rcode(dns.rcode.NXDOMAIN)
        if host == "dangling.example.com":
            response.set_rcode(dns.rcode.NXDOMAIN)
        wire = response.to_wire()
        self.pending.append(asyncio.get_running_loop().call_later(self.delay, self.transport.sendto, wire, address))


@pytest_asyncio.fixture(loop_scope="function")
async def dns_fixtures():
    servers = []

    async def create(mode="good", delay=0):
        transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: DNSFixture(mode, delay), local_addr=("127.0.0.1", 0)
        )
        servers.append((transport, server))
        return f"127.0.0.1:{transport.get_extra_info('sockname')[1]}", server

    yield create
    for transport, server in servers:
        for handle in server.pending:
            handle.cancel()
        transport.close()


async def test_resolvers_reject_hijacking_bad_ipv6_and_timeouts_and_rank_latency(dns_fixtures):
    fast, _ = await dns_fixtures()
    slow, _ = await dns_fixtures(delay=0.015)
    hijack, _ = await dns_fixtures("hijack")
    ipv6, _ = await dns_fixtures("bad-aaaa")
    dead, _ = await dns_fixtures("timeout")
    pool = ResolverPool(timeout=0.05, max_runtime=1)
    assert await pool.validate([slow, hijack, dead, ipv6, fast]) == [fast, slow]
    assert pool.measurements[0]["latency_ms"] < pool.measurements[1]["latency_ms"]
    assert await pool.confirm("v6.example.com", "AAAA")
    assert await pool.confirm("dangling.example.com", "A")
    assert not await pool.confirm("missing.example.com", "A")
    assert not await pool.confirm("wrong-owner.example.com", "A")


async def test_no_reachable_trusted_resolver_fails_closed_and_fallback_is_validated(dns_fixtures):
    dead, _ = await dns_fixtures("timeout")
    good, _ = await dns_fixtures()
    pool = ResolverPool(timeout=0.02, max_runtime=0.2)
    with pytest.raises(DNSError, match="No DNS resolver"):
        await pool.validate([dead])
    assert await pool.validate([dead], fallback=[good]) == [good]


async def test_priority_reservations_survive_normal_flood_and_release_unused_queries(bbot_scanner):
    scan = bbot_scanner(
        "example.com", modules=["dnsbrute", "dnsgen", "dnsdepth"], config={"dns": {"brute_max_candidates": 100}}
    )
    brute = scan.helpers.dns.brute
    static = SimpleNamespace(name="dnsbrute")
    generator = SimpleNamespace(name="dnsgen")
    for i in range(100):
        brute.claim(static, (f"s{i}.example.com", "A"))
    assert len(brute.queries_tried) == 50
    assert brute.remaining_candidates(generator) == 25
    for i in range(5):
        assert brute.claim(generator, (f"p{i}.example.com", "AAAA"))
    brute.release_reservation("dnsgen")
    brute.release_reservation("dnsdepth")
    assert brute.remaining_candidates(static) == 45
    assert brute.reservations_released.is_set()


async def test_two_massdns_processes_overlap_and_never_exceed_the_scan_cap(bbot_scanner):
    scan = bbot_scanner("example.com")
    brute = scan.helpers.dns.brute
    brute.resolver_file = AsyncMock(return_value="fixture.txt")
    active = peak = 0

    async def run(*args, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.03)
            return SimpleNamespace(stdout="")
        finally:
            active -= 1

    module = SimpleNamespace(run_process=run)

    async def query(kind):
        return [value async for value in brute._massdns(module, "example.com", ["api"], kind, timeout=1)]

    await asyncio.gather(*(query(kind) for kind in ("A", "AAAA", "A", "AAAA")))
    assert peak == 2
    assert active == 0


async def test_static_brute_batches_query_both_types_and_emit_each_name_once(bbot_scanner, tmp_path):
    scan = bbot_scanner("example.com", modules=["dnsbrute"], config={"modules": {"dnsbrute": {"dns_batch_size": 2}}})
    module = dnsbrute(scan)
    module._name = "dnsbrute"
    module.subdomain_file = tmp_path / "words.txt"
    module.subdomain_file.write_text("both\nv6\nmissing\n")
    await module.setup()
    module.emit_event = AsyncMock()
    seen = []

    async def brute(module, domain, words, type=None, **kwargs):
        seen.append((list(words), type))
        for word in words:
            scan.helpers.dns.brute.claim(module, (f"{word}.{domain}", type))
        return [f"{word}.{domain}" for word in words if word == "both" or (word == "v6" and type == "AAAA")]

    scan.helpers.dns.brute.dnsbrute = brute
    await module.handle_event(scan.make_event("example.com", "DNS_NAME", parent=scan.root_event))
    await module.worker_task
    assert {call.args[0] for call in module.emit_event.await_args_list} == {"both.example.com", "v6.example.com"}
    assert module.emit_event.await_count == 2
    assert len(seen) == 4
    assert {kind for _, kind in seen} == {"A", "AAAA"}
    assert all(len(words) <= 2 for words, _ in seen)


async def test_dnsgen_runs_before_finish_and_idle_time_does_not_consume_active_budget(bbot_scanner):
    scan = bbot_scanner(
        "example.com",
        modules=["dnsgen"],
        config={"modules": {"dnsgen": {"max_runtime": 0.3, "incremental_seeds": 1, "dns_batch_size": 10}}},
    )
    module = dnsgen(scan)
    module._name = "dnsgen"
    await module.setup()
    module.emit_event = AsyncMock()
    module.brute.dnsbrute = AsyncMock(return_value=[])
    await module.handle_event(scan.make_event("api.dev.example.com", "DNS_NAME", parent=scan.root_event))
    first = module.brute.dnsbrute.await_count
    assert first == 2
    await asyncio.sleep(0.35)
    await module.handle_event(scan.make_event("auth.dev.example.com", "DNS_NAME", parent=scan.root_event))
    assert module.brute.dnsbrute.await_count > first
    assert module.runtime_used < module.max_runtime
    assert module.rounds == 0


async def test_new_empty_ancestors_are_explored_before_finish_after_initial_survey(bbot_scanner):
    scan = bbot_scanner("example.com", modules=["dnsdepth"], config={"modules": {"dnsdepth": {"words_per_parent": 3}}})
    module = dnsdepth(scan)
    module._name = "dnsdepth"
    await module.setup()
    module.emit_event = AsyncMock()
    module.helpers.dns.resolve_status = AsyncMock(return_value={"status": "NXDOMAIN", "answers": []})
    module.helpers.dns.brute.dnsbrute = AsyncMock(return_value=[])
    await module.handle_event(scan.make_event("example.com", "DNS_NAME", parent=scan.root_event))
    initial = len(module.checked)

    async def status(host, **kwargs):
        return {"status": "NOERROR" if host == "branch.example.com" else "NXDOMAIN", "answers": []}

    module.helpers.dns.resolve_status = status
    await module.handle_event(scan.make_event("api.branch.example.com", "DNS_NAME", parent=scan.root_event))
    assert "branch.example.com" in module.empty_parents
    assert len(module.checked) > initial
    assert module.helpers.dns.brute.dnsbrute.await_count == 2


async def test_native_massdns_discovers_ipv6_and_reconfirms_results(bbot_scanner, dns_fixtures, tmp_path):
    binary = Path(
        os.environ.get("BBOT_TEST_MASSDNS", shutil.which("massdns") or str(Path.home() / ".bbot/tools/massdns"))
    )
    if not binary.is_file():
        pytest.skip("native massdns benchmark binary not available")
    endpoint, server = await dns_fixtures()
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    scan.helpers.tools_dir = binary.parent
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})
    await helper.resolver_pool.validate([endpoint])
    helper._resolver_file = scan.helpers.tempfile([endpoint], pipe=False)
    results = await asyncio.gather(
        *(
            helper(
                SimpleNamespace(name="native-fixture", run_process=scan.helpers.run),
                "example.com",
                ["both", "v6", "missing"],
                type=kind,
            )
            for kind in ("A", "AAAA")
        )
    )
    assert set(results[0]) == {"both.example.com"}
    assert set(results[1]) == {"both.example.com", "v6.example.com"}
    assert helper.resolver_pool.confirmations >= 3
    assert len(helper.queries_tried) == 6
    assert {kind for host, kind in server.queries if host == "v6.example.com"} == {"A", "AAAA"}


async def test_terminal_transport_failures_reduce_concurrency_and_retry_only_failed_names(bbot_scanner):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    helper.resolver_file = AsyncMock(return_value="fixture.txt")
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})
    failed = [f"n{i}.example.com" for i in range(6)]
    errors = "\n".join(json.dumps({"name": host + ".", "type": "A", "error": "TIMEOUT"}) for host in failed)
    answers = "\n".join(
        json.dumps(
            {
                "name": host + ".",
                "status": "NOERROR",
                "data": {"answers": [{"name": host, "type": "A", "data": "192.0.2.1"}]},
            }
        )
        for host in failed
    )
    run = AsyncMock(side_effect=[SimpleNamespace(stdout=errors), SimpleNamespace(stdout=answers)])
    results = await helper(
        SimpleNamespace(name="dnsbrute", run_process=run), "example.com", [f"n{i}" for i in range(6)]
    )
    assert set(results) == set(failed)
    assert helper.per_resolver_threads == 25
    assert helper.transport_failures == helper.transport_retries == 6
    assert run.await_count == 2
    assert run.await_args_list[1].kwargs["input"] == failed
    assert len(helper.queries_tried) == 6


async def test_real_scan_releases_priority_reserves_and_resumes_deferred_ipv6_work(bbot_scanner, tmp_path):
    words = tmp_path / "words.txt"
    words.write_text("both\nv6\n" + "\n".join(f"none{i}" for i in range(38)))
    scan = bbot_scanner(
        "example.com",
        modules=["dnsbrute", "dnsgen", "dnsdepth"],
        config={
            "deps": {"behavior": "disable"},
            "dns": {"brute_max_candidates": 40},
            "modules": {
                "dnsbrute": {"wordlist": str(words), "dns_batch_size": 10},
                "dnsgen": {"max_candidates": 4, "max_candidates_per_seed": 2},
                "dnsdepth": {"words_per_parent": 1, "survey_parents": 1, "max_parent_probes": 5},
            },
        },
    )
    await scan.helpers._mock_dns(
        {
            "example.com": {"A": ["192.0.2.10"]},
            "both.example.com": {"A": ["192.0.2.1"]},
            "v6.example.com": {"AAAA": ["2001:db8::2"]},
        }
    )
    helper = scan.helpers.dns.brute
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})

    async def massdns(module, domain, prefixes, rdtype, timeout=None):
        for prefix in prefixes:
            host = f"{prefix}.{domain}"
            if (host, rdtype) in {("both.example.com", "A"), ("v6.example.com", "AAAA")}:
                yield host, "192.0.2.1" if rdtype == "A" else "2001:db8::2", rdtype

    helper._massdns = massdns

    async def run():
        return [event async for event in scan.async_start()]

    events = await asyncio.wait_for(run(), 10)
    assert {"both.example.com", "v6.example.com"} <= {event.data for event in events if event.type == "DNS_NAME"}
    assert {"both.example.com", "v6.example.com"} <= set(scan.modules["dnsbrute"].queue.events)
    assert len(helper.queries_tried) == 40
    assert not helper.reservations
    assert (
        len([event for event in events if event.data == "both.example.com" and str(event.module) == "dnsbrute"]) == 1
    )
