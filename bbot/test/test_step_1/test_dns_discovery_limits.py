import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import dns.message
import dns.name
import dns.rdata
import dns.resolver
import dns.rrset
import pytest

from ..bbot_fixtures import *
from bbot.core.helpers.dns.engine import DNSEngine, all_rdtypes
from bbot.core.helpers.dns.helpers import extract_targets
from bbot.modules.dnsdepth import dnsdepth
from bbot.modules.dnsbrute import dnsbrute
from bbot.modules.baddns import baddns
from bbot.modules.baddns_zone import baddns_zone


@pytest.mark.parametrize(
    "kind,text,target",
    [
        ("HTTPS", '1 origin.eu.example.com. alpn="h2" ipv4hint=1.2.3.4', "origin.eu.example.com"),
        ("SVCB", "0 svc.example.com.", "svc.example.com"),
        ("NAPTR", '10 20 "S" "SIP+D2U" "" _sip._udp.example.com.', "_sip._udp.example.com"),
        ("DNAME", "new.example.com.", "new.example.com"),
    ],
)
def test_new_records_extract_names_and_are_queried_by_default(kind, text, target):
    assert kind in all_rdtypes
    assert (kind, target) in extract_targets(dns.rdata.from_text("IN", kind, text))


def test_https_same_owner_and_ip_hints_do_not_create_fake_hosts():
    assert extract_targets(dns.rdata.from_text("IN", "HTTPS", '1 . alpn="h2" ipv4hint=1.2.3.4')) == set()


async def test_resolve_status_distinguishes_nodata_nxdomain_and_timeout():
    engine = object.__new__(DNSEngine)
    response = dns.message.make_response(dns.message.make_query("dev.example.com", "A"))
    answer = dns.resolver.Answer(dns.name.from_text("dev.example.com"), 1, 1, response)
    engine.resolver = SimpleNamespace(
        resolve=AsyncMock(side_effect=[answer, dns.resolver.NXDOMAIN(), dns.exception.Timeout()])
    )
    assert (await engine.resolve_status("dev.example.com"))["status"] == "NOERROR"
    assert (await engine.resolve_status("missing.example.com"))["status"] == "NXDOMAIN"
    assert (await engine.resolve_status("timeout.example.com"))["status"] == "ERROR"


async def test_additional_records_flow_through_scan_as_full_raw_data(bbot_scanner):
    records = {
        "A": ["127.0.0.88"],
        "HTTPS": ['1 origin.example.com. alpn="h2" ech="AQID"'],
        "SVCB": ["0 svc.example.com."],
        "NAPTR": ['10 20 "S" "SIP+D2U" "" sip.example.com.'],
        "DNAME": ["new.example.com."],
    }
    scan = bbot_scanner("example.com", config={"dns": {"emit_unresolved": True, "minimal": False}})
    await scan.helpers._mock_dns({"example.com": records})
    events = [event async for event in scan.async_start()]
    emitted = {
        event.data["type"]: event.data["answer"]
        for event in events
        if event.type == "RAW_DNS_RECORD" and event.host == "example.com"
    }
    for kind in ("HTTPS", "SVCB", "NAPTR", "DNAME"):
        assert emitted[kind] == dns.rdata.from_text("IN", kind, records[kind][0]).to_text()
    names = {event.data for event in events if event.type.startswith("DNS_NAME")}
    assert {"origin.example.com", "svc.example.com", "sip.example.com", "new.example.com"} <= names


async def make_depth(bbot_scanner, config):
    scan = bbot_scanner(
        "example.com",
        modules=["dnsdepth"],
        config={"dns": {"emit_unresolved": False}, "modules": {"dnsdepth": config}},
    )
    module = dnsdepth(scan)
    module._name = "dnsdepth"
    await module.setup()
    module.emit_event = AsyncMock()
    return module


async def test_empty_parents_are_explored_with_unresolved_events_disabled(bbot_scanner):
    module = await make_depth(bbot_scanner, {"max_empty_parents": 1, "words_per_parent": 100})

    async def status(host, **kwargs):
        if host == "dev.example.com":
            return {"status": "NOERROR", "answers": []}
        return {"status": "NXDOMAIN", "answers": []}

    module.helpers.dns.resolve_status = status
    module.helpers.dns.brute.dnsbrute = AsyncMock(return_value=["api.dev.example.com"])
    await module.finish()
    assert module.empty_parents == {"dev.example.com"}
    assert module.emit_event.await_count == 1
    assert all(len(call.args[2]) == 100 for call in module.helpers.dns.brute.dnsbrute.await_args_list)


async def test_empty_target_discovery_emits_ipv6_child_through_real_scan(bbot_scanner):
    scan = bbot_scanner(
        "example.com",
        modules=["dnsdepth"],
        config={
            "deps": {"behavior": "disable"},
            "dns": {"emit_unresolved": False},
            "modules": {"dnsdepth": {"max_empty_parents": 1}},
        },
    )
    await scan.helpers._mock_dns({"_NOERROR": ["example.com"], "api.example.com": {"AAAA": ["2001:db8::1"]}})

    async def brute(module, domain, words, type=None, timeout=None):
        return ["api.example.com"] if domain == "example.com" and type == "AAAA" else []

    scan.helpers.dns.brute.dnsbrute = brute
    events = [event async for event in scan.async_start()]
    children = [event for event in events if event.type == "DNS_NAME" and event.data == "api.example.com"]
    assert len(children) == 1
    assert "dns-empty-parent-child" in children[0].tags
    assert children[0].resolved_hosts == {"2001:db8::1"}


async def test_empty_parent_flood_is_bounded(bbot_scanner):
    module = await make_depth(bbot_scanner, {"max_empty_parents": 2, "max_parent_probes": 5, "words_per_parent": 3})
    module.helpers.dns.resolve_status = AsyncMock(return_value={"status": "NOERROR", "answers": []})
    module.helpers.dns.brute.dnsbrute = AsyncMock(return_value=[])
    await module.finish()
    await module.finish()
    assert len(module.empty_parents) == 2
    assert len(module.checked) <= 5
    assert module.helpers.dns.brute.dnsbrute.await_count == 4


async def test_empty_parent_runtime_cancels_all_queries(bbot_scanner):
    module = await make_depth(bbot_scanner, {"max_runtime": 0.02})

    async def slow(*args, **kwargs):
        await asyncio.sleep(10)

    module.helpers.dns.resolve_status = slow
    await asyncio.wait_for(module.finish(), 1)
    assert not module.empty_parents


async def test_wildcards_require_distinct_stable_non_address_evidence(bbot_scanner):
    scan = bbot_scanner(
        "example.com", config={"dns": {"brute_wildcard_max_candidates": 3, "brute_wildcard_max_results": 1}}
    )
    helper = scan.helpers.dns.brute
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={"example.com": {"A": []}})

    async def status(host, type=None, **kwargs):
        records = []
        if type == "CNAME":
            # A constant wildcard containing 'api' must not turn api into a false positive.
            records = [{"owner": host, "type": type, "answer": "api.shared.example.net."}]
        if type == "TXT" and host == "real.example.com":
            records = [{"owner": host, "type": type, "answer": '"service=real"'}]
        return {"status": "NOERROR", "answers": records}

    helper.parent_helper.dns.resolve_status = status
    assert await helper(scan.helpers, "example.com", ["api", "fake", "real", "extra"]) == ["real.example.com"]
    assert await helper(scan.helpers, "example.com", [f"fake{i}" for i in range(1000)]) == []
    assert helper.wildcard_candidates["example.com"] == 3
    assert helper.wildcard_verified_names == {"real.example.com"}


async def test_rotating_wildcard_records_do_not_establish_existence(bbot_scanner):
    scan = bbot_scanner("example.com", config={"dns": {"brute_wildcard_max_candidates": 2}})
    helper = scan.helpers.dns.brute
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={"example.com": {"A": []}})

    async def status(host, type=None, **kwargs):
        return {"status": "NOERROR", "answers": [{"owner": host, "type": type, "answer": f'"dynamic={host}"'}]}

    helper.parent_helper.dns.resolve_status = status
    assert await helper(scan.helpers, "example.com", ["api", "admin"]) == []
    assert not helper.wildcard_verified_names


async def test_global_brute_deadline_is_shared_across_modules_and_rounds(bbot_scanner):
    scan = bbot_scanner("example.com", config={"dns": {"brute_max_runtime": 0.02}})
    helper = scan.helpers.dns.brute

    async def slow(*args, **kwargs):
        await asyncio.sleep(10)

    helper.parent_helper.dns.is_wildcard_domain = slow
    assert await asyncio.wait_for(helper(scan.helpers, "example.com", ["api"]), 1) == []
    assert await helper(scan.helpers, "dev.example.com", ["api"]) == []


async def test_delegated_zones_without_addresses_and_empty_seeds_are_enumerated(bbot_scanner, monkeypatch):
    scan = bbot_scanner("example.com", config={"dns": {"emit_unresolved": False}})
    module = baddns_zone(scan)
    module._name = "baddns_zone"
    await module.setup()
    checks = AsyncMock()
    monkeypatch.setattr(baddns, "handle_event", checks)

    async def status(host, type=None, **kwargs):
        owner = "dev.example.com" if host.endswith("dev.example.com") else "example.com"
        return {
            "status": "NOERROR",
            "answers": [],
            "authority": [
                {"owner": owner, "type": "SOA", "answer": "ns.example.com. hostmaster.example.com. 1 2 3 4 5"}
            ],
        }

    module.helpers.dns.resolve_status = status
    await module.handle_event(scan.make_event("api.dev.example.com", "DNS_NAME", parent=scan.root_event))
    await module.finish()
    await module.finish()
    assert {call.args[0].data for call in checks.await_args_list} == {"example.com", "dev.example.com"}
    assert checks.await_count == 2


async def test_zone_deadline_cancels_baddns_dispatch_tasks(bbot_scanner):
    scan = bbot_scanner("example.com")
    module = baddns_zone(scan)
    module._name = "baddns_zone"
    await module.setup()
    module.max_runtime = 0.02
    cancelled = asyncio.Event()

    class SlowZoneCheck:
        name = "NSEC"

        def __init__(self, *args, **kwargs):
            pass

        async def dispatch(self):
            try:
                await asyncio.sleep(10)
            finally:
                cancelled.set()

    module.select_modules = lambda: [SlowZoneCheck]
    module.helpers.dns.resolve_status = AsyncMock(
        return_value={
            "status": "NOERROR",
            "answers": [{"owner": "example.com", "type": "NS", "answer": "ns.example.com."}],
            "authority": [],
        }
    )
    await asyncio.wait_for(module.finish(), 1)
    assert cancelled.is_set()


async def test_bundled_wordlist_and_extra_lists_are_ranked_unique_and_bounded(bbot_scanner, tmp_path):
    words = (Path(__file__).parents[2] / "wordlists/subdomains-ranked.txt").read_text().splitlines()
    assert len(words) == len(set(words)) == 10000
    assert words[0] == "www"
    extra = tmp_path / "extra.txt"
    extra.write_text("www\nWWW\ncustom-new\n")
    scan = bbot_scanner(
        "example.com",
        modules=["dnsbrute"],
        config={"modules": {"dnsbrute": {"max_words": 10002, "wordlists": [str(extra)]}}},
    )
    module = dnsbrute(scan)
    module._name = "dnsbrute"
    module.subdomain_file = Path(__file__).parents[2] / "wordlists/subdomains-ranked.txt"
    await module.setup()
    assert module.subdomain_list[0] == "www"
    assert len(module.subdomain_list) == 10001
    assert module.subdomain_list[-1] == "custom-new"
