import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

from ..bbot_fixtures import *

# A stand-in massdns binary: it answers from a plan file and never touches the network.
# "never" names get no DNS answer on any pass, "late" ones only on a retry pass (massdns -i),
# "found" ones resolve on the first pass and everything else is NXDOMAIN. With "hang", the
# unanswered names get no output at all and the process stops writing, as a hung massdns would.
# Every name beneath a "silent" zone gets no answer on any pass. A retry pass with names left unanswered
# takes "retry_wait" seconds, as massdns waiting out its retry interval does. Each run is logged to runs.log.
FAKE_MASSDNS = """#!/usr/bin/env python3
import json, sys, time
from pathlib import Path
here = Path(__file__).parent
plan = json.loads((here / "plan.json").read_text())
args = sys.argv[1:]
rdtype = args[args.index("-t") + 1]
retry = "-i" in args
names = [line.strip() for line in sys.stdin if line.strip()]
with open(here / "asked.log", "a") as log:
    log.writelines(f"{name} {rdtype}\\n" for name in names)
start = time.time()
silent = tuple(plan["silent"])

def answer(name, address):
    data = {"answers": [{"name": name + ".", "type": "A", "data": address}]} if rdtype == "A" else {}
    return {"name": name + ".", "status": "NOERROR" if data else "NXDOMAIN", "data": data, "resolver": "192.0.2.53:53"}

pending = False
for name in names:
    if name in plan["never"] or name.endswith(silent) or (name in plan["late"] and not retry):
        pending = True
        if not plan["hang"]:
            print(json.dumps({"name": name + ".", "type": rdtype, "error": "TIMEOUT"}), flush=True)
    elif name in plan["refused"]:
        print(json.dumps({"name": name + ".", "status": "REFUSED", "data": {}, "resolver": "198.51.100.53:53"}), flush=True)
    elif name in plan["late"] or name in plan["found"]:
        print(json.dumps(answer(name, "192.0.2.7")), flush=True)
    else:
        print(json.dumps({"name": name + ".", "status": "NXDOMAIN", "data": {}, "resolver": "192.0.2.53:53"}), flush=True)
if plan["hang"] and pending:
    time.sleep(120)
if retry and pending:
    # A retry pass waits out massdns' interval for names that never answer.
    time.sleep(plan["retry_wait"])
with open(here / "runs.log", "a") as log:
    log.write(json.dumps({"s": int(args[args.index("-s") + 1]), "retry": retry, "names": names,
                          "start": start, "end": time.time()}) + "\\n")
"""


def install_fake_massdns(scan, tmp_path, never=(), late=(), found=(), hang=False, refused=(), silent=(), retry_wait=0):
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "plan.json").write_text(
        json.dumps({"never": list(never), "late": list(late), "found": list(found), "hang": hang, "refused": list(refused),
                    "silent": [f".{zone}" for zone in silent], "retry_wait": retry_wait})
    )
    binary = tools / "massdns"
    binary.write_text(FAKE_MASSDNS)
    binary.chmod(0o755)
    scan.helpers.tools_dir = tools
    helper = scan.helpers.dns.brute
    helper.resolver_file = AsyncMock(return_value=str(tmp_path / "resolvers.txt"))
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})
    return tools / "asked.log"


def dnsbrute_scan(bbot_scanner, tmp_path, coverage, resume=None):
    words = tmp_path / "words.txt"
    words.write_text("\n".join(f"w{i}" for i in range(10)))
    config = {"wordlist": str(words), "dns_batch_size": 10, "coverage_file": str(coverage)}
    if resume is not None:
        config.update(resume_file=str(resume), resume_only=True)
    return bbot_scanner(
        "example.com",
        modules=["dnsbrute"],
        config={
            "deps": {"behavior": "disable"},
            "dns": {"brute_max_candidates": 0, "brute_max_runtime": 60},
            "modules": {"dnsbrute": config},
        },
    )


async def run_scan(scan):
    await scan.helpers._mock_dns({"example.com": {"A": ["192.0.2.10"]}, "w5.example.com": {"A": ["192.0.2.7"]}})
    events = await asyncio.wait_for(_collect(scan), 60)
    return {event.data for event in events if event.type == "DNS_NAME" and str(event.module) == "dnsbrute"}


async def _collect(scan):
    return [event async for event in scan.async_start()]


async def test_words_without_a_dns_answer_are_never_counted_as_checked(bbot_scanner, tmp_path):
    coverage = tmp_path / "first.json"
    scan = dnsbrute_scan(bbot_scanner, tmp_path, coverage)
    install_fake_massdns(scan, tmp_path, never=["w3.example.com"], late=["w5.example.com"])
    found = await run_scan(scan)
    # A name answered only on a retry pass is still found.
    assert "w5.example.com" in found
    first = json.loads(coverage.read_text())
    # w3 never got an answer: coverage stops right before it although later words were asked.
    assert first["parents"]["example.com"] == [3, 10, False]
    assert first["resolver"]["unanswered_queries"] == 2  # w3 for A and AAAA
    assert first["resolver"]["transport_retry_failures"] == 2
    assert first["resolver"]["transport_unretried"] == 0

    # A resumed run asks again from the first unanswered word and, once answered, covers the rest.
    second_coverage = tmp_path / "second.json"
    resumed = dnsbrute_scan(bbot_scanner, tmp_path, second_coverage, resume=coverage)
    asked = install_fake_massdns(resumed, tmp_path)
    asked.unlink(missing_ok=True)
    await run_scan(resumed)
    wordlist = {f"w{i}.example.com" for i in range(10)}
    words = {line.split()[0] for line in asked.read_text().splitlines()} & wordlist
    assert words == {f"w{i}.example.com" for i in range(3, 10)}
    final = json.loads(second_coverage.read_text())
    # w5.example.com, a parent the first run found, is continued too although this run never finds it again.
    assert final["parents"] == {"example.com": [10, 10, False], "w5.example.com": [10, 10, False]}
    assert final["resolver"]["unanswered_queries"] == 0


async def test_batches_answered_on_some_pass_advance_coverage_fully(bbot_scanner, tmp_path):
    coverage = tmp_path / "coverage.json"
    scan = dnsbrute_scan(bbot_scanner, tmp_path, coverage)
    install_fake_massdns(scan, tmp_path, late=["w5.example.com", "w8.example.com"])
    assert "w5.example.com" in await run_scan(scan)
    result = json.loads(coverage.read_text())
    assert result["parents"]["example.com"] == [10, 10, False]
    assert result["resolver"]["unanswered_queries"] == 0
    assert result["resolver"]["transport_failures"] == 4  # w5 and w8, A and AAAA, first pass only


async def test_a_hung_massdns_is_killed_and_its_unfinished_names_stay_unanswered(bbot_scanner, tmp_path):
    scan = bbot_scanner("example.com", config={"dns": {"brute_stall_timeout": 1}})
    helper = scan.helpers.dns.brute
    install_fake_massdns(scan, tmp_path, never=["never.example.com"], late=["late.example.com"], hang=True)
    module = SimpleNamespace(name="dnsbrute", run_process_live=scan.helpers.run_live)
    started = time.monotonic()
    results = await helper(module, "example.com", ["api", "late", "never"], type="A")
    # Each hung pass costs about the stall timeout, not the whole runtime budget.
    assert time.monotonic() - started < 30
    assert results == ["late.example.com"]
    assert ("never.example.com", "A") in helper.unanswered
    assert ("api.example.com", "A") not in helper.unanswered
    metrics = helper.resolver_metrics()
    assert metrics["massdns_stalls"] == 4  # the first pass and all three retry passes
    assert metrics["unanswered_queries"] == 1


async def test_answers_and_refusals_are_counted_per_resolver(bbot_scanner, tmp_path):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    install_fake_massdns(scan, tmp_path, refused=["busy.example.com"])
    module = SimpleNamespace(name="dnsbrute", run_process_live=scan.helpers.run_live)
    await helper(module, "example.com", ["api", "www", "busy"], type="A")
    resolvers = helper.resolver_metrics()["resolvers"]
    # Two words and the wildcard canaries answered by one resolver; the other word was refused on the
    # first pass and on all three retry passes.
    assert resolvers == {"192.0.2.53": [2 + helper.num_canaries, 0], "198.51.100.53": [0, 4]}
    assert ("busy.example.com", "A") in helper.unanswered


def massdns_runs(tmp_path):
    path = tmp_path / "tools" / "runs.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


async def test_a_zone_that_answers_nothing_is_probed_with_a_sample_and_given_up(bbot_scanner, tmp_path):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    install_fake_massdns(scan, tmp_path, silent=["dead.example.com"], found=["api.example.com"])
    module = SimpleNamespace(name="dnsbrute", run_process_live=scan.helpers.run_live)
    assert await helper(module, "example.com", ["api", "www"], type="A") == ["api.example.com"]
    words = [f"w{i}" for i in range(200)]
    started = len(massdns_runs(tmp_path))
    assert await helper(module, "dead.example.com", words, type="A") == []
    runs = massdns_runs(tmp_path)[started:]
    # One full pass, then the retry passes only over a small sample.
    assert [run["retry"] for run in runs] == [False, True, True, True]
    assert all(len(run["names"]) <= 20 for run in runs[1:])
    assert set(helper.silent_domains) == {"dead.example.com"}
    # Nothing beneath it counts as checked.
    assert all((f"{word}.dead.example.com", "A") in helper.unanswered for word in words)
    # A zone that does not answer is not resolver load: concurrency is left alone.
    assert helper.concurrency_cuts == 0


async def test_when_no_parent_is_answered_every_name_is_retried_and_none_given_up(bbot_scanner, tmp_path):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    # Resolvers that answer nothing at all look the same from every parent: that is no reason to stop one.
    install_fake_massdns(scan, tmp_path, silent=["example.com"])
    module = SimpleNamespace(name="dnsbrute", run_process_live=scan.helpers.run_live)
    words = [f"w{i}" for i in range(60)]
    await helper(module, "example.com", words, type="A")
    runs = massdns_runs(tmp_path)
    assert not helper.silent_domains
    assert [len(run["names"]) for run in runs] == [len(words) + helper.num_canaries] * 4


async def test_retry_passes_keep_a_concurrency_floor_after_cuts(bbot_scanner, tmp_path):
    scan = bbot_scanner("example.com")
    helper = scan.helpers.dns.brute
    install_fake_massdns(scan, tmp_path, never=["slow.example.com"])
    module = SimpleNamespace(name="dnsbrute", run_process_live=scan.helpers.run_live)
    helper.per_resolver_threads = 5  # cut to its floor by earlier batches
    await helper(module, "example.com", ["api", "slow"], type="A")
    resolvers = max(1, len(helper.resolver_pool.selected))
    assert [run["s"] for run in massdns_runs(tmp_path) if run["retry"]] == [5 * resolvers] * 3


async def test_a_parent_whose_zone_answers_nothing_is_stopped_and_reported(bbot_scanner, tmp_path):
    coverage = tmp_path / "coverage.json"
    resume = tmp_path / "resume.json"
    resume.write_text(json.dumps({"parents": {"example.com": [0, 10], "dead.example.com": [0, 10]}}))
    scan = dnsbrute_scan(bbot_scanner, tmp_path, coverage, resume=resume)
    install_fake_massdns(scan, tmp_path, silent=["dead.example.com"])
    await scan.helpers._mock_dns({"example.com": {"A": ["192.0.2.10"]}, "dead.example.com": {"A": ["192.0.2.11"]}})
    await asyncio.wait_for(_collect(scan), 60)
    result = json.loads(coverage.read_text())
    assert result["parents"]["example.com"] == [10, 10, False]
    # Its words were never answered, so none counts as checked, and it is reported with why it stopped.
    assert result["parents"]["dead.example.com"][0] == 0
    assert "answered none" in result["skipped_parents"]["dead.example.com"]
    asked = [line.split()[0] for line in (tmp_path / "tools" / "asked.log").read_text().splitlines()]
    # Once given up, its later words are asked at most once each and never retried.
    assert all(asked.count(f"w{i}.dead.example.com") <= 4 for i in range(10))


async def test_other_parents_are_queried_while_a_parent_waits_out_its_retries(bbot_scanner, tmp_path):
    coverage = tmp_path / "coverage.json"
    resume = tmp_path / "resume.json"
    resume.write_text(json.dumps({"parents": {"example.com": [0, 10], "other.example.com": [0, 10]}}))
    words = tmp_path / "words.txt"
    words.write_text("\n".join(f"w{i}" for i in range(10)))
    scan = bbot_scanner(
        "example.com",
        modules=["dnsbrute"],
        config={
            "deps": {"behavior": "disable"},
            # One massdns slot, one parent per batch: only the scheduling can overlap their work.
            "dns": {"brute_max_candidates": 0, "brute_max_runtime": 60, "brute_parallel_batches": 1},
            "modules": {"dnsbrute": {"wordlist": str(words), "dns_batch_size": 5, "max_batch_parents": 1,
                                     "coverage_file": str(coverage), "resume_file": str(resume),
                                     "resume_only": True}},
        },
    )
    install_fake_massdns(scan, tmp_path, never=["w1.example.com"], found=["w2.other.example.com"], retry_wait=1)
    await scan.helpers._mock_dns({"example.com": {"A": ["192.0.2.10"]}, "other.example.com": {"A": ["192.0.2.11"]},
                                  "w2.other.example.com": {"A": ["192.0.2.7"]}})
    events = await asyncio.wait_for(_collect(scan), 60)
    runs = massdns_runs(tmp_path)
    waits = [run for run in runs if run["retry"] and "w1.example.com" in run["names"]]
    assert waits
    # A first pass ran while w1.example.com's retry pass was waiting, instead of queueing behind it.
    assert any(not run["retry"] and wait["start"] < run["start"] < wait["end"] for wait in waits for run in runs)
    assert "w2.other.example.com" in {event.data for event in events if event.type == "DNS_NAME"}
    # Coverage stays exact: example.com stops before its unanswered word, the other parent is fully covered.
    result = json.loads(coverage.read_text())
    assert result["parents"]["example.com"][0] == 1
    assert result["parents"]["other.example.com"] == [10, 10, False]
    asked = [line.split()[0] for line in (tmp_path / "tools" / "asked.log").read_text().splitlines()]
    # Overlapping batches never ask a word twice: once per record type.
    assert all(asked.count(f"w{i}.other.example.com") == 2 for i in range(10))
