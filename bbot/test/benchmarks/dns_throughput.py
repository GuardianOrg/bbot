import argparse
import asyncio
import json
import tempfile
import time
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from bbot.scanner import Scanner
from bbot.test.test_step_1.test_dns_throughput import DNSFixture


async def run(parallel, endpoint, threads=25):
    scan = Scanner(
        "example.com",
        config={
            "home": tempfile.mkdtemp(prefix="bbot-dns-bench-"),
            "dns": {"brute_parallel_batches": parallel, "brute_threads_per_resolver": threads},
        },
    )
    helper = scan.helpers.dns.brute
    scan.helpers.tools_dir = Path(args.binary).resolve().parent
    helper.parent_helper.dns.is_wildcard_domain = AsyncMock(return_value={})
    await helper.resolver_pool.validate([endpoint])
    helper._resolver_file = scan.helpers.tempfile([endpoint], pipe=False)
    module = SimpleNamespace(name="benchmark", run_process=scan.helpers.run)
    started = time.monotonic()
    groups = await asyncio.gather(
        *(helper(module, "example.com", [f"n{i}" for i in range(2000)], type=kind) for kind in ("A", "AAAA"))
    )
    elapsed = time.monotonic() - started
    assert set(groups[0]) == {f"n{i}.example.com" for i in range(0, 2000, 20)}
    assert set(groups[1]) == {f"n{i}.example.com" for i in range(1, 2000, 20)}
    return {
        "parallel_batches": parallel,
        "threads_per_resolver": threads,
        "seconds": round(elapsed, 3),
        "queries": len(helper.queries_tried),
        "confirmed_names": len(set(sum(groups, []))),
        "confirmations": helper.resolver_pool.confirmations,
    }


async def main():
    transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: DNSFixture("benchmark", 0.015), local_addr=("127.0.0.1", 0)
    )
    endpoint = f"127.0.0.1:{transport.get_extra_info('sockname')[1]}"
    try:
        results = []
        for _ in range(args.samples):
            for threads in args.threads:
                for parallel in args.parallel:
                    result = await run(parallel, endpoint, threads)
                    results.append(result)
                    print(json.dumps(result), flush=True)
        Path(args.output).write_text(json.dumps(results, indent=2))
    finally:
        for handle in server.pending:
            handle.cancel()
        transport.close()


parser = argparse.ArgumentParser(description="DNS-only loopback MassDNS benchmark with known A/AAAA ground truth")
parser.add_argument("--binary", default=shutil.which("massdns"))
parser.add_argument("--samples", type=int, default=3)
parser.add_argument("--threads", type=int, nargs="+", default=[10, 25, 50])
parser.add_argument("--parallel", type=int, nargs="+", default=[1, 2])
parser.add_argument("--output", default="/tmp/bbot-dns-benchmark.json")
args = parser.parse_args()
if not args.binary or not Path(args.binary).is_file() or not 1 <= args.samples <= 5:
    parser.error("provide a massdns binary and 1..5 samples")
asyncio.run(main())
