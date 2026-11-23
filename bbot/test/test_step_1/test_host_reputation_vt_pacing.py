import asyncio
import heapq
import types
from urllib.parse import quote

import bbot.modules.host_reputation as host_reputation_module
from bbot.modules.host_reputation import host_reputation

CLEAN = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}, "reputation": 0}}}


class VirusTotal:
    """Answers like VirusTotal's public API: 4 lookups per minute and a daily quota per key, on a simulated clock."""

    def __init__(self, monkeypatch, keys, daily=500, start=1_000.0):
        self.now = start
        self.sent = []  # (time, key, url)
        self.daily = {key: daily for key in keys}
        self.cache = {}
        module = object.__new__(host_reputation)
        module.virustotal_api_keys = list(keys)
        module.scan = types.SimpleNamespace(helpers=types.SimpleNamespace(quote=quote))
        module.request_json = self.request_json
        module.cached_api_response = self.cached_api_response
        self.module = module
        clock = types.SimpleNamespace(time=lambda: self.now, monotonic=lambda: self.now)

        self.sleepers = []

        async def sleep(seconds):
            wake = asyncio.get_running_loop().create_future()
            heapq.heappush(self.sleepers, (self.now + max(0, seconds), id(wake), wake))
            await wake

        monkeypatch.setattr(host_reputation_module, "time", clock)
        monkeypatch.setattr(host_reputation_module, "asyncio",
                            types.SimpleNamespace(sleep=sleep, Lock=asyncio.Lock))

    async def cached_api_response(self, url, **_):
        return self.cache.get(url)

    async def request_json(self, url, headers=None):
        key = headers["x-apikey"]
        self.sent.append((self.now, key, url))
        if self.daily[key] <= 0:
            return {"rate_limited": True, "status": 429, "code": "QuotaExceededError"}
        if len([1 for at, used, _ in self.sent[:-1] if used == key and self.now - at < 60]) >= 4:
            return {"rate_limited": True, "status": 429, "code": "TooManyRequestsError"}
        self.daily[key] -= 1
        return CLEAN

    def lookup(self, hosts):
        """Run the lookups concurrently; simulated time advances only when every lookup is waiting."""
        async def run():
            lookups = asyncio.gather(*(self.module.check_vt_domain(host) for host in hosts))
            while not lookups.done():
                for _ in range(20):
                    await asyncio.sleep(0)
                if self.sleepers and not lookups.done():
                    self.now, _, wake = heapq.heappop(self.sleepers)
                    wake.set_result(None)
            return await lookups
        return asyncio.run(run())


def test_concurrent_lookups_are_paced_per_key_so_every_host_gets_a_verdict(monkeypatch):
    vt = VirusTotal(monkeypatch, [f"k{i}" for i in range(5)])
    results = vt.lookup([f"h{i}.example.com" for i in range(60)])
    assert all(result.get("malicious") is False and not result.get("rate_limited") for result in results)
    assert len(vt.sent) == 60  # no request was refused, so none had to be repeated
    for key in {key for _, key, _ in vt.sent}:
        times = [at for at, used, _ in vt.sent if used == key]
        assert all(later - earlier >= 15 for earlier, later in zip(times, times[1:]))
    # five keys at 4 a minute: 60 hosts take about 3 minutes, not 60 x 15 s on one key
    assert vt.now - 1_000.0 <= 180


def test_a_throttled_key_rests_and_the_lookup_still_gets_a_verdict(monkeypatch):
    vt = VirusTotal(monkeypatch, ["a", "b"])
    vt.sent = [(vt.now - 1, "a", "earlier")] * 4  # another process already used key a this minute
    results = vt.lookup(["x.example.com"])
    assert results[0].get("malicious") is False and not results[0].get("rate_limited")
    statuses = [key for _, key, url in vt.sent if url != "earlier"]
    assert statuses[-1] == "b" or statuses.count("a") == 2


def test_spent_daily_quotas_stop_requests_until_the_reset(monkeypatch):
    vt = VirusTotal(monkeypatch, ["a", "b"], daily=1)
    results = vt.lookup([f"h{i}.example.com" for i in range(10)])
    verdicts = [result for result in results if "malicious" in result and not result.get("rate_limited")]
    assert len(verdicts) == 2
    assert all(result.get("rate_limited") for result in results if result not in verdicts)
    # each key is refused once; afterwards no host spends a request that is certain to fail
    assert len(vt.sent) == 4


def test_cached_answer_needs_no_key_and_no_turn(monkeypatch):
    vt = VirusTotal(monkeypatch, ["a"])
    url = "https://www.virustotal.com/api/v3/domains/cached.example.com"
    vt.cache[url] = types.SimpleNamespace(status_code=200, json=lambda: CLEAN)
    results = vt.lookup(["cached.example.com"] * 20)
    assert all(result.get("malicious") is False for result in results)
    assert vt.sent == [] and vt.now == 1_000.0
