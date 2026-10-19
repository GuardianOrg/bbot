import importlib
import json
from types import SimpleNamespace

from bbot.modules.nuclei import nuclei, nuclei_runtime_limits


def test_nuclei_keeps_the_existing_rate_for_small_scope():
    result = nuclei_runtime_limits(
        ["https://one.example/", "https://two.example/", "https://three.example/"],
        ratelimit=120,
        concurrency=20,
        bulk_size=10,
        per_host_rate=30,
        max_ratelimit=600,
    )
    assert result == (120, 20, 10)


def test_nuclei_scales_global_rate_with_distinct_hosts_and_caps_it():
    urls = [f"https://host-{i}.example/" for i in range(30)]
    assert nuclei_runtime_limits(
        urls, ratelimit=120, concurrency=20, bulk_size=10,
        per_host_rate=30, max_ratelimit=600,
    ) == (600, 100, 50)


def test_nuclei_does_not_multiply_rate_for_paths_or_ports_on_one_host():
    urls = [f"https://one.example:{8000 + i}/path" for i in range(25)]
    assert nuclei_runtime_limits(
        urls, ratelimit=120, concurrency=20, bulk_size=10,
        per_host_rate=30, max_ratelimit=600,
    ) == (120, 20, 10)
    assert nuclei_runtime_limits(
        [f"https://host-{i}.example/" for i in range(30)],
        ratelimit=120, concurrency=20, bulk_size=10,
        per_host_rate=0, max_ratelimit=0,
    ) == (120, 20, 10)


def test_nuclei_does_not_scale_mobile_file_targets_or_without_opt_in():
    urls = [f"/tmp/app-{i}.apk" for i in range(30)]
    assert nuclei_runtime_limits(
        urls, ratelimit=120, concurrency=20, bulk_size=10,
        per_host_rate=30, max_ratelimit=600,
    ) == (120, 20, 10)


def test_silent_nuclei_emits_compact_progress_only_when_requests_advance(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(importlib.import_module("bbot.modules.nuclei"), "time", SimpleNamespace(monotonic=lambda: clock[0]))
    module = object.__new__(nuclei)
    module.silent = True
    module.progress_stats = True
    messages = []
    module.info = messages.append

    def status(requests):
        return json.dumps({"startedAt": "batch-1", "requests": str(requests), "total": "100", "percent": "10"})

    module.log_nuclei_status(status(10))
    module.log_nuclei_status(status(10))
    clock[0] = 120.0
    module.log_nuclei_status(status(20))
    clock[0] = 161.0
    module.log_nuclei_status(status(30))

    assert len(messages) == 2
    assert "Requests: 10/100" in messages[0]
    assert "Requests: 30/100" in messages[1]
