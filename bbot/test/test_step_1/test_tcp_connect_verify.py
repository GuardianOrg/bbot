import asyncio
import ipaddress
import json

import pytest

from bbot.modules.naabu import naabu
from bbot.modules.tcp_connect_verify import tcp_connect_verify
from bbot.scanner import Scanner


@pytest.mark.asyncio
async def test_tcp_connect_verify_skips_rechecking_same_ip_across_batches(monkeypatch):
    scan = Scanner(
        "one.example",
        modules=[],
        config={"modules": {"tcp_connect_verify": {"ports": "443", "retries": 1, "connect_concurrency": 1}}},
        force_start=True,
    )

    try:
        module = tcp_connect_verify(scan)
        scan.modules["tcp_connect_verify"] = module
        assert await module.setup() is True
        module.configured_ports = [443]
        module.connect_concurrency = 1
        module.retries = 1

        parent_one = scan.make_event("one.example", "DNS_NAME", parent=scan.root_event)
        parent_two = scan.make_event("two.example", "DNS_NAME", parent=scan.root_event)
        event_one = scan.make_event("1.1.1.1", "IP_ADDRESS", parent=parent_one)
        event_two = scan.make_event("1.1.1.1", "IP_ADDRESS", parent=parent_two)

        connection_attempts = []
        emitted = []

        class DummyWriter:
            def close(self):
                return None

            async def wait_closed(self):
                return None

        async def fake_open_connection(host, port):
            connection_attempts.append((host, port))
            return object(), DummyWriter()

        async def fake_emit_open_port(host, port, parent_event):
            source = getattr(getattr(parent_event, "parent", None), "data", parent_event.data)
            emitted.append((str(host), port, source))
            return None

        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
        monkeypatch.setattr(module, "emit_open_port", fake_emit_open_port)

        await module.handle_batch(event_one)
        await module.handle_batch(event_two)

        assert connection_attempts == [("1.1.1.1", 443)]
        assert emitted == [
            ("1.1.1.1", 443, "one.example"),
            ("1.1.1.1", 443, "two.example"),
        ]
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_tcp_connect_verify_discards_ip_results_over_open_port_cap(monkeypatch):
    scan = Scanner(
        "one.example",
        modules=[],
        config={"modules": {"tcp_connect_verify": {"ports": "1-71", "retries": 1, "connect_concurrency": 10, "max_open_ports_per_ip": 70}}},
        force_start=True,
    )

    try:
        module = tcp_connect_verify(scan)
        scan.modules["tcp_connect_verify"] = module
        assert await module.setup() is True

        parent = scan.make_event("one.example", "DNS_NAME", parent=scan.root_event)
        event = scan.make_event("1.1.1.1", "IP_ADDRESS", parent=parent)
        emitted = []

        class DummyWriter:
            def close(self):
                return None

            async def wait_closed(self):
                return None

        async def fake_open_connection(host, port):
            return object(), DummyWriter()

        async def fake_emit_open_port(host, port, parent_event):
            emitted.append((str(host), port, parent_event.data))
            return None

        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
        monkeypatch.setattr(module, "emit_open_port", fake_emit_open_port)

        await module.handle_batch(event)

        assert emitted == []
        assert module.open_port_cache[hash(ipaddress.ip_address("1.1.1.1"))] == tuple()
    finally:
        await scan._cleanup()


@pytest.mark.asyncio
async def test_naabu_discards_ip_results_over_open_port_cap(monkeypatch):
    scan = Scanner(
        "1.1.1.1",
        modules=[],
        config={
            "deps": {"behavior": "disable"},
            "modules": {"naabu": {"ports": "1-71", "scan_individual_targets": False, "max_open_ports_per_ip": 70}},
        },
        force_start=True,
    )

    try:
        module = naabu(scan)
        scan.modules["naabu"] = module
        assert await module.setup() is True

        event = scan.make_event("1.1.1.1", "IP_ADDRESS", parent=scan.root_event)
        emitted = []

        async def fake_run_process_live(command, *args, **kwargs):
            for port in range(1, 72):
                yield json.dumps({"ip": "1.1.1.1", "port": port, "protocol": "tcp"})

        async def fake_emit_open_port(host, port, parent_event):
            emitted.append((str(host), port, parent_event.data))
            return None

        monkeypatch.setattr(module, "run_process_live", fake_run_process_live)
        monkeypatch.setattr(module, "emit_open_port", fake_emit_open_port)

        await module.handle_batch(event)

        assert emitted == []
        assert module.open_port_cache[hash(ipaddress.ip_address("1.1.1.1"))] == tuple()
    finally:
        await scan._cleanup()
