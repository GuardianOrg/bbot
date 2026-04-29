import asyncio

import pytest

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