import base64
import json
from pathlib import Path

import pytest

from .base import ModuleTestBase


@pytest.fixture
def mock_udpx(monkeypatch):
    async def fake_run_process(self, cmd, *args, **kwargs):
        target_file = Path(cmd[cmd.index("-tf") + 1])
        output_file = Path(cmd[cmd.index("-o") + 1])

        targets = target_file.read_text().splitlines()
        assert targets == ["1.2.3.4"]
        assert cmd[cmd.index("-c") + 1] == "8"
        assert cmd[cmd.index("-w") + 1] == "900"

        results = [
            {
                "address": "1.2.3.4",
                "port": 53,
                "service": "dns",
                "response_data": base64.b64encode(b"BIND 9.18").decode(),
            },
            {
                "address": "1.2.3.4",
                "port": 161,
                "service": "snmp",
                "response_data": base64.b64encode(bytes.fromhex("302a02010004067075626c6963")).decode(),
            },
        ]
        output_file.write_text("\n".join(json.dumps(result) for result in results) + "\n")

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    from bbot.modules.base import BaseModule
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    async def fake_install_core_deps(self):
        return None

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)
    monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)


@pytest.mark.usefixtures("mock_udpx")
class TestUdpx(ModuleTestBase):
    targets = ["1.2.3.4"]
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {"udpx": {"binary": "udpx", "concurrency": 8, "timeout_ms": 900}},
    }

    def check(self, module_test, events):
        assert any(e.type == "OPEN_UDP_PORT" and e.data == "1.2.3.4:53" for e in events), "Missing DNS UDP port event"
        assert any(e.type == "OPEN_UDP_PORT" and e.data == "1.2.3.4:161" for e in events), "Missing SNMP UDP port event"

        dns_protocol = next(
            (e for e in events if e.type == "PROTOCOL" and e.data.get("protocol") == "DNS" and e.data.get("port") == 53),
            None,
        )
        assert dns_protocol is not None, "Missing DNS protocol event"
        assert dns_protocol.data.get("transport") == "udp"
        assert dns_protocol.data.get("banner") == "BIND 9.18"

        snmp_protocol = next(
            (e for e in events if e.type == "PROTOCOL" and e.data.get("protocol") == "SNMP" and e.data.get("port") == 161),
            None,
        )
        assert snmp_protocol is not None, "Missing SNMP protocol event"
        assert snmp_protocol.data.get("transport") == "udp"
        assert snmp_protocol.data.get("banner") == "302a02010004067075626c6963"