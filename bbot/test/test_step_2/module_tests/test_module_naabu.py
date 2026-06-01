import json
from pathlib import Path

import pytest

from .base import ModuleTestBase


@pytest.fixture
def mock_naabu(monkeypatch):
    async def fake_run_process_live(self, command, *args, **kwargs):
        target_file = Path(command[command.index("-list") + 1])
        targets = set(target_file.read_text().splitlines())
        assert targets
        assert targets.issubset({"1.2.3.4", "2001:db8::1"})
        assert command[command.index("-p") + 1] == "443"

        for target in targets:
            yield json.dumps({"ip": target, "port": 443, "protocol": "tcp"})
        if "1.2.3.4" in targets:
            yield json.dumps({"ip": "1.2.3.4", "port": 53, "protocol": "udp"})

    from bbot.modules.base import BaseModule
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    async def fake_install_core_deps(self):
        return None

    monkeypatch.setattr(BaseModule, "run_process_live", fake_run_process_live)
    monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)


@pytest.mark.usefixtures("mock_naabu")
class TestNaabu(ModuleTestBase):
    targets = ["1.2.3.4", "2001:db8::1"]
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {"naabu": {"ports": "443", "top_ports": "", "scan_individual_targets": False}},
    }

    def check(self, module_test, events):
        tcp_ports = [event for event in events if event.type == "OPEN_TCP_PORT"]
        assert any(str(event.host) == "1.2.3.4" and event.port == 443 for event in tcp_ports)
        assert any(str(event.host) == "2001:db8::1" and event.port == 443 for event in tcp_ports)
        assert not any(event.port == 53 for event in tcp_ports)
