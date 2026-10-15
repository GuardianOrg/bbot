import base64
import json
from pathlib import Path

import pytest
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .base import ModuleTestBase
from bbot.modules.udpx import parse_udp_response


def test_dns_version_is_only_attributed_to_version_bind_response():
    query = dns.message.make_query("version.bind.", dns.rdatatype.TXT, dns.rdataclass.CH)
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text("version.bind.", 0, "CH", "TXT", '"BIND 9.18.0"'))
    observed = parse_udp_response("dns", base64.b64encode(response.to_wire()).decode())
    assert observed["product"] == "BIND"
    assert observed["version"] == "9.18.0"
    assert observed["details"]["version_bind"] == "BIND 9.18.0"

    unrelated = dns.message.make_response(dns.message.make_query("example.com.", dns.rdatatype.TXT))
    unrelated.answer.append(dns.rrset.from_text("example.com.", 0, "IN", "TXT", '"BIND 9.18.0"'))
    observed = parse_udp_response("dns", base64.b64encode(unrelated.to_wire()).decode())
    assert "version" not in observed


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
                "response_data": base64.b64encode(bytes.fromhex("34ef818500010000000000000756455253494f4e0442494e440000100003")).decode(),
            },
            {
                "address": "1.2.3.4",
                "port": 161,
                "service": "snmp",
                "response_data": base64.b64encode(bytes.fromhex("302a02010004067075626c6963")).decode(),
            },
            {
                "address": "1.2.3.4",
                "port": 123,
                "service": "ntp",
                "response_data": base64.b64encode(bytes.fromhex(
                    "240304e7000007360000004d0a280873ee7be1de77a99ef9c54f234b71b152f3ee7be1df82eef403ee7be1df82f368b4"
                )).decode(),
            },
            {
                "address": "1.2.3.4",
                "port": 1900,
                "service": "ssdp",
                "response_data": base64.b64encode(
                    b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n"
                    b"SERVER: Linux/5.10 UPnP/1.0 MiniUPnPd/2.3\r\n\r\n"
                ).decode(),
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
        assert dns_protocol.data.get("banner") == "DNS VERSION.BIND response: REFUSED"
        assert dns_protocol.data.get("details") == {
            "response_bytes": 30, "response_code": "REFUSED",
            "authoritative": False, "recursion_available": True,
            "answer_count": 0, "query_name": "VERSION.BIND", "query_type": "TXT",
        }

        ntp_protocol = next(
            (e for e in events if e.type == "PROTOCOL" and e.data.get("protocol") == "NTP" and e.data.get("port") == 123),
            None,
        )
        assert ntp_protocol is not None, "Missing NTP protocol event"
        assert ntp_protocol.data.get("banner") == "NTPv4 server; stratum 3"
        assert ntp_protocol.data.get("details", {}).get("protocol_version") == 4
        assert ntp_protocol.data.get("details", {}).get("response_bytes") == 48

        ssdp_protocol = next(
            (e for e in events if e.type == "PROTOCOL" and e.data.get("protocol") == "SSDP" and e.data.get("port") == 1900),
            None,
        )
        assert ssdp_protocol is not None, "Missing SSDP protocol event"
        assert ssdp_protocol.data.get("details", {}).get("server") == "Linux/5.10 UPnP/1.0 MiniUPnPd/2.3"
        assert "MiniUPnPd/2.3" in ssdp_protocol.data.get("banner", "")

        snmp_protocol = next(
            (e for e in events if e.type == "PROTOCOL" and e.data.get("protocol") == "SNMP" and e.data.get("port") == 161),
            None,
        )
        assert snmp_protocol is not None, "Missing SNMP protocol event"
        assert snmp_protocol.data.get("transport") == "udp"
        assert snmp_protocol.data.get("banner") == "302a02010004067075626c6963"
