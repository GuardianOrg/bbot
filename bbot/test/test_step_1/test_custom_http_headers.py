import asyncio
import re

import pytest

from bbot.modules import originfinder as originfinder_module
from bbot.modules.deadfinder import deadfinder
from bbot.modules.dnsreaper import dnsreaper
from bbot.modules.domain_phishing import domain_phishing
from bbot.modules.gowitness import gowitness
from bbot.modules.nuclei_takeover import nuclei_takeover
from bbot.modules.originfinder import originfinder
from bbot.modules.smuggler import smuggler
from bbot.modules.subzy import subzy
from bbot.modules.wafw00f import wafw00f
from bbot.modules.wpscan import wpscan
from ..bbot_fixtures import *

HEADERS = {"X-Assessment": "assess42"}


def make(module_class, scan, name):
    # The shared test config sets a header of its own; each test states exactly which headers its scan has.
    scan.custom_http_headers = scan.web_config.get("http_headers", {})
    module = module_class(scan)
    module._name = name
    return module


def header_scan(bbot_scanner, module_name, headers=HEADERS):
    scan = bbot_scanner("example.com", modules=[module_name])
    scan.web_config = {**scan.web_config, "http_headers": dict(headers)}
    return scan


def flag_values(command, flag):
    return [command[index + 1] for index, part in enumerate(command) if part == flag]


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [HEADERS, {}])
async def test_gowitness_wpscan_and_deadfinder_pass_the_scan_headers_only_when_set(bbot_scanner, headers, tmp_path):
    expected = [f"{name}: {value}" for name, value in headers.items()]

    scan = header_scan(bbot_scanner, "gowitness", headers)
    module = make(gowitness, scan, "gowitness")
    module.chrome_path = None
    module.db_path = tmp_path / "db"
    module.screenshot_path = tmp_path / "shots"
    module.proxy = ""
    module.resolution_x = module.resolution_y = 1440
    module.threads = 2
    module.timeout = 10
    command = module.construct_command()
    assert flag_values(command, "--chrome-header") == expected
    # The input marker must stay last so gowitness still reads URLs from stdin.
    assert command[-3:] == ["file", "-f", "-"]

    scan = header_scan(bbot_scanner, "wpscan", headers)
    module = make(wpscan, scan, "wpscan")
    await module.setup()
    command = module.construct_command("https://example.com/")
    assert flag_values(command, "--headers") == (["X-Assessment: assess42"] if headers else [])

    scan = header_scan(bbot_scanner, "deadfinder", headers)
    module = make(deadfinder, scan, "deadfinder")
    module.timeout, module.concurrency, module.include_30x = 10, 5, False
    command = module._build_command(tmp_path / "out.json")
    assert flag_values(command, "--headers") == expected
    # Dead external links are third-party sites and never receive the scan's headers.
    assert "--worker_headers" not in command


@pytest.mark.asyncio
async def test_wpscan_joins_several_headers_into_its_single_list(bbot_scanner):
    scan = header_scan(bbot_scanner, "wpscan", {"X-One": "a1", "X-Two": "b2"})
    module = make(wpscan, scan, "wpscan")
    await module.setup()
    assert flag_values(module.construct_command("https://example.com/"), "--headers") == ["X-One: a1;X-Two: b2"]


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [HEADERS, {}])
async def test_nuclei_takeover_runs_nuclei_with_the_scan_headers(bbot_scanner, headers, tmp_path):
    scan = header_scan(bbot_scanner, "nuclei_takeover", headers)
    module = make(nuclei_takeover, scan, "nuclei_takeover")
    module.nuclei_bin = "nuclei"
    module.nuclei_templates_dir = tmp_path / "templates"
    module.takeover_templates_dir = tmp_path / "templates" / "takeovers"
    module.templates, module.etags, module.tags = "", "", "takeover"
    module.ratelimit, module.retries, module.timeout, module.module_timeout = 10, 1, 10, 30
    module.silent = True
    commands = []

    class Process:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def aclose(self):
            pass

    def run_process_live(command, **kwargs):
        commands.append(command)
        return Process()

    module.run_process_live = run_process_live
    event = scan.make_event("app.example.com", "DNS_NAME", parent=scan.root_event)
    await module.handle_batch(event)

    assert len(commands) == 1
    assert flag_values(commands[0], "-H") == [f"{name}: {value}" for name, value in headers.items()]


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [HEADERS, {}])
async def test_wafw00f_sends_the_scan_headers_on_every_probe(bbot_scanner, bbot_httpserver, headers):
    bbot_httpserver.expect_request(uri=re.compile(".*")).respond_with_data("ok")
    scan = header_scan(bbot_scanner, "wafw00f", headers)
    module = make(wafw00f, scan, "wafw00f")
    url = bbot_httpserver.url_for("/")

    engine = module.probe(url)
    engine.identwaf(True)
    engine.genericdetect()

    requests = [request for request, _ in bbot_httpserver.log]
    # The constructor's request, the central attack and genericdetect's probes, one of which drops User-Agent.
    assert len(requests) >= 4
    for request in requests:
        if headers:
            assert request.headers.get("X-Assessment") == "assess42"
        else:
            assert "X-Assessment" not in request.headers
    if headers:
        # The module keeps wafw00f's own defaults next to the custom header.
        assert any(request.headers.get("Accept-Language") for request in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("headers", [HEADERS, {}])
async def test_originfinder_raw_requests_carry_the_scan_headers(bbot_scanner, headers):
    received = []

    async def handle(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        scan = header_scan(bbot_scanner, "originfinder", headers)
        module = make(originfinder, scan, "originfinder")
        response = await module.fetch_website("127.0.0.1", "app.example.com", port, False, "/login")
    finally:
        server.close()
        await server.wait_closed()

    assert response["status"] == 200
    request = received[0].decode()
    assert request.startswith("GET /login HTTP/1.1\r\n")
    assert ("X-Assessment: assess42\r\n" in request) == bool(headers)
    assert request.endswith("\r\n\r\n") and request.count("\r\n\r\n") == 1


@pytest.mark.asyncio
async def test_originfinder_never_sends_a_header_that_would_split_the_request():
    received = []

    async def handle(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        await originfinder_module.fetch_website(
            "127.0.0.1", "app.example.com", port, False, headers={"X-Ok": "1", "X-Bad": "a\r\nX-Injected: 1"}
        )
    finally:
        server.close()
        await server.wait_closed()
    assert "X-Ok: 1\r\n" in received[0].decode()
    assert "X-Injected" not in received[0].decode()


@pytest.mark.asyncio
@pytest.mark.parametrize("module_class,name", [(subzy, "subzy"), (dnsreaper, "dnsreaper"), (smuggler, "smuggler")])
async def test_tools_without_a_header_option_stand_down_only_when_headers_are_set(bbot_scanner, module_class, name):
    module = make(module_class, header_scan(bbot_scanner, name), name)
    result = await module.setup()
    # (None, reason) is BBOT's soft failure: the module is disabled and the scan continues.
    assert isinstance(result, tuple) and result[0] is None and "custom HTTP headers" in result[1]

    module = make(module_class, header_scan(bbot_scanner, name, {}), name)
    result = await module.setup()
    assert not (isinstance(result, tuple) and result[0] is None and "custom HTTP headers" in str(result[1]))


@pytest.mark.asyncio
@pytest.mark.parametrize("headers,expected", [(HEADERS, False), ({}, True)])
async def test_domain_phishing_page_similarity_is_off_when_headers_are_set(bbot_scanner, headers, expected):
    scan = bbot_scanner(
        "example.com", modules=["domain_phishing"], config={"modules": {"domain_phishing": {"lsh": True}}}
    )
    scan.web_config = {**scan.web_config, "http_headers": dict(headers)}
    module = make(domain_phishing, scan, "domain_phishing")
    await module.setup()
    assert module.enable_lsh is expected


@pytest.mark.asyncio
async def test_dns_audit_doh_probe_sends_the_scan_headers_only_to_in_scope_nameservers(bbot_scanner, monkeypatch):
    from bbot.modules import domain_config_dns_audit as dns_audit_module

    sent = {}

    class Connection:
        def __init__(self, host, **kwargs):
            self.host = host

        def request(self, method, url, headers):
            sent[self.host] = headers

        def getresponse(self):
            class Response:
                status = 200

                def read(self, size):
                    return b""

            return Response()

        def close(self):
            pass

    monkeypatch.setattr(dns_audit_module.http.client, "HTTPSConnection", Connection)
    scan = header_scan(bbot_scanner, "domain_config_dns_audit")
    module = make(dns_audit_module.domain_config_dns_audit, scan, "domain_config_dns_audit")

    assert module._sync_check_doh("ns1.example.com", "/dns-query") is True
    assert module._sync_check_doh("ns1.thirdparty-dns.net", "/dns-query") is True
    assert sent["ns1.example.com"] == {"Accept": "application/dns-json", "X-Assessment": "assess42"}
    assert sent["ns1.thirdparty-dns.net"] == {"Accept": "application/dns-json"}
