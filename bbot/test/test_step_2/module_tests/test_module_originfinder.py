import asyncio
import ssl
import zlib
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from bbot.modules import originfinder as originfinder_module
from bbot.modules.originfinder import (
    HTTP_PORTS,
    decode_http_body,
    fetch_website,
    originfinder,
    same_host_redirect_path,
    similarity,
)


BODY = (
    "<html><title>Guardian Audits</title><body>"
    + " ".join(f"distinctive-content-word-{index}" for index in range(80))
    + "</body></html>"
).encode()
CONTROL_BODY = b"<html><title>Default server</title><body>Unrelated virtual host</body></html>"


def response(body=BODY):
    return {"status": 200, "body": body, "headers": "HTTP/1.1 200 OK", "cert_sha256": None}


def test_similarity_rejects_shared_title_without_matching_content():
    assert similarity(response(), response()) == 1
    assert similarity(response(), response(CONTROL_BODY)) == 0
    assert similarity(response(), {"status": 302, "body": BODY}) == 0


def test_chunked_and_gzip_http_bodies_match_the_same_page():
    chunks = [BODY[:100], BODY[100:]]
    wire = b"".join(f"{len(part):X}\r\n".encode() + part + b"\r\n" for part in chunks) + b"0\r\n\r\n"
    assert decode_http_body("Transfer-Encoding: chunked\r\n", wire) == BODY
    gzip_wire = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    compressed = gzip_wire.compress(BODY) + gzip_wire.flush()
    assert decode_http_body("Content-Encoding: gzip\r\n", compressed) == BODY
    assert similarity(response(), response(decode_http_body("Transfer-Encoding: chunked\r\n", wire))) == 1


def test_single_page_app_matches_distinctive_static_resources_but_not_generic_title():
    resources = [f"/assets/product-bundle-{index:02d}-abc12345.js" for index in range(12)]

    def page(urls):
        return (
            "<html><title>Bakkt</title>"
            + "".join(f'<script src="{url}"></script>' for url in urls)
            + "<body>App</body></html>"
        ).encode()

    first = page(resources)
    reordered = page(list(reversed(resources)))
    unrelated = page([f"/assets/other-bundle-{index:02d}-xyz78900.js" for index in range(12)])
    assert similarity(response(first), response(reordered)) == 1
    assert similarity(response(first), response(unrelated)) == 0


def test_only_same_host_redirects_can_supply_a_comparable_path():
    assert (
        same_host_redirect_path(
            {"status": 302, "headers": "HTTP/1.1 302 Found\r\nLocation: /login\r\n"}, "app.example.com"
        )
        == "/login"
    )
    assert (
        same_host_redirect_path(
            {"status": 301, "headers": "HTTP/1.1 301 Moved\r\nLocation: https://other.example.com/\r\n"},
            "app.example.com",
        )
        is None
    )


@pytest.mark.asyncio
async def test_direct_probe_sends_requested_host_and_path_to_candidate_ip():
    requests = []

    async def handler(reader, writer):
        requests.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await fetch_website("127.0.0.1", "app.example.com", port, False, "/login")
    finally:
        server.close()
        await server.wait_closed()
    assert result["status"] == 200
    assert result["body"] == b"origin"
    assert requests[0].startswith(b"GET /login HTTP/1.1\r\n")
    assert f"Host: app.example.com:{port}\r\n".encode() in requests[0]


@pytest.mark.asyncio
async def test_https_direct_probe_sends_hostname_as_tls_sni():
    observed = {"sni": None, "request": None}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fixture_dir = Path(__file__).parents[2]
    context.load_cert_chain(fixture_dir / "testsslcert.pem", fixture_dir / "testsslkey.pem")
    context.set_servername_callback(lambda _socket, name, _context: observed.__setitem__("sni", name))

    async def handler(reader, writer):
        observed["request"] = await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=context)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await fetch_website("127.0.0.1", "app.example.com", port, True)
    finally:
        server.close()
        await server.wait_closed()
    assert result["status"] == 200
    assert len(result["cert_sha1"]) == 40
    assert len(result["cert_sha256"]) == 64
    assert observed["sni"] == "app.example.com"
    assert f"Host: app.example.com:{port}\r\n".encode() in observed["request"]


def fake_module(monkeypatch, origin_response):
    module = object.__new__(originfinder)
    host = "www.guardianaudits.com"
    ip = "8.8.8.8"
    parent = SimpleNamespace(
        data=host, resolved_hosts={"104.16.1.1"}, dns_children={"CNAME": {"example.cloudfront.net"}}
    )
    module.websites = {
        host: {
            "urls": {f"https://{host}/": parent},
            "ips": {"104.16.1.1"},
            "cnames": {"example.cloudfront.net"},
            "certs": set(),
        }
    }
    module.host_events = {host: parent}
    module.ip_frontends = {"104.16.1.1": {"isFrontedProxy": True}}
    module.histories = defaultdict(dict, {host: {ip: {"sources": {"historical-dns:robtex"}, "ports": set()}}})
    module.ports = defaultdict(set)
    module.certificates = defaultdict(set)
    module.processed_hosts = {}
    module.reported_origins = set()
    module.scan = SimpleNamespace(
        helpers=SimpleNamespace(parent_domain=lambda _: "guardianaudits.com"),
        in_scope=lambda name: name == "guardianaudits.com" or name.endswith(".guardianaudits.com"),
    )
    events = []
    calls = []

    async def emit(data, kind, parent_event, **_kwargs):
        events.append((kind, data, parent_event))
        return SimpleNamespace(type=kind, data=data)

    def make_event(data, kind, parent_event, **_kwargs):
        return SimpleNamespace(type=kind, data=data, parent=parent_event, scope_distance=1)

    async def emit_existing(event):
        events.append((event.type, event.data, event.parent))
        return event

    async def emit_any(*args, **kwargs):
        if len(args) == 1 and hasattr(args[0], "type"):
            return await emit_existing(args[0])
        return await emit(*args, **kwargs)

    async def fetch(address, host_header, port, tls, path="/", timeout=4):
        calls.append((address, host_header, port, tls))
        if address == host:
            return response()
        if host_header.endswith(".invalid"):
            return response(CONTROL_BODY)
        return origin_response

    async def no_apis(*_args):
        return []

    async def no_dns(*_args):
        return None

    async def not_frontend(*_args):
        return False

    monkeypatch.setattr(module, "emit_event", emit_any)
    monkeypatch.setattr(module, "make_event", make_event)
    monkeypatch.setattr(module, "api_candidates", no_apis)
    monkeypatch.setattr(module, "query_sibling_dns", no_dns)
    monkeypatch.setattr(module, "is_frontend_ip", not_frontend)
    monkeypatch.setattr(originfinder_module, "fetch_website", fetch)
    return module, events, calls


@pytest.mark.asyncio
async def test_verified_origin_emits_frontend_relation_ip_and_finding(monkeypatch):
    module, events, calls = fake_module(monkeypatch, response())
    await module.finish()
    assert [event[0] for event in events] == ["WEB_FRONTEND", "WEB_ORIGIN", "IP_ADDRESS", "OPEN_TCP_PORT", "FINDING"]
    assert events[1][1]["ip"] == "8.8.8.8"
    assert events[1][1]["sources"] == ["historical-dns:robtex"]
    assert events[4][1]["affected_endpoints"] == ["8.8.8.8:80/tcp"]
    assert calls[1] == ("8.8.8.8", "www.guardianaudits.com", 80, False)


@pytest.mark.asyncio
async def test_out_of_scope_service_cname_skips_origin_probes(monkeypatch):
    module, events, calls = fake_module(monkeypatch, response())
    cname = "bakkt-api-a864616d.readmessl.com"
    module.websites["www.guardianaudits.com"]["cnames"] = {cname}
    module.host_events["www.guardianaudits.com"].dns_children["CNAME"] = {cname}
    await module.finish()
    assert [kind for kind, *_ in events] == ["WEB_FRONTEND"]
    assert f"out-of-scope service {cname}" in events[0][1]["evidence"]
    assert not any(address == "8.8.8.8" for address, *_ in calls)


@pytest.mark.asyncio
async def test_explicitly_scoped_service_cname_can_be_checked(monkeypatch):
    module, events, _ = fake_module(monkeypatch, response())
    cname = "docs.other-authorized.com"
    module.websites["www.guardianaudits.com"]["cnames"] = {cname}
    module.host_events["www.guardianaudits.com"].dns_children["CNAME"] = {cname}
    module.scan.in_scope = lambda name: name == cname or name.endswith(".guardianaudits.com")
    await module.finish()
    assert any(kind == "WEB_ORIGIN" for kind, *_ in events)


@pytest.mark.asyncio
async def test_root_domain_history_does_not_mutate_during_candidate_iteration(monkeypatch):
    module, events, _ = fake_module(monkeypatch, response())
    original_host = "www.guardianaudits.com"
    root = "guardianaudits.com"
    website = module.websites.pop(original_host)
    website["urls"] = {f"https://{root}/": SimpleNamespace(data=root)}
    module.websites[root] = website
    module.host_events[root] = module.host_events.pop(original_host)
    module.histories[root] = module.histories.pop(original_host)
    await module.finish()
    assert any(kind == "WEB_FRONTEND" for kind, *_ in events)


@pytest.mark.asyncio
async def test_later_finishing_round_uses_new_history_without_duplicate_findings(monkeypatch):
    module, events, _ = fake_module(monkeypatch, response())
    host = "www.guardianaudits.com"
    module.histories[host].clear()
    await module.finish()
    assert [event[0] for event in events] == ["WEB_FRONTEND"]
    module.add_candidate(host, "8.8.8.8", "late-history")
    await module.finish()
    assert [event[0] for event in events].count("WEB_ORIGIN") == 1
    await module.finish()
    assert [event[0] for event in events].count("WEB_ORIGIN") == 1
    assert [event[0] for event in events].count("FINDING") == 1


@pytest.mark.asyncio
async def test_unrelated_candidate_tries_all_default_http_ports_without_promoting_ip(monkeypatch):
    module, events, calls = fake_module(monkeypatch, response(CONTROL_BODY))
    await module.finish()
    assert [event[0] for event in events] == ["WEB_FRONTEND"]
    probes = {(port, tls) for address, _, port, tls in calls if address == "8.8.8.8"}
    assert probes == set(HTTP_PORTS) | {(port, not tls) for port, tls in HTTP_PORTS}


@pytest.mark.asyncio
async def test_provider_observed_unusual_port_is_probed_first(monkeypatch):
    module, events, calls = fake_module(monkeypatch, response())

    async def api_candidates(*_args):
        return [("8.8.8.8", 49152, "shodan:hostname")]

    async def fetch(address, host_header, port, tls, path="/", timeout=4):
        calls.append((address, host_header, port, tls))
        if address == "www.guardianaudits.com":
            return response()
        if port == 49152 and host_header == "www.guardianaudits.com":
            return response()
        return response(CONTROL_BODY)

    monkeypatch.setattr(module, "api_candidates", api_candidates)
    monkeypatch.setattr(originfinder_module, "fetch_website", fetch)
    await module.finish()
    candidate_calls = [call for call in calls if call[0] == "8.8.8.8"]
    assert candidate_calls[0][2] == 49152
    assert next(data for kind, data, _ in events if kind == "FINDING")["affected_endpoints"] == ["8.8.8.8:49152/tcp"]


@pytest.mark.asyncio
async def test_other_website_load_balancer_ip_is_excluded_before_probing(monkeypatch):
    module, events, calls = fake_module(monkeypatch, response())
    module.host_events["other.example.com"] = SimpleNamespace(
        resolved_hosts={"8.8.8.8"},
        dns_children={"CNAME": {"app.other-123.eu-west-1.elb.amazonaws.com"}},
    )
    module.ip_classifications = {}

    async def lookup(_ip):
        return []

    module.scan.helpers.cloudcheck = SimpleNamespace(lookup=lookup)
    monkeypatch.setattr(module, "is_frontend_ip", originfinder.is_frontend_ip.__get__(module))
    await module.finish()
    assert module.ip_frontends["8.8.8.8"]["isLoadBalancer"] is True
    assert not any(call[0] == "8.8.8.8" for call in calls)
    assert [kind for kind, *_ in events] == ["WEB_FRONTEND"]


@pytest.mark.asyncio
async def test_default_virtual_host_does_not_confirm_origin(monkeypatch):
    module, events, _ = fake_module(monkeypatch, response())

    async def all_hosts_same(address, host_header, port, tls, path="/", timeout=4):
        return response()

    monkeypatch.setattr(originfinder_module, "fetch_website", all_hosts_same)
    await module.finish()
    assert [event[0] for event in events] == ["WEB_FRONTEND"]


@pytest.mark.asyncio
async def test_censys_starter_results_supply_ip_and_observed_port(monkeypatch):
    module = object.__new__(originfinder)
    calls = []

    async def request(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "result": {
                    "hits": [
                        {"host_v1": {"resource": {"ip": "8.8.8.8", "services": [{"port": 9443, "protocol": "HTTP"}]}}}
                    ]
                }
            },
        )

    async def no_favicon(*_args, **_kwargs):
        return None

    module.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))
    module.shodan_key = ""
    module.censys_key = "fake-starter-token"
    module.censys_organization_id = "1988436e-c699-44e7-9873-e140f7a992dd"
    module.api_cache = {}
    monkeypatch.setattr(originfinder_module, "fetch_website", no_favicon)
    results = await module.api_candidates("audit.guardianaudits.com", {"a" * 64}, response())
    assert ("8.8.8.8", 9443, "censys:certificate") in results
    assert ("8.8.8.8", 9443, "censys:dns-name") in results
    assert "organization_id=1988436e-c699-44e7-9873-e140f7a992dd" in calls[0][0]
    assert calls[0][1]["json"]["fields"] == ["host.ip", "host.services.port", "host.services.protocol"]


@pytest.mark.asyncio
async def test_shodan_certificate_pivot_uses_sha1_not_censys_sha256(monkeypatch):
    module = object.__new__(originfinder)
    queries = []

    async def request(url, **_kwargs):
        queries.append(parse_qs(urlparse(url).query)["query"][0])
        return SimpleNamespace(status_code=200, json=lambda: {"matches": [], "total": 0})

    async def no_favicon(*_args, **_kwargs):
        return None

    module.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))
    module.shodan_key = "fake-shodan-token"
    module.censys_key = ""
    module.censys_organization_id = ""
    module.api_cache = {}
    monkeypatch.setattr(originfinder_module, "fetch_website", no_favicon)
    await module.api_candidates("audit.guardianaudits.com", {"a" * 64}, {**response(), "cert_sha1": "b" * 40})
    assert f"ssl.cert.fingerprint:{'b' * 40}" in queries
    assert not any("a" * 64 in query for query in queries)


@pytest.mark.asyncio
async def test_censys_paginates_candidate_ips_without_losing_observed_ports(monkeypatch):
    module = object.__new__(originfinder)
    calls = []

    async def request(url, **kwargs):
        calls.append(kwargs["json"])
        next_page = kwargs["json"].get("page_token")
        ip, token = ("8.8.4.4", "next-page") if next_page is None else ("8.8.8.8", "")
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "result": {
                    "next_page_token": token,
                    "hits": [{"host_v1": {"resource": {"ip": ip, "services": [{"port": 8080}]}}}],
                }
            },
        )

    async def no_favicon(*_args, **_kwargs):
        return None

    module.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))
    module.shodan_key = ""
    module.censys_key = "fake-starter-token"
    module.censys_organization_id = "1988436e-c699-44e7-9873-e140f7a992dd"
    module.api_cache = {}
    monkeypatch.setattr(originfinder_module, "fetch_website", no_favicon)
    results = await module.api_candidates("audit.guardianaudits.com", set(), response())
    assert ("8.8.4.4", 8080, "censys:dns-name") in results
    assert ("8.8.8.8", 8080, "censys:dns-name") in results
    assert any(call.get("page_token") == "next-page" for call in calls)
