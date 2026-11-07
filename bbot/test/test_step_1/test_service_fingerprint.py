"""The service_fingerprint cascade: Nerva, then Recog on its banner, then Nuclei on what is still unknown.

Tool output below was recorded from Nerva 1.84.2 and Nuclei 3.6.2 against real services.
"""

import json
import asyncio
from types import SimpleNamespace

import pytest

from ..bbot_fixtures import *  # noqa: F401, F403
from bbot.core.helpers.recog import Recog, ruby_to_python_regex
from bbot.modules.service_fingerprint import service_fingerprint

SSH_BANNERS = """<?xml version="1.0"?>
<fingerprints matches="ssh.banner" protocol="ssh" database_type="service">
  <fingerprint pattern="^OpenSSH_([\\w.]+)\\z" flags="REG_ICASE">
    <param pos="0" name="service.vendor" value="OpenBSD"/>
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="service.cpe23" value="cpe:/a:openbsd:openssh:{service.version}"/>
  </fingerprint>
</fingerprints>
"""

SMTP_BANNERS = """<?xml version="1.0"?>
<fingerprints matches="smtp.banner" protocol="smtp" database_type="service">
  <fingerprint pattern="^(?&lt;host&gt;[\\w.-]+) ESMTP Postfix(?: \\(([^)]+)\\))?$">
    <param pos="0" name="service.vendor" value="Postfix"/>
    <param pos="0" name="service.product" value="Postfix"/>
    <param pos="2" name="service.version"/>
    <param pos="0" name="service.cpe23" value="cpe:/a:postfix:postfix:{service.version}"/>
  </fingerprint>
  <fingerprint pattern="ESMTP">
    <param pos="0" name="service.product" value="Generic SMTP"/>
  </fingerprint>
</fingerprints>
"""

HTTP_SERVERS = """<?xml version="1.0"?>
<fingerprints matches="http_header.server" protocol="http" database_type="service">
  <fingerprint pattern="^squid/(\\d[\\w.]+)$">
    <param pos="0" name="service.product" value="Squid"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>
"""

NERVA = {
    "redis:6379": {"host": "redis", "ip": "172.18.0.3", "port": 6379, "protocol": "redis", "transport": "tcp", "version": "7.2.4", "metadata": {"auth_required": False, "cpes": ["cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*"]}},
    "ssh:22": {"host": "ssh", "ip": "172.18.0.2", "port": 22, "protocol": "ssh", "transport": "tcp", "metadata": {"banner": "SSH-2.0-OpenSSH_9.7\r\n", "password_auth_enabled": True}},
    "postfix:25": {"host": "postfix", "ip": "172.18.0.24", "port": 25, "protocol": "smtp", "transport": "tcp", "metadata": {"banner": "220 mail.bench.local ESMTP Postfix\r\n"}},
    "grafana:3000": {"host": "grafana", "ip": "172.18.0.7", "port": 3000, "protocol": "http", "transport": "tcp", "metadata": {"technologies": ["grafana:10.2.3"], "cpes": ["cpe:2.3:a:grafana:grafana:10.2.3:*:*:*:*:*:*:*"], "fingerprint_metadata": {"grafana": {}}}},
    "httpd:80": {"host": "httpd", "ip": "172.18.0.10", "port": 80, "protocol": "http", "transport": "tcp", "version": "Apache/2.4.58 (Unix)", "metadata": {"technologies": ["UNIX", "Apache HTTP Server:2.4.58", "apache_httpd:2.4.58"], "cpes": ["cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"], "fingerprint_metadata": {"apache_httpd": {}}}},
    "squid:3128": {"host": "squid", "ip": "172.18.0.11", "port": 3128, "protocol": "http", "transport": "tcp", "version": "squid/5.9", "metadata": {"response_headers": {"Server": ["squid/5.9"]}}},
    "tomcat:8080": {"host": "tomcat", "ip": "172.18.0.18", "port": 8080, "protocol": "http", "transport": "tcp", "metadata": {"status_code": 404}},
}

# Ports only Nerva's thorough mode names: no plugin is registered for their port number.
THOROUGH_ONLY = {"squid:3128"}
# A silent port: thorough mode tries every plugin on it and reports nothing until stopped.
SILENT = "samba:139"

NUCLEI = {
    "proftpd:21": {"template-id": "proftpd-server-detect", "host": "proftpd", "port": "21", "matched-at": "proftpd:21", "info": {"name": "ProFTPD Server Detect", "metadata": {"max-request": 1, "shodan-query": 'product:"ProFTPD"', "verified": True}}},
    "postfix:25": {"template-id": "smtp-detect", "host": "postfix", "port": "25", "matched-at": "postfix:25", "info": {"name": "SMTP Detection", "metadata": {"max-request": 1}}},
}


@pytest.fixture
def recog_dir(tmp_path):
    for name, content in (("ssh_banners", SSH_BANNERS), ("smtp_banners", SMTP_BANNERS), ("http_servers", HTTP_SERVERS)):
        (tmp_path / f"{name}.xml").write_text(content)
    return tmp_path


@pytest.fixture
def cascade(bbot_scanner, recog_dir, monkeypatch, tmp_path):
    module = service_fingerprint(bbot_scanner("127.0.0.1"))
    module.timeout_ms, module.workers, module.nuclei_timeout = 2000, 50, 5
    module.nuclei_fallback = True
    module.nuclei_templates_dir = tmp_path / "nuclei-templates"
    module.recog = Recog(recog_dir)
    module.thorough_timeout = 60
    module.thorough_slots = asyncio.Semaphore(50)
    module.nerva_inputs = []
    module.nuclei_inputs = []
    module.emitted = []

    async def fake_nerva(command, input, idle_timeout=None, **kwargs):
        # Like Nerva, all results come back at once when the run ends.
        depth = command[command.index("--scan-depth") + 1]
        module.nerva_inputs.append((depth, list(input), idle_timeout))
        if depth == "thorough" and SILENT in input:
            raise asyncio.TimeoutError
        found = [t for t in input if t in NERVA and (depth == "thorough" or t not in THOROUGH_ONLY)]
        return SimpleNamespace(stdout="\n".join(json.dumps(NERVA[t]) for t in found))

    async def fake_nuclei(command, input, **kwargs):
        module.nuclei_inputs.append(list(input))
        for target in input:
            if target in NUCLEI:
                yield json.dumps(NUCLEI[target])

    async def record_event(data, event_type, **kwargs):
        module.emitted.append((event_type, data, kwargs))

    monkeypatch.setattr(module, "run_process", fake_nerva)
    monkeypatch.setattr(module, "run_process_live", fake_nuclei)
    monkeypatch.setattr(module, "emit_event", record_event)
    return module


def parent(netloc):
    host, port = netloc.rsplit(":", 1)
    return SimpleNamespace(data=netloc, host=host, port=int(port))


def protocols(module):
    return {f"{d['host']}:{d['port']}": d for t, d, _ in module.emitted if t == "PROTOCOL"}


def test_recog_translates_ruby_regex_syntax():
    assert ruby_to_python_regex(r"^(?<name>\w+)\z") == r"^(?P<name>\w+)\Z"
    assert ruby_to_python_regex(r"(?<=a)(?<!b)\h\Z") == r"(?<=a)(?<!b)[0-9a-fA-F](?=\n?\Z)"


def test_recog_interpolates_and_trims_unknown_cpe_version(recog_dir):
    recog = Recog(recog_dir)
    assert recog.match("ssh_banners", "OpenSSH_9.7") == {
        "service.vendor": "OpenBSD",
        "service.product": "OpenSSH",
        "service.version": "9.7",
        "service.cpe23": "cpe:/a:openbsd:openssh:9.7",
    }
    # An optional group that did not match leaves the CPE at the product.
    assert recog.match("smtp_banners", "mail.bench.local ESMTP Postfix")["service.cpe23"] == "cpe:/a:postfix:postfix"
    # The first fingerprint that matches wins, as in Recog.
    assert recog.match("smtp_banners", "mail.bench.local ESMTP Postfix")["service.product"] == "Postfix"
    assert recog.match("smtp_banners", "mx ESMTP Exim 4.96")["service.product"] == "Generic SMTP"


@pytest.mark.asyncio
async def test_nerva_versioned_service_stops_the_cascade(cascade):
    await cascade.handle_batch(parent("redis:6379"))

    redis = protocols(cascade)["redis:6379"]
    assert (redis["product"], redis["version"], redis["details"]["fingerprint_source"]) == ("redis", "7.2.4", "nerva")
    assert redis["cpes"] == ["cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*"]
    assert cascade.nuclei_inputs == []
    assert cascade.nerva_inputs == [("fast", ["redis:6379"], None)]


@pytest.mark.asyncio
async def test_thorough_nerva_runs_each_port_fast_missed_on_its_own(cascade):
    await cascade.handle_batch(parent("redis:6379"), parent("squid:3128"), parent(SILENT))

    assert cascade.nerva_inputs == [
        ("fast", ["redis:6379", "squid:3128", SILENT], None),
        ("thorough", ["squid:3128"], 60),
        ("thorough", [SILENT], 60),
    ]
    found = protocols(cascade)
    # The silent port running out of time does not cost the port Nerva named.
    assert (found["squid:3128"]["product"], found["squid:3128"]["version"]) == ("Squid", "5.9")
    # The port it never named still gets the Nuclei pass.
    assert cascade.nuclei_inputs == [[SILENT]]


@pytest.mark.asyncio
async def test_thorough_nerva_pass_can_be_turned_off(cascade):
    cascade.thorough_timeout = 0
    await cascade.handle_batch(parent("redis:6379"), parent("squid:3128"))

    assert cascade.nerva_inputs == [("fast", ["redis:6379", "squid:3128"], None)]
    assert "squid:3128" not in protocols(cascade)


@pytest.mark.asyncio
async def test_recog_completes_a_bare_nerva_banner(cascade):
    await cascade.handle_batch(parent("ssh:22"))

    ssh = protocols(cascade)["ssh:22"]
    assert (ssh["protocol"], ssh["product"], ssh["version"]) == ("SSH", "OpenSSH", "9.7")
    assert ssh["details"] == {"fingerprint_source": "recog", "vendor": "OpenBSD"}
    assert "cpe:/a:openbsd:openssh:9.7" in ssh["cpes"]
    assert cascade.nuclei_inputs == []


@pytest.mark.asyncio
async def test_only_still_unknown_ports_reach_nuclei(cascade):
    await cascade.handle_batch(parent("redis:6379"), parent("ssh:22"), parent("postfix:25"), parent("proftpd:21"))

    assert cascade.nuclei_inputs == [["postfix:25", "proftpd:21"]]
    found = protocols(cascade)
    # Recog named Postfix; the generic SMTP template adds nothing and does not replace it.
    assert (found["postfix:25"]["product"], found["postfix:25"].get("version")) == ("Postfix", None)
    # Nerva did not answer for this port; Nuclei's detection template named it.
    assert (found["proftpd:21"]["protocol"], found["proftpd:21"]["product"]) == ("PROFTPD", "ProFTPD")
    assert found["proftpd:21"]["details"]["fingerprint_source"] == "nuclei"


@pytest.mark.asyncio
async def test_web_products_come_from_nerva_fingerprinters_or_the_server_header(cascade):
    await cascade.handle_batch(parent("grafana:3000"), parent("httpd:80"), parent("squid:3128"), parent("tomcat:8080"))

    found = protocols(cascade)
    assert (found["grafana:3000"]["product"], found["grafana:3000"]["version"]) == ("grafana", "10.2.3")
    assert (found["httpd:80"]["product"], found["httpd:80"]["version"]) == ("Apache HTTP Server", "2.4.58")
    assert (found["squid:3128"]["product"], found["squid:3128"]["version"]) == ("Squid", "5.9")
    assert "product" not in found["tomcat:8080"]
    # Web services are left to the URL-level modules rather than the network detection templates.
    assert cascade.nuclei_inputs == []
    urls = {d for t, d, _ in cascade.emitted if t == "URL_UNVERIFIED"}
    assert urls == {"http://grafana:3000", "http://httpd", "http://squid:3128", "http://tomcat:8080"}


@pytest.mark.asyncio
async def test_ipv6_web_url(cascade):
    NERVA["[2001:db8::1]:443"] = {"ip": "2001:db8::1", "host": "2001:db8::1", "port": 443, "protocol": "https", "metadata": {}}
    try:
        event = SimpleNamespace(data="[2001:db8::1]:443", host="2001:db8::1", port=443)
        await cascade.handle_batch(event)
    finally:
        del NERVA["[2001:db8::1]:443"]

    assert any(t == "PROTOCOL" and d["protocol"] == "HTTPS" for t, d, _ in cascade.emitted)
    assert any(
        t == "URL_UNVERIFIED" and d == "https://[2001:db8::1]" and kwargs["parent"] is event
        for t, d, kwargs in cascade.emitted
    )
