import asyncio
import json
import os
import subprocess
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bbot.core.event.base import make_event
from bbot.modules.whatweb import access_challenge, favicon_fingerprint, icon_urls, normalized_technologies, whatweb
from bbot.modules.retirejs import retirejs


def test_positive_challenge_signals_and_negative_controls():
    assert access_challenge({"CF-Mitigated": ["challenge"]}, 403)["provider"] == "Cloudflare"
    assert access_challenge({"x-amzn-waf-action": ["challenge"]}, 202)["action"] == "challenge"
    assert access_challenge({"x-amzn-waf-action": ["captcha"]}, 405)["action"] == "captcha"
    for headers, status in [
        ({}, 403),
        ({"server": ["cloudflare"], "cf-ray": ["abc"]}, 403),
        ({"x-amzn-waf-action": ["challenge"]}, 200),
        ({"cf-mitigated": ["challenge", "none"]}, 403),
    ]:
        assert access_challenge(headers, status) is None


def test_normalized_technologies_preserve_distinct_versions_and_omit_page_metadata():
    result = normalized_technologies(
        ["WordPress:6.6.2", "wordpress", "jQuery:3.4.1"],
        {
            "WordPress": {"version": ["6.6.2"]},
            "jQuery": {"version": ["3.4.1", "3.7.1"]},
            "Title": {"string": ["Welcome"]},
            "IP": {"string": ["1.2.3.4"]},
        },
    )
    assert [(t["name"], t["version"]) for t in result] == [
        ("WordPress", "6.6.2"),
        ("jQuery", "3.4.1"),
        ("jQuery", "3.7.1"),
    ]
    assert "WhatWeb" in result[0]["evidence"] and "httpx" in result[0]["evidence"]


def test_icon_scope_base_url_and_html_negative_control():
    assert icon_urls(
        "https://example.com/blog/", '<base href="/assets/"><link rel="shortcut icon" href="icon.png">'
    ) == ["https://example.com/assets/icon.png", "https://example.com/favicon.ico"]
    assert icon_urls("https://example.com/", '<link rel="icon" href="https://third.party/icon.png">') == [
        "https://example.com/favicon.ico"
    ]
    assert favicon_fingerprint("https://example.com/favicon.ico", b"<html>Log in</html>") is None
    # Fixed known bytes: SHA-256 is over the icon, mmh3 over MIME base64 with line breaks (Shodan convention).
    result = favicon_fingerprint("https://example.com/icon.svg", b"<svg></svg>")
    assert result["sha256"] == "b12e0d83ce2357d80b89c57694814d0a3abdaf8c40724f2049af8b7f01b7812b"
    assert isinstance(result["mmh3"], int)


def test_existing_technology_schema_retains_normalized_fields():
    event = make_event(
        {
            "host": "example.com",
            "url": "https://example.com/",
            "technology": "WordPress",
            "version": "6.6.2",
            "evidence": "WhatWeb response signature",
        },
        "TECHNOLOGY",
        dummy=True,
    )
    assert event.data["version"] == "6.6.2"
    assert event.data["evidence"] == "WhatWeb response signature"


def make_module(cls, config=None):
    module = cls.__new__(cls)
    module._name = cls.__name__
    module.scan = SimpleNamespace(
        config={"modules": {cls.__name__: config or {}}},
        in_scope=lambda value: True,
        helpers=SimpleNamespace(tools_dir=Path("/tmp/tools")),
    )
    return module


@pytest.mark.asyncio
async def test_response_enrichment_reaches_the_original_event_and_keeps_identity():
    module = make_module(whatweb)
    module.pages, module.icons, module.max_pages = {}, {}, 3
    module.fingerprint = AsyncMock(return_value={"WordPress": {"version": ["6.6.2"]}})
    module.find_favicon = AsyncMock(
        return_value={"url": "https://example.com/favicon.ico", "sha256": "abc", "mmh3": -123}
    )
    module.emit_event = AsyncMock()
    event = make_event(
        {
            "url": "https://example.com/",
            "method": "GET",
            "status_code": 200,
            "raw_header": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
            "body": "<html></html>",
        },
        "HTTP_RESPONSE",
        dummy=True,
    )
    identifier = event.id
    assert await module.handle_event(event) is True
    assert event.data["technologies"][0]["name"] == "WordPress"
    assert event.data["favicon"]["mmh3"] == -123
    assert event.id == identifier
    module.emit_event.assert_awaited_once()
    await module.handle_event(event)
    module.find_favicon.assert_awaited_once()


@pytest.mark.asyncio
async def test_challenged_response_is_forwarded_without_fetching_icons():
    module = make_module(whatweb)
    module.pages, module.icons, module.max_pages = {}, {}, 3
    module.fingerprint, module.find_favicon, module.emit_event = AsyncMock(), AsyncMock(), AsyncMock()
    event = SimpleNamespace(
        host="example.com",
        data={
            "url": "https://example.com/",
            "status_code": 403,
            "header-dict": {"cf-mitigated": ["challenge"]},
            "contentType": "text/html",
            "body": "<html>Wait</html>",
        },
    )
    assert await module.handle_event(event) is True
    assert event.data["access_challenge"]["provider"] == "Cloudflare"
    module.fingerprint.assert_not_awaited()
    module.find_favicon.assert_not_awaited()


@pytest.mark.asyncio
async def test_retirejs_cves_are_structured_and_string_url_parent_is_supported():
    module = make_module(retirejs, {"severity": "low"})
    module.scan.helpers.request = AsyncMock(return_value=SimpleNamespace(status_code=200, text="jQuery v3.4.1"))
    module.scan.helpers.tempfile = lambda *args, **kwargs: "/tmp/library.js"
    module.execute_retirejs = AsyncMock(
        return_value=json.dumps(
            {
                "data": [
                    {
                        "results": [
                            {
                                "component": "jquery",
                                "version": "3.4.1",
                                "vulnerabilities": [
                                    {
                                        "severity": "low",
                                        "identifiers": {"CVE": ["CVE-2020-11022"]},
                                        "info": [
                                            "https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2"
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
    )
    module.emit_event = AsyncMock()
    parent = SimpleNamespace(type="URL", data="https://example.com/", parent=None)
    event = SimpleNamespace(data="https://example.com/jquery.js", parent=parent)
    await module.handle_event(event)
    finding = module.emit_event.call_args.args[0]
    assert finding["url"] == "https://example.com/"
    assert finding["javascript_url"] == event.data
    assert finding["version"] == "3.4.1" and finding["cves"] == ["CVE-2020-11022"]
    assert "has not been verified" in finding["description"]
    module.scan.helpers.request.assert_awaited_once_with(event.data, follow_redirects=False)


@pytest.mark.asyncio
async def test_real_whatweb_offline_packet(tmp_path):
    binary = os.getenv("BBOT_TEST_WHATWEB_BINARY")
    if not binary:
        pytest.skip("Set BBOT_TEST_WHATWEB_BINARY to exercise installed WhatWeb")
    module = make_module(whatweb)
    module.binary, module.timeout = binary, 30

    async def run(command, **kwargs):
        return await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True, timeout=30)

    module.run_process = run
    plugins = await module.fingerprint(
        {
            "status_code": 200,
            "raw_header": "HTTP/2 200 OK\r\nServer: nginx/1.24.0",
            "body": '<html><head><meta name="generator" content="WordPress 6.6.2" /></head><body></body></html>',
        }
    )
    assert plugins["WordPress"]["version"] == ["6.6.2"]
    assert plugins["nginx"]["version"] == ["1.24.0"]


@pytest.mark.asyncio
async def test_real_retirejs_advisory_matching(tmp_path):
    binary = os.getenv("BBOT_TEST_RETIRE_BINARY")
    repository = os.getenv("BBOT_TEST_RETIRE_REPOSITORY")
    if not binary or not repository:
        pytest.skip("Set BBOT_TEST_RETIRE_BINARY and BBOT_TEST_RETIRE_REPOSITORY to exercise installed RetireJS")
    from bbot.test.test_step_2.module_tests.test_module_retirejs import TestRetireJS

    tools = tmp_path / "tools"
    (tools / "node" / "bin").mkdir(parents=True)
    (tools / "node" / "bin" / "node").symlink_to(shutil.which("node"))
    (tools / "retirejs" / "node_modules" / ".bin").mkdir(parents=True)
    (tools / "retirejs" / "node_modules" / ".bin" / "retire").symlink_to(Path(binary).resolve())
    cache = tmp_path / "cache"
    (cache / "retire_cache").mkdir(parents=True)
    script = tmp_path / "jquery.js"
    script.write_text(TestRetireJS.jquery_content)
    module = make_module(retirejs)
    module.scan.helpers.tools_dir, module.scan.helpers.cache_dir = tools, cache
    module.scan.web_config = {}
    module.repofile = repository
    module.verbose = lambda *args: None

    async def run(command, **kwargs):
        result = await asyncio.to_thread(subprocess.run, command, capture_output=True, text=True, timeout=30)
        assert result.returncode in (0, 13), result.stderr
        return result

    module.run_process = run
    results = json.loads(await module.execute_retirejs(str(script)))
    components = [entry for file in results["data"] for entry in file["results"]]
    assert any(
        entry["component"] == "jquery"
        and entry["version"] == "3.4.1"
        and "CVE-2020-11022" in vuln.get("identifiers", {}).get("CVE", [])
        for entry in components
        for vuln in entry["vulnerabilities"]
    )
