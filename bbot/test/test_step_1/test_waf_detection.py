import asyncio
from types import SimpleNamespace

import pytest

from bbot.modules.nuclei import nuclei
from bbot.modules.wafw00f import wafw00f


@pytest.mark.asyncio
async def test_wafw00f_requests_every_match_and_emits_each_vendor(monkeypatch):
    class StackedWafs:
        def __init__(self, url, followredirect=False):
            self.url = url

        def identwaf(self, findall=False):
            assert findall is True
            return ["Cloudfront (Amazon)", "Cloudflare (Cloudflare Inc.)"], self.url + "?probe=attack"

    monkeypatch.setattr("bbot.modules.wafw00f.wafw00f_main.WAFW00F", StackedWafs)
    emitted = []

    async def emit_event(data, event_type, **kwargs):
        emitted.append((event_type, data["waf"], data["url"]))

    async def run_in_executor(callable_, *args, **kwargs):
        return await asyncio.to_thread(callable_, *args, **kwargs)

    module = SimpleNamespace(
        helpers=SimpleNamespace(run_in_executor=run_in_executor),
        config={"find_all": True},
        emit_event=emit_event,
    )
    event = SimpleNamespace(
        parsed_url=SimpleNamespace(scheme="https", netloc="example.com"), host="example.com"
    )
    await wafw00f.handle_event(module, event)
    assert emitted == [
        ("WAF", "Cloudfront (Amazon)", "https://example.com/"),
        ("WAF", "Cloudflare (Cloudflare Inc.)", "https://example.com/"),
    ]


@pytest.mark.asyncio
async def test_nuclei_waf_matches_are_assets_not_findings():
    emitted = []
    url = "https://example.com/"
    class UrlEvent:
        type = "URL"
        data = url
        host = "example.com"

    event = UrlEvent()

    async def execute_nuclei(inputs, include_mobile_templates=False):
        assert inputs == [url]
        for name in ("cloudfront", "cloudflare"):
            yield {
                "severity": "INFO", "template": "waf-detect", "tags": ["waf", "tech"],
                "host": url, "url": url, "matched_at": url, "name": name,
            }

    async def emit_event(data, event_type, *args, **kwargs):
        emitted.append((event_type, data["waf"]))

    class Target:
        def add(self, key, value):
            pass

        def get(self, key):
            return key

    module = SimpleNamespace(
        _is_mobile_artifact=lambda _: False,
        helpers=SimpleNamespace(make_target=Target, is_url=lambda value: value.startswith("https://")),
        execute_nuclei=execute_nuclei,
        emit_event=emit_event,
        mobile_app_discovered=False,
    )
    await nuclei.handle_batch(module, event)
    assert emitted == [("WAF", "cloudfront"), ("WAF", "cloudflare")]
