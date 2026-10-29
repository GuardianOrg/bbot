from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from bbot.modules.nuclei import nuclei


def test_vendor_waf_fingerprint_is_metadata():
    result = {
        "severity": "INFO",
        "template": "cloudflare",
        "tags": ["waf", "fuzz", "fuzzing", "vuln"],
        "description": "A web application firewall was detected.",
        "name": "cloudflare",
    }

    assert nuclei.is_waf_detection_result(result)
    assert nuclei.is_waf_detection_result({**result, "tags": "waf,fuzz,fuzzing,vuln"})
    assert nuclei.is_waf_detection_result({**result, "template": "waf-detect"})
    assert not nuclei.is_waf_detection_result({**result, "severity": "HIGH"})
    assert not nuclei.is_waf_detection_result({**result, "description": "A WAF bypass was confirmed."})
    assert not nuclei.is_waf_detection_result({**result, "tags": ["fuzz", "vuln"]})


@pytest.mark.asyncio
async def test_nuclei_emits_waf_metadata_and_preserves_bypass_vulnerability():
    url = "https://app.example.com/"
    parent_event = Mock(type="URL", data=url, host="app.example.com", resolved_hosts=set())
    emitted = []

    async def execute_nuclei(inputs, **_kwargs):
        assert inputs == [url]
        for result in (
            {"severity": "INFO", "template": "cloudflare", "tags": ["waf", "fuzz", "vuln"],
             "description": "A web application firewall was detected.", "name": "cloudflare"},
            {"severity": "HIGH", "template": "cloudflare-waf-bypass", "tags": ["waf", "fuzz", "vuln"],
             "description": "A WAF bypass was confirmed.", "name": "Cloudflare WAF bypass"},
        ):
            yield {**result, "host": url, "url": url, "matched_at": url}

    async def emit_event(data, event_type, _parent, **_kwargs):
        emitted.append((event_type, data))

    target = SimpleNamespace(add=lambda *_args: None, get=lambda *_args: None)
    subject = SimpleNamespace(
        _is_mobile_artifact=lambda _event: False,
        mobile_app_discovered=False,
        helpers=SimpleNamespace(make_target=lambda: target, is_ip=lambda _host: False, is_url=lambda _url: True),
        execute_nuclei=execute_nuclei,
        is_waf_detection_result=nuclei.is_waf_detection_result,
        is_takeover_result=lambda _result: False,
        emit_event=emit_event,
    )

    await nuclei.handle_batch(subject, parent_event)

    assert [(event_type, data.get("waf") or data.get("title")) for event_type, data in emitted] == [
        ("WAF", "cloudflare"), ("VULNERABILITY", "Cloudflare WAF bypass"),
    ]
    assert emitted[0][1]["url"] == url
    assert emitted[0][1]["info"] == "Nuclei cloudflare template"
