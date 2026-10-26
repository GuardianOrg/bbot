import pytest

from bbot.modules.httpx import httpx
from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_httpx_probes_public_dns_names_only_when_enabled(bbot_scanner):
    scan = bbot_scanner(
        "example.com", modules=["httpx"], config={"modules": {"httpx": {"probe_dns_names": True}}}
    )
    module = httpx(scan)
    module._name = "httpx"

    event = scan.make_event("app.example.com", "DNS_NAME", parent=scan.root_event)
    event.scope_distance = 0
    event._resolved_hosts = {"93.184.215.14"}
    assert await module.filter_event(event) is True
    assert module.make_url_metadata(event)[0] == "app.example.com"

    event._resolved_hosts = {"10.0.0.1", "100.64.0.1"}
    assert (await module.filter_event(event))[0] is False

    event._resolved_hosts = set()
    assert (await module.filter_event(event))[0] is False

    disabled_scan = bbot_scanner("example.com", modules=["httpx"])
    disabled_module = httpx(disabled_scan)
    disabled_module._name = "httpx"
    public_event = disabled_scan.make_event("app.example.com", "DNS_NAME", parent=disabled_scan.root_event)
    public_event.scope_distance = 0
    public_event._resolved_hosts = {"93.184.215.14"}
    assert (await disabled_module.filter_event(public_event))[0] is False
