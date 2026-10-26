from types import SimpleNamespace

import pytest

from bbot.modules.naabu import naabu
from ..bbot_fixtures import *


@pytest.mark.asyncio
async def test_naabu_skips_managed_frontend_ips_but_scans_dedicated_ips(bbot_scanner):
    scan = bbot_scanner("example.com", modules=["naabu"],
                        config={"modules": {"naabu": {"skip_shared_frontends": True}}})
    module = naabu(scan)
    module._name = "naabu"

    def ip_event(cname=(), tags=()):
        parent = SimpleNamespace(type="DNS_NAME", dns_children={"CNAME": cname})
        return SimpleNamespace(tags=tags, get_parents=lambda include_self=False: [parent])

    assert (await module.filter_event(ip_event(("app.cloudfront.net",))))[0] is False
    assert (await module.filter_event(ip_event(("app.eu-west-1.elb.amazonaws.com",))))[0] is False
    assert (await module.filter_event(ip_event(("tenant.vercel-dns.com",))))[0] is False
    assert (await module.filter_event(ip_event(tags={"cdn-cloudflare"})))[0] is False
    assert await module.filter_event(ip_event(("app.example.com",), {"cloud-amazon"})) is True
