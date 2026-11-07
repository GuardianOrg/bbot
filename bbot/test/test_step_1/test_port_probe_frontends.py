"""Every module that probes an address directly leaves CDN, WAF, load balancer and shared platform addresses alone."""

from types import SimpleNamespace

import pytest

from bbot.core.helpers import shared_infra
from bbot.modules.naabu import naabu
from bbot.modules.tcp_connect_verify import tcp_connect_verify
from bbot.modules.udpx import udpx
from ..bbot_fixtures import *

PROBES = {"naabu": naabu, "tcp_connect_verify": tcp_connect_verify, "udpx": udpx}


def address(host, cname=(), tags=(), parent=None):
    name = parent or SimpleNamespace(type="DNS_NAME", dns_children={"CNAME": cname})
    return SimpleNamespace(host=host, tags=set(tags), get_parents=lambda include_self=False: [name])


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(PROBES))
async def test_direct_probes_skip_shared_frontends_but_probe_dedicated_addresses(bbot_scanner, name):
    scan = bbot_scanner("example.com", modules=[name], config={"modules": {name: {"skip_shared_frontends": True}}})
    module = PROBES[name](scan)
    module._name = name
    shared_infra.remember_frontend(scan, "104.16.1.1", "cdn", "cloudflare")

    for skipped in (
        address("1.2.3.4", cname=("app.cloudfront.net",)),
        address("1.2.3.4", cname=("app.eu-west-1.elb.amazonaws.com",)),
        address("1.2.3.4", tags={"cdn-cloudflare"}),
        address("1.2.3.4", tags={"shared-frontend"}),
        # Classified earlier in the scan, whichever module reported the address now.
        address("104.16.1.1"),
    ):
        assert (await module.filter_event(skipped))[0] is False

    assert await module.filter_event(address("1.2.3.4", cname=("app.example.com",), tags={"cloud-amazon"})) is True
    # The origin behind a frontend is the organisation's own server.
    origin = SimpleNamespace(type="WEB_ORIGIN")
    assert await module.filter_event(address("1.2.3.4", parent=origin)) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["tcp_connect_verify", "udpx"])
async def test_direct_probes_keep_probing_everything_when_the_gate_is_off(bbot_scanner, name):
    scan = bbot_scanner("example.com", modules=[name])
    module = PROBES[name](scan)
    module._name = name
    assert await module.filter_event(address("1.2.3.4", tags={"shared-frontend"})) is True
