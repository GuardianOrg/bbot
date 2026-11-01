"""A bare CDN, WAF, load balancer, API gateway or SaaS address must never become a website (URL).

cloudcheck decides once per address; every later event on that address (Shodan ports, speculated URLs, httpx
answers) inherits the verdict, and httpx only visits DNS names behind such frontends, not the shared address.
"""

import pytest

from bbot.core.helpers import shared_infra
from bbot.modules.httpx import httpx
from bbot.modules.internal.cloudcheck import CloudCheck
from ..bbot_fixtures import *

CLOUDFLARE_IP = "104.16.1.1"


class Ingress:
    """Collects what an intercept module emits; a full scan would hand these to its ingress module."""

    def __init__(self):
        self.events = []

    async def queue_event(self, event, kwargs=None):
        self.events.append(event)


def make_cloudcheck(scan):
    scan.ingress_module = Ingress()
    module = CloudCheck(scan)
    module._name = "cloudcheck"
    module.scope_input_only = True
    module.probe_cloud_frontends = False
    module.probe_timeout = 1
    module.service_ranges = None
    module._probe_verdicts = {}
    module._probe_tasks = {}
    return module


def make_httpx(scan):
    module = httpx(scan)
    module._name = "httpx"
    return module


def emitted(module):
    events = []
    while module.outgoing_event_queue.qsize():
        events.append(module.outgoing_event_queue.get_nowait()[0])
    return events


def shared_scan(bbot_scanner, skip=True):
    return bbot_scanner("example.com", modules=["httpx"], config={"modules": {
        "httpx": {"skip_shared_frontends": skip, "probe_dns_names": True},
        "cloudcheck": {"scope_input_only": True}}})


async def classified_cloudflare_address(scan, cloudcheck):
    ip_event = scan.make_event(CLOUDFLARE_IP, "IP_ADDRESS", parent=scan.root_event)
    assert await cloudcheck.filter_event(ip_event) is True
    await cloudcheck.handle_event(ip_event)
    assert "shared-frontend" in ip_event.tags
    return ip_event


@pytest.mark.asyncio
async def test_ports_and_urls_on_a_classified_address_inherit_the_verdict_and_are_not_visited(bbot_scanner):
    scan = shared_scan(bbot_scanner)
    cloudcheck, web = make_cloudcheck(scan), make_httpx(scan)
    ip_event = await classified_cloudflare_address(scan, cloudcheck)

    # Shodan-style open port and the URL speculated from it: cloudcheck would otherwise skip them under
    # scope_input_only, so they used to reach httpx untagged and became http://<cloudflare-ip>:2095/ URLs.
    port = scan.make_event(f"{CLOUDFLARE_IP}:2095", "OPEN_TCP_PORT", parent=ip_event)
    port.scope_distance = 0
    assert await cloudcheck.filter_event(port) is True
    await cloudcheck.handle_event(port)
    assert "shared-frontend" in port.tags
    verdict = await web.filter_event(port)
    assert verdict[0] is False and "shared frontend" in verdict[1]

    url = scan.make_event(f"http://{CLOUDFLARE_IP}:2095/", "URL_UNVERIFIED", parent=port)
    url.scope_distance = 0
    await cloudcheck.handle_event(url)
    assert "shared-frontend" in url.tags
    assert (await web.filter_event(url))[0] is False

    # Even an event that never passed through cloudcheck is recognised from the scan-wide verdict.
    untagged = scan.make_event(f"https://{CLOUDFLARE_IP}:8443/", "URL_UNVERIFIED", parent=port)
    untagged.scope_distance = 0
    assert "shared-frontend" not in untagged.tags
    assert (await web.filter_event(untagged))[0] is False


@pytest.mark.asyncio
async def test_dns_names_behind_a_shared_frontend_remain_websites(bbot_scanner):
    scan = shared_scan(bbot_scanner)
    cloudcheck, web = make_cloudcheck(scan), make_httpx(scan)
    await classified_cloudflare_address(scan, cloudcheck)

    name = scan.make_event("app.example.com", "DNS_NAME", parent=scan.root_event)
    name.scope_distance = 0
    name._resolved_hosts = {CLOUDFLARE_IP}
    await cloudcheck.handle_event(name)
    assert "shared-frontend" in name.tags
    assert await web.filter_event(name) is True

    site = scan.make_event("https://app.example.com:8443/", "URL_UNVERIFIED", parent=name)
    site.scope_distance = 0
    assert await web.filter_event(site) is True


@pytest.mark.asyncio
async def test_explicit_targets_and_dedicated_addresses_are_still_visited(bbot_scanner):
    scan = shared_scan(bbot_scanner)
    cloudcheck, web = make_cloudcheck(scan), make_httpx(scan)
    ip_event = await classified_cloudflare_address(scan, cloudcheck)

    target = scan.make_event(f"https://{CLOUDFLARE_IP}/", "URL_UNVERIFIED", parent=ip_event, tags=["target"])
    target.scope_distance = 0
    assert await web.filter_event(target) is True

    dedicated = scan.make_event("93.184.215.14:443", "OPEN_TCP_PORT", parent=scan.root_event)
    dedicated.scope_distance = 0
    await cloudcheck.handle_event(dedicated)
    assert "shared-frontend" not in dedicated.tags
    assert await web.filter_event(dedicated) is True

    disabled = shared_scan(bbot_scanner, skip=False)
    shared_infra.remember_frontend(disabled, CLOUDFLARE_IP, "cdn", "cloudflare")
    port = disabled.make_event(f"{CLOUDFLARE_IP}:2095", "OPEN_TCP_PORT", parent=disabled.root_event)
    port.scope_distance = 0
    assert await make_httpx(disabled).filter_event(port) is True


@pytest.mark.asyncio
async def test_ipv6_frontend_addresses_match_in_any_spelling(bbot_scanner):
    scan = shared_scan(bbot_scanner)
    web = make_httpx(scan)
    shared_infra.remember_frontend(scan, "2606:4700:0020:0000:0000:0000:681a:0ade", "cdn", "cloudflare")
    assert shared_infra.known_frontend(scan, "[2606:4700:20::681a:ade]") == ("cdn", "cloudflare")
    url = scan.make_event("http://[2606:4700:20::681a:ade]:2052/", "URL_UNVERIFIED", parent=scan.root_event)
    url.scope_distance = 0
    assert (await web.filter_event(url))[0] is False


@pytest.mark.asyncio
async def test_an_answer_from_a_load_balancer_records_the_address_instead_of_a_website(bbot_scanner):
    scan = shared_scan(bbot_scanner)
    web = make_httpx(scan)
    port = scan.make_event("52.3.199.81:443", "OPEN_TCP_PORT", parent=scan.root_event)
    elb_answer = {"status_code": 503, "header": {"server": "awselb/2.0"}, "body": ""}

    assert await web.handle_shared_frontend_answer(port, "https://52.3.199.81/", elb_answer) is True
    assert shared_infra.known_frontend(scan, "52.3.199.81") == ("load_balancer", "aws")
    [geolocation] = emitted(web)
    assert geolocation.type == "GEOLOCATION"
    assert geolocation.data["ip"] == "52.3.199.81"
    assert geolocation.data["isLoadBalancer"] is True and geolocation.data["isFrontedProxy"] is True
    assert "shared-frontend" in geolocation.tags

    # The next port on the same address is not even visited.
    other = scan.make_event("52.3.199.81:8443", "OPEN_TCP_PORT", parent=scan.root_event)
    other.scope_distance = 0
    assert (await web.filter_event(other))[0] is False

    gateway = {"status_code": 403, "header": {"x_amzn_errortype": "ForbiddenException"}, "body": "{}"}
    assert await web.handle_shared_frontend_answer(port, "https://100.27.180.63/", gateway) is True
    assert shared_infra.known_frontend(scan, "100.27.180.63") == ("api_gateway", "aws")


@pytest.mark.asyncio
async def test_answers_that_stay_websites(bbot_scanner):
    scan = shared_scan(bbot_scanner)
    web = make_httpx(scan)
    port = scan.make_event("54.9.9.9:443", "OPEN_TCP_PORT", parent=scan.root_event)
    elb_answer = {"status_code": 503, "header": {"server": "awselb/2.0"}, "body": ""}

    # A dedicated server answering as itself.
    assert await web.handle_shared_frontend_answer(port, "https://54.9.9.9/", {"status_code": 200, "header": {
        "server": "nginx/1.25"}, "body": "<html>app</html>"}) is False
    assert shared_infra.known_frontend(scan, "54.9.9.9") is None
    # The same load balancer reached through the organisation's DNS name is its website.
    assert await web.handle_shared_frontend_answer(port, "https://app.example.com/", elb_answer) is False
    # An explicit target is always reported.
    target = scan.make_event("https://52.3.199.81/", "URL_UNVERIFIED", parent=scan.root_event, tags=["target"])
    assert await web.handle_shared_frontend_answer(target, "https://52.3.199.81/", elb_answer) is False
    assert emitted(web) == []

    disabled = shared_scan(bbot_scanner, skip=False)
    disabled_port = disabled.make_event("52.3.199.81:443", "OPEN_TCP_PORT", parent=disabled.root_event)
    assert await make_httpx(disabled).handle_shared_frontend_answer(
        disabled_port, "https://52.3.199.81/", elb_answer) is False
