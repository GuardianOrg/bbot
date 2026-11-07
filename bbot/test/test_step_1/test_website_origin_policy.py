"""A website-only scan reaches exactly the origins it was given: no other host, scheme or port, and no DNS, address
or port discovery around them."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from bbot.modules.retirejs import RETIREJS_REPOSITORY_URL
from bbot.modules.website_origin_policy import website_origin_policy

ORIGINS = ["https://example.com", "http://www.example.com:8080"]


def make_policy(origins=ORIGINS, headers=None, request=None, download=None):
    web = SimpleNamespace(request=request or AsyncMock(return_value="response"), download=download or AsyncMock())
    scan = SimpleNamespace(
        config={"modules": {"website_origin_policy": {"website_origins": list(origins)}}, "web": {}},
        web_config={},
        helpers=SimpleNamespace(web=web),
        custom_http_headers=dict(headers or {}),
    )
    policy = website_origin_policy(scan)
    policy._name = "website_origin_policy"
    assert asyncio.run(policy.setup()) is True
    return policy


def check(policy, kind, data, parent=None, module=None):
    return asyncio.run(policy.handle_event(SimpleNamespace(type=kind, data=data, parent=parent, module=module)))


def test_only_the_supplied_origins_pass():
    policy = make_policy()
    assert check(policy, "URL", "https://example.com/blog") is True
    assert check(policy, "HTTP_RESPONSE", {"url": "http://www.example.com:8080/api"}) is True
    for url in (
        "https://child.example.com/",
        "http://example.com/",
        "https://example.com:8443/",
        "https://elsewhere.example/",
        "https://user:pw@example.com/",
    ):
        assert check(policy, "URL", url)[0] is False, url


def test_discovery_around_the_origins_is_refused():
    policy = make_policy()
    for kind in ("DNS_NAME", "IP_ADDRESS", "OPEN_TCP_PORT", "TLS_CERTIFICATE", "EMAIL_ADDRESS", "CODE_REPOSITORY"):
        assert check(policy, kind, "example.com")[0] is False, kind


def test_an_event_without_a_url_takes_the_origin_of_its_nearest_url_ancestor():
    policy = make_policy()
    root = SimpleNamespace(type="SCAN", data={"id": "scan"}, parent=None)
    page = SimpleNamespace(data="https://example.com/", parent=root)
    assert check(policy, "FINDING", {"description": "website observation"}, page) is True
    other = SimpleNamespace(data="https://child.example.com/", parent=root)
    assert check(policy, "FINDING", {"description": "website observation"}, other)[0] is False
    assert check(policy, "FINDING", {"description": "no website"}, root)[0] is False


def test_grouped_summary_passes_only_when_every_endpoint_is_a_supplied_origin():
    policy = make_policy()
    root = SimpleNamespace(type="SCAN", data={"id": "scan"}, parent=None)

    def grouped(endpoints, module="hardening_aggregate"):
        data = {
            "category": "grouped-hardening",
            "title": "Missing HTTP security headers",
            "affected_endpoints": endpoints,
        }
        return check(policy, "VULNERABILITY", data, root, module)

    assert grouped(["https://example.com", "http://www.example.com:8080"]) is True
    assert grouped(["https://example.com", "https://child.example.com"])[0] is False
    assert grouped([])[0] is False
    # Another module cannot borrow the grouped category to cross the boundary.
    assert grouped(["https://example.com"], module="nuclei")[0] is False


def test_organisation_scans_are_untouched():
    policy = make_policy(origins=[])
    assert check(policy, "DNS_NAME", "child.example.com") is True
    assert check(policy, "URL", "https://elsewhere.example/") is True


def test_engine_requests_stay_on_the_origins_carry_the_headers_and_never_redirect():
    request = AsyncMock(return_value="response")
    policy = make_policy(headers={"X-Assessment": "assess42"}, request=request)
    web = policy.helpers.web

    assert asyncio.run(
        web.request("https://example.com/a", headers={"Accept": "text/html"}, allow_redirects=True)
    ) == ("response")
    assert request.call_args.kwargs == {
        "headers": {"Accept": "text/html", "X-Assessment": "assess42"},
        "follow_redirects": False,
    }
    assert asyncio.run(web.request("https://child.example.com/a")) is None
    assert request.call_count == 1


def test_advisory_data_is_fetched_without_the_scan_headers():
    download = AsyncMock()
    policy = make_policy(headers={"X-Assessment": "assess42"}, download=download)
    asyncio.run(policy.helpers.web.download(RETIREJS_REPOSITORY_URL, cache_hrs=24))
    assert download.call_args.kwargs["headers"] == {}


def test_website_only_preset_runs_the_policy_first_and_no_discovery_module():
    from pathlib import Path

    from bbot.scanner import Preset

    path = Path(__file__).parents[3] / "my_bbot" / "website-only.yml"
    preset = Preset("https://example.com/login")
    preset.merge(Preset.from_yaml_file(path))
    baked = preset.bake()
    assert {"website_origin_policy", "offchain_scope_filter", "httpx", "wafw00f"} <= set(baked.scan_modules)
    assert not {"naabu", "dnsbrute", "subfinder", "nuclei", "service_fingerprint"} & set(baked.scan_modules)
    assert baked.config.speculate is False and baked.config.cloudcheck is False
    assert baked.config.scope.strict is True
    assert "DNS_NAME" in baked.config.omit_event_types
