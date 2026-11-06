import asyncio
import json
from types import SimpleNamespace

import dns.rdata
import pytest

from bbot.modules.subzy import subzy

VERCEL_DEPLOYMENT = {"Server": "Vercel", "X-Vercel-Id": "cdg1::abc"}


def response(status_code, headers, text=""):
    return SimpleNamespace(status_code=status_code, headers=headers, text=text)


def test_subzy_recognizes_claimed_gitbook_site_response():
    claimed = response(200, {"X-GitBook-Route-Site": "lab.example.com/", "X-GitBook-Target": "site"})

    assert subzy.is_claimed_provider_response(claimed, "Readme.io") is True


def test_subzy_does_not_suppress_unclaimed_or_unrecognized_pages():
    assert subzy.is_claimed_provider_response(response(404, {"X-GitBook-Target": "site"}), "GitBook") is False
    assert subzy.is_claimed_provider_response(response(200, {"Server": "nginx"}), "Gemfury") is False
    assert subzy.is_claimed_provider_response(None, "Gemfury") is False


def test_subzy_ignores_gemfury_fingerprint_embedded_in_active_non_vercel_site():
    # developers.fomopay.com serves its own Next.js documentation with this
    # generic text in the HTML, even though the page itself returns HTTP 200.
    live_site = response(200, {"Server": "fomogroup", "Via": "1.1 google"}, "404: This page could not be found.")
    unclaimed = response(404, {"Server": "Gemfury"}, "404: This page could not be found.")
    redirect_to_error = response(302, {"Location": "https://gemfury.com/404"})

    assert subzy.is_claimed_provider_response(live_site, "Gemfury") is True
    assert subzy.is_claimed_provider_response(unclaimed, "Gemfury") is False
    assert subzy.is_claimed_provider_response(redirect_to_error, "Gemfury") is False
    assert subzy.is_claimed_provider_response(live_site, "Vercel") is False


def test_subzy_drops_generic_matches_on_an_active_vercel_deployment():
    # demo.layerzero.network: a live Next.js site on Vercel whose pages embed the Gemfury fingerprint text.
    assert subzy.is_claimed_provider_response(response(200, VERCEL_DEPLOYMENT), "Gemfury") is True
    assert subzy.is_claimed_provider_response(response(200, VERCEL_DEPLOYMENT), "Vercel") is True


def test_subzy_keeps_upstream_providers_behind_a_vercel_rewrite():
    # A Vercel rewrite proxies the upstream's body and status: an unclaimed upstream stays a takeover.
    for engine in ("Readme.io", "Help Scout", "Ghost", "subzy"):
        assert subzy.is_claimed_provider_response(response(200, VERCEL_DEPLOYMENT), engine) is False


def test_subzy_keeps_unclaimed_vercel_hosts():
    unclaimed = response(404, {**VERCEL_DEPLOYMENT, "X-Vercel-Error": "DEPLOYMENT_NOT_FOUND"})
    errored = response(200, {**VERCEL_DEPLOYMENT, "X-Vercel-Error": "X"})

    assert subzy.is_claimed_provider_response(unclaimed, "Vercel") is False
    assert subzy.is_claimed_provider_response(errored, "Vercel") is False


def test_subzy_ignores_cargo_match_on_unrelated_nginx_ingress():
    # A generic nginx 404 matched Subzy's Cargo Collective fingerprint on 17
    # Cumberland hosts, although these hosts resolve directly to an ingress IP.
    nginx_404 = response(
        404,
        {"Server": "nginx"},
        "<html><head><title>404 Not Found</title></head>"
        "<body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>",
    )
    assert subzy.is_claimed_provider_response(nginx_404, "Cargo Collective", {"A": {"3.23.242.41"}}) is True
    assert subzy.is_claimed_provider_response(nginx_404, "Cargo Collective", {"CNAME": {"site.cargo.site"}}) is False
    assert subzy.is_claimed_provider_response(nginx_404, "Cargo Collective", {}) is False


def test_subzy_ignores_cargo_match_on_other_provider_or_generic_openresty():
    nginx_404 = response(404, {}, "<title>404 Not Found</title><center>nginx</center>")
    openresty_404 = response(404, {}, "<title>404 Not Found</title><center>openresty</center>")
    readme_site = response(302, {"Location": "/reference"})

    assert subzy.is_claimed_provider_response(nginx_404, "Cargo Collective", {"CNAME": {"sendgrid.net."}}) is True
    assert subzy.is_claimed_provider_response(readme_site, "Cargo Collective", {"CNAME": {"site.readmessl.com."}}) is True
    assert subzy.is_claimed_provider_response(openresty_404, "Cargo Collective", {"A": {"104.18.79.118"}}) is True
    assert subzy.is_claimed_provider_response(openresty_404, "Cargo Collective", {"CNAME": {"site.cargo.site."}}) is False


def test_subzy_ignores_predict_provider_mismatches_without_hiding_provider_matches():
    # The Predict hosts resolve to AWS ELB and Ghost, not Cargo Collective or Intercom.
    # Keep a genuine provider CNAME eligible for the same detector.
    generic_404 = response(404, {"Server": "nginx"}, "404 Not Found")
    alb = "ae546f541b7b945d9abba99dfcfce8b3-381839622.ap-northeast-1.elb.amazonaws.com."
    assert subzy.is_claimed_provider_response(
        generic_404, "Cargo Collective", {"CNAME": {alb}}, host="graphql.apne1.predict.fun"
    ) is True
    assert subzy.is_claimed_provider_response(
        generic_404, "Intercom", {"CNAME": {"predict-fun.ghost.io."}}, host="news.predict.fun"
    ) is True
    assert subzy.is_claimed_provider_response(
        generic_404, "Cargo Collective", {"CNAME": {"site.cargo.site."}}, host="site.example.com"
    ) is False
    assert subzy.is_claimed_provider_response(
        generic_404, "Intercom", {"CNAME": {"custom.intercom.help."}}, host="help.example.com"
    ) is False


def test_subzy_rejects_ghost_intercom_mismatch_even_when_http_is_unavailable():
    mod = object.__new__(subzy)
    requests = []

    async def request(url):
        requests.append(url)
        return None

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(request=request))

    assert asyncio.run(mod.is_claimed_provider_host(
        "news.predict.fun", "Intercom", {"CNAME": {"predict-fun.ghost.io."}}
    )) is True
    assert requests == []


def test_subzy_recovers_missing_cname_metadata_before_intercom_alert():
    mod = object.__new__(subzy)
    requests = []

    async def resolve_raw(host, type):
        assert (host, type) == ("news.predict.fun", "CNAME")
        return [("CNAME", "predict-fun.ghost.io.")], []

    async def request(url):
        requests.append(url)
        return None

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(resolve_raw=resolve_raw, request=request))

    assert asyncio.run(mod.is_claimed_provider_host("news.predict.fun", "Intercom")) is True
    assert requests == []


def test_subzy_keeps_intercom_cname_and_unknown_dns_results_eligible():
    mod = object.__new__(subzy)
    requests = []

    async def resolve_raw(_host, type):
        assert type == "CNAME"
        return [], [("CNAME", "timeout")]

    async def request(url):
        requests.append(url)
        return None

    mod.scan = SimpleNamespace(helpers=SimpleNamespace(resolve_raw=resolve_raw, request=request))

    assert asyncio.run(mod.is_claimed_provider_host(
        "help.example.com", "Intercom", {"CNAME": {"custom.intercom.help."}}
    )) is False
    assert asyncio.run(mod.is_claimed_provider_host("unknown.example.com", "Intercom")) is False
    assert requests == [
        "https://help.example.com", "http://help.example.com",
        "https://unknown.example.com", "http://unknown.example.com",
    ]


def test_subzy_ignores_uptimerobot_match_on_cloudflare_default_404():
    # Fifteen Coinbase hosts with direct Cloudflare A records served the same
    # generic 404, which contains Subzy's broad "page not found" fingerprint.
    cloudflare_404 = response(404, {"Server": "cloudflare"}, "404 page not found\n")

    assert subzy.is_claimed_provider_response(
        cloudflare_404, "Uptimerobot", {"A": {"104.18.35.15", "172.64.152.241"}}
    ) is True
    assert subzy.is_claimed_provider_response(
        cloudflare_404, "Uptimerobot", {"CNAME": {"stats.uptimerobot.com"}}
    ) is False
    assert subzy.is_claimed_provider_response(cloudflare_404, "Uptimerobot", {}) is False
    assert subzy.is_claimed_provider_response(
        response(404, {"Server": "cloudflare"}, "page not found"),
        "Uptimerobot",
        {"A": {"104.18.35.15"}},
    ) is False


def test_subzy_ignores_cargo_match_on_own_apex_varnish_404():
    # direct.panteracapital.com CNAMEs to panteracapital.com. Its generic
    # Varnish 404 is not a dangling Cargo site.
    varnish_404 = response(404, {"Server": "Varnish"}, "404 Not Found")

    assert subzy.is_claimed_provider_response(
        varnish_404,
        "Cargo Collective",
        {"CNAME": {"panteracapital.com."}, "A": {"23.185.0.2"}},
        host="direct.panteracapital.com",
    ) is True
    assert subzy.is_claimed_provider_response(
        varnish_404,
        "Cargo Collective",
        {"CNAME": {"site.cargo.site."}},
        host="direct.panteracapital.com",
    ) is False


# Entries as published in can-i-take-over-xyz's fingerprints.json, which subzy matches against.
FINGERPRINTS = [
    {"service": "Ghost", "status": "Vulnerable", "cname": ["ghost.io"]},
    {"service": "AWS/S3", "status": "Vulnerable", "cname": ["s3.amazonaws.com"]},
    {"service": "SmartJobBoard", "status": "Vulnerable", "cname": ["52.16.160.97"]},
    {"service": "Pantheon", "status": "Vulnerable", "cname": []},
    {"service": "Getresponse", "status": "Vulnerable", "cname": []},
    {"service": "Unbounce", "status": "Not vulnerable", "cname": []},
    {"service": "Netlify", "status": "Edge case", "cname": []},
]


def rdata(rdtype, value):
    return dns.rdata.from_text("IN", rdtype, value)


def run_subzy(tmp_path, findings, dns_answers=None, fingerprints=FINGERPRINTS):
    """Run handle_batch on subzy's JSON output. findings: (host, engine, raw_dns_records)."""
    fingerprints_file = tmp_path / "fingerprints.json"
    if fingerprints is not None:
        fingerprints_file.write_text(json.dumps(fingerprints))
    files = iter((tmp_path / "targets.txt", tmp_path / "subzy.json"))
    dns_answers = dns_answers or {}
    emitted = []

    async def resolve_raw(name, type):
        answer = dns_answers.get((name, type), [])
        if answer is None:
            return [], [("timeout", type)]
        return [rdata(type, value) for value in answer], []

    class TestSubzy(subzy):
        @property
        def helpers(self):
            return SimpleNamespace(tempfile=lambda *args, **kwargs: next(files), resolve_raw=resolve_raw)

        async def is_claimed_provider_host(self, *args, **kwargs):
            return False

    module = object.__new__(TestSubzy)
    module.binary = "subzy"
    module.concurrency = 1
    module.timeout = 5
    module.https = False
    module.verify_ssl = False
    module.fingerprints_path = fingerprints_file
    module.debug = lambda *args, **kwargs: None

    async def run_process(*args, **kwargs):
        results = [{"status": "vulnerable", "subdomain": host, "engine": engine} for host, engine, _ in findings]
        (tmp_path / "subzy.json").write_text(json.dumps(results))

    async def emit_event(data, *args, **kwargs):
        emitted.append(data["host"])

    module.run_process = run_process
    module.emit_event = emit_event
    events = [SimpleNamespace(host=host, raw_dns_records=records) for host, _, records in findings]
    asyncio.run(module.handle_batch(*events))
    return emitted


def test_subzy_drops_engines_that_its_fingerprints_do_not_rate_vulnerable(tmp_path):
    emitted = run_subzy(
        tmp_path,
        [
            ("lp.example.com", "Unbounce", {}),
            ("www.example.com", "Netlify", {"CNAME": {"example.netlify.app."}}),
            ("blog.example.com", "Ghost", {"CNAME": {"example.ghost.io."}}),
        ],
    )

    assert emitted == ["blog.example.com"]


def test_subzy_requires_the_host_to_point_to_the_engine_provider(tmp_path):
    emitted = run_subzy(
        tmp_path,
        [
            # A docs page quoting Ghost's error text, served from the company's own CDN.
            ("docs.example.com", "Ghost", {"CNAME": {"docs.example-cdn.net."}}),
            # Its own servers, no CNAME at all.
            ("api.example.com", "Pantheon", {"A": {"203.0.113.10"}}),
            ("jobs.example.com", "SmartJobBoard", {"A": {"203.0.113.11"}}),
            # Reached through an intermediate CNAME.
            ("news.example.com", "Ghost", {"CNAME": {"news.edge.example.net."}}),
            ("assets.example.com", "AWS/S3", {"CNAME": {"assets.example.com.s3-website-us-east-1.amazonaws.com."}}),
            ("careers.example.com", "SmartJobBoard", {"A": {"52.16.160.97"}}),
            ("live.example.com", "Pantheon", {"CNAME": {"live-example.pantheonsite.io."}}),
            # The CNAME lookup failed, or the engine names no provider domain: nothing disproves the match.
            ("unknown.example.com", "Ghost", {}),
            ("mail.example.com", "Getresponse", {"A": {"203.0.113.12"}}),
        ],
        dns_answers={
            ("news.edge.example.net", "CNAME"): ["example.ghost.io."],
            ("api.example.com", "CNAME"): [],
            ("unknown.example.com", "CNAME"): None,
        },
    )

    assert emitted == [
        "news.example.com",
        "assets.example.com",
        "careers.example.com",
        "live.example.com",
        "unknown.example.com",
        "mail.example.com",
    ]


def test_subzy_fails_when_its_fingerprints_cannot_be_checked(tmp_path):
    with pytest.raises(RuntimeError, match="fingerprints"):
        run_subzy(tmp_path, [("blog.example.com", "Ghost", {})], fingerprints=None)
    with pytest.raises(RuntimeError, match="Brand New Host"):
        run_subzy(tmp_path, [("blog.example.com", "Brand New Host", {})])
