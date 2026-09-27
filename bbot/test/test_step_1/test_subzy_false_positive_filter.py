from types import SimpleNamespace

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
