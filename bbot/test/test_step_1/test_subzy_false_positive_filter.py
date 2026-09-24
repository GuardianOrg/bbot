from types import SimpleNamespace

from bbot.modules.subzy import subzy

VERCEL_DEPLOYMENT = {"Server": "Vercel", "X-Vercel-Id": "cdg1::abc"}


def response(status_code, headers):
    return SimpleNamespace(status_code=status_code, headers=headers)


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
