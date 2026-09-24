from types import SimpleNamespace

from bbot.modules.subzy import subzy


def test_subzy_recognizes_claimed_gitbook_site_response():
    response = SimpleNamespace(
        status_code=200,
        headers={
            "X-GitBook-Route-Site": "lab.example.com/",
            "X-GitBook-Target": "site",
        },
    )

    assert subzy.is_claimed_provider_response(response) is True


def test_subzy_does_not_suppress_unclaimed_or_unrecognized_pages():
    unclaimed = SimpleNamespace(status_code=404, headers={"X-GitBook-Target": "site"})
    unrelated = SimpleNamespace(status_code=200, headers={"Server": "nginx"})

    assert subzy.is_claimed_provider_response(unclaimed) is False
    assert subzy.is_claimed_provider_response(unrelated) is False

def test_subzy_recognizes_an_active_vercel_deployment():
    # demo.layerzero.network: a live Vercel site whose Next.js 404 text is also the Gemfury fingerprint.
    response = SimpleNamespace(status_code=200, headers={"Server": "Vercel", "X-Vercel-Id": "cdg1::abc"})

    assert subzy.is_claimed_provider_response(response) is True

def test_subzy_keeps_unclaimed_vercel_hosts():
    unclaimed = SimpleNamespace(
        status_code=404,
        headers={"Server": "Vercel", "X-Vercel-Id": "cdg1::abc", "X-Vercel-Error": "DEPLOYMENT_NOT_FOUND"},
    )
    errored = SimpleNamespace(status_code=200, headers={"X-Vercel-Id": "cdg1::abc", "X-Vercel-Error": "X"})

    assert subzy.is_claimed_provider_response(unclaimed) is False
    assert subzy.is_claimed_provider_response(errored) is False
