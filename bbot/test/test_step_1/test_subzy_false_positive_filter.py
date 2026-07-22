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
