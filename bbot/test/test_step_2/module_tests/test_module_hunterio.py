import re

from .base import ModuleTestBase


def hunter_email(address, **person):
    return {
        "value": address,
        "type": "personal" if person else "generic",
        "confidence": 77,
        **person,
        "sources": [
            {
                "domain": "blacklanternsecurity.com",
                "uri": "http://blacklanternsecurity.com",
                "extracted_on": "2021-06-09",
                "last_seen_on": "2023-03-21",
                "still_on_page": True,
            }
        ],
    }


def domain_search(emails, results, offset):
    return {
        "data": {"domain": "blacklanternsecurity.com", "emails": emails},
        "meta": {"results": results, "limit": 10, "offset": offset},
    }


def hunter_requests(module_test):
    return [
        request
        for request in module_test.httpx_mock.get_requests()
        if request.url.host == "api.hunter.io" and request.url.path == "/v2/domain-search"
    ]


def search_url(offset):
    return re.compile(
        rf"https://api\.hunter\.io/v2/domain-search\?domain=blacklanternsecurity\.com&api_key=\w+&limit=10&offset={offset}$"
    )


class TestHunterio(ModuleTestBase):
    module_name = "hunterio"
    config_overrides = {"modules": {"hunterio": {"api_key": ["asdf", "1234", "4321", "fdsa"]}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.hunter.io/v2/account?api_key=asdf",
            json={"data": {"plan_name": "Starter", "requests": {"searches": {"used": 998, "available": 1000}}}},
        )
        first_page = [hunter_email(f"user{i}@blacklanternsecurity.com") for i in range(9)]
        first_page.append(
            hunter_email(
                "jon@blacklanternsecurity.com",
                first_name="Jon",
                last_name="Snow",
                position="Lord Commander",
                department="management",
                linkedin="https://www.linkedin.com/in/jonsnow",
                phone_number="+1 555 0100",
                verification={"date": "2024-01-01", "status": "valid"},
            )
        )
        # The second page repeats an address; it must be emitted once
        second_page = [hunter_email("USER0@blacklanternsecurity.com"), hunter_email("last@blacklanternsecurity.com")]
        module_test.httpx_mock.add_response(url=search_url(0), json=domain_search(first_page, 12, 0))
        module_test.httpx_mock.add_response(url=search_url(10), json=domain_search(second_page, 12, 10))

    def check(self, module_test, events):
        emails = [e.data for e in events if e.type == "EMAIL_ADDRESS"]
        assert "jon@blacklanternsecurity.com" in emails
        assert "last@blacklanternsecurity.com" in emails
        assert len(emails) == 11
        profiles = [e for e in events if e.type == "EMAIL_PROFILE"]
        # Generic addresses carry no personal details and get no profile
        assert len(profiles) == 1
        assert profiles[0].parent.data == "jon@blacklanternsecurity.com"
        assert profiles[0].host == "blacklanternsecurity.com"
        assert profiles[0].data["first_name"] == "Jon"
        assert profiles[0].data["position"] == "Lord Commander"
        assert profiles[0].data["phone_number"] == "+1 555 0100"
        assert profiles[0].data["verification_status"] == "valid"
        assert profiles[0].data["provider"] == "hunterio"
        assert [request.url.params["offset"] for request in hunter_requests(module_test)] == ["0", "10"]


class TestHunterioMaxPages(TestHunterio):
    config_overrides = {"modules": {"hunterio": {"api_key": ["asdf", "1234", "4321", "fdsa"], "max_pages": 1}}}

    def check(self, module_test, events):
        emails = [e.data for e in events if e.type == "EMAIL_ADDRESS"]
        assert len(emails) == 10
        assert [request.url.params["offset"] for request in hunter_requests(module_test)] == ["0"]


class TestHunterioSkipsSubdomainTargets(TestHunterio):
    targets = ["api.blacklanternsecurity.com"]

    def check(self, module_test, events):
        assert not hunter_requests(module_test)
        assert not [e for e in events if e.type == "EMAIL_ADDRESS"]
