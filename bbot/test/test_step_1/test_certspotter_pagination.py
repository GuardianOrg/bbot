from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import quote, parse_qs, urlsplit

import httpx
import pytest

from bbot.modules.certspotter import certspotter


@pytest.mark.parametrize(
    "next_page, expected",
    [
        ([], set()),
        ([{"id": "first", "dns_names": ["api.dev.example.com"]}], {"api.dev.example.com"}),
        ([{"dns_names": ["api.dev.example.com"]}], {"api.dev.example.com"}),
        ({"code": "not_allowed_by_plan"}, set()),
        ("invalid json", set()),
        (None, set()),
        (httpx.Response(429, json={"code": "rate_limited"}), set()),
        (RuntimeError("request failed"), set()),
    ],
)
async def test_pagination_stops_and_preserves_previous_results(next_page, expected):
    module = object.__new__(certspotter)
    module.scan = SimpleNamespace(helpers=SimpleNamespace(quote=quote))
    module.warning = Mock()
    module.info = Mock()
    if next_page is not None and not isinstance(next_page, (httpx.Response, Exception)):
        if next_page == "invalid json":
            next_page = httpx.Response(200, text="invalid json")
        else:
            next_page = httpx.Response(200, json=next_page)
    module.api_request = AsyncMock(
        side_effect=[
            httpx.Response(200, json=[{"id": "first", "dns_names": ["www.example.com"]}]),
            next_page,
        ]
    )

    found = set()
    async for names in module.query_paginated("example.com"):
        found.update(names)

    assert found == {"www.example.com"} | expected
    assert module.api_request.await_count == 2
    params = parse_qs(urlsplit(module.api_request.await_args.args[0]).query)
    assert params == {
        "domain": ["example.com"],
        "include_subdomains": ["true"],
        "expand": ["dns_names"],
        "after": ["first"],
    }


async def test_pagination_advances_when_page_has_no_dns_names():
    module = object.__new__(certspotter)
    module.scan = SimpleNamespace(helpers=SimpleNamespace(quote=quote))
    module.api_request = AsyncMock(
        side_effect=[
            httpx.Response(200, json=[{"id": "1", "dns_names": []}]),
            httpx.Response(200, json=[{"id": "2", "dns_names": ["*.api.dev.example.com."]}]),
            httpx.Response(200, json=[]),
        ]
    )

    batches = [names async for names in module.query_paginated("example.com")]

    assert batches == [set(), {"api.dev.example.com"}]
    assert module.api_request.await_count == 3
