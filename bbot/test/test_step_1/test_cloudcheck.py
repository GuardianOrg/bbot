from types import SimpleNamespace

import pytest

from bbot.modules.internal.cloudcheck import CloudCheck


def make_event(host, event_type="DNS_NAME", tags=None):
    return SimpleNamespace(host=host, type=event_type, tags=tags or [])


@pytest.mark.asyncio
async def test_cloudcheck_scope_input_only_filter():
    module = CloudCheck.__new__(CloudCheck)
    module.scope_input_only = True

    assert await module.filter_event(make_event("example.com", tags=["target"])) is True
    assert await module.filter_event(make_event("api.example.com")) == (
        False,
        "cloudcheck is limited to explicit scan input events",
    )


@pytest.mark.asyncio
async def test_cloudcheck_default_filter_keeps_discovered_hosts():
    module = CloudCheck.__new__(CloudCheck)
    module.scope_input_only = False

    assert await module.filter_event(make_event("api.example.com")) is True

