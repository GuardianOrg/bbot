from types import SimpleNamespace

import pytest

from bbot.modules.github_org import github_org


@pytest.mark.asyncio
async def test_out_of_scope_github_org_does_not_enumerate_its_members():
    calls = []

    async def validate_org(name):
        assert name == "sherlock-audit"
        return True, False

    async def query_org_members(name):
        calls.append(name)
        return ["utkutugrul"]

    module = SimpleNamespace(
        include_members=True,
        validate_org=validate_org,
        query_org_members=query_org_members,
        verbose=lambda *_: None,
        make_event=lambda *_, **__: None,
    )
    event = SimpleNamespace(
        type="SOCIAL",
        data={"platform": "github", "profile_name": "sherlock-audit"},
        tags=set(),
    )

    await github_org.handle_event(module, event)
    assert calls == []
