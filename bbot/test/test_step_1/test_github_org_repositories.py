from types import SimpleNamespace

import pytest

from bbot.modules.github_org import github_org
from bbot.modules.git_clone import git_clone
from bbot.modules.templates.code_repository_scope import code_repository_scope


class Event(SimpleNamespace):
    def get_parent(self):
        return getattr(self, "parent", None)


class Response:
    status_code = 200

    def __init__(self, records):
        self.records = records

    def json(self):
        return self.records


@pytest.mark.asyncio
async def test_github_org_repository_listing_excludes_forks_on_every_page():
    requested = []

    async def pages(url, _json=False):
        requested.append(url)
        yield Response(
            [
                {"html_url": "https://github.com/company/first", "fork": False, "private": False},
                {"html_url": "https://github.com/company/fork", "fork": True, "private": False},
                {"html_url": "https://github.com/company/private", "fork": False, "private": True},
                {"html_url": "https://github.com/company/unknown", "private": False},
            ]
        )
        yield Response([{"html_url": "https://github.com/company/second", "fork": False, "private": False}])

    module = SimpleNamespace(
        base_url="https://api.github.com",
        helpers=SimpleNamespace(quote=lambda value: value),
        api_page_iter=pages,
        include_forks=False,
        warning=lambda *_: None,
    )
    expected = ["https://github.com/company/first", "https://github.com/company/second"]
    assert await github_org.query_org_repos(module, "company") == expected
    assert await github_org.query_user_repos(module, "employee") == expected
    assert requested == [
        "https://api.github.com/orgs/company/repos?type=public&sort=pushed&direction=desc&per_page=100&page={page}",
        "https://api.github.com/users/employee/repos?type=owner&sort=pushed&direction=desc&per_page=100&page={page}",
    ]


@pytest.mark.asyncio
async def test_repository_and_public_member_limits_stop_pagination():
    requested = []

    async def pages(url, _json=False):
        requested.append(url)
        if "/public_members?" in url:
            yield Response([{"login": f"member-{number}"} for number in range(100)])
        else:
            yield Response(
                [
                    {"html_url": f"https://github.com/company/repo-{number}", "fork": False, "private": False}
                    for number in range(100)
                ]
            )
        yield Response(
            [{"html_url": "https://github.com/company/should-not-be-fetched", "fork": False, "private": False}]
        )

    module = SimpleNamespace(
        base_url="https://api.github.com",
        helpers=SimpleNamespace(quote=lambda value: value),
        api_page_iter=pages,
        include_forks=False,
        max_org_repos=100,
        max_org_members=20,
        max_member_repos=20,
        warning=lambda *_: None,
    )
    assert len(await github_org.query_org_repos(module, "company")) == 100
    assert await github_org.query_org_members(module, "company") == [f"member-{number}" for number in range(20)]
    assert len(await github_org.query_user_repos(module, "employee")) == 20
    assert len(requested) == 3
    assert "/public_members?" in requested[1]


@pytest.mark.asyncio
async def test_private_org_repos_require_explicit_opt_in_and_user_token():
    requested = []

    async def pages(url, _json=False):
        requested.append(url)
        yield Response(
            [
                {"html_url": "https://github.com/company/private", "fork": False, "private": True},
                {"html_url": "https://github.com/company/public", "fork": False, "private": False},
            ]
        )

    module = SimpleNamespace(
        base_url="https://api.github.com",
        helpers=SimpleNamespace(quote=lambda value: value),
        api_page_iter=pages,
        include_forks=False,
        include_private_org_repos=True,
        api_key="user-token",
        _private_org_repo_urls=set(),
        warning=lambda *_: None,
    )
    assert await github_org.query_org_repos(module, "company") == [
        "https://github.com/company/private",
        "https://github.com/company/public",
    ]
    assert module._private_org_repo_urls == {"https://github.com/company/private"}
    assert "type=all" in requested[0]

    module.api_key = ""
    module._private_org_repo_urls.clear()
    assert await github_org.query_org_repos(module, "company") == ["https://github.com/company/public"]
    assert not module._private_org_repo_urls
    assert "type=public" in requested[1]


@pytest.mark.asyncio
async def test_private_clone_accepts_only_verified_org_repository_events():
    module = SimpleNamespace(config={"private_only": True})
    event = Event(type="CODE_REPOSITORY", tags={"git", "github-private-repo", "github-org-scope"}, module="github_org")
    assert await git_clone.filter_event(module, event) is True
    event.module = "other_module"
    assert (await git_clone.filter_event(module, event))[0] is False


def test_only_verified_org_and_member_repositories_enter_secret_scanner_scope():
    scope = code_repository_scope()
    scope.allowed_code_repositories = set()
    scope.allowed_code_repository_owners = set()

    org = Event(type="SOCIAL", data={"profile_name": "company"}, tags={"github-org"})
    member = Event(
        type="SOCIAL", data={"profile_name": "employee"}, tags={"github-org-member"}, module="github_org", parent=org
    )
    repo = Event(
        type="CODE_REPOSITORY",
        data={"url": "https://github.com/employee/project"},
        tags={"git", "github", "github-org-scope"},
        module="github_org",
        parent=member,
    )
    assert scope.is_code_repository_in_scope(repo)
    company_repo = Event(
        type="CODE_REPOSITORY",
        data={"url": "https://github.com/company/project"},
        tags={"git", "github", "github-org-scope"},
        module="github_org",
        parent=org,
    )
    assert scope.is_code_repository_in_scope(company_repo)
    repo.parent = Event(
        type="SOCIAL", data={"profile_name": "stranger"}, tags={"github-org-member"}, module="github_org", parent=org
    )
    assert not scope.is_code_repository_in_scope(repo)
    repo.parent = member
    repo.module = "other_module"
    assert not scope.is_code_repository_in_scope(repo)
    repo.module = "github_org"
    repo.tags = {"git", "github"}
    assert not scope.is_code_repository_in_scope(repo)
