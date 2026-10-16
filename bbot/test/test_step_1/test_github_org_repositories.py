from types import SimpleNamespace

import pytest

from bbot.modules.github_org import github_org
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
                {"html_url": "https://github.com/company/first", "fork": False},
                {"html_url": "https://github.com/company/fork", "fork": True},
                {"html_url": "https://github.com/company/unknown"},
            ]
        )
        yield Response([{"html_url": "https://github.com/company/second", "fork": False}])

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
        "https://api.github.com/orgs/company/repos?per_page=100&page={page}",
        "https://api.github.com/users/employee/repos?per_page=100&page={page}",
    ]


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
