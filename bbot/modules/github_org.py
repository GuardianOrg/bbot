from bbot.modules.templates.github import github


class github_org(github):
    watched_events = ["ORG_STUB", "SOCIAL", "CODE_REPOSITORY_OWNER"]
    produced_events = ["CODE_REPOSITORY"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Query Github's API for organization and member repositories",
        "created_date": "2023-12-14",
        "author": "@domwhewell-sage",
    }
    options = {
        "api_key": "",
        "include_members": True,
        "include_member_repos": False,
        "include_forks": True,
        "include_private_org_repos": False,
        "max_org_repos": 100,
        "max_org_members": 20,
        "max_member_repos": 20,
        "max_fork_checks": 5,
    }
    options_desc = {
        "api_key": "Github token",
        "include_members": "Enumerate organization members",
        "include_member_repos": "Also enumerate organization members' repositories",
        "include_forks": "Include forked repositories when listing organization and member repositories",
        "include_private_org_repos": "Include private repositories of scoped organizations only when the scan supplies the signed-in user's token",
        "max_org_repos": "Maximum recent public repositories to list per organization (up to 100)",
        "max_org_members": "Maximum publicly listed members to enumerate per organization (up to 20)",
        "max_member_repos": "Maximum recent public repositories to list per member (up to 20)",
        "max_fork_checks": "Without include_forks, forks checked per scan for commits of their own (two API calls each)",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.include_members = self.config.get("include_members", True)
        self.include_member_repos = self.config.get("include_member_repos", False)
        self.include_forks = self.config.get("include_forks", True)
        self.include_private_org_repos = self.config.get("include_private_org_repos", False)
        self._private_org_repo_urls = set()
        self.max_org_repos = max(0, min(int(self.config.get("max_org_repos", 100)), 100))
        self.max_org_members = max(0, min(int(self.config.get("max_org_members", 20)), 20))
        self.max_member_repos = max(0, min(int(self.config.get("max_member_repos", 20)), 20))
        self.max_fork_checks = max(0, min(int(self.config.get("max_fork_checks", 5)), 50))
        self._fork_checks = 0
        # Only GitHub logins naming a seed domain (e.g. "acmesec" -> AcmeSecurity) cost a profile lookup.
        self._company_stubs = set()
        for seed in getattr(self.scan.target.seeds, "event_seeds", ()):
            if seed.type == "DNS_NAME":
                stub = str(getattr(self.helpers.tldextract(seed.data), "domain", "") or "").lower()
            elif seed.type == "ORG_STUB":
                stub = str(seed.data).lower()
            else:
                continue
            if len(stub) >= 4:
                self._company_stubs.add(stub)
        return await super().setup()

    def _api_response_is_success(self, r):
        # we allow 404s because they're normal
        return r.is_success or getattr(r, "status_code", 0) == 404

    async def filter_event(self, event):
        if event.type == "SOCIAL":
            if event.data.get("platform", "") != "github":
                return False, "event is not a github profile"
            # reject org members if the setting isn't enabled
            # this prevents gathering of org member repos
            if (not self.include_member_repos) and ("github-org-member" in event.tags):
                return False, "include_member_repos is False"
        return True

    async def handle_event(self, event):
        # handle explicit GitHub repository owner scope
        if event.type == "CODE_REPOSITORY_OWNER":
            if "github" not in event.tags:
                return
            user = event.data.get("url", "").rstrip("/").split("/")[-1]
            if not user:
                return
            self.verbose(f"Searching for repos belonging to explicit GitHub owner {user}")
            for repo_url in await self.query_owner_repos(user):
                repo_name = repo_url.rstrip("/").split("/")[-1]
                repo_event = self.make_event(
                    {"url": repo_url, "platform": "github", "owner": user, "repo_name": repo_name},
                    "CODE_REPOSITORY",
                    tags=["git", "github"] + (["github-private-repo"] if repo_url in self._private_org_repo_urls else []),
                    parent=event,
                )
                if not repo_event:
                    continue
                await self.emit_event(
                    repo_event,
                    context=f"{{module}} listed repos for explicit GitHub owner and discovered {{event.type}}: {repo_url}",
                )

        # handle github profile
        elif event.type == "SOCIAL":
            user = event.data.get("profile_name", "")
            in_scope = False
            if "github-org-member" in event.tags:
                is_org = False
            elif "github-org" in event.tags:
                is_org = True
                in_scope = True
            else:
                is_org, in_scope = await self.validate_org(user)
            # A company can publish its code from a GitHub User account (its profile names the company's domain).
            company_user = not is_org and "github-org-member" not in event.tags and await self.validate_company_user(user)

            # find repos from user/org (SOCIAL --> CODE_REPOSITORY)
            repos = []
            if is_org:
                if in_scope:
                    self.verbose(f"Searching for repos belonging to organization {user}")
                    repos = await self.query_org_repos(user)
                else:
                    self.verbose(f"Organization {user} does not appear to be in-scope")
            elif company_user:
                self.verbose(f"Searching for repos belonging to in-scope company account {user}")
                repos = await self.query_user_repos(user, limit=getattr(self, "max_org_repos", 100))
            elif "github-org-member" in event.tags:
                self.verbose(f"Searching for repos belonging to user {user}")
                repos = await self.query_user_repos(user)
            for repo_url in repos:
                repo_name = repo_url.rstrip("/").split("/")[-1]
                repo_event = self.make_event(
                    {"url": repo_url, "platform": "github", "owner": user, "repo_name": repo_name},
                    "CODE_REPOSITORY",
                    tags=["git", "github", "github-org-scope"]
                    + (["github-private-repo"] if repo_url in self._private_org_repo_urls else []),
                    parent=event,
                )
                if not repo_event:
                    continue
                await self.emit_event(
                    repo_event,
                    context=f"{{module}} listed repos for GitHub profile and discovered {{event.type}}: {repo_url}",
                )

            # find members from org (SOCIAL --> SOCIAL)
            if is_org and in_scope and self.include_members:
                self.verbose(f"Searching for any members belonging to {user}")
                org_members = await self.query_org_members(user)
                for member in org_members:
                    member_url = f"https://github.com/{member}"
                    event_data = {"platform": "github", "profile_name": member, "url": member_url}
                    member_event = self.make_event(event_data, "SOCIAL", tags="github-org-member", parent=event)
                    if member_event:
                        await self.emit_event(
                            member_event,
                            context=f"{{module}} listed members of GitHub organization and discovered {{event.type}}: {member_url}",
                        )

        # find valid orgs from stub (ORG_STUB --> SOCIAL)
        elif event.type == "ORG_STUB":
            user = event.data
            self.verbose(f"Validating whether the organization {user} is within our scope...")
            is_org, in_scope = await self.validate_org(user)
            if "target" in event.tags:
                in_scope = True
            if not is_org or not in_scope:
                self.verbose(f"Unable to validate that {user} is in-scope, skipping...")
                return

            user_url = f"https://github.com/{user}"
            event_data = {"platform": "github", "profile_name": user, "url": user_url}
            github_org_event = self.make_event(event_data, "SOCIAL", tags="github-org", parent=event)
            if github_org_event:
                await self.emit_event(
                    github_org_event,
                    context=f'{{module}} tried "{user}" as GitHub profile and discovered {{event.type}}: {user_url}',
                )

    async def query_org_repos(self, query):
        repos = []
        limit = getattr(self, "max_org_repos", 100)
        if not limit:
            return repos
        include_private = bool(getattr(self, "include_private_org_repos", False) and getattr(self, "api_key", ""))
        repo_type = "all" if include_private else "public"
        url = (
            f"{self.base_url}/orgs/{self.helpers.quote(query)}/repos?type={repo_type}&sort=pushed&direction=desc&per_page=100&page="
            + "{page}"
        )
        agen = self.api_page_iter(url, _json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 403:
                    self.warning("Github is rate-limiting us (HTTP status: 403)")
                    break
                if status_code != 200:
                    break
                try:
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j:
                    if not isinstance(item, dict) or item.get("private") not in ({False, True} if include_private else {False}):
                        continue
                    if item.get("fork") is not False and not await self.keep_fork(item):
                        continue
                    html_url = item.get("html_url", "")
                    if html_url:
                        repos.append(html_url)
                        if item["private"] and hasattr(self, "_private_org_repo_urls"):
                            self._private_org_repo_urls.add(html_url)
                    if len(repos) >= limit:
                        break
                if len(repos) >= limit:
                    break
        finally:
            await agen.aclose()
        return repos

    async def query_org_members(self, query):
        members = []
        limit = getattr(self, "max_org_members", 20)
        if not limit:
            return members
        url = f"{self.base_url}/orgs/{self.helpers.quote(query)}/public_members?per_page=100&page=" + "{page}"
        agen = self.api_page_iter(url, _json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 403:
                    self.warning("Github is rate-limiting us (HTTP status: 403)")
                    break
                if status_code != 200:
                    break
                try:
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j:
                    login = item.get("login", "") if isinstance(item, dict) else ""
                    if login:
                        members.append(login)
                    if len(members) >= limit:
                        break
                if len(members) >= limit:
                    break
        finally:
            await agen.aclose()
        return members

    async def query_user_repos(self, query, limit=None):
        repos = []
        # Public employees use the smaller member cap. An explicitly scoped
        # company account can be a GitHub User rather than an Organization;
        # give that owner the organization-sized cap instead.
        limit = getattr(self, "max_member_repos", 20) if limit is None else limit
        if not limit:
            return repos
        url = (
            f"{self.base_url}/users/{self.helpers.quote(query)}/repos?type=owner&sort=pushed&direction=desc&per_page=100&page="
            + "{page}"
        )
        agen = self.api_page_iter(url, _json=False)
        try:
            async for r in agen:
                if r is None:
                    break
                status_code = getattr(r, "status_code", 0)
                if status_code == 403:
                    self.warning("Github is rate-limiting us (HTTP status: 403)")
                    break
                if status_code != 200:
                    break
                try:
                    j = r.json()
                except Exception as e:
                    self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
                    break
                if not j:
                    break
                for item in j:
                    if not isinstance(item, dict) or item.get("private") is not False:
                        continue
                    if item.get("fork") is not False and not await self.keep_fork(item):
                        continue
                    html_url = item.get("html_url", "")
                    if html_url:
                        repos.append(html_url)
                    if len(repos) >= limit:
                        break
                if len(repos) >= limit:
                    break
        finally:
            await agen.aclose()
        return repos

    async def keep_fork(self, item):
        """Without include_forks, a fork is kept only when it carries commits of its own: an untouched copy
        is the upstream project's code, not the owner's."""
        if self.include_forks:
            return True
        checked = getattr(self, "_fork_checks", 0)
        if checked >= self.max_fork_checks or not isinstance(item.get("full_name"), str):
            return False
        self._fork_checks = checked + 1
        r = await self.api_request(f"{self.base_url}/repos/{item['full_name']}")
        try:
            repo = r.json() if getattr(r, "status_code", 0) == 200 else {}
        except Exception:
            return False
        parent = repo.get("parent") if isinstance(repo, dict) else None
        branch = repo.get("default_branch") if isinstance(repo, dict) else None
        if not isinstance(parent, dict) or not parent.get("full_name") or not parent.get("default_branch") or not branch:
            return False
        owner, name = item["full_name"].split("/", 1)
        r = await self.api_request(
            f"{self.base_url}/repos/{parent['full_name']}/compare/"
            f"{self.helpers.quote(parent['default_branch'])}...{owner}:{name}:{self.helpers.quote(branch)}"
        )
        try:
            ahead = r.json().get("ahead_by", 0) if getattr(r, "status_code", 0) == 200 else 0
        except Exception:
            return False
        return isinstance(ahead, int) and ahead > 0

    async def validate_company_user(self, user):
        """A GitHub User (not an Organization) whose own profile names an in-scope hostname."""
        if not any(stub in user.lower() for stub in getattr(self, "_company_stubs", ())):
            return False
        r = await self.api_request(f"{self.base_url}/users/{self.helpers.quote(user)}")
        if getattr(r, "status_code", 0) != 200:
            return False
        try:
            profile = r.json()
        except Exception:
            return False
        if not isinstance(profile, dict) or profile.get("type") != "User":
            return False
        fields = " ".join(str(profile.get(key) or "") for key in ("blog", "email", "bio", "company"))
        return bool(await self.scan.extract_in_scope_hostnames(fields))

    async def validate_org(self, org):
        is_org = False
        in_scope = False
        url = f"{self.base_url}/orgs/{org}"
        r = await self.api_request(url)
        if r is None:
            return is_org, in_scope
        status_code = getattr(r, "status_code", 0)
        if status_code == 403:
            self.warning("Github is rate-limiting us (HTTP status: 403)")
            return is_org, in_scope
        if status_code == 200:
            is_org = True
        in_scope_hosts = await self.scan.extract_in_scope_hostnames(getattr(r, "text", ""))
        if in_scope_hosts:
            self.verbose(
                f'Found in-scope hostname(s): "{in_scope_hosts}" for github org: {org}, it appears to be in-scope'
            )
            in_scope = True
        return is_org, in_scope

    async def query_owner_repos(self, query):
        repos = []
        seen = set()
        for repo_url in [*await self.query_org_repos(query),
                         *await self.query_user_repos(query, limit=getattr(self, "max_org_repos", 100))]:
            normalized = repo_url.rstrip("/")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            repos.append(repo_url)
        return repos
