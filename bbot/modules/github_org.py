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
        # html_url -> what fork_details found (None when GitHub could not tell)
        self._fork_info = {}
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
                data, fork_tags = self.fork_event_fields(repo_url)
                repo_event = self.make_event(
                    {"url": repo_url, "platform": "github", "owner": user, "repo_name": repo_name, **data},
                    "CODE_REPOSITORY",
                    tags=["git", "github"]
                    + fork_tags
                    + (["github-private-repo"] if repo_url in self._private_org_repo_urls else []),
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
                data, fork_tags = self.fork_event_fields(repo_url)
                repo_event = self.make_event(
                    {"url": repo_url, "platform": "github", "owner": user, "repo_name": repo_name, **data},
                    "CODE_REPOSITORY",
                    tags=["git", "github", "github-org-scope"]
                    + fork_tags
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
        """Works out which commits of a fork are its own (see fork_details). Without include_forks, a fork is
        kept only when it has some: an untouched copy is the upstream project's code, not the owner's."""
        if not self.include_forks:
            checked = getattr(self, "_fork_checks", 0)
            if checked >= self.max_fork_checks:
                return False
            self._fork_checks = checked + 1
        details = await self.fork_details(item)
        if isinstance(item.get("html_url"), str):
            self._fork_info[item["html_url"]] = details
        return self.include_forks or bool(details and details["ahead"])

    def fork_event_fields(self, repo_url):
        """CODE_REPOSITORY data and tags telling secret scanners which commits of a fork are the owner's."""
        if repo_url not in getattr(self, "_fork_info", {}):
            return {}, []
        details = self._fork_info[repo_url]
        if details and details["ahead"] and not details["since"]:
            # Its history shares nothing with the parent: all of it is the owner's.
            return {}, []
        if not details:
            return {}, ["fork"]
        if not details["ahead"]:
            return {"fork_branch": details["branch"]}, ["fork", "fork-unmodified"]
        return {"fork_branch": details["branch"], "fork_since_commit": details["since"]}, ["fork"]

    async def fork_details(self, item, max_pages=5):
        """The fork's default branch, its commit count ahead of its parent, and the commit it last synced
        with the parent ("since"): only changes after it are the owner's.

        Following the branch's first parents back from its head, the last sync is a merge that brought in a
        parent commit, or else the parent commit the branch was forked or fast-forwarded from. Commits the
        fork made before a sync are left out, so a sync that drags in a large upstream history cannot make
        its secrets look like the owner's. None when GitHub does not answer.
        """
        if not isinstance(item.get("full_name"), str) or "/" not in item["full_name"]:
            return None
        r = await self.api_request(f"{self.base_url}/repos/{item['full_name']}")
        try:
            repo = r.json() if getattr(r, "status_code", 0) == 200 else {}
        except Exception:
            return None
        parent = repo.get("parent") if isinstance(repo, dict) else None
        branch = repo.get("default_branch") if isinstance(repo, dict) else None
        if not isinstance(parent, dict) or not parent.get("full_name") or not parent.get("default_branch") or not branch:
            return None
        owner, name = item["full_name"].split("/", 1)
        compare_url = (
            f"{self.base_url}/repos/{parent['full_name']}/compare/"
            f"{self.helpers.quote(parent['default_branch'])}...{owner}:{name}:{self.helpers.quote(branch)}"
        )
        first = await self._compare_page(compare_url, 1)
        if first is None:
            return None
        ahead = first.get("ahead_by", 0)
        merge_base = (first.get("merge_base_commit") or {}).get("sha")
        if not isinstance(ahead, int) or not merge_base:
            return None
        if not ahead:
            return {"branch": branch, "ahead": 0, "since": merge_base}
        # Commits come oldest first; the newest pages hold the branch head and its latest sync.
        last_page = -(-ahead // 100)
        pages = {1: first}
        for page in range(last_page, max(1, last_page - max_pages + 1) - 1, -1):
            if page not in pages:
                pages[page] = await self._compare_page(compare_url, page)
                if pages[page] is None:
                    return None
        parents = {}
        for page in pages.values():
            for commit in page.get("commits") or []:
                if isinstance(commit, dict) and isinstance(commit.get("sha"), str):
                    parents[commit["sha"]] = [p.get("sha") for p in commit.get("parents") or [] if isinstance(p, dict)]
        head = str(first.get("permalink_url") or "").rsplit(":", 1)[-1]
        if head not in parents:
            return {"branch": branch, "ahead": ahead, "since": merge_base}
        complete = len(parents) >= ahead
        commit = head
        while True:
            commit_parents = parents.get(commit)
            if commit_parents is None or not commit_parents:
                # Unrelated history (a root commit of its own), or older commits than the pages fetched.
                return {"branch": branch, "ahead": ahead, "since": None if complete else merge_base}
            if any(p not in parents for p in commit_parents[1:]):
                synced = commit if complete else merge_base
                return {"branch": branch, "ahead": ahead, "since": synced}
            if commit_parents[0] not in parents:
                return {"branch": branch, "ahead": ahead, "since": commit_parents[0] if complete else merge_base}
            commit = commit_parents[0]

    async def _compare_page(self, compare_url, page):
        r = await self.api_request(f"{compare_url}?per_page=100&page={page}")
        try:
            return r.json() if getattr(r, "status_code", 0) == 200 else None
        except Exception:
            return None

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
        # Whole hostnames only: "seraph.com" or "seraph.company" does not name the target seraph.co.
        hosts = await self.helpers.re.findall(self.helpers.regexes.dns_name_extraction_regex, fields)
        return any(self.scan.whitelisted(host.rstrip(".")) for host in set(hosts))

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
