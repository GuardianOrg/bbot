from urllib.parse import urlparse


class code_repository_scope:
    CODE_REPOSITORY_PLATFORM_HOSTS = {
        "github.com": "github",
        "gitlab.com": "gitlab",
        "bitbucket.org": "bitbucket",
    }

    def setup_repository_scope(self):
        self.allowed_code_repositories = set()
        self.allowed_code_repository_owners = set()

        target = getattr(getattr(self, "scan", None), "target", None)
        seeds = getattr(getattr(target, "seeds", None), "event_seeds", []) or []
        for seed in seeds:
            seed_type = getattr(seed, "type", "")
            data = getattr(seed, "data", None)

            if seed_type == "CODE_REPOSITORY":
                repo = self.parse_code_repository_scope_url(data.get("url", "") if isinstance(data, dict) else "")
                if repo:
                    self.allowed_code_repositories.add(repo)
                continue

            if seed_type == "CODE_REPOSITORY_OWNER":
                owner = self.parse_code_repository_owner_scope_url(
                    data.get("url", "") if isinstance(data, dict) else ""
                )
                if owner:
                    self.allowed_code_repository_owners.add(owner)
                continue

            if seed_type == "ORG_STUB":
                owner = self.normalize_code_repository_owner(str(data or ""))
                if owner:
                    self.allowed_code_repository_owners.add(("*", owner))
                continue

            if seed_type == "URL":
                owner = self.parse_code_repository_owner_scope_url(str(data or ""))
                if owner:
                    self.allowed_code_repository_owners.add(owner)

    def has_code_repository_scope(self):
        return bool(self.allowed_code_repositories or self.allowed_code_repository_owners)

    def is_code_repository_in_scope(self, event_or_url):
        data = getattr(event_or_url, "data", event_or_url)
        url = data.get("url", "") if isinstance(data, dict) else str(data or "")
        repo = self.parse_code_repository_scope_url(url)
        if not repo:
            return False

        # github_org only marks repositories that it listed for a validated
        # organization or one of that organization's public members. Keep
        # unrelated GitHub links subject to the explicit seed scope below.
        if self.is_discovered_github_org_repository(event_or_url, repo):
            return True

        if not self.has_code_repository_scope():
            return "target" in getattr(event_or_url, "tags", [])

        platform, owner, repo_name = repo
        if (platform, owner, repo_name) in self.allowed_code_repositories:
            return True
        return (platform, owner) in self.allowed_code_repository_owners or (
            "*",
            owner,
        ) in self.allowed_code_repository_owners

    @staticmethod
    def is_discovered_github_org_repository(event, repo):
        if repo[0] != "github" or str(getattr(event, "module", "")) != "github_org":
            return False
        if "github-org-scope" not in getattr(event, "tags", ()):
            return False
        get_parent = getattr(event, "get_parent", None)
        parent = get_parent() if callable(get_parent) else getattr(event, "parent", None)
        if getattr(parent, "type", "") != "SOCIAL":
            return False
        profile = getattr(parent, "data", {})
        if not isinstance(profile, dict) or str(profile.get("profile_name", "")).lower() != repo[1]:
            return False
        if "github-org-member" in getattr(parent, "tags", ()):
            if str(getattr(parent, "module", "")) != "github_org":
                return False
            get_grandparent = getattr(parent, "get_parent", None)
            grandparent = get_grandparent() if callable(get_grandparent) else getattr(parent, "parent", None)
            return getattr(grandparent, "type", "") == "SOCIAL" and "github-org" in getattr(grandparent, "tags", ())
        return True

    def parse_code_repository_scope_url(self, url):
        try:
            parsed = urlparse(str(url).strip())
        except Exception:
            return None

        host = parsed.netloc.lower()
        path_parts = [part for part in parsed.path.split("/") if part]
        platform = self.CODE_REPOSITORY_PLATFORM_HOSTS.get(host)
        if platform and len(path_parts) >= 2:
            owner = self.normalize_code_repository_owner(path_parts[0])
            repo_name = path_parts[1].lower().removesuffix(".git")
            if owner and repo_name:
                return platform, owner, repo_name

        if host == "hub.docker.com" and len(path_parts) >= 3 and path_parts[0] == "r":
            owner = self.normalize_code_repository_owner(path_parts[1])
            repo_name = path_parts[2].lower()
            if owner and repo_name:
                return "docker", owner, repo_name

        if host == "www.postman.com" and len(path_parts) >= 2:
            owner = self.normalize_code_repository_owner(path_parts[0])
            repo_name = path_parts[1].lower()
            if owner and repo_name:
                return "postman", owner, repo_name

        return None

    def parse_code_repository_owner_scope_url(self, url):
        try:
            parsed = urlparse(str(url).strip())
        except Exception:
            return None

        host = parsed.netloc.lower()
        platform = self.CODE_REPOSITORY_PLATFORM_HOSTS.get(host)
        if not platform:
            return None
        path_parts = [part for part in parsed.path.split("/") if part]
        if len(path_parts) != 1:
            return None
        owner = self.normalize_code_repository_owner(path_parts[0])
        return (platform, owner) if owner else None

    def normalize_code_repository_owner(self, value):
        owner = str(value or "").strip().strip("@").lower()
        return owner or None
