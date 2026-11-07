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

    @staticmethod
    def fork_scan_range(event):
        """The commit after which a forked repository's changes are its owner's (github_org works it out).

        None means the repository is not a known fork and is scanned whole. An empty string means there is
        nothing of the owner's to scan: the fork has no commits of its own, or GitHub could not tell which they
        are. Scanning a fork whole would report the upstream project's history as the owner's secrets.
        """
        repository = code_repository_scope.cloned_repository(event)
        if repository is None or "fork" not in getattr(repository, "tags", ()):
            return None
        data = repository.data if isinstance(repository.data, dict) else {}
        return data.get("fork_since_commit") or ""

    @staticmethod
    def fork_branch(event):
        """The fork's default branch, the one its `fork_scan_range` applies to."""
        repository = code_repository_scope.cloned_repository(event)
        data = getattr(repository, "data", None)
        return data.get("fork_branch") if isinstance(data, dict) else None

    @staticmethod
    def cloned_repository(event):
        """The CODE_REPOSITORY a scanner input stands for: itself, or the repository git_clone cloned to a folder."""
        if getattr(event, "type", "") == "FILESYSTEM" and "git" in getattr(event, "tags", ()):
            get_parent = getattr(event, "get_parent", None)
            event = get_parent() if callable(get_parent) else None
        return event if getattr(event, "type", "") == "CODE_REPOSITORY" else None

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
        if not self.has_code_repository_scope():
            return "target" in getattr(event_or_url, "tags", [])

        platform, owner, repo_name = repo
        if (platform, owner, repo_name) in self.allowed_code_repositories:
            return True
        return (platform, owner) in self.allowed_code_repository_owners or (
            "*",
            owner,
        ) in self.allowed_code_repository_owners

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
