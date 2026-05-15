import re
from bbot.modules.base import BaseModule
from bbot.modules.templates.code_repository_scope import code_repository_scope
from urllib.parse import urlparse


class code_repository(code_repository_scope, BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["CODE_REPOSITORY"]
    meta = {
        "description": "Look for code repository links in webpages",
        "created_date": "2024-05-15",
        "author": "@domwhewell-sage",
    }
    flags = ["passive", "safe", "code-enum"]
    # platform name : (regex, case_sensitive)
    code_repositories = {
        "git": [
            (r"github.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
            (r"gitlab.(?:com|org)/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
        ],
        "docker": (r"hub.docker.com/r/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
        "postman": (r"www.postman.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+", False),
    }

    scope_distance_modifier = 1

    async def setup(self):
        self.setup_repository_scope()
        self.compiled_regexes = {}
        for k, v in self.code_repositories.items():
            if isinstance(v, list):
                self.compiled_regexes[k] = [(re.compile(pattern), c) for pattern, c in v]
            else:
                pattern, c = v
                self.compiled_regexes[k] = (re.compile(pattern), c)
        return True

    async def handle_event(self, event):
        for platform, regexes in self.compiled_regexes.items():
            if not isinstance(regexes, list):
                regexes = [regexes]
            for regex, case_sensitive in regexes:
                for match in regex.finditer(event.data):
                    url = match.group()
                    if not case_sensitive:
                        url = url.lower()
                    url = f"https://{url}"
                    if not self.is_code_repository_in_scope(url):
                        self.debug(f"Skipping out-of-repository-scope CODE_REPOSITORY: {url}")
                        continue
                    parsed = self.parse_repo_url(url, platform)
                    repo_event = self.make_event(
                        {"url": url, **parsed},
                        "CODE_REPOSITORY",
                        tags=platform,
                        parent=event,
                    )
                    await self.emit_event(
                        repo_event,
                        context=f"{{module}} detected {platform} {{event.type}} at {url}",
                    )

    def parse_repo_url(self, url, platform):
        parsed = urlparse(url)
        path_parts = [part for part in parsed.path.split("/") if part]
        owner = path_parts[0] if path_parts else parsed.netloc
        repo_name = path_parts[1] if len(path_parts) > 1 else owner
        return {"platform": platform, "owner": owner, "repo_name": repo_name}
