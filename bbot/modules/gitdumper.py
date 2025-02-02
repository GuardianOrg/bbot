import sys
import git_dumper
from pathlib import Path
from bbot.modules.base import BaseModule


class gitdumper(BaseModule):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow", "code-enum"]
    meta = {
        "description": "Download a leaked .git folder recursively or by fuzzing common names",
        "created_date": "",
        "author": "@domwhewell-sage",
    }
    options = {
        "output_folder": "",
        "jobs": 10,
        "retry": 3,
        "timeout": 3,
    }
    options_desc = {
        "output_folder": "Folder to download repositories to",
        "jobs": "Number of concurrent jobs to run",
        "retry": "Number of retries for each request",
        "timeout": "Request timeout",
    }

    deps_pip = ["git-dumper~=1.0.8"]
    deps_apt = ["git"]

    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "git_repos"
        else:
            self.output_dir = self.scan.home / "git_repos"
        self.helpers.mkdir(self.output_dir)
        self.jobs = self.config.get("jobs", 10)
        self.retry = self.config.get("retry", 3)
        self.timeout = self.config.get("timeout", 3)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "git-directory" not in event.tags:
                return False, "event is not a leaked .git directory"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        self.verbose(f"Processing leaked .git directory at {repo_url}")
        repo_folder = self.output_dir / self.helpers.tagify(repo_url)
        self.helpers.mkdir(repo_folder)
        error = await self.helpers.run_in_executor(self.process_repo, repo_url, repo_folder)
        if not error:
            codebase_event = self.make_event({"path": str(repo_folder)}, "FILESYSTEM", tags=["git"], parent=event)
            await self.emit_event(
                codebase_event,
                context=f"{{module}} cloned git repo at {repo_url} to {{event.type}}: {str(repo_folder)}",
            )
        else:
            self.helpers.rm_rf(repo_folder)

    def process_repo(self, repo_url, repo_folder):
        http_headers = {"User-Agent": self.scan.useragent}
        for hk, hv in self.scan.custom_http_headers.items():
            http_headers[hk] = hv
        result = git_dumper.fetch_git(repo_url, repo_folder, self.jobs, self.retry, self.timeout, http_headers)
        return result
