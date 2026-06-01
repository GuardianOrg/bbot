from pathlib import Path
from subprocess import CalledProcessError

from bbot.modules.base import BaseModule
from bbot.modules.templates.code_repository_scope import code_repository_scope
from bbot.modules.templates.github_leak_formatter import github_leak_formatter


class code_secret_scanner(code_repository_scope, github_leak_formatter, BaseModule):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    deps_apt = ["git"]

    options = {
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }

    scope_distance_modifier = 2

    async def setup(self):
        self.setup_repository_scope()
        output_folder = self.config.get("output_folder", "")
        self.clone_repositories = bool(self.config.get("clone_repositories", True))
        if output_folder:
            self.output_dir = Path(output_folder) / "code_repos" / self.name
        else:
            self.output_dir = self.scan.temp_dir / "code_repos" / self.name
        self.helpers.mkdir(self.output_dir)
        return True

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if not self.is_code_repository_in_scope(event):
                return False, "CODE_REPOSITORY is outside configured repository owner/repo scope"
            if "git" not in event.tags:
                return False, "event is not a git repository"
            if not self.clone_repositories:
                return False, "clone_repositories is False"
            return True

        if event.type == "FILESYSTEM":
            if "unarchived-folder" in event.tags:
                return False, "not accepting unarchived-folder events"
            path = event.data.get("path", "") if isinstance(event.data, dict) else ""
            if not path:
                return False, "filesystem event path is empty"
            return True

        return False, "event type is not supported"

    async def handle_event(self, event):
        description = ""
        if isinstance(event.data, dict):
            description = event.data.get("description", "")

        host = event.host if event.type == "CODE_REPOSITORY" else str(getattr(event.parent, "host", "") or "")

        scan_path, cleanup = await self.prepare_scan_path(event)
        if scan_path is None:
            return

        try:
            async for finding in self.iter_findings(scan_path, event):
                normalized = self.normalize_finding(finding, scan_path, description, host)
                if not normalized:
                    continue

                verified = normalized.pop("verified", False)
                force_finding = normalized.pop("force_finding", False)
                dedupe_key = normalized.pop("dedupe_key", "")
                finding_type = "FINDING" if force_finding else ("VULNERABILITY" if verified else "FINDING")
                finding_event = self.make_event(
                    normalized,
                    finding_type,
                    event,
                    context=f"{{module}} scanned {{event.type}} for secrets and found {{event.type}}: {{event.data}}",
                )
                if finding_event is None:
                    continue
                if dedupe_key:
                    finding_event._dedupe_key = dedupe_key
                if isinstance(finding_event.data, dict) and "tool" in finding_event.data:
                    stripped_data = dict(finding_event.data)
                    stripped_data.pop("host", None)
                    if "url" in normalized:
                        stripped_data["url"] = normalized["url"]
                    finding_event.data = stripped_data
                await self.emit_event(finding_event)
        finally:
            if cleanup and scan_path.exists():
                self.helpers.rm_rf(scan_path, ignore_errors=True)

    async def prepare_scan_path(self, event):
        if event.type == "FILESYSTEM":
            scan_path = Path(event.data.get("path", ""))
            if not scan_path.exists():
                self.debug(f"Filesystem path does not exist: {scan_path}")
                return None, False
            return scan_path, False

        repository_url = event.data.get("url", "")
        if not repository_url:
            return None, False
        repo_path = await self.clone_git_repository(repository_url)
        if repo_path is None:
            return None, False
        return repo_path, True

    async def clone_git_repository(self, repository_url):
        repo_name = self.helpers.tagify(repository_url, maxlen=80)
        repo_path = self.output_dir / repo_name
        self.helpers.rm_rf(repo_path, ignore_errors=True)

        command = ["git", "clone", repository_url, str(repo_path)]
        try:
            output = await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, check=True)
            self.debug(f"Git clone output: {output.stdout}")
        except CalledProcessError as e:
            self.debug(f"Error cloning {repository_url}. STDERR: {repr(e.stderr)}")
            self.helpers.rm_rf(repo_path, ignore_errors=True)
            return None

        self.helpers.sanitize_git_repo(repo_path)
        return repo_path

    def normalize_finding(self, finding, scan_path, source_description, host):
        if not isinstance(finding, dict):
            return None

        data = {k: v for k, v in finding.items() if k not in {"verified", "severity"}}
        description = str(finding.get("description", "")).strip()
        if not description and "tool" not in data:
            return None

        if source_description:
            description = f"{description} Source description: [{source_description}]"

        if description:
            data["description"] = description
        if host:
            data["host"] = host

        severity = str(finding.get("severity", "")).strip()
        if severity:
            data["severity"] = severity
        elif finding.get("verified", False):
            data["severity"] = "High"

        data["verified"] = bool(finding.get("verified", False))
        return data

    async def iter_findings(self, scan_path, event):
        if False:
            yield {"description": ""}
