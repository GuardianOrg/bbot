from pathlib import Path
from subprocess import CalledProcessError
import os
from bbot.modules.templates.github import github


class git_clone(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow", "code-enum"]
    meta = {
        "description": "Clone or update github repositories safely without exposing tokens",
        "created_date": "2024-03-08",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": "", "output_folder": ""}
    options_desc = {
        "api_key": "Github token",
        "output_folder": (
            "Folder to clone repositories to. "
            "If not specified, cloned repositories will be deleted when the scan completes, to minimize disk usage."
        ),
    }

    deps_apt = ["git"]
    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder")
        self.output_dir = Path(output_folder) / "git_repos" if output_folder else self.scan.temp_dir / "git_repos"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY" and "git" not in event.tags:
            return False, "event is not a git repository"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        repo_path = await self.clone_git_repository(repo_url)
        if repo_path:
            self.verbose(f"Cloned/updated {repo_url} at {repo_path}")
            codebase_event = self.make_event({"path": str(repo_path)}, "FILESYSTEM", tags=["git"], parent=event)
            await self.emit_event(
                codebase_event,
                context=f"{{module}} cloned/updated git repo at {repo_url} to {{event.type}}: {repo_path}",
            )

    async def clone_git_repository(self, repository_url):
        # owner and repo name
        owner = repository_url.rstrip("/").split("/")[-2]
        folder = self.output_dir / owner
        self.helpers.mkdir(folder)

        repo_name = repository_url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        repo_path = folder / repo_name

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        if self.api_key:
            env["GIT_HELPER"] = (
                f'!f() {{ case "$1" in get) '
                f"echo username=x-access-token; "
                f"echo password={self.api_key};; "
                f'esac; }}; f "$@"'
            )
            base_command = [
                "git",
                "-c",
                "credential.helper=",
                "-c",
                "credential.useHttpPath=true",
                "--config-env=credential.helper=GIT_HELPER",
            ]
        else:
            base_command = []

        # Clone new repo or fetch if exists
        try:
            if repo_path.exists():
                # Update existing repo
                command = base_command + ["-C", str(repo_path), "fetch", "--all"]
            else:
                # Clone fresh
                command = base_command + ["-C", str(folder), "clone", repository_url]

            await self.run_process(command, env=env, check=True)

        except CalledProcessError as e:
            self.debug(f"Error cloning/updating {repository_url}. STDERR: {repr(e.stderr)}")
            return

        return repo_path
