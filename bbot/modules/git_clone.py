from pathlib import Path
from subprocess import CalledProcessError
import os
import tempfile
from bbot.modules.templates.github import github


class git_clone(github):
    watched_events = ["CODE_REPOSITORY"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive", "safe", "slow", "code-enum"]
    meta = {
        "description": "Clone code github repositories safely without exposing tokens",
        "created_date": "2024-03-08",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": "", "output_folder": ""}
    options_desc = {
        "api_key": "Github token",
        "output_folder": "Folder to clone repositories to. If not specified, cloned repositories will be deleted when the scan completes, to minimize disk usage.",
    }

    deps_apt = ["git"]

    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "git_repos"
        else:
            self.output_dir = self.scan.temp_dir / "git_repos"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if "git" not in event.tags:
                return False, "event is not a git repository"
        return True

    async def handle_event(self, event):
        repo_url = event.data.get("url")
        repo_path = await self.clone_git_repository(repo_url)
        if repo_path:
            self.verbose(f"Cloned {repo_url} to {repo_path}")
            codebase_event = self.make_event(
                {"path": str(repo_path)}, "FILESYSTEM", tags=["git"], parent=event
            )
            await self.emit_event(
                codebase_event,
                context=f"{{module}} downloaded git repo at {repo_url} to {{event.type}}: {repo_path}",
            )

    async def clone_git_repository(self, repository_url):
        owner = repository_url.split("/")[-2]
        folder = self.output_dir / owner
        self.helpers.mkdir(folder)

        #  env
        clone_env = os.environ.copy()
        clone_env["GIT_TERMINAL_PROMPT"] = "0"  # disable interactive prompts

        askpass_script_path = None
        if self.api_key:
            # Create temp GIT_ASKPASS script to supply token safely
            askpass_script = tempfile.NamedTemporaryFile(delete=False, mode="w")
            askpass_script.write(f'#!/bin/sh\necho "{self.api_key}"\n')
            askpass_script.close()
            os.chmod(askpass_script.name, 0o700)
            clone_env["GIT_ASKPASS"] = askpass_script.name
            askpass_script_path = askpass_script.name

        # Clone repository without embedding token in URL
        command = ["git", "-C", str(folder), "clone", repository_url]
        try:
            await self.run_process(command, env=clone_env, check=True)
        except CalledProcessError as e:
            self.debug(f"Error cloning {repository_url}. STDERR: {repr(e.stderr)}")
            if askpass_script_path:
                os.unlink(askpass_script_path)
            return

        # Clean .git/config to remove any accidental token
        repo_name = repository_url.rstrip("/").split("/")[-1].replace(".git", "")
        git_config = folder / repo_name / ".git" / "config"
        if git_config.exists() and self.api_key:
            text = git_config.read_text()
            text = text.replace(self.api_key, "")
            git_config.write_text(text)

        # Remove temp GIT_ASKPASS script
        if askpass_script_path:
            os.unlink(askpass_script_path)

        return folder / repo_name
