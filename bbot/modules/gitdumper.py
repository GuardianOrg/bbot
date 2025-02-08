from pathlib import Path
from subprocess import CalledProcessError
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
    }
    options_desc = {
        "output_folder": "Folder to download repositories to",
    }

    deps_apt = ["git"]

    scope_distance_modifier = 2

    async def setup(self):
        output_folder = self.config.get("output_folder")
        if output_folder:
            self.output_dir = Path(output_folder) / "git_repos"
        else:
            self.output_dir = self.scan.home / "git_repos"
        self.helpers.mkdir(self.output_dir)
        self.git_files = [
            ".git/",
            "config",
            "hooks/",
            "hooks/applypatch-msg",
            "hooks/commit-msg",
            "hooks/fsmonitor-watchman",
            "hooks/post-update",
            "hooks/pre-applypatch",
            "hooks/pre-commit",
            "hooks/pre-merge-commit",
            "hooks/pre-push",
            "hooks/pre-rebase",
            "hooks/pre-receive",
            "hooks/prepare-commit-msg",
            "hooks/update",
            "COMMIT_EDITMSG",
            "description",
            "FETCH_HEAD",
            "HEAD",
            "index",
            "info/",
            "info/exclude",
            "logs",
            "logs/HEAD",
            "logs/refs/",
            "logs/refs/remotes/",
            "logs/refs/remotes/origin/",
            "logs/refs/remotes/origin/HEAD",
            "logs/refs/stash",
            "ORIG_HEAD",
            "packed-refs",
            "refs/",
            "refs/remotes/",
            "refs/remotes/origin/",
            "refs/remotes/origin/HEAD",
            "refs/stash",
            "objects/",
            "objects/info/",
            "objects/info/alternates",
            "objects/info/http-alternates",
            "objects/info/packs",
        ]
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
        dir_listing = await self.directory_listing_enabled(repo_url)
        if dir_listing:
            urls = await self.recursive_dir_list(dir_listing)
            result = await self.download_files(urls, repo_folder)
        else:
            self.debug("Directory listing not enabled, fuzzing common git files")
            url_list = []
            for file in self.git_files:
                url = self.helpers.urljoin(repo_url, file)
                url_list.append(self.helpers.urlparse(url))
            result = await self.download_files(url_list, repo_folder)
        if result:
            await self.git_checkout(repo_folder)
            codebase_event = self.make_event({"path": str(repo_folder)}, "FILESYSTEM", tags=["git"], parent=event)
            await self.emit_event(
                codebase_event,
                context=f"{{module}} cloned git repo at {repo_url} to {{event.type}}: {str(repo_folder)}",
            )
        else:
            self.helpers.rm_rf(repo_folder)

    async def directory_listing_enabled(self, repo_url):
        response = await self.helpers.request(repo_url)
        if "<title>Index of" in response.text:
            self.info(f"Directory listing enabled at {repo_url}")
            return response
        return None

    async def recursive_dir_list(self, dir_listing):
        file_list = []
        soup = self.helpers.beautifulsoup(dir_listing.text, "html.parser")
        links = soup.find_all("a")
        for link in links:
            href = link["href"]
            if href == "../" or href == "/":
                continue
            if href.endswith("/"):
                folder_url = self.helpers.urljoin(str(dir_listing.url), href)
                url = self.helpers.urlparse(folder_url)
                file_list.append(url)
                response = await self.helpers.request(folder_url)
                if response.status_code == 200:
                    file_list.extend(await self.recursive_dir_list(response))
            else:
                file_url = self.helpers.urljoin(str(dir_listing.url), href)
                # Ensure the file is in the same domain as the directory listing
                if file_url.startswith(str(dir_listing.url)):
                    url = self.helpers.urlparse(file_url)
                    file_list.append(url)
        return file_list

    async def add_git_files(self, repo_url):
        url_list = []
        self.debug("Adding basic git files to fuzz list")
        for file in self.git_files:
            url = self.helpers.urljoin(repo_url, file)
            url_list.append(url)
        return url_list

    async def download_files(self, urls, folder):
        self.verbose(f"Downloading the git files to {folder}")
        for url in urls:
            git_index = url.path.find(".git")
            if url.path.endswith("/"):
                self.helpers.mkdir(folder / url.path[git_index:])
            else:
                file_url = url.geturl()
                filename = str(folder / url.path[git_index:])
                self.debug(f"Downloading {file_url} to {filename}")
                await self.helpers.download(file_url, filename=filename)
        if any(folder.rglob("*")):
            return True
        else:
            self.debug(f"Unable to download git files to {folder}")
            return False

    async def git_checkout(self, folder):
        self.verbose(f"Running git checkout to reconstruct the git repository at {folder}")
        command = ["git", "checkout"]
        try:
            await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, cwd=folder, check=True)
        except CalledProcessError as e:
            # Still emit the event even if the checkout fails
            self.debug(f"Error running git checkout in {folder}. STDERR: {repr(e.stderr)}")
