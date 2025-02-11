import regex as re
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
            "HEAD",
            "description",
            "config",
            "COMMIT_EDITMSG",
            "index",
            "packed-refs",
            "info/refs",
            "info/exclude",
            "refs/stash",
            "refs/heads/master",
            "refs/remotes/origin/HEAD",
            "refs/wip/index/refs/heads/master",
            "refs/wip/wtree/refs/heads/master",
            "logs/HEAD",
            "logs/refs/heads/master",
            "logs/refs/remotes/origin/HEAD",
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
            result = await self.git_fuzz(repo_url, repo_folder)
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

    async def git_fuzz(self, repo_url, repo_folder):
        self.debug("Directory listing not enabled, fuzzing common git files")
        url_list = []
        for file in self.git_files:
            url_list.append(self.helpers.urlparse(self.helpers.urljoin(repo_url, file)))
        result = await self.download_files(url_list, repo_folder)
        if result:
            for object in await self.regex_files(r"[a-f0-9]{40}", folder=repo_folder):
                await self.download_object(object, repo_url, repo_folder)
            return True
        else:
            return False

    async def regex_files(self, regex_pattern, folder=Path(), file=Path(), files=[]):
        regex = re.compile(regex_pattern)
        results = []
        if folder:
            if folder.is_dir():
                for file_path in folder.rglob("*"):
                    if file_path.is_file():
                        results.extend(await self.regex_file(regex, file_path))
        if files:
            for file in files:
                results.extend(await self.regex_file(regex, file))
        if file:
            results.extend(await self.regex_file(regex, file))
        return results

    async def regex_file(self, regex, file=Path()):
        self.debug(f"Searching {file} for regex pattern {regex.pattern}")
        if file.exists() and file.is_file():
            with file.open("r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
                matches = await self.helpers.re.findall(regex, content)
                if matches:
                    return matches
        return []

    async def download_object(self, object, repo_url, repo_folder):
        await self.download_files(
            [self.helpers.urlparse(self.helpers.urljoin(repo_url, f"objects/{object[:2]}/{object[2:]}"))], repo_folder
        )
        regex = re.compile(r"[a-f0-9]{40}")
        output = await self.git_catfile(object, option="-p", folder=repo_folder)
        for obj in await self.helpers.re.findall(regex, output):
            await self.download_object(obj, repo_url, repo_folder)

    async def download_files(self, urls, folder):
        self.verbose(f"Downloading the git files to {folder}")
        for url in urls:
            git_index = url.path.find(".git")
            file_url = url.geturl()
            filename = folder / url.path[git_index:]
            self.helpers.mkdir(filename.parent)
            self.debug(f"Downloading {file_url} to {filename}")
            await self.helpers.download(file_url, filename=filename, warn=False)
        if any(folder.rglob("*")):
            return True
        else:
            self.debug(f"Unable to download git files to {folder}")
            return False

    async def git_catfile(self, hash, option="-t", folder=Path()):
        command = ["git", "cat-file", option, hash]
        try:
            output = await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, cwd=folder, check=True)
        except CalledProcessError as e:
            # Still emit the event even if the checkout fails
            self.debug(f"Error running git cat-file in {folder}. STDERR: {repr(e.stderr)}")
            return ""

        return output.stdout

    async def git_checkout(self, folder):
        self.verbose(f"Running git checkout to reconstruct the git repository at {folder}")
        command = ["git", "checkout", "."]
        try:
            await self.run_process(command, env={"GIT_TERMINAL_PROMPT": "0"}, cwd=folder, check=True)
        except CalledProcessError as e:
            # Still emit the event even if the checkout fails
            self.debug(f"Error running git checkout in {folder}. STDERR: {repr(e.stderr)}")
