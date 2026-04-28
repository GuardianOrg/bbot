from pathlib import Path
from hashlib import sha256
from urllib.parse import urlparse


class github_leak_formatter:
    async def get_repository_url(self, event, scan_path):
        if isinstance(getattr(event, "data", None), dict):
            repository_url = str(event.data.get("url", "")).strip()
            if repository_url:
                return self.normalize_repository_url(repository_url)

        cache = getattr(self, "_github_repo_url_cache", None)
        if cache is None:
            cache = {}
            self._github_repo_url_cache = cache

        cache_key = str(scan_path)
        if cache_key in cache:
            return cache[cache_key]

        result = await self.run_process(
            ["git", "-C", str(scan_path), "config", "--get", "remote.origin.url"],
            _log_stderr=False,
        )
        repository_url = self.normalize_repository_url(getattr(result, "stdout", "") or "")
        cache[cache_key] = repository_url
        return repository_url

    async def get_repository_commit(self, scan_path):
        cache = getattr(self, "_github_repo_commit_cache", None)
        if cache is None:
            cache = {}
            self._github_repo_commit_cache = cache

        cache_key = str(scan_path)
        if cache_key in cache:
            return cache[cache_key]

        result = await self.run_process(
            ["git", "-C", str(scan_path), "rev-parse", "HEAD"],
            _log_stderr=False,
        )
        commit = str(getattr(result, "stdout", "") or "").strip()
        cache[cache_key] = commit
        return commit

    def normalize_repository_url(self, repository_url):
        repository_url = str(repository_url or "").strip()
        if not repository_url:
            return ""

        if repository_url.startswith("git@github.com:"):
            repository_url = "https://github.com/" + repository_url.split(":", 1)[1]
        if repository_url.startswith("ssh://git@github.com/"):
            repository_url = "https://github.com/" + repository_url.split("github.com/", 1)[1]
        if repository_url.endswith(".git"):
            repository_url = repository_url[:-4]
        return repository_url.rstrip("/")

    def is_github_repository(self, repository_url):
        parsed = urlparse(str(repository_url or "").strip())
        return parsed.scheme in ("http", "https") and parsed.netloc.lower() == "github.com"

    def build_commit_url(self, repository_url, commit):
        repository_url = self.normalize_repository_url(repository_url)
        commit = str(commit or "").strip()
        if not repository_url or not commit:
            return ""
        return f"{repository_url}/commit/{commit}"

    def build_blob_url(self, repository_url, file_path, line=None, commit=""):
        repository_url = self.normalize_repository_url(repository_url)
        file_path = str(file_path or "").strip().lstrip("/")
        commit = str(commit or "").strip()
        if not repository_url or not file_path or not commit:
            return ""
        blob_url = f"{repository_url}/blob/{commit}/{file_path}"
        if line not in (None, "", "?"):
            blob_url += f"#L{line}"
        return blob_url

    def relative_file_path(self, scan_path, file_path):
        file_path = str(file_path or "").strip()
        if not file_path:
            return ""
        try:
            return str(Path(file_path).resolve().relative_to(Path(scan_path).resolve()))
        except Exception:
            pass

        scan_path_str = str(scan_path).rstrip("/") + "/"
        if file_path.startswith(scan_path_str):
            return file_path[len(scan_path_str) :]
        return file_path.lstrip("/")

    async def format_github_leak(
        self,
        event,
        scan_path,
        leak,
        *,
        detector="",
        file_path="",
        line=None,
        commit="",
        verified=False,
        severity="",
        finding_details=None,
        extra_fields=None,
    ):
        repository_url = await self.get_repository_url(event, scan_path)
        if not repository_url:
            return None

        repository_url = self.normalize_repository_url(repository_url)
        commit = str(commit or "").strip()
        if not commit:
            commit = await self.get_repository_commit(scan_path)

        relative_path = self.relative_file_path(scan_path, file_path)
        commit_url = self.build_commit_url(repository_url, commit)
        github_url = self.build_blob_url(repository_url, relative_path, line=line, commit=commit) or commit_url or repository_url

        leak_value = str(leak or "").strip()
        rule_name = str(detector or "").strip()
        leak_fingerprint = sha256(leak_value.encode("utf-8", errors="ignore")).hexdigest() if leak_value else ""
        secret_fingerprint = f"sha256:{leak_fingerprint}" if leak_fingerprint else ""
        dedupe_parts = [repository_url, leak_value]
        tool_name = getattr(self, "name", "")
        location_parts = []
        if relative_path:
            location_parts.append(relative_path)
        if line not in (None, "", "?"):
            location_parts.append(f"line {line}")
        location = " at " + ":".join(location_parts) if location_parts else ""
        rule_suffix = f" ({rule_name})" if rule_name else ""
        data = {
            "url": github_url,
            "repository_url": repository_url,
            "tool": tool_name,
            "rule": rule_name,
            "title": f"{tool_name} detected a possible secret{rule_suffix}",
            "category": "secret",
            "description": f"{tool_name} detected a possible secret{rule_suffix} in {repository_url}{location}.",
            "poc": f"Repository: {repository_url}\nLocation: {github_url}\nRule: {rule_name or 'unknown'}\nSecret value: {leak_value}",
            "severity": severity or ("High" if verified else "Medium"),
            "force_finding": True,
            "dedupe_key": "github-leak:" + ":".join(dedupe_parts),
        }
        if leak_value:
            data["secretValue"] = leak_value
            data["secret_value"] = leak_value
        if secret_fingerprint:
            data["secretFingerprint"] = secret_fingerprint
            data["secret_fingerprint"] = secret_fingerprint
        if relative_path:
            data["path"] = relative_path
        if line not in (None, "", "?"):
            data["line"] = str(line)
        if commit:
            data["commit"] = commit
        if extra_fields:
            data.update({k: v for k, v in extra_fields.items() if v not in ("", None, [], {})})
        return data
