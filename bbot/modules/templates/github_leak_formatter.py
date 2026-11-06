from pathlib import Path
from hashlib import sha256
from urllib.parse import urlparse, urlsplit
import base64
import binascii
import json
import os
import re
import shutil
import tempfile
import time
from bbot.core.helpers.observation_dates import indexed_date

# Parent hops searched for the URL an artifact (downloaded file, app package, image) came from.
ARTIFACT_SOURCE_MAX_DEPTH = 5
SECRET_ROTATION_GUIDANCE = (
    "Anyone who obtains a valid secret may authenticate as the affected account or service, causing account takeover, unauthorized data access, cloud resource abuse, source code access, or lateral movement. "
    "Rotate or revoke the credential, review access logs for misuse, remove the secret from history where practical, and move future secrets to a managed secret store or deployment-time configuration."
)
# Directories that by convention hold other projects' code (package managers, vendoring, submodules).
THIRD_PARTY_DIRS = {
    "node_modules",
    "bower_components",
    "jspm_packages",
    "vendor",
    "third_party",
    "third-party",
    "thirdparty",
    "3rdparty",
    "site-packages",
    "dist-packages",
    "pods",
    "carthage",
}
# A released library committed as a binary (e.g. jython-standalone-2.7.2.jar): its contents are the library's.
VERSIONED_LIBRARY_ARCHIVE = re.compile(
    r"^[a-z][\w.+-]*?-\d+(\.\d+)+([.-][\w.]+)?\.(jar|aar|war|whl|egg|nupkg|gem)$", re.I
)


class github_leak_formatter:
    def submodule_paths(self, scan_path):
        """Paths, relative to the checkout, that any .gitmodules in it declares as another repository."""
        cache = getattr(self, "_submodule_paths_cache", None)
        if cache is None:
            cache = self._submodule_paths_cache = {}
        key = str(scan_path)
        if key not in cache:
            paths = set()
            root = Path(scan_path)
            if root.is_dir():
                for gitmodules in root.rglob(".gitmodules"):
                    if ".git" in gitmodules.relative_to(root).parts[:-1]:
                        continue
                    try:
                        text = gitmodules.read_text(errors="replace")
                    except OSError:
                        continue
                    paths |= self.gitmodules_paths(text, gitmodules.parent.relative_to(root).as_posix())
            cache[key] = paths
        return cache[key]

    @staticmethod
    def gitmodules_paths(text, base=""):
        """The submodule paths a .gitmodules declares, relative to the repository root (`base` is its directory)."""
        paths = set()
        for match in re.finditer(r"^\s*path\s*=\s*(.+?)\s*$", text, re.M):
            sub = (Path(base) / match.group(1).strip()).as_posix()
            if sub and sub != "." and not sub.startswith(".."):
                paths.add(sub)
        return paths

    async def remote_submodule_paths(self, url, commit, relative_path):
        """Submodule paths declared by the .gitmodules in the directories above `relative_path` at `commit`,
        for a repository scanned by URL (no local checkout). Uses one blobless bare clone per URL, fetched
        only when a finding needs it; `cleanup_remote_clones()` removes them."""
        relative_path = str(relative_path or "").strip().lstrip("/")
        commit = str(commit or "").strip()
        if not relative_path or not commit:
            return set()
        clones = getattr(self, "_remote_clones", None)
        if clones is None:
            clones = self._remote_clones = {}
        cache = getattr(self, "_remote_gitmodules_cache", None)
        if cache is None:
            cache = self._remote_gitmodules_cache = {}
        if url not in clones:
            clone = Path(tempfile.mkdtemp(prefix="bbot-gitmodules-"))
            result = await self.run_process(
                ["git", "clone", "--bare", "--filter=blob:none", "--quiet", url, str(clone)],
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            )
            if getattr(result, "returncode", 1) != 0:
                self.debug(f"Could not clone {url} to read its .gitmodules")
                shutil.rmtree(clone, ignore_errors=True)
                clone = None
            clones[url] = clone
        clone = clones[url]
        if clone is None:
            return set()
        paths = set()
        parents = Path(relative_path).parents
        for directory in [p.as_posix() for p in reversed(parents)]:
            directory = "" if directory == "." else directory
            key = (url, commit, directory)
            if key not in cache:
                spec = f"{commit}:{directory + '/' if directory else ''}.gitmodules"
                result = await self.run_process(["git", "-C", str(clone), "show", spec])
                text = result.stdout if getattr(result, "returncode", 1) == 0 else ""
                cache[key] = self.gitmodules_paths(text or "", directory)
            paths |= cache[key]
        return paths

    def cleanup_remote_clones(self):
        for clone in (getattr(self, "_remote_clones", None) or {}).values():
            if clone is not None:
                shutil.rmtree(clone, ignore_errors=True)
        self._remote_clones = {}

    def is_third_party_path(self, scan_path, relative_path, submodules=None):
        """A secret inside another project's code (a dependency, vendored copy, submodule or released
        library binary) belongs to that project, not to the scanned organization. `submodules` overrides
        the paths read from a local checkout at `scan_path` (e.g. for a repository scanned by URL)."""
        relative_path = str(relative_path or "").strip().lstrip("/")
        if not relative_path:
            return False
        archive = relative_path.partition("!")[0]
        if VERSIONED_LIBRARY_ARCHIVE.match(Path(archive).name):
            return True
        parts = Path(archive).parts
        if any(part.lower() in THIRD_PARTY_DIRS for part in parts[:-1]):
            return True
        path = Path(archive).as_posix()
        if submodules is None:
            submodules = self.submodule_paths(scan_path)
        return any(path.startswith(sub + "/") for sub in submodules)

    @staticmethod
    def secret_dedupe_key(repository_url, secret_fingerprint):
        # One credential exposed repeatedly in a repository is one issue,
        # regardless of scanner, file, or historical commit. Keep separate
        # repositories separate so no affected codebase disappears.
        repository_url = str(repository_url).rstrip("/")
        if urlsplit(repository_url).hostname == "github.com":
            repository_url = repository_url.lower()
        return f"github-leak-secret:{repository_url}:{secret_fingerprint}"

    async def get_exposure_commit_date(self, scan_path, commit):
        # Never interpret an arbitrary scanner string as a git option/revision expression.
        if not re.fullmatch(r"[a-fA-F0-9]{7,40}", str(commit or "")):
            return None
        result = await self.run_process(
            ["git", "-C", str(scan_path), "show", "-s", "--format=%cI", commit, "--"],
            _log_stderr=False,
        )
        return indexed_date({"date": str(getattr(result, "stdout", "") or "").strip()})

    async def get_repository_url(self, event, scan_path):
        if isinstance(getattr(event, "data", None), dict):
            repository_url = str(event.data.get("url", "")).strip()
            if repository_url:
                return self.normalize_repository_url(repository_url)
        # Authenticated clones have their git configuration stripped before
        # scanning. Their parent event still carries the scoped repository URL.
        parent = event.get_parent() if callable(getattr(event, "get_parent", None)) else getattr(event, "parent", None)
        if getattr(parent, "type", "") == "CODE_REPOSITORY" and isinstance(getattr(parent, "data", None), dict):
            repository_url = str(parent.data.get("url", "")).strip()
            if repository_url:
                return self.normalize_repository_url(repository_url)

        cache = getattr(self, "_github_repo_url_cache", None)
        if cache is None:
            cache = {}
            self._github_repo_url_cache = cache

        cache_key = str(scan_path)
        if cache_key in cache:
            return cache[cache_key]
        if not Path(scan_path).is_dir():
            # A single downloaded file is never a Git checkout; skip the git subprocess.
            return ""

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
            # Not a Git checkout (a downloaded file, app package, container image...): the secret is
            # just as exposed, so report it where the artifact was obtained instead of dropping it.
            return self.format_artifact_leak(
                event,
                scan_path,
                leak,
                detector=detector,
                file_path=file_path,
                line=line,
                verified=verified,
                severity=severity,
                extra_fields=extra_fields,
            )

        repository_url = self.normalize_repository_url(repository_url)
        commit = str(commit or "").strip()
        # A fallback HEAD is a link target, not evidence dating a historical leak.
        commit_date = await self.get_exposure_commit_date(scan_path, commit) if commit else None
        if not commit:
            commit = await self.get_repository_commit(scan_path)

        relative_path = self.relative_file_path(scan_path, file_path)
        if self.is_third_party_path(scan_path, relative_path):
            self.debug(f"Skipping a {detector or 'secret'} leak in third-party code: {repository_url} {relative_path}")
            return None
        commit_url = self.build_commit_url(repository_url, commit)
        blob_url = self.build_blob_url(repository_url, relative_path, line=line, commit=commit)
        finding_url = blob_url or commit_url or repository_url

        leak_value = str(leak or "").strip()
        rule_name = str(detector or "").strip()
        leak_type = rule_name or "secret"
        secret_fingerprint = self.secret_fingerprint(leak_value)
        if secret_fingerprint:
            dedupe_key = self.secret_dedupe_key(repository_url, secret_fingerprint)
        else:
            dedupe_key = "github-leak:" + ":".join([repository_url, leak_type, relative_path, str(line or "")])
        source_location = self.source_location(relative_path, line)
        source_suffix = f" in {source_location}" if source_location else ""
        leak_description = f"A Git leak of type {leak_type}{source_suffix} was identified."
        if leak_value:
            leak_description += f" Leaked value: {leak_value}."
        leak_description += (
            " This value may also be exposed in other commits; one confirmed exposure is sufficient to "
            "treat the credential as compromised and rotate or revoke it."
        )
        leak_description = (
            f"{leak_description} "
            "A credential, token, password, or API key connected to the target was found in source code history. "
            "Treat it as compromised even if the current branch no longer contains it, because Git history, forks, local clones, CI logs, build artifacts, and external caches may preserve older values. "
            f"{SECRET_ROTATION_GUIDANCE}"
        )
        poc_parts = [
            f"Repository: {repository_url}",
            f"Commit URL: {commit_url or repository_url}",
            f"Leak type: {leak_type}",
            f"Secret value: {leak_value}",
        ]
        if source_location:
            poc_parts.insert(2, f"Source location: {source_location}")
        if blob_url:
            poc_parts.insert(3 if source_location else 2, f"File URL: {blob_url}")
        data = {
            "url": finding_url,
            "location": finding_url,
            "tool": getattr(self, "name", self.__class__.__name__),
            "repository_url": repository_url,
            "rule": rule_name,
            "leak_type": leak_type,
            "leakType": leak_type,
            "secretType": leak_type,
            "title": f"Git Leak of {leak_type} detected",
            "category": "secret",
            "description": leak_description,
            "poc": "\n".join(poc_parts),
            "severity": severity or ("High" if verified else "Medium"),
            "force_finding": True,
            "dedupe_key": dedupe_key,
        }
        if commit_url:
            data["commit_url"] = commit_url
        if blob_url:
            data["file_url"] = blob_url
            data["blob_url"] = blob_url
        if commit:
            data["commit"] = commit
        if commit_date:
            data["secret_latest_commit_at"] = commit_date
        return self.add_secret_fields(data, leak_value, secret_fingerprint, relative_path, line, extra_fields)

    def format_artifact_leak(
        self,
        event,
        scan_path,
        leak,
        *,
        detector="",
        file_path="",
        line=None,
        verified=False,
        severity="",
        extra_fields=None,
    ):
        if (
            self.is_public_recaptcha_site_key(scan_path, file_path, line, leak, detector, verified)
            or self.is_public_google_maps_javascript_key(scan_path, file_path, line, leak, detector, verified)
            or self.is_public_amplitude_api_key(scan_path, file_path, line, leak, detector)
            or self.is_documentation_placeholder(leak, detector, verified)
            or self.is_labelled_example_key(scan_path, file_path, line, leak, detector, verified)
            or self.is_expired_jwt(leak, detector, verified)
            or self.is_public_gitbook_content_token(scan_path, file_path, line, leak, detector, verified)
        ):
            return None
        source_url = self.get_artifact_source_url(event)
        if Path(scan_path).is_file():
            # A scanned file reports its own path, or "<file>!<member>" inside an archive.
            reported = str(file_path or scan_path)
            suffix = reported[len(str(scan_path)) :] if reported.startswith(str(scan_path)) else ""
            artifact_path = Path(str(scan_path)).name + suffix
        else:
            artifact_path = self.relative_file_path(scan_path, file_path)

        leak_value = str(leak or "").strip()
        rule_name = str(detector or "").strip()
        leak_type = rule_name or "secret"
        secret_fingerprint = self.secret_fingerprint(leak_value)
        source_location = self.source_location(artifact_path, line)
        origin = f"downloaded from {source_url}" if source_url else "retrieved from the target"

        description = f"A leak of type {leak_type}"
        if source_location:
            description += f" in {source_location}"
        description += f" was identified in an artifact {origin}."
        if leak_value:
            description += f" Leaked value: {leak_value}."
        description += (
            " A credential, token, password, or API key connected to the target is publicly retrievable, so anyone who "
            "can fetch the artifact can read it. Treat it as compromised even if the artifact is later removed, because "
            f"caches, mirrors, and prior downloads may preserve it. {SECRET_ROTATION_GUIDANCE}"
        )
        poc_parts = [f"Artifact source: {source_url}"] if source_url else []
        if source_location:
            poc_parts.append(f"Source location: {source_location}")
        poc_parts += [f"Leak type: {leak_type}", f"Secret value: {leak_value}"]

        data = {
            "tool": getattr(self, "name", self.__class__.__name__),
            "rule": rule_name,
            "leak_type": leak_type,
            "leakType": leak_type,
            "secretType": leak_type,
            "title": f"Leak of {leak_type} detected in a public artifact",
            "category": "secret",
            "description": description,
            "poc": "\n".join(poc_parts),
            "severity": severity or ("High" if verified else "Medium"),
            "force_finding": True,
        }
        if source_url:
            data["url"] = source_url
            data["location"] = source_url
        if secret_fingerprint:
            # Same key as Git leaks: one secret exposed in several places is one credential to rotate.
            data["dedupe_key"] = f"github-leak-secret:{secret_fingerprint}"
        return self.add_secret_fields(data, leak_value, secret_fingerprint, artifact_path, line, extra_fields)

    @staticmethod
    def is_public_recaptcha_site_key(scan_path, file_path, line, leak, detector, verified):
        """A client-side site key is deliberately public; require its source label before filtering."""
        if verified or str(detector or "").lower() != "recaptcha api key":
            return False
        key = str(leak or "").strip()
        try:
            source = Path(scan_path).resolve()
            reported = Path(file_path).resolve()
            line_number = int(line)
        except (OSError, TypeError, ValueError):
            return False
        if not key or line_number < 1 or source != reported or not source.is_file():
            return False
        try:
            with source.open(encoding="utf-8", errors="ignore") as stream:
                source_line = next((text for index, text in enumerate(stream, 1) if index == line_number), "")
        except OSError:
            return False
        site_key_label = r"(?:data-sitekey|recaptcha[_-]?site[_-]?key|site[_-]?key)"
        return bool(
            re.search(rf"{site_key_label}\s*[=:]\s*[\"']?{re.escape(key)}(?=[\"'\s<]|$)", source_line, re.IGNORECASE)
        )

    @staticmethod
    def is_public_amplitude_api_key(scan_path, file_path, line, leak, detector):
        """Amplitude project apiKey values are client-side identifiers, not analytics secret keys."""
        if str(detector or "").strip().lower() != "amplitude secret key":
            return False
        key = str(leak or "").strip()
        try:
            source = Path(scan_path).resolve()
            reported = Path(file_path).resolve()
            line_number = int(line)
        except (OSError, TypeError, ValueError):
            return False
        if not key or line_number < 1 or source != reported or not source.is_file():
            return False
        try:
            with source.open(encoding="utf-8", errors="ignore") as stream:
                source_line = next((text for index, text in enumerate(stream, 1) if index == line_number), "")
        except OSError:
            return False
        source_line = re.sub(r'\\+"', '"', source_line)
        pattern = rf'"amplitude"\s*:\s*\{{\s*"apiKey"\s*:\s*"{re.escape(key)}"'
        return bool(re.search(pattern, source_line, re.IGNORECASE))

    @staticmethod
    def is_public_google_maps_javascript_key(scan_path, file_path, line, leak, detector, verified):
        """A Maps JavaScript script URL necessarily exposes its browser key to visitors."""
        if verified or str(detector or "").strip().lower() not in {"google api key", "gcp-api-key"}:
            return False
        key = str(leak or "").strip()
        try:
            source = Path(scan_path).resolve()
            reported = Path(file_path).resolve()
            line_number = int(line)
        except (OSError, TypeError, ValueError):
            return False
        if not key or line_number < 1 or source != reported or not source.is_file():
            return False
        try:
            with source.open(encoding="utf-8", errors="ignore") as stream:
                source_line = next((text for index, text in enumerate(stream, 1) if index == line_number), "")
        except OSError:
            return False
        pattern = (
            rf'\bsrc\s*=\s*["\']https://maps\.googleapis\.com/maps/api/js\?'
            rf'(?:[^"\'\s<>]*&)?key={re.escape(key)}(?=[&"\'\s<>]|$)'
        )
        return bool(re.search(pattern, source_line, re.IGNORECASE))

    @staticmethod
    def is_documentation_placeholder(leak, detector, verified):
        if verified:
            return False
        value = str(leak or "").strip().strip("\"'")
        detector = str(detector or "").strip().lower()
        if github_leak_formatter.is_example_value(github_leak_formatter.normalize_secret_value(value), detector):
            return True
        if detector == "http bearer token":
            return bool(re.fullmatch(r"Authorization:\s*Bearer\s+YOUR_[A-Z0-9_]+", value, re.IGNORECASE))
        if detector == "generic secret":
            return bool(re.fullmatch(r"SECRET\s*=\s*[\"']?X{8,}", value, re.IGNORECASE))
        if detector == "private-key":
            # Documentation can show an escaped PEM skeleton followed by sample code.
            # Require the literal placeholder as the complete PEM body.
            normalized = value.replace(r"\n", "\n")
            return bool(
                re.match(
                    r"^-----BEGIN (?P<kind>(?:EC |RSA )?)PRIVATE KEY-----\n"
                    r"YOUR PRIVATE KEY\n"
                    r"-----END (?P=kind)PRIVATE KEY-----",
                    normalized,
                    re.IGNORECASE,
                )
            )
        return False

    @staticmethod
    def is_example_value(value, detector):
        """Values that documentation writes in place of a real credential."""
        lowered = value.lower()
        if "dummy" in lowered or any(marker in value for marker in ("${", "{{", "process.env", "os.environ")):
            return True
        if re.fullmatch(r"(?:token|key|secret|password|api[_-]?key)[_-]?\d{1,6}", value, re.IGNORECASE):
            return True
        if re.match(r"(?:GET_FROM_|YOUR_|REPLACE_|INSERT_|<)", value, re.IGNORECASE):
            return True
        # A run of one repeated character standing for an id or key, e.g. a UUID ending in 111111111111.
        return detector != "private-key" and bool(re.search(r"(?:^|[-_:=])(.)\1{7,}(?:$|[-_])", value))

    @staticmethod
    def is_labelled_example_key(scan_path, file_path, line, leak, detector, verified):
        """Documentation presents sample key pairs under an "Example values" or "sample key" label."""
        if verified or str(detector or "").strip().lower() != "private-key":
            return False
        try:
            source = Path(scan_path).resolve()
            reported = Path(file_path).resolve()
            line_number = int(line)
        except (OSError, TypeError, ValueError):
            return False
        if line_number < 1 or source != reported or not source.is_file():
            return False
        try:
            with source.open(encoding="utf-8", errors="ignore") as stream:
                lines = [text for index, text in enumerate(stream, 1) if line_number - 5 <= index <= line_number]
        except OSError:
            return False
        if not lines:
            return False
        lines[-1] = lines[-1].split("-----BEGIN", 1)[0]
        label = r"\b(?:example|sample)\s+(?:values?|(?:private\s+)?keys?)\b"
        return bool(re.search(label, "".join(lines), re.IGNORECASE))

    @staticmethod
    def is_expired_jwt(leak, detector, verified):
        if verified or str(detector or "").strip().lower() not in {"jwt", "json web token (base64url-encoded)"}:
            return False
        value = str(leak or "").strip()
        if not re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", value):
            return False
        try:
            header, claims, _ = value.split(".")
            header = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
            claims = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
        except (ValueError, binascii.Error):
            return False
        if not isinstance(header, dict) or not isinstance(header.get("alg"), str) or not isinstance(claims, dict):
            return False
        expires_at = claims.get("exp")
        return (
            isinstance(expires_at, (int, float))
            and not isinstance(expires_at, bool)
            and expires_at <= time.time() - 300
        )

    @staticmethod
    def is_public_gitbook_content_token(scan_path, file_path, line, leak, detector, verified):
        """GitBook embeds its read-only site content token in every public page's route data."""
        if verified or str(detector or "").strip().lower() not in {"jwt", "json web token (base64url-encoded)"}:
            return False
        value = str(leak or "").strip()
        if not re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
            return False
        try:
            source = Path(scan_path).resolve()
            reported = Path(file_path).resolve()
            line_number = int(line)
            claims_part = value.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(claims_part + "=" * (-len(claims_part) % 4)))
        except (OSError, TypeError, ValueError, binascii.Error):
            return False
        if not isinstance(claims, dict) or source != reported or line_number < 1 or not source.is_file():
            return False
        if not (
            claims.get("kind") == "site"
            and claims.get("target") == "content"
            and claims.get("visitorType") == "human"
            and claims.get("draft") is False
            and str(claims.get("sub", "")).startswith("content_")
            and all(isinstance(claims.get(key), str) and claims[key] for key in ("organization", "site", "siteSpace"))
            and isinstance(claims.get("spaces"), list)
            and not any(key in claims for key in ("email", "role", "permissions"))
        ):
            return False
        try:
            with source.open(encoding="utf-8", errors="ignore") as stream:
                source_line = next((text for index, text in enumerate(stream, 1) if index == line_number), "")
        except OSError:
            return False
        marker = f"apiToken%3A{value}%2C"
        token_at = source_line.find(marker)
        if token_at < 0:
            return False
        context = source_line[max(0, token_at - 500) : token_at + len(marker) + 500]
        return "siteData" in context and "siteSpace%3A" in context

    def get_artifact_source_url(self, event):
        current = event
        for _ in range(ARTIFACT_SOURCE_MAX_DEPTH):
            if current is None or getattr(current, "type", "") == "SCAN":
                break
            data = getattr(current, "data", None)
            if isinstance(data, dict):
                url = str(data.get("url", "") or "").strip()
            elif str(getattr(current, "type", "")).startswith("URL"):
                url = str(data or "").strip()
            else:
                url = ""
            if url.startswith(("http://", "https://")):
                return url
            parent = getattr(current, "parent", None)
            current = parent if parent is not current else None
        return ""

    @staticmethod
    def normalize_secret_value(leak_value):
        """Reduce a match to the secret itself, so one secret matched by different rules is one value."""
        value = str(leak_value or "").strip().replace('\\"', '"')
        value = re.sub(r"^(?:Authorization:\s*)?Bearer\s+", "", value, flags=re.IGNORECASE)
        assignment = re.match(r"""["'`]?[A-Za-z_][\w.-]*["'`]?\s*(?:=|:(?!//))\s*(.+)""", value, re.DOTALL)
        if assignment and len(assignment.group(1).strip("\"'`,; ")) >= 8:
            value = assignment.group(1)
        return value.strip().strip("\"'`,;").strip()

    @staticmethod
    def secret_fingerprint(leak_value):
        value = github_leak_formatter.normalize_secret_value(leak_value)
        if not value:
            return ""
        return "sha256:" + sha256(value.encode("utf-8", errors="ignore")).hexdigest()

    @staticmethod
    def source_location(path, line):
        parts = [path] if path else []
        if line not in (None, "", "?"):
            parts.append(f"line {line}")
        return ":".join(parts)

    @staticmethod
    def add_secret_fields(data, leak_value, secret_fingerprint, path, line, extra_fields):
        if leak_value:
            data["secretValue"] = leak_value
            data["secret_value"] = leak_value
        if secret_fingerprint:
            data["secretFingerprint"] = secret_fingerprint
            data["secret_fingerprint"] = secret_fingerprint
        if path:
            data["path"] = path
        if line not in (None, "", "?"):
            data["line"] = str(line)
        if extra_fields:
            data.update({k: v for k, v in extra_fields.items() if v not in ("", None, [], {})})
        return data
