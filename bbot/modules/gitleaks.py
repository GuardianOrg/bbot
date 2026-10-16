import json
import os
import re

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class gitleaks(code_secret_scanner):
    fatal_on_error = True
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find exposed credentials, tokens, passwords, and API keys in source code history",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }

    options = {
        "version": "8.30.0",
        "config": "",
        "redact": False,
        "output_folder": "",
        "clone_repositories": True,
        "disabled_rules": ["generic-api-key"],
        "git_commits_per_batch": 100,
    }
    options_desc = {
        "version": "gitleaks version",
        "config": "File path or URL to a Gitleaks TOML config",
        "redact": "Redact secrets in command output/report",
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
        "disabled_rules": "Gitleaks rule IDs to suppress after scanning. Defaults to generic-api-key to reduce false positives.",
        "git_commits_per_batch": "Maximum Git commits scanned in one Gitleaks process; every reachable commit is still scanned.",
    }
    deps_ansible = [
        {
            "name": "Set gitleaks architecture",
            "set_fact": {
                "bbot_gitleaks_arch": "{{ 'x64' if ansible_facts['architecture'] in ['x86_64', 'amd64'] else 'arm64' if ansible_facts['architecture'] in ['aarch64', 'arm64'] else ansible_facts['architecture'] }}"
            },
        },
        {
            "name": "Download gitleaks",
            "shell": {
                "cmd": "set -e\nif [ -x \"#{BBOT_TOOLS}/gitleaks\" ]; then exit 0; fi\ntmpdir=\"$(mktemp -d)\"\ntrap 'rm -rf \"$tmpdir\"' EXIT\ncurl -fsSL --retry 3 --connect-timeout 20 --max-time 180 -o \"$tmpdir/gitleaks.tar.gz\" \"https://github.com/gitleaks/gitleaks/releases/download/v#{BBOT_MODULES_GITLEAKS_VERSION}/gitleaks_#{BBOT_MODULES_GITLEAKS_VERSION}_#{BBOT_OS_PLATFORM}_{{ bbot_gitleaks_arch }}.tar.gz\"\ntar -xzf \"$tmpdir/gitleaks.tar.gz\" -C \"$tmpdir\" gitleaks\ninstall -m 0755 \"$tmpdir/gitleaks\" \"#{BBOT_TOOLS}/gitleaks\""
            },
        },
    ]

    async def setup_deps(self):
        self.config_file = self.config.get("config", "")
        if self.config_file:
            self.config_file = await self.helpers.wordlist(self.config_file)
        return True

    async def setup(self):
        self.redact = bool(self.config.get("redact", False))
        self.disabled_rules = self.parse_disabled_rules(self.config.get("disabled_rules", ["generic-api-key"]))
        return await super().setup()

    async def iter_findings(self, scan_path, event):
        if event.type == "CODE_REPOSITORY":
            count_result = await self.run_process(["git", "-C", str(scan_path), "rev-list", "--count", "--all"])
            if getattr(count_result, "returncode", 1) != 0:
                raise RuntimeError("Could not count Git commits before Gitleaks scan")
            try:
                commit_count = int(str(count_result.stdout).strip())
            except (ValueError, TypeError) as error:
                raise RuntimeError("Could not parse Git commit count before Gitleaks scan") from error
            batch_size = max(1, int(self.config.get("git_commits_per_batch", 100)))
            for offset in range(0, commit_count, batch_size):
                async for finding in self.scan_git_batch(scan_path, event, offset, min(batch_size, commit_count - offset)):
                    yield finding
        else:
            async for finding in self.scan_batch(scan_path, event):
                yield finding

    async def scan_git_batch(self, scan_path, event, offset, size):
        try:
            async for finding in self.scan_batch(scan_path, event, offset=offset, size=size):
                yield finding
        except GitleaksKilled:
            if size <= 1:
                raise RuntimeError(f"Gitleaks was killed while scanning commit at offset {offset}")
            midpoint = size // 2
            self.warning(f"Gitleaks was killed scanning {size} commits; retrying two smaller batches")
            async for finding in self.scan_git_batch(scan_path, event, offset, midpoint):
                yield finding
            async for finding in self.scan_git_batch(scan_path, event, offset + midpoint, size - midpoint):
                yield finding

    async def scan_batch(self, scan_path, event, offset=None, size=None):
        report_file = self.helpers.temp_filename(extension="json")
        use_git_mode = event.type == "CODE_REPOSITORY"

        try:
            # Use git mode for repositories so gitleaks includes commit metadata.
            command = [
                "gitleaks",
                "git" if use_git_mode else "dir",
                str(scan_path),
                "--report-format",
                "json",
                "--report-path",
                str(report_file),
                "--exit-code",
                "0",
                "--no-banner",
            ]
            if self.redact:
                command.append("--redact")
            if self.config_file:
                command.extend(["--config", str(self.config_file)])
            if use_git_mode and size is not None:
                # Gitleaks otherwise feeds the complete git log into one process.
                # These stable, disjoint Git-log windows cover every reachable commit.
                log_options = f"--full-history --all --diff-filter=tuxdb --max-count={size} --skip={offset}"
                command.extend(["--log-opts", log_options])

            scanner_env = {**os.environ, "GOMEMLIMIT": "1024MiB", "GOGC": "50"}
            result = await self.run_process(command, env=scanner_env)
            if getattr(result, "returncode", None) == -9:
                raise GitleaksKilled()

            # Backward-compatible fallback used by older versions.
            stderr = str(getattr(result, "stderr", "") or "").lower()
            old_cli = 'unknown command "git"' in stderr or 'unknown flag: --report-path' in stderr
            if getattr(result, "returncode", 0) != 0 and not report_file.is_file() and old_cli:
                fallback = [
                    "gitleaks",
                    "detect",
                    "--source",
                    str(scan_path),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_file),
                    "--exit-code",
                    "0",
                    "--no-banner",
                ]
                if not use_git_mode:
                    fallback.append("--no-git")
                if self.redact:
                    fallback.append("--redact")
                if self.config_file:
                    fallback.extend(["--config", str(self.config_file)])
                result = await self.run_process(fallback, env=scanner_env)
                if getattr(result, "returncode", None) == -9:
                    raise GitleaksKilled()

            try:
                raw = report_file.read_text(encoding="utf-8")
                parsed = json.loads(raw)
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                # Keep the process exit code and parser failure type visible:
                # a killed scanner and malformed output need different fixes.
                raise RuntimeError(
                    f"Gitleaks report could not be read (exit {getattr(result, 'returncode', 'unknown')}; "
                    f"{type(error).__name__})"
                ) from error
            # Go's JSON encoder may serialize a nil findings slice as null.
            findings = parsed.get("findings") if isinstance(parsed, dict) else parsed
            if parsed is None:
                findings = []
            if not isinstance(findings, list):
                raise RuntimeError("Gitleaks returned an unexpected report shape")
            malformed = False
            for finding in findings:
                if not isinstance(finding, dict):
                    malformed = True
                    continue
                rule = finding.get("RuleID") or finding.get("rule") or "unknown"
                if str(rule).strip().lower() in self.disabled_rules:
                    self.debug(f"Skipping disabled gitleaks rule: {rule}")
                    continue
                file_name = finding.get("File") or finding.get("file") or str(scan_path)
                line = finding.get("StartLine") or finding.get("line") or "?"
                secret = finding.get("Secret") or finding.get("Match") or "<redacted>"
                commit = finding.get("Commit") or finding.get("commit") or ""
                if not commit:
                    commit = self.commit_from_fingerprint(finding.get("Fingerprint", ""))
                yield await self.format_github_leak(
                    event,
                    scan_path,
                    secret,
                    detector=rule,
                    file_path=file_name,
                    line=line,
                    commit=commit,
                    verified=False,
                    severity="Medium",
                )
            if malformed or getattr(result, "returncode", None) != 0:
                raise RuntimeError("Gitleaks scan failed or returned malformed records")
        finally:
            report_file.unlink(missing_ok=True)

    def commit_from_fingerprint(self, fingerprint):
        fingerprint_prefix = str(fingerprint or "").split(":", 1)[0].strip()
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", fingerprint_prefix):
            return fingerprint_prefix
        return ""

    def parse_disabled_rules(self, value):
        if value is None:
            return set()
        if isinstance(value, str):
            items = re.split(r"[\s,]+", value)
        else:
            try:
                items = list(value)
            except TypeError:
                items = [value]
        return {str(item).strip().lower() for item in items if str(item).strip()}


class GitleaksKilled(RuntimeError):
    """The OS killed Gitleaks before it could produce a complete report."""
