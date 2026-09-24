import json

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class kingfisher(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find exposed credentials, tokens, passwords, and API keys in source code history",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }

    options = {
        "version": "1.84.0",
        "output_folder": "",
        "clone_repositories": True,
        "jobs": 1,
    }
    options_desc = {
        "version": "Kingfisher version",
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
        "jobs": "Parallel scanning jobs per Kingfisher invocation (keep low; many scans can share a host).",
    }
    # Kingfisher exits 0 when nothing was found and 200 when it reports findings; anything else is a failure.
    # docs/USAGE.md: 0 no findings, 200 findings, 205 validated (live) findings.
    success_exit_codes = (0, 200, 205)
    # Queued downloaded files are scanned together to pay Kingfisher's startup once per batch.
    _batch_size = 100
    deps_ansible = [
        {
            "name": "Set kingfisher architecture",
            "set_fact": {
                "bbot_kingfisher_arch": "{{ 'x64' if ansible_facts['architecture'] in ['x86_64', 'amd64'] else 'arm64' if ansible_facts['architecture'] in ['aarch64', 'arm64'] else ansible_facts['architecture'] }}"
            },
        },
        {
            "name": "Download kingfisher",
            "shell": {
                "cmd": "set -e\nif [ -x \"#{BBOT_TOOLS}/kingfisher\" ]; then exit 0; fi\ntmpdir=\"$(mktemp -d)\"\ntrap 'rm -rf \"$tmpdir\"' EXIT\ncurl -fsSL --retry 3 --connect-timeout 20 --max-time 180 -o \"$tmpdir/kingfisher.tgz\" \"https://github.com/mongodb/kingfisher/releases/download/v#{BBOT_MODULES_KINGFISHER_VERSION}/kingfisher-#{BBOT_OS_PLATFORM}-{{ bbot_kingfisher_arch }}.tgz\"\ntar -xzf \"$tmpdir/kingfisher.tgz\" -C \"$tmpdir\"\ninstall -m 0755 \"$(find \"$tmpdir\" -type f -name kingfisher | head -n1)\" \"#{BBOT_TOOLS}/kingfisher\""
            },
            "when": "ansible_facts['system'] in ['Linux', 'Darwin']",
        },
    ]

    async def setup(self):
        self.jobs = max(1, int(self.config.get("jobs", 1) or 1))
        return await super().setup()

    async def iter_findings(self, scan_path, event):
        for record in await self.run_kingfisher([scan_path]) or []:
            yield await self.format_record(event, scan_path, record)

    async def scan_file_batch(self, paths):
        records = await self.run_kingfisher(paths)
        if records is None:
            return None
        return [(record.get("finding", {}).get("path", ""), record) for record in records]

    async def run_kingfisher(self, paths):
        """Run one Kingfisher scan over `paths` and return its finding records, or None if it failed.

        Kingfisher spends seconds compiling its rules on every start, regardless of input size, so
        downloaded files are scanned in batches (see `_batch_size`) rather than one process each.
        """
        target = paths[0] if len(paths) == 1 else f"{len(paths)} files"
        command = [
            "kingfisher",
            "scan",
            *(str(path) for path in paths),
            "--format",
            "json",
            "--quiet",
            "--no-update-check",
            # Report every file a secret appears in, as separate per-file scans would.
            "--no-dedup",
            "--jobs",
            str(self.jobs),
        ]
        result = await self.run_process(command, _log_stderr=False)
        returncode = getattr(result, "returncode", None)
        if returncode not in self.success_exit_codes:
            stderr = str(getattr(result, "stderr", "") or "").strip()
            self.error(f"Kingfisher failed on {target} (rc={returncode}): {stderr[-500:]}")
            return None
        raw = str(getattr(result, "stdout", "") or "").strip()
        if not raw:
            # --quiet prints nothing for a clean scan.
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            self.error(f"Kingfisher returned unparseable JSON for {target} (rc={returncode}): {e}")
            return None
        findings = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
        if not isinstance(findings, list):
            self.error(f"Kingfisher returned an unexpected JSON shape for {target}: {type(findings).__name__}")
            return None
        return [
            record for record in findings if isinstance(record, dict) and isinstance(record.get("finding", {}), dict)
        ]

    async def format_record(self, event, scan_path, record):
        rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
        finding = record.get("finding") if isinstance(record.get("finding"), dict) else {}
        detector = rule.get("name") or rule.get("id") or "unknown"
        snippet = finding.get("snippet") or ""
        validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
        validation_status = str(validation.get("status", "unknown")).lower()
        # Kingfisher reports "Active Credential", "Inactive Credential" or "Not Attempted".
        verified = validation_status.startswith("active")
        git_metadata = finding.get("git_metadata") if isinstance(finding.get("git_metadata"), dict) else {}
        commit = git_metadata.get("commit") or ""
        if isinstance(commit, dict):
            commit = commit.get("id") or ""
        return await self.format_github_leak(
            event,
            scan_path,
            snippet,
            detector=detector,
            file_path=finding.get("path") or "",
            line=finding.get("line") or "",
            commit=commit,
            verified=verified,
            severity="High" if verified else "Medium",
            finding_details=record,
            extra_fields={
                "fingerprint": finding.get("fingerprint") or "",
                "validation_status": validation_status,
            },
        )
