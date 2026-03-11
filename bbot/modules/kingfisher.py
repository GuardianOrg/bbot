import json
from contextlib import suppress

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class kingfisher(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find hardcoded secrets using Kingfisher",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }

    options = {
        "version": "1.84.0",
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "version": "Kingfisher version",
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }
    deps_ansible = [
        {
            "name": "Set kingfisher architecture",
            "set_fact": {
                "bbot_kingfisher_arch": "{{ 'x64' if ansible_facts['architecture'] in ['x86_64', 'amd64'] else 'arm64' if ansible_facts['architecture'] in ['aarch64', 'arm64'] else ansible_facts['architecture'] }}"
            },
        },
        {
            "name": "Download kingfisher",
            "unarchive": {
                "src": "https://github.com/mongodb/kingfisher/releases/download/v#{BBOT_MODULES_KINGFISHER_VERSION}/kingfisher-#{BBOT_OS_PLATFORM}-{{ bbot_kingfisher_arch }}.tgz",
                "include": "kingfisher",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
            "when": "ansible_facts['system'] in ['Linux', 'Darwin']",
        },
    ]

    async def iter_findings(self, scan_path, event):
        command_variants = [
            ["kingfisher", "scan", str(scan_path), "--format", "json", "--quiet"],
            ["kingfisher", "scan", str(scan_path), "--format", "json"],
        ]
        for command in command_variants:
            result = await self.run_process(command, _log_stderr=False)
            raw = getattr(result, "stdout", "") or ""
            if not raw:
                continue
            with suppress(Exception):
                parsed = json.loads(raw)
                findings = parsed.get("findings", []) if isinstance(parsed, dict) else parsed
                if not isinstance(findings, list):
                    continue
                for record in findings:
                    if not isinstance(record, dict):
                        continue
                    rule = record.get("rule") if isinstance(record.get("rule"), dict) else {}
                    finding = record.get("finding") if isinstance(record.get("finding"), dict) else {}
                    detector = rule.get("name") or rule.get("id") or "unknown"
                    snippet = finding.get("snippet") or ""
                    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
                    validation_status = str(validation.get("status", "unknown")).lower()
                    verified = validation_status in ("active", "valid")
                    git_metadata = finding.get("git_metadata") if isinstance(finding.get("git_metadata"), dict) else {}
                    yield await self.format_github_leak(
                        event,
                        scan_path,
                        snippet,
                        detector=detector,
                        file_path=finding.get("path") or "",
                        line=finding.get("line") or "",
                        commit=git_metadata.get("commit") or "",
                        verified=verified,
                        severity="High" if verified else "Medium",
                        finding_details=record,
                        extra_fields={
                            "fingerprint": finding.get("fingerprint") or "",
                            "validation_status": validation_status,
                        },
                    )
                return
