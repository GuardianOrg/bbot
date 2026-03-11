import json
import os
from contextlib import suppress

from bbot.modules.templates.code_secret_scanner import code_secret_scanner


class ggshield(code_secret_scanner):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Find hardcoded secrets using GitGuardian ggshield",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
    }
    deps_pip = ["ggshield"]

    options = {
        "output_folder": "",
        "clone_repositories": True,
    }
    options_desc = {
        "output_folder": "Folder to clone repositories to. If not specified, repositories are deleted after scanning.",
        "clone_repositories": "Clone CODE_REPOSITORY events before scanning.",
    }

    async def setup(self):
        setup_result = await super().setup()
        if setup_result is not True:
            return setup_result

        has_api_key = bool(os.getenv("GITGUARDIAN_API_KEY") or os.getenv("GGSHIELD_API_KEY"))
        if not has_api_key:
            return None, "Set GITGUARDIAN_API_KEY or GGSHIELD_API_KEY to enable ggshield secret scanning"
        return True

    async def iter_findings(self, scan_path, event):
        command = [
            "ggshield",
            "secret",
            "scan",
            "path",
            "--recursive",
            "--json",
            str(scan_path),
        ]
        result = await self.run_process(command, _log_stderr=False)
        raw = getattr(result, "stdout", "") or ""
        if not raw:
            return

        with suppress(Exception):
            parsed = json.loads(raw)
            entries = parsed if isinstance(parsed, list) else [parsed]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                incidents = entry.get("policy_breaks", [])
                if not incidents and isinstance(entry.get("secrets"), list):
                    incidents = entry["secrets"]
                if not isinstance(incidents, list):
                    continue

                for incident in incidents:
                    if not isinstance(incident, dict):
                        continue
                    policy = incident.get("policy")
                    if isinstance(policy, dict):
                        policy_name = policy.get("name", "unknown")
                    else:
                        policy_name = policy or "unknown"
                    match = incident.get("match") or incident.get("matches") or ""
                    validity = str(incident.get("validity", "unknown")).lower()
                    verified = validity in ("valid", "active")
                    location = incident.get("location") if isinstance(incident.get("location"), dict) else {}
                    file_name = (
                        incident.get("filename")
                        or incident.get("file")
                        or incident.get("path")
                        or location.get("path")
                        or ""
                    )
                    line = (
                        incident.get("line_start")
                        or incident.get("start_line")
                        or incident.get("line")
                        or location.get("line_start")
                        or location.get("line")
                        or ""
                    )
                    yield await self.format_github_leak(
                        event,
                        scan_path,
                        match,
                        detector=policy_name,
                        file_path=file_name,
                        line=line,
                        verified=verified,
                        severity="High" if verified else "Medium",
                        finding_details=incident,
                    )
