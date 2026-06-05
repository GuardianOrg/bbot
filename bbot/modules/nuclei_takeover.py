import json
import os
import asyncio
import subprocess
from urllib.parse import urlparse

from bbot.modules.base import BaseModule


class nuclei_takeover(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "subdomain-hijack"]
    meta = {
        "description": "Check potential subdomain takeovers from stale or unclaimed DNS records",
        "created_date": "2026-02-20",
        "author": "@carlospolop",
    }

    options = {
        "version": "3.6.2",
        "tags": "takeover",
        "templates": "",
        "etags": "",
        "ratelimit": 150,
        "concurrency": 25,
        "retries": 1,
        "timeout": 10,
        "module_timeout": 180,
        "check_unresolved": False,
        "silent": True,
    }
    options_desc = {
        "version": "nuclei version",
        "tags": "Nuclei tags to run (default: takeover)",
        "templates": "Optional nuclei templates/template-dirs to include",
        "etags": "Optional nuclei tags to exclude",
        "ratelimit": "Nuclei request rate limit per second",
        "concurrency": "Nuclei template concurrency",
        "retries": "Nuclei retries",
        "timeout": "Nuclei timeout in seconds",
        "module_timeout": "Maximum seconds to wait for a nuclei takeover batch before skipping it",
        "check_unresolved": "Also run takeover templates against DNS_NAME_UNRESOLVED events",
        "silent": "Only show findings output from nuclei",
    }

    deps_ansible = [
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v#{BBOT_MODULES_NUCLEI_TAKEOVER_VERSION}/nuclei_#{BBOT_MODULES_NUCLEI_TAKEOVER_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "nuclei",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]
    _batch_size = 500
    in_scope_only = True
    domain_seed_scope_only = True

    async def setup(self):
        self.nuclei_bin = str((self.helpers.tools_dir / "nuclei").resolve())
        if not os.path.isfile(self.nuclei_bin):
            return None, 'nuclei binary "nuclei" was not found in PATH'
        self.nuclei_templates_dir = self.helpers.tools_dir / "nuclei-templates"
        should_update_templates = (
            os.environ.get("BBOT_NUCLEI_UPDATE_TEMPLATES") == "1" or not self.nuclei_templates_dir.exists()
        )
        if should_update_templates:
            self.info("Updating Nuclei templates for takeover scans")
            update_result = await self.run_process(
                [self.nuclei_bin, "-update-template-dir", self.nuclei_templates_dir, "-update-templates"]
            )
            if update_result.returncode != 0:
                self.warning(f"Failed to update nuclei templates: {update_result.stderr}")
        elif self.nuclei_templates_dir.exists():
            self.info("Using existing Nuclei templates for takeover scans")
        else:
            self.warning(
                "Nuclei templates directory does not exist and template updates are disabled; "
                "set BBOT_NUCLEI_UPDATE_TEMPLATES=1 to auto-download templates"
            )
        self.takeover_templates_dir = self.nuclei_templates_dir / "http" / "takeovers"
        self.tags = str(self.config.get("tags", "takeover")).strip() or "takeover"
        self.templates = str(self.config.get("templates", "")).strip()
        self.etags = str(self.config.get("etags", "")).strip()
        self.ratelimit = int(self.config.get("ratelimit", 150))
        self.concurrency = int(self.config.get("concurrency", 25))
        self.retries = int(self.config.get("retries", 1))
        self.timeout = int(self.config.get("timeout", 10))
        self.module_timeout = int(self.config.get("module_timeout", 180))
        self.check_unresolved = bool(self.config.get("check_unresolved", False))
        self.silent = bool(self.config.get("silent", True))
        return True

    async def filter_event(self, event):
        if event.type == "DNS_NAME_UNRESOLVED" and not self.check_unresolved:
            return False, "unresolved DNS takeover checks are disabled"
        return True

    async def handle_batch(self, *events):
        targets = []
        parent_by_host = {}
        for event in events:
            host = str(event.host or "").strip().rstrip(".").lower()
            if not host:
                continue
            if host not in parent_by_host:
                parent_by_host[host] = event
                targets.append(host)

        if not targets:
            return

        command = [
            self.nuclei_bin,
            "-jsonl",
            "-disable-update-check",
            "-update-template-dir",
            self.nuclei_templates_dir,
            "-tags",
            self.tags,
            "-rate-limit",
            str(self.ratelimit),
            "-retries",
            str(self.retries),
            "-timeout",
            str(self.timeout),
        ]
        if self.silent:
            command.append("-silent")
        if self.templates:
            command += ["-t", self.templates]
        elif self.takeover_templates_dir.exists():
            command += ["-t", str(self.takeover_templates_dir)]
        elif self.nuclei_templates_dir.exists():
            command += ["-t", str(self.nuclei_templates_dir), "-tags", self.tags]
        if self.etags:
            command += ["-etags", self.etags]
        target_file = self.helpers.tempfile(targets, pipe=False)
        command += ["-l", target_file]
        self.info(f"Running nuclei takeover command: {' '.join(str(part) for part in command)}")
        process = self.run_process_live(command, stderr=subprocess.DEVNULL)
        try:
            async with asyncio.timeout(self.module_timeout):
                async for line in process:
                    self.info(f"nuclei_takeover raw output: {line}")
                    try:
                        finding = json.loads(line)
                    except Exception:
                        self.warning(f"nuclei_takeover failed to parse line: {line}")
                        continue

                    host = self.normalize_host(finding.get("host", "") or finding.get("matched-at", ""))
                    if not host:
                        continue
                    parent_event = parent_by_host.get(host)
                    if parent_event is None:
                        continue

                    info = finding.get("info", {}) if isinstance(finding.get("info"), dict) else {}
                    template_id = finding.get("template-id", "unknown")
                    name = info.get("name", "unknown")
                    matched_at = finding.get("matched-at", "")
                    matcher = finding.get("matcher-name", "")
                    extracted = finding.get("extracted-results", [])
                    if isinstance(extracted, list) and extracted:
                        extracted_str = ",".join(str(x) for x in extracted[:8])
                    else:
                        extracted_str = ""

                    description = (
                        f"The hostname matched a subdomain takeover condition [{template_id}] named [{name}] at [{matched_at}]. "
                        "Subdomain takeover can happen when DNS still points a hostname to an external provider resource that the organization no longer owns, has not claimed, or has not finished configuring. "
                        "The attacker does not need to compromise DNS or the main application; they may only need to claim the missing provider-side resource. "
                        "If confirmed, they can publish content under a trusted hostname, enabling phishing, malicious redirects, fake login pages, cookie or token exposure, content spoofing, and reputational damage. "
                        "Reclaim the external resource, complete the provider configuration, or remove the stale DNS record."
                    )
                    if matcher:
                        description += f" matcher [{matcher}]"
                    if extracted_str:
                        description += f" extracted [{extracted_str}]"

                    severity = str(info.get("severity", "")).lower().strip()
                    event_type = "VULNERABILITY"
                    poc_parts = []
                    if matched_at:
                        poc_parts.append(f"Matched At: {matched_at}")
                    if extracted_str:
                        poc_parts.append(f"Extracted Results: {extracted_str}")
                    if matcher:
                        poc_parts.append(f"Matcher: {matcher}")
                    url_value = matched_at if "://" in str(matched_at) else None
                    event_data = {
                        "title": name,
                        "category": "subdomain-takeover",
                        "description": description,
                        "recommendation": "Validate the dangling DNS target and reclaim or remove the stale integration before it can be taken over.",
                        "host": host,
                        "url": url_value,
                        "poc": "\n".join(poc_parts) or None,
                    }
                    if severity in ("info", "unknown", ""):
                        event_type = "FINDING"
                    else:
                        event_data["severity"] = severity.upper()

                    await self.emit_event(
                        event_data,
                        event_type,
                        parent_event,
                        tags=["takeover", "nuclei-takeover"],
                        context=f'{{module}} used nuclei takeover templates and found {{event.type}} on "{host}"',
                    )
        except TimeoutError:
            self.warning(
                f"nuclei_takeover exceeded {self.module_timeout:g}s for batch of {len(targets)} targets, skipping batch"
            )
        finally:
            await process.aclose()

    @staticmethod
    def normalize_host(value):
        text = str(value or "").strip()
        if not text:
            return ""
        if "://" in text:
            text = urlparse(text).hostname or ""
        else:
            text = text.split("/")[0]
            text = text.split(":")[0]
        return text.strip().rstrip(".").lower()
