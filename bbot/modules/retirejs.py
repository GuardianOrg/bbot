import json
from bbot.modules.base import BaseModule


class retirejs(BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Detect vulnerable/out-of-date JavaScript libraries",
        "created_date": "2025-08-19",
        "author": "@liquidsec",
    }
    scope_distance_modifier = 1
    options = {
        "version": "5.3.0",
    }
    options_desc = {
        "version": "retire.js version",
    }

    deps_ansible = [
        # Check if Node.js and npm are already installed
        {
            "name": "Check if Node.js is installed",
            "command": "which node",
            "register": "node_installed",
            "ignore_errors": True,
        },
        {
            "name": "Check if npm is installed",
            "command": "which npm",
            "register": "npm_installed",
            "ignore_errors": True,
        },
        # Install Node.js + npm
        {
            "name": "Install Node.js and npm",
            "package": {"name": ["nodejs", "npm"], "state": "present"},
            "become": True,
            "when": "node_installed.rc != 0 or npm_installed.rc != 0",
        },
        # Create retire.js local directory
        {
            "name": "Create retire.js directory in BBOT_TOOLS",
            "file": {"path": "#{BBOT_TOOLS}/retirejs", "state": "directory", "mode": "0755"},
        },
        # Check if retire.js is already installed locally
        {
            "name": "Check if retire.js is installed locally",
            "command": "test -f #{BBOT_TOOLS}/retirejs/node_modules/.bin/retire",
            "register": "retire_local_installed",
            "ignore_errors": True,
        },
        # Install retire.js locally
        {
            "name": "Install retire.js locally",
            "shell": "cd #{BBOT_TOOLS}/retirejs && npm install retire@#{BBOT_MODULES_RETIREJS_VERSION}",
            "when": "retire_local_installed.rc != 0",
        },
        # Create retire cache directory
        {
            "name": "Create retire cache directory",
            "file": {"path": "#{BBOT_CACHE}/retire_cache", "state": "directory", "mode": "0755"},
        },
    ]

    accept_js_url = True

    async def setup(self):
        excavate_enabled = self.scan.config.get("excavate")
        if not excavate_enabled:
            return False, "retirejs will not function without excavate enabled"
        return True

    async def handle_event(self, event):
        js_file = await self.helpers.request(event.data)
        if js_file:
            js_file_body = js_file.text
            if js_file_body:
                js_file_body_saved = self.helpers.tempfile(js_file_body, pipe=False, extension="js")
                results = await self.execute_retirejs(js_file_body_saved)
                if not results:
                    self.warning("no output from retire.js")
                    return
                results_json = json.loads(results)
                if results_json.get("data"):
                    for file_result in results_json["data"]:
                        for component_result in file_result.get("results", []):
                            component = component_result.get("component", "unknown")
                            version = component_result.get("version", "unknown")
                            vulnerabilities = component_result.get("vulnerabilities", [])
                            for vuln in vulnerabilities:
                                severity = vuln.get("severity", "unknown")
                                identifiers = vuln.get("identifiers", {})
                                summary = identifiers.get("summary", "Unknown vulnerability")
                                cves = identifiers.get("CVE", [])
                                description_parts = [
                                    f"Vulnerable JavaScript library detected: {component} v{version}",
                                    f"Severity: {severity.upper()}",
                                    f"Summary: {summary}",
                                    f"JavaScript URL: {event.data}",
                                ]
                                if cves:
                                    description_parts.append(f"CVE(s): {', '.join(cves)}")

                                below_version = vuln.get("below", "")
                                at_or_above = vuln.get("atOrAbove", "")
                                if at_or_above and below_version:
                                    description_parts.append(f"Affected versions: [{at_or_above} to {below_version})")
                                elif below_version:
                                    description_parts.append(f"Affected versions: [< {below_version}]")
                                elif at_or_above:
                                    description_parts.append(f"Affected versions: [>= {at_or_above}]")
                                description = " ".join(description_parts)
                                data = {
                                    "description": description,
                                    "severity": severity,
                                    "component": component,
                                    "url": event.parent.data["url"],
                                }
                                await self.emit_event(
                                    data,
                                    "FINDING",
                                    parent=event,
                                    context=f"{{module}} identified vulnerable JavaScript library {component} v{version} ({severity} severity)",
                                )

    async def filter_event(self, event):
        if str(event.parent.module) != "httpx" or event.parent.type != "HTTP_RESPONSE":
            return False, f"parent event was not an HTTP_RESPONSE from httpx ({event.parent.module})"
        return True

    async def execute_retirejs(self, js_file):
        cache_dir = self.helpers.cache_dir / "retire_cache"
        retire_dir = self.scan.helpers.tools_dir / "retirejs"

        command = [
            "npm",
            "exec",
            "--prefix",
            str(retire_dir),
            "retire",
            "--",
            "--outputformat",
            "json",
            "--cachedir",
            str(cache_dir),
            "--path",
            js_file,
        ]

        proxy = self.scan.web_config.get("http_proxy")
        if proxy:
            command.extend(["--proxy", proxy])

        self.verbose(f"Running retire.js on {js_file}")
        self.verbose(f"retire.js command: {command}")

        result = await self.run_process(command)
        return result.stdout
