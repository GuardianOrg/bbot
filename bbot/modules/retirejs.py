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
        "node_version": "18.19.1",
    }
    options_desc = {
        "version": "retire.js version",
        "node_version": "Node.js version to install locally",
    }

    deps_ansible = [
        # Download Node.js binary (Linux x64)
        {
            "name": "Download Node.js binary (Linux x64)",
            "get_url": {
                "url": "https://nodejs.org/dist/v#{BBOT_MODULES_RETIREJS_NODE_VERSION}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64.tar.xz",
                "dest": "#{BBOT_TEMP}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64.tar.xz",
                "mode": "0644",
            },
        },
        # Extract Node.js binary (x64)
        {
            "name": "Extract Node.js binary (x64)",
            "unarchive": {
                "src": "#{BBOT_TEMP}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64.tar.xz",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
        # Remove existing node directory if it exists
        {
            "name": "Remove existing node directory",
            "file": {"path": "#{BBOT_TOOLS}/node", "state": "absent"},
        },
        # Rename extracted directory to 'node' (x64)
        {
            "name": "Rename Node.js directory (x64)",
            "command": "mv #{BBOT_TOOLS}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-x64 #{BBOT_TOOLS}/node",
        },
        # Make Node.js binary executable
        {
            "name": "Make Node.js binary executable",
            "file": {"path": "#{BBOT_TOOLS}/node/bin/node", "mode": "0755"},
        },
        # Make npm executable
        {
            "name": "Make npm executable",
            "file": {"path": "#{BBOT_TOOLS}/node/bin/npm", "mode": "0755"},
        },
        # Create retire.js local directory
        {
            "name": "Create retire.js directory in BBOT_TOOLS",
            "file": {"path": "#{BBOT_TOOLS}/retirejs", "state": "directory", "mode": "0755"},
        },
        # Install retire.js locally using local Node.js
        {
            "name": "Install retire.js locally",
            "shell": "cd #{BBOT_TOOLS}/retirejs && #{BBOT_TOOLS}/node/bin/node #{BBOT_TOOLS}/node/lib/node_modules/npm/bin/npm-cli.js install retire@#{BBOT_MODULES_RETIREJS_VERSION} --no-fund --no-audit --silent --no-optional",
            "args": {"creates": "#{BBOT_TOOLS}/retirejs/node_modules/.bin/retire"},
            "timeout": 600,
            "ignore_errors": False,
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
        local_node_dir = self.scan.helpers.tools_dir / "node"

        command = [
            str(local_node_dir / "bin" / "npm"),
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
