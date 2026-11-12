import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from enum import IntEnum
from urllib.parse import urlsplit
from bbot.modules.base import BaseModule


class RetireJSSeverity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, severity_str):
        try:
            return cls[severity_str.upper()]
        except (KeyError, AttributeError):
            return cls.NONE


# Advisory data the module reads; it is tooling input, never a scan target.
RETIREJS_REPOSITORY_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
EXPLOITABILITY_NOTE = "Version matched to public advisories; application exploitability has not been verified."
COVERAGE_FIELDS = (
    "offered", "downloaded", "download_failed", "oversized", "empty",
    "no_output", "analysis_failed", "analyzed", "findings",
)


def affected_versions(vuln):
    below_version = vuln.get("below", "")
    at_or_above = vuln.get("atOrAbove", "")
    if at_or_above and below_version:
        return f"[{at_or_above} to {below_version})"
    if below_version:
        return f"[< {below_version}]"
    if at_or_above:
        return f"[>= {at_or_above}]"
    return ""


def advisory_text(vuln):
    """One advisory as the finding lists it: severity, summary, CVEs and affected versions."""
    identifiers = vuln.get("identifiers", {})
    cves = identifiers.get("CVE", [])
    if isinstance(cves, str):
        cves = [cves]
    parts = [f"[{str(vuln.get('severity', 'unknown')).upper()}] {identifiers.get('summary', 'Unknown vulnerability')}"]
    if cves:
        parts.append(f"CVE(s): {', '.join(cves)}")
    versions = affected_versions(vuln)
    if versions:
        parts.append(f"Affected versions: {versions}")
    return " ".join(parts), cves


def library_findings(results_json, min_severity, javascript_url, page_url):
    """
    One finding per library version a script bundles, listing every advisory at or above
    `min_severity` and rated by the most severe of them. Advisories of one library version
    are one fix (upgrade it), so they are one finding, not one each.
    """
    findings = []
    for file_result in results_json.get("data") or []:
        for component_result in file_result.get("results", []):
            component = component_result.get("component", "unknown")
            version = component_result.get("version", "unknown")
            advisories = [
                vuln
                for vuln in component_result.get("vulnerabilities", [])
                if RetireJSSeverity.from_string(vuln.get("severity", "unknown")) >= min_severity
            ]
            if not advisories:
                continue
            advisories.sort(key=lambda vuln: -RetireJSSeverity.from_string(vuln.get("severity", "unknown")))
            severity = advisories[0].get("severity", "unknown")
            texts, cves, advisory_urls = [], [], []
            for vuln in advisories:
                text, vuln_cves = advisory_text(vuln)
                texts.append(text)
                cves.extend(cve for cve in vuln_cves if cve not in cves)
                advisory_urls.extend(url for url in vuln.get("info") or [] if url not in advisory_urls)
            count = f"{len(advisories)} advisor{'y' if len(advisories) == 1 else 'ies'}"
            description = (
                f"Vulnerable JavaScript library detected: {component} v{version} Severity: {severity.upper()} "
                f"JavaScript URL: {javascript_url} {count}: {'; '.join(texts)}. {EXPLOITABILITY_NOTE}"
            )
            data = {
                "title": f"Vulnerable JavaScript library {component} v{version}",
                "description": description,
                "severity": severity,
                "component": component,
                "version": version,
                "cves": cves,
                "javascript_url": javascript_url,
                "url": page_url,
            }
            if advisory_urls:
                data["advisory_urls"] = advisory_urls
            findings.append(data)
    return findings


def url_origin(url):
    try:
        parsed = urlsplit(str(url or ""))
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    except ValueError:
        return str(url or "")


class retirejs(BaseModule):
    watched_events = ["URL_UNVERIFIED"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Detect vulnerable/out-of-date JavaScript libraries",
        "created_date": "2025-08-19",
        "author": "@liquidsec",
    }
    options = {
        "version": "5.3.0",
        "node_version": "18.19.1",
        "severity": "medium",
        "max_js_size": 5242880,
        "timeout": 30,
    }
    options_desc = {
        "version": "retire.js version",
        "node_version": "Node.js version to install locally",
        "severity": "Minimum severity level to report (none, low, medium, high, critical)",
        "max_js_size": "Maximum complete JavaScript bytes to analyze (oversized scripts are reported as skipped)",
        "timeout": "Maximum seconds per script download or RetireJS analysis",
    }

    deps_ansible = [
        # Pick the proper Node.js architecture for this runtime
        {
            "name": "Set Node.js architecture",
            "set_fact": {
                "bbot_retirejs_node_arch": "{{ 'x64' if ansible_architecture in ['x86_64', 'amd64'] else 'arm64' if ansible_architecture in ['aarch64', 'arm64'] else ansible_architecture }}"
            },
        },
        # Download Node.js binary
        {
            "name": "Download Node.js binary",
            "get_url": {
                "url": "https://nodejs.org/dist/v#{BBOT_MODULES_RETIREJS_NODE_VERSION}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux-{{ bbot_retirejs_node_arch }}.tar.xz",
                "dest": "#{BBOT_TEMP}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux.tar.xz",
                "mode": "0644",
            },
        },
        # Remove existing node directory if it exists
        {
            "name": "Remove existing node directory",
            "file": {"path": "#{BBOT_TOOLS}/node", "state": "absent"},
        },
        # Create node directory
        {
            "name": "Create node directory",
            "file": {"path": "#{BBOT_TOOLS}/node", "state": "directory", "mode": "0755"},
        },
        # Extract Node.js binary into #{BBOT_TOOLS}/node
        {
            "name": "Extract Node.js binary",
            "unarchive": {
                "src": "#{BBOT_TEMP}/node-v#{BBOT_MODULES_RETIREJS_NODE_VERSION}-linux.tar.xz",
                "dest": "#{BBOT_TOOLS}/node",
                "remote_src": True,
                "extra_opts": ["--strip-components=1"],
            },
        },
        # Set permissions on entire Node.js bin directory
        {
            "name": "Set permissions on Node.js bin directory",
            "file": {"path": "#{BBOT_TOOLS}/node/bin", "mode": "0755", "recurse": "yes"},
        },
        # Make Node.js binary executable
        {
            "name": "Make Node.js binary executable",
            "file": {"path": "#{BBOT_TOOLS}/node/bin/node", "mode": "0755"},
        },
        # Remove existing retirejs directory if it exists
        {
            "name": "Remove existing retirejs directory",
            "file": {"path": "#{BBOT_TOOLS}/retirejs", "state": "absent"},
        },
        # Create retire.js local directory
        {
            "name": "Create retire.js directory in BBOT_TOOLS",
            "file": {"path": "#{BBOT_TOOLS}/retirejs", "state": "directory", "mode": "0755"},
        },
        # Install retire.js locally using local Node.js
        {
            "name": "Install retire.js locally",
            "shell": "cd #{BBOT_TOOLS}/retirejs && #{BBOT_TOOLS}/node/bin/node #{BBOT_TOOLS}/node/lib/node_modules/npm/bin/npm-cli.js install --prefix . retire@#{BBOT_MODULES_RETIREJS_VERSION} --no-fund --no-audit --silent --no-optional",
            "args": {"creates": "#{BBOT_TOOLS}/retirejs/node_modules/.bin/retire"},
            "timeout": 600,
            "ignore_errors": False,
        },
        # Make retire script executable
        {
            "name": "Make retire script executable",
            "file": {"path": "#{BBOT_TOOLS}/retirejs/node_modules/.bin/retire", "mode": "0755"},
        },
        # Create retire cache directory
        {
            "name": "Create retire cache directory",
            "file": {"path": "#{BBOT_CACHE}/retire_cache", "state": "directory", "mode": "0755"},
        },
    ]

    accept_url_special = True
    scope_distance_modifier = 1
    _module_threads = 4

    async def setup(self):
        self._coverage = {field: 0 for field in COVERAGE_FIELDS}
        excavate_enabled = self.scan.config.get("excavate")
        if not excavate_enabled:
            return None, "retirejs will not function without excavate enabled"

        # Validate severity level
        valid_severities = ["none", "low", "medium", "high", "critical"]
        configured_severity = self.config.get("severity", "medium").lower()
        if configured_severity not in valid_severities:
            return (
                False,
                f"Invalid severity level '{configured_severity}'. Valid options are: {', '.join(valid_severities)}",
            )

        self.repofile = await self.helpers.download(RETIREJS_REPOSITORY_URL, cache_hrs=24)
        if not self.repofile:
            return False, "failed to download retire.js repository file"
        # (website origin, library, version) already reported: other scripts of the
        # website bundling the same library version add nothing to fix.
        self._reported = set()
        return True

    async def handle_event(self, event):
        if not hasattr(self, "_coverage"):
            self._coverage = {field: 0 for field in COVERAGE_FIELDS}
        self._coverage["offered"] += 1
        max_size = max(1, int(self.config.get("max_js_size", 5242880)))
        timeout = max(1, int(self.config.get("timeout", 30)))
        with TemporaryDirectory(prefix="bbot-retirejs-") as directory:
            filename = Path(directory) / "library.js"
            try:
                downloaded = await asyncio.wait_for(
                    self.helpers.download(
                        event.data,
                        filename=filename,
                        max_size=max_size + 8192,
                        follow_redirects=False,
                        timeout=timeout,
                        warn=False,
                        headers=dict(self.scan.custom_http_headers),
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                self._coverage["download_failed"] += 1
                self.warning(f"JavaScript download exceeded {timeout}s: {event.data}")
                return
            except Exception:
                self._coverage["download_failed"] += 1
                raise
            if not downloaded:
                self._coverage["download_failed"] += 1
                return
            self._coverage["downloaded"] += 1
            if filename.stat().st_size > max_size:
                self._coverage["oversized"] += 1
                self.warning(f"Skipping JavaScript larger than {max_size} bytes: {event.data}")
                return
            if not filename.stat().st_size:
                self._coverage["empty"] += 1
                return
            try:
                results = await self.execute_retirejs(str(filename))
                if not results:
                    self._coverage["no_output"] += 1
                    await self.report_results(event, results)
                    return
                await self.report_results(event, results)
            except Exception:
                self._coverage["analysis_failed"] += 1
                raise
            self._coverage["analyzed"] += 1

    async def report(self):
        coverage = getattr(self, "_coverage", {field: 0 for field in COVERAGE_FIELDS})
        self.info(f"RetireJS coverage: {json.dumps(coverage, sort_keys=True, separators=(',', ':'))}")

    async def report_results(self, event, results):
        if not results:
            self.warning("no output from retire.js")
            return
        min_severity = RetireJSSeverity.from_string(self.config.get("severity", "medium"))
        page_url = self.page_url(event)
        for data in library_findings(json.loads(results), min_severity, event.data, page_url):
            key = (url_origin(page_url), data["component"].lower(), data["version"])
            if key in self._reported:
                self.debug(f"{data['component']} v{data['version']} on {key[0]} is already reported")
                continue
            self._reported.add(key)
            await self.emit_event(
                data,
                "FINDING",
                parent=event,
                context=f"{{module}} identified vulnerable JavaScript library {data['component']} v{data['version']} ({data['severity']} severity)",
            )
            self._coverage["findings"] += 1

    async def filter_event(self, event):
        if not self.scan.in_scope(event):
            return False, "script is outside scan scope"
        url_extension = getattr(event, "url_extension", "")
        if url_extension != "js":
            return False, f"it is a {url_extension} URL but retirejs only accepts js URLs"
        return True

    @staticmethod
    def page_url(event):
        parent = event.parent
        # BBOT's SCAN root deliberately points to itself.
        while parent is not None and parent.type != "SCAN":
            if parent.type == "HTTP_RESPONSE" and isinstance(parent.data, dict):
                return parent.data.get("url") or event.data
            if parent.type == "URL" and isinstance(parent.data, str):
                return parent.data
            parent = parent.parent
        return event.data

    async def execute_retirejs(self, js_file):
        cache_dir = self.helpers.cache_dir / "retire_cache"
        retire_dir = self.scan.helpers.tools_dir / "retirejs"
        local_node_dir = self.scan.helpers.tools_dir / "node"

        # Use the retire binary directly with our local Node.js
        retire_binary_path = retire_dir / "node_modules" / ".bin" / "retire"
        command = [
            str(local_node_dir / "bin" / "node"),
            str(retire_binary_path),
            "--outputformat",
            "json",
            "--cachedir",
            str(cache_dir),
            "--path",
            js_file,
            "--jsrepo",
            str(self.repofile),
        ]

        proxy = self.scan.web_config.get("http_proxy")
        if proxy:
            command.extend(["--proxy", proxy])

        self.verbose(f"Running retire.js on {js_file}")
        self.verbose(f"retire.js command: {command}")

        result = await self.run_process(command, idle_timeout=max(1, int(self.config.get("timeout", 30))))
        # RetireJS uses 13 to report successfully identified vulnerable libraries.
        if result is None or result.returncode not in (0, 13):
            raise RuntimeError("RetireJS analysis failed")
        return result.stdout
