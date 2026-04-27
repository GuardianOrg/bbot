import json
from pathlib import Path

from bbot.modules.templates.subdomain_enum import subdomain_enum


class subfinder(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Enumerate subdomains with ProjectDiscovery Subfinder",
        "created_date": "2026-04-24",
        "author": "@carlospolop",
    }
    options = {
        "binary": "subfinder",
        "version": "2.13.0",
        "all": True,
        "recursive": False,
        "collect_sources": True,
        "timeout": 45,
        "max_time": 30,
        "rate_limit": 0,
        "provider_config": "",
        "sources": "",
        "exclude_sources": "",
    }
    options_desc = {
        "binary": "Path to the subfinder executable",
        "version": "Subfinder version to install",
        "all": "Use all passive sources supported by subfinder",
        "recursive": "Restrict enumeration to recursive-capable sources only",
        "collect_sources": "Collect source names in JSON output for debugging",
        "timeout": "Seconds to wait before timing out source requests",
        "max_time": "Maximum number of minutes to wait for enumeration results",
        "rate_limit": "Maximum HTTP requests per second across sources (0 disables)",
        "provider_config": "Optional path to a provider-config.yaml file",
        "sources": "Optional comma-separated list of sources to include",
        "exclude_sources": "Optional comma-separated list of sources to exclude",
    }
    deps_ansible = [
        {
            "name": "Download subfinder",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/subfinder/releases/download/v#{BBOT_MODULES_SUBFINDER_VERSION}/subfinder_#{BBOT_MODULES_SUBFINDER_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "subfinder",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
        {
            "name": "Ensure subfinder executable mode",
            "file": {"path": "#{BBOT_TOOLS}/subfinder", "mode": "0755"},
        },
    ]

    @property
    def source_pretty_name(self):
        return "Subfinder"

    async def setup(self):
        self.binary = str(self.config.get("binary", "subfinder")).strip()
        self.use_all = bool(self.config.get("all", True))
        self.recursive_only = bool(self.config.get("recursive", False))
        self.collect_sources = bool(self.config.get("collect_sources", True))
        self.timeout = max(1, int(self.config.get("timeout", 30)))
        self.max_time = max(1, int(self.config.get("max_time", 15)))
        self.rate_limit = max(0, int(self.config.get("rate_limit", 0)))
        self.provider_config = str(self.config.get("provider_config", "")).strip()
        self.sources = self._normalize_csv_option(self.config.get("sources", ""))
        self.exclude_sources = self._normalize_csv_option(self.config.get("exclude_sources", ""))

        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"subfinder binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            tools_binary = self.helpers.tools_dir / self.binary
            if tools_binary.is_file():
                self.binary = str(tools_binary)
            else:
                return None, f'subfinder binary "{self.binary}" was not found in PATH'

        return await super().setup()

    def _normalize_csv_option(self, value):
        if isinstance(value, (list, tuple, set)):
            return [str(entry).strip() for entry in value if str(entry).strip()]
        if isinstance(value, str):
            return [entry.strip() for entry in value.split(",") if entry.strip()]
        return []

    def _build_command(self, query):
        subfinder_command = [
            self.binary,
            "-d",
            query,
            "-silent",
            "-oJ",
            "-duc",
            "-timeout",
            str(self.timeout),
            "-max-time",
            str(self.max_time),
        ]

        if self.collect_sources:
            subfinder_command.append("-cs")
        if self.use_all:
            subfinder_command.append("-all")
        if self.recursive_only:
            subfinder_command.append("-recursive")
        if self.rate_limit > 0:
            subfinder_command.extend(["-rl", str(self.rate_limit)])
        if self.provider_config:
            subfinder_command.extend(["-pc", self.provider_config])
        if self.sources:
            subfinder_command.extend(["-s", ",".join(self.sources)])
        if self.exclude_sources:
            subfinder_command.extend(["-es", ",".join(self.exclude_sources)])

        timeout_binary = self.helpers.which("timeout")
        if timeout_binary:
            # Subfinder occasionally keeps provider workers alive after it has already
            # emitted results. Give it a little extra time past max_time, then force
            # termination so BBOT can complete and persist the collected output.
            hard_timeout_seconds = max((self.max_time * 60) + 120, self.timeout + 30)
            return [timeout_binary, str(hard_timeout_seconds), *subfinder_command]

        return subfinder_command

    async def query(self, query, request_fn=None, parse_fn=None):
        command = self._build_command(query)
        result = await self.run_process(command, _log_stderr=False)

        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""
        returncode = getattr(result, "returncode", 0)

        if returncode != 0 and not stdout.strip():
            self.info(f'Subfinder query for "{query}" failed with code {returncode}: {stderr.strip()}')
            return []

        discovered = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            candidate = None
            try:
                entry = json.loads(line)
            except Exception:
                candidate = line
            else:
                candidate = entry.get("host") or entry.get("domain") or entry.get("input")

            if not isinstance(candidate, str):
                continue

            hostname = candidate.lower().strip().rstrip(".")
            while hostname.startswith("*."):
                hostname = hostname[2:]
            if hostname:
                discovered.add(hostname)

        if not discovered:
            self.debug(f'No results for "{query}"')
        return discovered
