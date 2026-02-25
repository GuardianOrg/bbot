import json
from bbot.modules.base import BaseModule


class deadfinder(BaseModule):
    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Detect dead-links (broken links) in discovered web pages",
        "created_date": "2026-02-25",
        "author": "@TheTechromancer",
    }
    options = {
        "version": "1.10.0",
        "timeout": 10,
        "concurrency": 50,
        "include_30x": False,
        "dryrun": False,
    }
    options_desc = {
        "version": "Deadfinder version to install",
        "timeout": "Per-request timeout in seconds",
        "concurrency": "Number of concurrent URL checks",
        "include_30x": "Include 30x redirects when identifying dead links",
        "dryrun": "Run in dry-run mode (only validate dependencies and inputs)",
    }
    deps_ansible = [
        {
            "name": "Install Ruby (Debian)",
            "package": {"name": ["ruby", "ruby-dev"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian'",
        },
        {
            "name": "Install Ruby (Arch)",
            "package": {"name": "ruby", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Archlinux'",
        },
        {
            "name": "Install Ruby (RedHat)",
            "package": {"name": "ruby", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'RedHat'",
        },
        {
            "name": "Install Ruby (Alpine)",
            "package": {"name": ["ruby", "ruby-dev"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Alpine'",
        },
        {
            "name": "Install deadfinder Ruby gem",
            "gem": {
                "name": "deadfinder",
                "version": "#{BBOT_MODULES_DEADFINDER_VERSION}",
                "state": "present",
                "user_install": False,
                "extra_args": "--no-document",
            },
            "become": True,
        },
    ]
    _batch_size = 200

    async def setup(self):
        self.timeout = self.config.get("timeout", 10)
        self.concurrency = self.config.get("concurrency", 50)
        self.include_30x = bool(self.config.get("include_30x", False))
        self.dryrun = self.config.get("dryrun", False)
        if not self.helpers.which("deadfinder"):
            return False, "deadfinder is not installed. Ensure dependencies are installed with --force-deps"
        return True

    async def handle_batch(self, *events):
        if self.dryrun:
            return

        url_events = {str(e.data): e for e in events if isinstance(e.data, str)}
        urls = list(url_events.keys())
        if not urls:
            return

        output_file = self.helpers.tempfile("", pipe=False, extension="json")
        command = self._build_command(output_file)
        process_result = await self.run_process(command, input=urls)

        deadfinder_results = self._load_results(output_file)
        if not deadfinder_results:
            if process_result.returncode != 0:
                self.warning(f"deadfinder exited with code {process_result.returncode}: {process_result.stderr}")
            return

        for target_url, dead_links in deadfinder_results.items():
            source_event = url_events.get(target_url)
            if source_event is None:
                source_event = next((event for event in events if target_url == str(event.data)), None)
            if source_event is None:
                continue
            if not dead_links:
                continue
            for dead_link in dead_links:
                if not dead_link:
                    continue
                await self.emit_event(
                    {
                        "severity": "MEDIUM",
                        "host": str(source_event.host),
                        "url": str(source_event.data),
                        "dead_link": dead_link,
                        "description": f"Dead link found while scanning {target_url}: {dead_link}",
                    },
                    "VULNERABILITY",
                    parent=source_event,
                    tags=["deadlink", "deadfinder"],
                    context=f'{{module}} found a dead link on {{event.host}}: {dead_link}',
                )

    def _build_command(self, output_file):
        command = [
            "deadfinder",
            "pipe",
            "-o",
            str(output_file),
            "-f",
            "json",
            "--silent",
            "--timeout",
            str(self.timeout),
            "--concurrency",
            str(self.concurrency),
        ]
        if self.include_30x:
            command.append("--include30x")
        return command

    def _load_results(self, output_file):
        try:
            with open(output_file, "r", errors="ignore") as result_file:
                payload = json.load(result_file)
        except json.JSONDecodeError as e:
            self.debug(f"Failed to decode deadfinder output JSON ({output_file}): {e}")
            return {}
        except Exception as e:
            self.warning(f"Unable to read deadfinder output file {output_file}: {e}")
            return {}

        if not isinstance(payload, dict):
            return {}

        if "dead_links" in payload:
            dead_links_payload = payload.get("dead_links", {})
            if isinstance(dead_links_payload, dict):
                return dead_links_payload
            return {}

        return payload
