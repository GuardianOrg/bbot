import sys

from bbot.modules.base import BaseModule


"""
wrapper for https://github.com/defparam/smuggler.git
"""


class smuggler(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "slow", "web-thorough"]
    meta = {"description": "Check for HTTP smuggling", "created_date": "2022-07-06", "author": "@liquidsec"}

    in_scope_only = True
    per_hostport_only = True

    deps_ansible = [
        {
            "name": "Get smuggler repo",
            "git": {"repo": "https://github.com/defparam/smuggler.git", "dest": "#{BBOT_TOOLS}/smuggler"},
        }
    ]

    async def handle_event(self, event):
        command = [
            sys.executable,
            f"{self.scan.helpers.tools_dir}/smuggler/smuggler.py",
            "--no-color",
            "-q",
            "-u",
            event.data,
        ]
        async for line in self.run_process_live(command):
            for f in line.split("\r"):
                if "Issue Found" in f:
                    technique = f.split(":")[0].rstrip()
                    text = f.split(":")[1].split("-")[0].strip()
                    description = (
                        f"The endpoint showed signs of HTTP request smuggling using the {technique} technique. "
                        "Request smuggling can cause front-end and back-end servers to disagree about request boundaries, potentially allowing cache poisoning, authentication bypass, request hijacking, or access to internal functionality. "
                        "For a non-specialist, the issue happens when one server thinks a request ends in one place while another server thinks it continues. "
                        "That mismatch can let an attacker hide a second request inside the first one and make the backend process it as if it came from another user or trusted component. "
                        "The affected proxy, load balancer, and application server should be patched and configured to reject ambiguous Content-Length or Transfer-Encoding combinations consistently. "
                        f"Observed evidence: [{text}]."
                    )
                    await self.emit_event(
                        {"host": str(event.host), "url": event.data, "description": description},
                        "FINDING",
                        parent=event,
                        context=f"{{module}} scanned {event.data} and found HTTP smuggling ({{event.type}}): {text}",
                    )
