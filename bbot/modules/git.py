import re

from bbot.modules.base import BaseModule


class git(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING", "CODE_REPOSITORY"]
    flags = ["active", "safe", "web-basic", "code-enum"]
    meta = {
        "description": "Check for exposed .git repositories",
        "created_date": "2023-05-30",
        "author": "@TheTechromancer",
    }

    in_scope_only = True

    fp_regex = re.compile(r"<html|<body", re.I)

    async def handle_event(self, event):
        base_url = event.data.rstrip("/")
        urls = {
            # look for git config in both
            self.helpers.urljoin(base_url, ".git/config"),
            self.helpers.urljoin(f"{base_url}/", ".git/config"),
        }
        async for url, response in self.helpers.request_batch(urls):
            text = getattr(response, "text", "")
            if not text:
                text = ""
            if text:
                if getattr(response, "status_code", 0) == 200 and "[core]" in text and not self.fp_regex.match(text):
                    description = (
                        f"The Git configuration file is publicly accessible at {url}. "
                        "Exposed .git metadata can allow attackers to reconstruct repository contents, review source code history, find secrets, and understand application internals. "
                        "The .git directory is the private working data used by Git to store commits, branches, remotes, and file history. "
                        "If enough of it is downloadable from the web server, an attacker may recover source code that was never meant to be public, including deleted files and older versions that still contain credentials or security mistakes. "
                        "Block web access to all .git paths and rotate any secrets that may have been present in the repository history."
                    )
                    await self.emit_event(
                        {"host": str(event.host), "url": url, "description": description},
                        "FINDING",
                        event,
                        context="{module} detected {event.type}: {description}",
                    )
                    await self.emit_event(
                        {"url": url.rstrip("config")},
                        "CODE_REPOSITORY",
                        event,
                        tags="git_directory",
                        context="{module} detected {event.type}: {description}",
                    )
