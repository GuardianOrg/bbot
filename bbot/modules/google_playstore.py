import regex as re

from bbot.modules.base import BaseModule


class google_playstore(BaseModule):
    watched_events = ["ORG_STUB", "CODE_REPOSITORY"]
    # OPTIONAL_MOBILE_APP: a same-named app whose listing names no in-scope domain or email.
    # No module watches it, so it is only reported for the user to add to scope later.
    produced_events = ["MOBILE_APP", "OPTIONAL_MOBILE_APP"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "Search for android applications on play.google.com",
        "created_date": "2024-10-08",
        "author": "@domwhewell-sage",
    }

    base_url = "https://play.google.com"

    async def setup(self):
        self.app_link_regex = re.compile(r"/store/apps/details\?id=([a-zA-Z0-9._-]+)")
        return True

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            repo_url = event.data.get("url", "") if isinstance(event.data, dict) else ""
            if "android" not in event.tags and "play.google.com/store/apps/details" not in repo_url:
                return False, "event is not an android repository"
        elif event.type == "ORG_STUB":
            if "target" not in event.tags and event.scope_distance > 0:
                return False, "event is not a target org stub"
            root_seed_type = self._event_root_seed_type(event)
            if root_seed_type not in {
                "ORG_STUB",
                "DNS_NAME",
                "URL",
                "URL_UNVERIFIED",
                "EMAIL_ADDRESS",
                "CODE_REPOSITORY",
                "MOBILE_APP",
            }:
                return (
                    False,
                    f"org stub came from {root_seed_type or 'unknown'} seed, not an explicit org/domain/mobile/code target",
                )
        return True

    async def handle_event(self, event):
        if event.type == "CODE_REPOSITORY":
            await self.handle_url(event)
        elif event.type == "ORG_STUB":
            await self.handle_org_stub(event)

    async def handle_url(self, event):
        repo_url = event.data.get("url")
        app_id = repo_url.split("id=")[1].split("&")[0]
        await self.emit_event(
            {"id": app_id, "url": repo_url, "platform": "android"},
            "MOBILE_APP",
            tags="android",
            parent=event,
            context=f'{{module}} extracted the mobile app name "{app_id}"  from: {repo_url}',
        )

    async def handle_org_stub(self, event):
        org_name = event.data
        self.verbose(f"Searching for any android applications for {org_name}")
        for apk_name in await self.query(org_name):
            data = {"id": apk_name, "url": f"{self.base_url}/store/apps/details?id={apk_name}", "platform": "android"}
            if await self.validate_apk(apk_name):
                self.verbose(f"Got {apk_name} from playstore")
                await self.emit_event(
                    data,
                    "MOBILE_APP",
                    tags="android",
                    parent=event,
                    context=f'{{module}} searched play.google.com for apps belonging to "{org_name}" and found "{apk_name}" to be in scope',
                )
            elif self._package_matches_org_stub(apk_name, org_name):
                self.verbose(
                    f"Got {apk_name} from playstore as an optional app: only its package name matches {org_name}"
                )
                await self.emit_event(
                    {
                        **data,
                        "reason": f'Package name matches "{org_name}", but the store listing names no in-scope domain or email',
                    },
                    "OPTIONAL_MOBILE_APP",
                    tags=["android", "optional"],
                    parent=event,
                    context=f'{{module}} searched play.google.com for apps belonging to "{org_name}" and found "{apk_name}", whose listing does not tie it to the target',
                )
            else:
                self.debug(f"Got {apk_name} from playstore app details does not contain any in-scope URLs or Emails")

    async def query(self, query):
        app_links = []
        url = f"{self.base_url}/store/search?q={self.helpers.quote(query)}&c=apps"
        r = await self.helpers.request(url, headers=self._request_headers())
        if r is None:
            return app_links
        status_code = getattr(r, "status_code", 0)
        try:
            html_content = r.content.decode("utf-8")
            # Use regex to find all app links
            app_links = await self.helpers.re.findall(self.app_link_regex, html_content)
        except Exception as e:
            self.warning(f"Failed to parse html response from {r.url} (HTTP status: {status_code}): {e}")
            return app_links
        return app_links

    async def validate_apk(self, apk_name):
        """
        Check the app details page the "App support" section will include URLs or Emails to the app developer
        """
        in_scope = False
        url = f"{self.base_url}/store/apps/details?id={apk_name}"
        r = await self.helpers.request(url, headers=self._request_headers())
        if r is None:
            return in_scope
        status_code = getattr(r, "status_code", 0)
        if status_code == 200:
            # Whole hostnames only: the scan's prefix matcher would take "seraph.com" for "seraph.co".
            hosts = await self.helpers.re.findall(self.helpers.regexes.dns_name_extraction_regex, r.text)
            in_scope = any(self.scan.whitelisted(host.rstrip(".")) for host in set(hosts))
        else:
            self.warning(f"Failed to fetch {url} (HTTP status: {status_code})")
        return in_scope

    def _package_matches_org_stub(self, apk_name, org_name):
        org_token = re.sub(r"[^a-z0-9]+", "", str(org_name or "").lower())
        if not org_token:
            return False
        package_parts = [part for part in str(apk_name or "").lower().split(".") if part]
        return org_token in package_parts

    def _request_headers(self):
        return {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121 Safari/537.36",
        }
