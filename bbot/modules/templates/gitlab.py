from bbot.modules.base import BaseModule
from urllib.parse import quote


class GitLabBaseModule(BaseModule):
    """Common functionality for interacting with GitLab instances.

    This template is intended to be inherited by two concrete modules:
    1. ``gitlab_com``   – Handles public SaaS instances (gitlab.com / gitlab.org).
    2. ``gitlab_onprem`` – Handles self-hosted, on-premises GitLab servers.

    Both child modules share identical behaviour when talking to the GitLab
    REST API; they only differ in which events they are willing to accept.
    """

    # domains owned by GitLab
    saas_domains = ["gitlab.com", "gitlab.org"]

    async def setup(self):
        if self.options.get("api_key") is not None:
            await self.require_api_key()
        return True

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            if "headers" not in kwargs:
                kwargs["headers"] = {}
            kwargs["headers"]["PRIVATE-TOKEN"] = self.api_key
        return url, kwargs

    async def handle_repository_owner(self, event):
        """Enumerate projects for an explicit GitLab user/group owner URL."""
        owner_path = self.get_repository_owner_path(event)
        if not owner_path:
            return

        base_url = self.get_base_url(event)
        encoded_owner = quote(owner_path, safe="")
        urls = [
            self.helpers.urljoin(base_url, f"api/v4/users/{encoded_owner}/projects?simple=true&per_page=100"),
            self.helpers.urljoin(base_url, f"api/v4/groups/{encoded_owner}/projects?simple=true&per_page=100&include_subgroups=true"),
        ]
        for url in urls:
            await self.handle_projects_url(url, event)

    async def handle_social(self, event):
        """Enumerate projects belonging to a user or group profile."""
        username = event.data.get("profile_name", "")
        if not username:
            return
        base_url = self.get_base_url(event)
        encoded_username = quote(username, safe="")
        urls = [
            # User-owned projects
            self.helpers.urljoin(base_url, f"api/v4/users/{encoded_username}/projects?simple=true&per_page=100"),
            # Group-owned projects
            self.helpers.urljoin(base_url, f"api/v4/groups/{encoded_username}/projects?simple=true&per_page=100&include_subgroups=true"),
        ]
        for url in urls:
            await self.handle_projects_url(url, event)

    async def handle_projects_url(self, projects_url, event):
        for project in await self.gitlab_json_request(projects_url):
            project_url = project.get("web_url", "")
            if project_url:
                namespace = project.get("path_with_namespace", "")
                namespace_parts = [part for part in str(namespace).split("/") if part]
                code_event = self.make_event(
                    {
                        "url": project_url,
                        "platform": "gitlab",
                        "owner": namespace_parts[0] if namespace_parts else "unknown",
                        "repo_name": namespace_parts[-1] if namespace_parts else project_url.rstrip("/").split("/")[-1],
                    },
                    "CODE_REPOSITORY",
                    tags=["git", "gitlab"],
                    parent=event,
                )
                if not code_event:
                    continue
                await self.emit_event(
                    code_event,
                    context=f"{{module}} enumerated projects and found {{event.type}} at {project_url}",
                )
            namespace = project.get("namespace", {})
            if namespace:
                await self.handle_namespace(namespace, event)

    async def handle_groups_url(self, groups_url, event):
        for group in await self.gitlab_json_request(groups_url):
            await self.handle_namespace(group, event)

    async def gitlab_json_request(self, url):
        """Helper that performs an HTTP request and safely returns JSON list."""
        results = []
        page = 1
        while page:
            separator = "&" if "?" in url else "?"
            page_url = f"{url}{separator}page={page}"
            response = await self.api_request(page_url)
            if response is None:
                break
            try:
                json_data = response.json()
            except Exception:
                break
            if json_data and isinstance(json_data, list):
                results.extend(json_data)

            next_page = getattr(response, "headers", {}).get("x-next-page", "")
            try:
                page = int(next_page) if next_page else 0
            except ValueError:
                page = 0
        return results

    async def handle_namespace(self, namespace, event):
        namespace_name = namespace.get("path", "")
        namespace_url = namespace.get("web_url", "")
        namespace_path = namespace.get("full_path", "")

        if not (namespace_name and namespace_url and namespace_path):
            return

        namespace_url = self.helpers.parse_url(namespace_url)._replace(path=f"/{namespace_path}").geturl()

        social_event = self.make_event(
            {
                "platform": "gitlab",
                "profile_name": namespace_path,
                "url": namespace_url,
            },
            "SOCIAL",
            parent=event,
        )
        await self.emit_event(
            social_event,
            context=f'{{module}} found GitLab namespace ({{event.type}}) "{namespace_name}" at {namespace_url}',
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def get_base_url(self, event):
        base_url = event.data.get("url", "")
        if not base_url:
            base_url = f"https://{event.host}"
        return self.helpers.urlparse(base_url)._replace(path="/").geturl()

    def get_repository_owner_path(self, event):
        url = event.data.get("url", "")
        parsed = self.helpers.urlparse(url)
        path_parts = [part for part in parsed.path.split("/") if part]
        if len(path_parts) != 1:
            return ""
        return path_parts[0]
