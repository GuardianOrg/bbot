from bbot.modules.templates.postman import postman


class postman(postman):
    watched_events = ["ORG_STUB", "SOCIAL"]
    produced_events = ["CODE_REPOSITORY"]
    flags = ["passive", "subdomain-enum", "safe", "code-enum"]
    meta = {
        "description": "Query Postman's API for related workspaces, collections, requests and download them",
        "created_date": "2024-09-07",
        "author": "@domwhewell-sage",
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Postman API Key"}
    reject_wildcards = False

    async def handle_event(self, event):
        # Handle postman profile
        if event.type == "SOCIAL":
            owner = event.data.get("profile_name", "")
            data = await self.process_workspaces(user=owner)
            repo_url = data["url"]
            repo_name = data["repo_name"]
            context = f'{{module}} searched postman.com for workspaces belonging to "{owner}" and found "{repo_name}" at {{event.type}}: {repo_url}'
        elif event.type == "ORG_STUB":
            owner = event.data
            data = await self.process_workspaces(org=owner)
            repo_url = data["url"]
            repo_name = data["repo_name"]
            context = f'{{module}} searched postman.com for "{owner}" and found matching workspace "{repo_name}" at {{event.type}}: {repo_url}'
        if data:
            repo_url = data["url"]
            repo_name = data["repo_name"]
            await self.emit_event(
                {"url": repo_url},
                "CODE_REPOSITORY",
                tags="postman",
                parent=event,
                context=context,
            )

    async def process_workspaces(self, user=None, org=None):
        owner = user or org
        if owner:
            self.verbose(f"Searching for postman workspaces, collections, requests for {owner}")
            for item in await self.query(owner):
                workspace = item["document"]
                slug = workspace["slug"]
                profile = workspace["publisherHandle"]
                repo_url = f"{self.html_url}/{profile}/{slug}"
                workspace_id = await self.get_workspace_id(repo_url)
                if (org and workspace_id) or (user and owner.lower() == profile.lower()):
                    self.verbose(f"Found workspace ID {workspace_id} for {repo_url}")
                    data = await self.request_workspace(workspace_id)
                    workspace = data["workspace"]
                    environments = data["environments"]
                    collections = data["collections"]
                    in_scope = await self.validate_workspace(workspace, environments, collections)
                    if in_scope:
                        return {"url": repo_url, "repo_name": slug}
                    else:
                        self.verbose(
                            f"Failed to validate {repo_url} is in our scope as it does not contain any in-scope dns_names / emails"
                        )
        return None

    async def query(self, query):
        data = []
        url = f"{self.base_url}/ws/proxy"
        json = {
            "service": "search",
            "method": "POST",
            "path": "/search-all",
            "body": {
                "queryIndices": [
                    "collaboration.workspace",
                ],
                "queryText": self.helpers.quote(query),
                "size": 100,
                "from": 0,
                "clientTraceId": "",
                "requestOrigin": "srp",
                "mergeEntities": "true",
                "nonNestedRequests": "true",
                "domain": "public",
            },
        }
        r = await self.helpers.request(url, method="POST", json=json, headers=self.headers)
        if r is None:
            return data
        status_code = getattr(r, "status_code", 0)
        try:
            json = r.json()
        except Exception as e:
            self.warning(f"Failed to decode JSON for {r.url} (HTTP status: {status_code}): {e}")
            return None
        return json.get("data", [])
