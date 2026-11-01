from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class hunterio(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "EMAIL_PROFILE", "DNS_NAME", "URL_UNVERIFIED"]
    flags = ["passive", "email-enum", "subdomain-enum", "safe"]
    meta = {
        "description": "Query hunter.io for emails",
        "created_date": "2022-04-25",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "max_pages": 10}
    options_desc = {
        "api_key": "Hunter.IO API key",
        "max_pages": "Maximum Domain Search pages per registrable domain (10 emails per page, 1 search credit each, capped at 10)",
    }

    base_url = "https://api.hunter.io/v2"
    ping_url = f"{base_url}/account?api_key={{api_key}}"
    # Hunter bills one search per 10 returned emails, so small pages cap spend precisely
    page_size = 10
    # never more than 10 searches (100 emails) per domain, whatever the config says
    max_pages_limit = 10
    # wildcard DNS says nothing about which mailboxes exist
    reject_wildcards = False

    async def setup(self):
        self.max_pages = min(self.max_pages_limit, max(0, int(self.config.get("max_pages", 10))))
        return await super().setup()

    async def filter_event(self, event):
        # Hunter indexes each subdomain separately; only spend credits on registrable domains
        query = self.make_query(event)
        if self.helpers.split_domain(query)[1] != query:
            return False, f'"{query}" is not a registrable domain'
        return await super().filter_event(event)

    async def handle_event(self, event):
        query = self.make_query(event)
        for entry in await self.query(query):
            email = entry.get("value", "")
            sources = entry.get("sources", [])
            if email:
                email_event = self.make_event(email, "EMAIL_ADDRESS", event)
                if email_event:
                    await self.emit_event(
                        email_event,
                        context=f'{{module}} queried Hunter.IO API for "{query}" and found {{event.type}}: {{event.data}}',
                    )
                    profile = self.email_profile(email_event.data, entry)
                    if profile:
                        await self.emit_event(
                            profile,
                            "EMAIL_PROFILE",
                            email_event,
                            context=f"{{module}} found the person Hunter.IO associates with {email_event.data}",
                        )
                    for source in sources:
                        domain = source.get("domain", "")
                        if domain:
                            await self.emit_event(
                                domain,
                                "DNS_NAME",
                                email_event,
                                context=f"{{module}} originally found {email} at {{event.type}}: {{event.data}}",
                            )
                        url = source.get("uri", "")
                        if url:
                            await self.emit_event(
                                url,
                                "URL_UNVERIFIED",
                                email_event,
                                context=f"{{module}} originally found {email} at {{event.type}}: {{event.data}}",
                            )

    @staticmethod
    def email_profile(email, entry):
        """Keep the personal fields Hunter returns; skip addresses with none."""

        def text(value):
            value = str(value or "").strip()
            return value[:500] or None

        profile = {
            field: text(entry.get(field))
            for field in (
                "first_name",
                "last_name",
                "position",
                "seniority",
                "department",
                "linkedin",
                "twitter",
                "phone_number",
            )
        }
        if not any(profile.values()):
            return None
        confidence = entry.get("confidence")
        sources = [str(source.get("uri")) for source in entry.get("sources") or [] if source.get("uri")]
        profile.update(
            host=email.rsplit("@", 1)[-1],
            email=email,
            provider="hunterio",
            email_type=text(entry.get("type")),
            confidence=confidence if isinstance(confidence, int) else None,
            verification_status=text((entry.get("verification") or {}).get("status")),
            sources=sources[:10] or None,
        )
        return {key: value for key, value in profile.items() if value is not None}

    async def query(self, query):
        emails = {}
        for page in range(self.max_pages):
            offset = page * self.page_size
            response = await self.api_request(
                f"{self.base_url}/domain-search?domain={query}&api_key={{api_key}}&limit={self.page_size}&offset={offset}"
            )
            if response is None or response.status_code != 200:
                break
            try:
                j = response.json()
            except Exception:
                break
            page_emails = j.get("data", {}).get("emails", [])
            new = 0
            for entry in page_emails:
                email = str(entry.get("value", "")).lower()
                if email and email not in emails:
                    emails[email] = entry
                    new += 1
            total = j.get("meta", {}).get("results")
            if (
                not new
                or len(page_emails) < self.page_size
                or (total is not None and offset + self.page_size >= total)
            ):
                break
        return list(emails.values())
