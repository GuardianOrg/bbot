from bbot.modules.templates.osintverse import osintverse_leak


class leakradar(osintverse_leak):
    watched_events = ["DNS_NAME"]
    produced_events = ["LEAKED_CREDENTIAL", "PASSWORD", "USERNAME", "EMAIL_ADDRESS", "URL_UNVERIFIED", "DNS_NAME"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query LeakRadar through OSINTverse for credentials leaked in stealer logs, combolists and dumps",
        "created_date": "2026-11-01",
        "author": "@carlospolop",
        "auth_required": True,
    }
    options = {
        "osintverse_api_key": "",
        "categories": ["employees", "third_parties", "customers"],
        "history_file": "",
        "legacy_events": True,
    }
    options_desc = {
        "osintverse_api_key": "OSINTverse API key ($1.00 per domain search, includes the first 1,000 credentials)",
        "categories": "LeakRadar credential categories to report (employees, third_parties, customers)",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
        "legacy_events": "Also emit the flat USERNAME and PASSWORD events next to LEAKED_CREDENTIAL",
    }
    target_only = True

    SOURCE = "leakradar"
    source_name = "LeakRadar"
    osintverse_provider = "leakradar"

    async def setup(self):
        self.categories = {str(c).strip().lower() for c in self.config.get("categories", []) or [] if str(c).strip()}
        return await super().setup()

    async def fetch_records(self, query, event):
        search = await self.osintverse.search(self.osintverse_provider, "domain", query)
        sources, matches = self.osintverse.results(search)
        self.log_coverage(query, sources)

        entries = []
        emitted_urls = set()
        for match in matches:
            if match.get("type") != "leak":
                continue
            category = str(match.get("category") or "").lower()
            if self.categories and category and category not in self.categories:
                continue
            tags = [f"leakradar-{category}"] if category else []

            url = str(match.get("url") or "").strip()
            if url.lower().startswith(("http://", "https://")) and url not in emitted_urls:
                emitted_urls.add(url)
                url_event = self.make_event(url, "URL_UNVERIFIED", parent=event, tags=tags)
                if url_event is not None:
                    await self.emit_event(
                        url_event,
                        context=f'{{module}} searched {self.source_name} for "{query}" and found leaked credentials for {{event.type}}: {{event.data}}',
                    )

            username = str(match.get("username") or "").strip()
            if not username:
                continue
            is_email = bool(match.get("is_email")) or "@" in username
            password = match.get("password") if match.get("unlocked") else None
            entries.append(
                {
                    "email": [username] if is_email else [],
                    "username": [] if is_email else [username],
                    "password": [password] if password else [],
                    "hashed_password": [],
                    "database_name": "",
                    "indexed_at": match.get("added_at"),
                    "url": url,
                    "category": category,
                    "password_strength": match.get("password_strength") if password else None,
                    "tags": tags,
                }
            )
        return entries

    def log_coverage(self, query, sources):
        for source in sources:
            total = int(source.get("total") or 0)
            unlocked = int(source.get("total_unlocked") or 0)
            if total:
                self.verbose(
                    f'LeakRadar has {total:,} leaked credentials for "{query}" '
                    f"(employees: {source.get('employees_compromised')}, third parties: {source.get('third_parties_compromised')}, "
                    f"customers: {source.get('customers_compromised')})"
                )
            if total > unlocked:
                self.info(
                    f'LeakRadar has {total - unlocked:,} more locked credentials for "{query}". '
                    "Unlock them from the OSINTverse search at $0.50 per 1,000."
                )
