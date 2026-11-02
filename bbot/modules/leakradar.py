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
        "max_credentials": 5000,
        "history_file": "",
        "legacy_events": True,
    }
    options_desc = {
        "osintverse_api_key": "OSINTverse API key ($1.00 per domain search, includes the first 1,000 credentials)",
        "categories": "LeakRadar credential categories to report (employees, third_parties, customers)",
        "max_credentials": "Unlock the credentials past the first 1,000 ($0.50 per 1,000) only when the domain has at most this many in total. 0 disables unlocking",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
        "legacy_events": "Also emit the flat USERNAME and PASSWORD events next to LEAKED_CREDENTIAL",
    }
    target_only = True

    SOURCE = "leakradar"
    source_name = "LeakRadar"
    osintverse_provider = "leakradar"

    async def setup(self):
        self.categories = {str(c).strip().lower() for c in self.config.get("categories", []) or [] if str(c).strip()}
        try:
            self.max_credentials = max(0, int(self.config.get("max_credentials", 5000) or 0))
        except (TypeError, ValueError):
            self.max_credentials = 0
        return await super().setup()

    async def fetch_records(self, query, event):
        search = await self.osintverse.search(self.osintverse_provider, "domain", query)
        sources, matches = self.osintverse.results(search)
        search, sources, matches = await self.unlock_remaining(query, search, sources, matches)
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

            # rows without a username still belong to the domain
            username = str(match.get("username") or "").strip()
            is_email = bool(match.get("is_email")) or "@" in username
            password = match.get("password") if match.get("unlocked") else None
            entries.append(
                {
                    "email": [username] if username and is_email else [],
                    "username": [username] if username and not is_email else [],
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

    async def unlock_remaining(self, query, search, sources, matches):
        """
        The search includes the first 1,000 credentials. OSINTverse unlocks all the rest in one call, so do it only
        when the whole domain fits max_credentials; on any failure keep the rows already returned.
        """
        total = sum(int(s.get("total") or 0) for s in sources)
        unlocked = sum(int(s.get("total_unlocked") or 0) for s in sources)
        if total <= unlocked:
            return search, sources, matches
        if total > self.max_credentials:
            self.info(
                f'Not unlocking the {total - unlocked:,} remaining LeakRadar credentials for "{query}": '
                f"{total:,} in total is over max_credentials ({self.max_credentials:,})"
            )
            return search, sources, matches
        updated = await self.osintverse.unlock(search)
        new_sources, new_matches = self.osintverse.results(updated)
        if not new_matches:
            return search, sources, matches
        # never lose a row the first search returned
        seen = {str(m.get("id")) for m in new_matches if m.get("id") not in (None, "")}
        kept = [m for m in matches if m.get("id") in (None, "") or str(m.get("id")) not in seen]
        if kept:
            self.verbose(f'{len(kept):,} LeakRadar rows for "{query}" were only in the first response')
        return updated, new_sources or sources, new_matches + [m for m in kept if m.get("type") == "leak"]

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
