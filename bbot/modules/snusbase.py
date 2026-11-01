from bbot.modules.templates.osintverse import osintverse_leak


class snusbase(osintverse_leak):
    watched_events = ["DNS_NAME"]
    produced_events = [
        "LEAKED_CREDENTIAL",
        "EMAIL_PROFILE",
        "PASSWORD",
        "HASHED_PASSWORD",
        "USERNAME",
        "EMAIL_ADDRESS",
        "DNS_NAME",
    ]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query Snusbase through OSINTverse for exposed credentials",
        "created_date": "2026-11-01",
        "author": "@carlospolop",
        "auth_required": True,
    }
    options = {"osintverse_api_key": "", "history_file": "", "legacy_events": True}
    options_desc = {
        "osintverse_api_key": "OSINTverse API key ($0.30 per domain search)",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
        "legacy_events": "Also emit the flat USERNAME, PASSWORD and HASHED_PASSWORD events next to LEAKED_CREDENTIAL",
    }
    target_only = True

    SOURCE = "snusbase"
    source_name = "Snusbase"
    osintverse_provider = "snusbase"

    async def fetch_records(self, query, event):
        search = await self.osintverse.search(self.osintverse_provider, "domain", query)
        sources, matches = self.osintverse.results(search)
        self.log_truncation(sources, query)
        entries = []
        for match in matches:
            if match.get("type") != "breach_record":
                continue
            entries.append(self.normalize_breach_record(match))
            # stealer-log rows can name the host the credential was used on
            host = str(match.get("host") or "").strip().lower()
            if host.endswith(f".{query}"):
                await self.emit_event(
                    host,
                    "DNS_NAME",
                    parent=event,
                    abort_if=self.abort_if,
                    context=f'{{module}} searched {self.source_name} for "{query}" and found {{event.type}}: {{event.data}}',
                )
        return entries
