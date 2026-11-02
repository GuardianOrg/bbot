from contextlib import suppress

from bbot.modules.templates.osintverse import osintverse_leak


class dehashed(osintverse_leak):
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
        "description": "Execute queries against dehashed.com (directly or through OSINTverse) for exposed credentials",
        "created_date": "2023-10-12",
        "author": "@SpamFaux",
        "auth_required": True,
    }
    options = {"api_key": "", "osintverse_api_key": "", "history_file": "", "legacy_events": True}
    options_desc = {
        "api_key": "DeHashed API Key (takes precedence over osintverse_api_key)",
        "osintverse_api_key": "OSINTverse API key, used when no DeHashed API key is set ($0.30 per domain search)",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
        "legacy_events": "Also emit the flat USERNAME, PASSWORD and HASHED_PASSWORD events next to LEAKED_CREDENTIAL",
    }
    target_only = True

    SOURCE = "dehashed"
    source_name = "dehashed.com"
    osintverse_provider = "dehashed"
    base_url = "https://api.dehashed.com/v2/search"

    async def setup_api(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Dehashed-Api-Key": self.api_key,
        }
        if self.api_key:
            return True, ""
        if self.osintverse.api_key:
            return await super().setup_api()
        # soft-fail if we don't have the necessary information to make queries
        return None, "No API key set (api_key or osintverse_api_key)"

    async def fetch_records(self, query, event):
        if not self.api_key:
            search = await self.osintverse.search(self.osintverse_provider, "domain", query)
            sources, matches = self.osintverse.results(search)
            self.log_truncation(sources, query)
            # OSINTverse also passes DeHashed's own entries through. Unlike the flattened matches they keep
            # every field: the leaked login URLs and each hash separately.
            raw = ((search or {}).get("result") or {}).get("raw")
            entries = raw.get("entries") if isinstance(raw, dict) else None
            entries = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
            records = [m for m in matches if m.get("type") == "breach_record"]
            # Never lose a returned row: if the raw list is shorter than the matches (e.g. trimmed on a large
            # result), add the matches it lacks, joined by DeHashed id or, without ids, by count.
            ids = {str(e["id"]) for e in entries if e.get("id") not in (None, "")}
            if ids:
                missing = [m for m in records if str(m.get("id")) not in ids]
            else:
                missing = records if len(records) > len(entries) else []
                entries = [] if missing else entries
            if missing:
                self.verbose(f'{len(missing):,} DeHashed rows for "{query}" were only in the normalized matches')
            return entries + [self.normalize_breach_record(m) for m in missing]
        entries = []
        async for batch in self.query(query):
            entries += batch
        return entries

    async def query(self, domain):
        url = self.base_url
        json = {
            "query": "",
            "page": 1,
            "size": 10000,  # The maximum permitted size and pagination.
        }
        json["query"] = f"domain:{domain}"
        json["page"] = 1
        max_pages = 1
        agen = self.api_page_iter(url=url, headers=self.headers, _json=False, method="POST", json=json)
        async for result in agen:
            result_json = {}
            with suppress(Exception):
                result_json = result.json()
            total = result_json.get("total", 0)
            entries = result_json.get("entries", [])
            json["page"] += 1
            if result is not None and result.status_code != 200:
                self.warning(
                    f"Error retrieving results from dehashed.com (status code {result.status_code}): {result.text}"
                )
            elif (json["page"] > max_pages) and (total > (json["size"] * max_pages)):
                self.info(
                    f"{domain} has {total:,} results in Dehashed. The API can only process the first 10,000 results. Please check dehashed.com to get the remaining results."
                )
            if entries:
                yield entries
            if not entries or json["page"] > max_pages:
                await agen.aclose()
                break
