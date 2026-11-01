from bbot.modules.templates.osintverse import osintverse_leak


class leakosintbot(osintverse_leak):
    watched_events = ["DNS_NAME"]
    produced_events = [
        "LEAKED_CREDENTIAL",
        "EMAIL_PROFILE",
        "PASSWORD",
        "HASHED_PASSWORD",
        "USERNAME",
        "EMAIL_ADDRESS",
        "URL_UNVERIFIED",
        "DNS_NAME",
    ]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query LeakOSINTbot through OSINTverse for credentials in breach databases and stealer logs",
        "created_date": "2026-11-01",
        "author": "@carlospolop",
        "auth_required": True,
    }
    options = {"osintverse_api_key": "", "history_file": "", "legacy_events": True}
    options_desc = {
        "osintverse_api_key": "OSINTverse API key ($0.20 per domain search)",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
        "legacy_events": "Also emit the flat USERNAME, PASSWORD and HASHED_PASSWORD events next to LEAKED_CREDENTIAL",
    }
    target_only = True

    SOURCE = "leakosintbot"
    source_name = "LeakOSINTbot"
    osintverse_provider = "leakosintbot"

    # LeakOSINT rows have no fixed schema: field names depend on the dump they came from
    email_fields = {"email", "mail", "e-mail", "emailaddress", "email address"}
    username_fields = {"nickname", "nick", "login", "username", "user", "user name"}
    # stealer-log rows are often keyed by the phone number used to log in instead of an email or username
    phone_fields = {"phone", "telephone", "mobile"}
    url_fields = {"url", "link", "site", "website", "host"}

    async def fetch_records(self, query, event):
        search = await self.osintverse.search(self.osintverse_provider, "domain", query)
        sources, matches = self.osintverse.results(search)
        for source in sources:
            self.verbose(
                f'LeakOSINTbot returned {source.get("num_of_results")} results from {source.get("num_of_databases")} databases for "{query}"'
            )

        entries = []
        emitted_urls = set()
        for database in matches:
            if database.get("type") != "breach_database":
                continue
            db_name = str(database.get("name") or "")
            for row in database.get("data") or []:
                if not isinstance(row, dict):
                    continue
                entry = self.normalize_row(row, db_name)
                entry["database_description"] = str(database.get("info_leak") or "")
                # rows with nothing tying them to an account (e.g. password lists) still belong to the domain
                url = entry["url"]
                if url and url not in emitted_urls and self.url_in_domain(url, query):
                    emitted_urls.add(url)
                    url_event = self.make_event(url, "URL_UNVERIFIED", parent=event, tags=[f"db-{db_name}"])
                    if url_event is not None:
                        await self.emit_event(
                            url_event,
                            context=f'{{module}} searched {self.source_name} for "{query}" and found leaked credentials for {{event.type}}: {{event.data}}',
                        )
                entries.append(entry)
        return entries

    def normalize_row(self, row, db_name):
        entry = {
            "email": [],
            "username": [],
            "phone": [],
            "password": [],
            "hashed_password": [],
            "database_name": db_name,
            "url": "",
        }
        profile_aliases = {alias for aliases in self.profile_fields.values() for alias in aliases}
        for key, value in row.items():
            if value in (None, "") or isinstance(value, (dict, list)):
                continue
            value = str(value).strip()
            field = str(key).strip().lower()
            if field in self.email_fields:
                entry["email"].append(value)
            elif field in self.username_fields:
                entry["username"].append(value)
            elif field in self.phone_fields:
                entry["phone"].append(value)
            elif field.startswith("password"):
                # e.g. "Password", "Password(MD5)", "Password(MD5+salt)", "Password(bcrypt)"
                if "(" in field:
                    entry["hashed_password"].append(value)
                    entry["hash_type"] = field.split("(", 1)[1].rstrip(")")
                else:
                    entry["password"].append(value)
            elif "hash" in field:
                entry["hashed_password"].append(value)
            elif field == "salt":
                entry["salt"] = value
            elif field in self.url_fields and not entry["url"]:
                entry["url"] = value if "://" in value else f"https://{value}"
            elif field in profile_aliases:
                entry.setdefault(field, []).append(value)
        return entry

    def url_in_domain(self, url, domain):
        try:
            host = self.helpers.urlparse(url).hostname or ""
        except Exception:
            return False
        host = host.lower()
        return host == domain or host.endswith(f".{domain}")
