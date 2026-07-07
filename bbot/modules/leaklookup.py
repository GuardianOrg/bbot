import asyncio
from contextlib import suppress

from bbot.core.helpers.leak_history import LeakHistory, leak_fingerprint, record_fingerprint
from bbot.modules.templates.subdomain_enum import subdomain_enum


class leaklookup(subdomain_enum):
    watched_events = ["DNS_NAME", "HASHED_PASSWORD"]
    produced_events = ["EMAIL_ADDRESS", "FINDING", "HASHED_PASSWORD", "PASSWORD", "USERNAME"]
    flags = ["passive", "safe", "email-enum"]
    meta = {
        "description": "Query leak-lookup.com for leaked credentials (public key detects breaches, paid key pulls records)",
        "created_date": "2026-02-19",
        "author": "@carlospolop",
        "auth_required": True,
    }
    options = {
        "public_api_key": "",
        "private_api_key": "",
        "api_key": "",
        "history_file": "",
    }
    options_desc = {
        "public_api_key": "Leak-Lookup public API key (used to detect which breaches contain the domain)",
        "private_api_key": "Leak-Lookup paid/private API key (used to pull the actual leaked records once the public key shows hits)",
        "api_key": "Legacy alias for public_api_key",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
    }

    search_url = "https://leak-lookup.com/api/search"
    hash_url = "https://leak-lookup.com/api/hash"

    SOURCE = "leaklookup"

    email_fields = {
        "email_address",
        "emailaddress",
        "email",
        "email_address2",
        "emailaddress2",
        "email2",
    }
    username_fields = {"membername", "username", "uname", "user_name", "member_name"}
    password_fields = {"password", "password2", "password3", "password4", "plaintext", "secret", "key"}
    hashed_password_fields = {"hash"}

    async def setup(self):
        self.public_api_key = str(self.config.get("public_api_key", "") or self.config.get("api_key", "")).strip()
        self.private_api_key = str(self.config.get("private_api_key", "")).strip()
        self.history = LeakHistory(str(self.config.get("history_file", "")).strip(), warn=self.warning)
        self._state_lock = asyncio.Lock()
        if not self.public_api_key and not self.private_api_key:
            return None, "No API key set (public_api_key/private_api_key)"
        return await super().setup()

    @property
    def detection_key(self):
        # Prefer the public key for the (cheap) detection query; fall back to the private key.
        return self.public_api_key or self.private_api_key

    def _incoming_dedup_hash(self, event):
        if event.type == "DNS_NAME":
            return hash(self.make_query(event)), "dedup_strategy=highest_parent"
        if event.type == "HASHED_PASSWORD":
            _, hash_value = self._split_hashed_password_event(event)
            return hash(hash_value), "dedup_strategy=hash_value"
        return super()._incoming_dedup_hash(event)

    def make_query(self, event):
        if event.type != "DNS_NAME":
            return event.data
        return super().make_query(event)

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_dns_name_event(event)
        elif event.type == "HASHED_PASSWORD":
            await self.handle_hashed_password_event(event)

    async def handle_dns_name_event(self, event):
        query = self.make_query(event)
        # Step 1: detect which breaches contain the domain (public key).
        detection = await self._search(self.detection_key, query)
        if not detection:
            return

        # Step 2: choose which breaches to act on. With a paid key we re-pull EVERY detected
        # breach (dedup happens per-record below), so a breach that later gains new records
        # for the domain is still caught — the public key only ever returns breach names, so
        # re-pulling is the only way to see a breach grow. Without a paid key we can only see
        # breach names, so we skip breaches already alerted to avoid re-alerting the name.
        if self.private_api_key:
            breaches = [breach for breach in detection if breach]
        else:
            breaches = [breach for breach in detection if breach and not self.history.contains(self._breach_fp(query, breach))]
        if not breaches:
            return

        # Step 3: obtain the actual records. If the detection response already carried records
        # (the key was private) use them; otherwise escalate to the paid key when available.
        records_by_breach = detection if self._has_records(detection) else {}
        if not records_by_breach and self.private_api_key and self.private_api_key != self.detection_key:
            records_by_breach = await self._search(self.private_api_key, query)
        if not isinstance(records_by_breach, dict):
            records_by_breach = {}

        for breach in breaches:
            rows = [row for row in records_by_breach.get(breach, []) if isinstance(row, dict)]
            if rows:
                source_tag = f"leaklookup-source-{self.helpers.tagify(breach, maxlen=48)}"
                for row in rows:
                    await self._emit_row_results(row, event, query, breach, source_tag)
            elif not self.history.contains(self._breach_fp(query, breach)):
                # No records (public-only, or the paid key returned nothing) — alert on the
                # breach-name hit, deduped by breach so we do not re-emit it every scan.
                await self._emit_public_breach_finding(breach, event, query)
                self.history.add(self._breach_fp(query, breach))

        await self._save_history()

    def _breach_fp(self, query, breach):
        # Scope the breach hit to the queried domain so a shared history file does not let
        # the first domain in a breach suppress every other domain that shares that breach.
        return leak_fingerprint(self.SOURCE, breach, None, None, scope=query)

    async def _save_history(self):
        async with self._state_lock:
            self.history.save()

    async def _emit_public_breach_finding(self, breach, event, query):
        await self.emit_event(
            {
                "host": query,
                "title": f"Leak-Lookup breach match for {query}: {breach}",
                "category": "credential-exposure",
                "description": (
                    f'The public Leak-Lookup API reports that "{query}" appears in the breach dataset "{breach}". '
                    "Accounts, passwords, or hashes associated with the domain may be exposed in this dataset. "
                    "A paid Leak-Lookup key (or Dehashed) is required to retrieve the individual leaked records. "
                    "Review exposed accounts, prioritize privileged users and accounts without MFA, and enforce password resets where reuse is possible."
                ),
                "recommendation": (
                    "Retrieve the individual records with a paid key or alternate telemetry, then rotate any affected credentials."
                ),
                "evidence": f"Breach source: {breach}",
                "leaklookup_breach": breach,
            },
            "FINDING",
            parent=event,
            tags=["leaklookup-public-api", f"leaklookup-source-{self.helpers.tagify(breach, maxlen=48)}"],
            context=f'{{module}} queried Leak-Lookup (public) and found {{event.type}} breach match for "{query}": {breach}',
        )
        return True

    async def _emit_row_results(self, row, parent_event, query, breach, source_tag):
        emails = await self._extract_emails_from_row(row)
        usernames = self._extract_values_by_fields(row, self.username_fields)
        passwords = self._extract_values_by_fields(row, self.password_fields)
        hashed_passwords = self._extract_values_by_fields(row, self.hashed_password_fields)

        # Dedup at the leaked-record granularity over all identities + secrets on the row.
        record_fp = record_fingerprint(self.SOURCE, breach, emails, usernames, passwords, hashed_passwords)
        if self.history.contains(record_fp):
            return False
        self.history.add(record_fp)

        for email in emails:
            email_event = self.make_event(email, "EMAIL_ADDRESS", parent=parent_event, tags=[source_tag])
            if email_event is None:
                continue
            await self.emit_event(
                email_event,
                context=f'{{module}} searched Leak-Lookup for "{query}" and found {{event.type}}: {{event.data}}',
            )
            for username in usernames:
                await self.emit_event(
                    f"{email}:{username}",
                    "USERNAME",
                    parent=email_event,
                    tags=[source_tag],
                    context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                )
            for password in passwords:
                await self.emit_event(
                    f"{email}:{password}",
                    "PASSWORD",
                    parent=email_event,
                    tags=[source_tag],
                    context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                )
            for hashed_password in hashed_passwords:
                await self.emit_event(
                    f"{email}:{hashed_password}",
                    "HASHED_PASSWORD",
                    parent=email_event,
                    tags=[source_tag],
                    context=f"{{module}} found {email} with {{event.type}}: {{event.data}}",
                )
        return True

    async def handle_hashed_password_event(self, event):
        identity, hash_value = self._split_hashed_password_event(event)
        if not hash_value:
            return

        crack_key = self.private_api_key or self.detection_key
        response = await self.helpers.request(
            self.hash_url,
            method="POST",
            data={"key": crack_key, "query": hash_value},
        )
        json_result = self._safe_json(response)
        if not json_result:
            return
        if str(json_result.get("error", "")).lower() == "true":
            message = json_result.get("message", "")
            self.warning(f'Leak-Lookup hash lookup failed for "{hash_value}": {message}')
            return

        message = json_result.get("message", {})
        if not isinstance(message, dict):
            return

        emitted = False
        for source_rows in message.values():
            if not isinstance(source_rows, list):
                continue
            for row in source_rows:
                if not isinstance(row, dict):
                    continue
                plaintext = str(row.get("plaintext", "")).strip()
                if not plaintext:
                    continue
                # Skip a crack already emitted on a previous scan (when history_file is set)
                # so we do not re-spend the paid key / re-emit the same PASSWORD every run.
                crack_fp = leak_fingerprint(self.SOURCE, "hash-crack", identity, plaintext, scope=hash_value)
                if self.history.contains(crack_fp):
                    continue
                self.history.add(crack_fp)
                emitted = True
                password_data = plaintext if not identity else f"{identity}:{plaintext}"
                await self.emit_event(
                    password_data,
                    "PASSWORD",
                    parent=event,
                    context=f'{{module}} cracked hash "{hash_value}" and found {{event.type}}: {{event.data}}',
                )
        if emitted:
            await self._save_history()

    async def _search(self, key, query):
        if not key:
            return {}
        response = await self.helpers.request(
            self.search_url,
            method="POST",
            data={"key": key, "type": "domain", "query": query},
        )
        json_result = self._safe_json(response)
        if not json_result:
            return {}
        if str(json_result.get("error", "")).lower() == "true":
            self.warning(f'Leak-Lookup returned an error for "{query}": {json_result.get("message", "")}')
            return {}
        message = json_result.get("message", {})
        return message if isinstance(message, dict) else {}

    @staticmethod
    def _has_records(result):
        return any(isinstance(rows, list) and rows for rows in result.values())

    async def _extract_emails_from_row(self, row):
        emails = set()
        for value in self._extract_values_by_fields(row, self.email_fields):
            for extracted in await self.helpers.re.extract_emails(value):
                emails.add(extracted)
        return emails

    def _extract_values_by_fields(self, row, field_names):
        values = set()
        for field in field_names:
            value = row.get(field, None)
            if value is None:
                continue
            if isinstance(value, list):
                for nested in value:
                    normalized = str(nested).strip()
                    if normalized:
                        values.add(normalized)
                continue
            normalized = str(value).strip()
            if normalized:
                values.add(normalized)
        return values

    def _split_hashed_password_event(self, event):
        data = str(event.data)
        if ":" in data:
            identity, hash_value = data.split(":", 1)
            return identity.strip(), hash_value.strip()
        return "", data.strip()

    def _safe_json(self, response):
        if response is None:
            return {}
        if getattr(response, "status_code", 0) != 200:
            self.warning(f"Error retrieving results from leak-lookup.com (status code {response.status_code})")
            return {}
        json_result = {}
        with suppress(Exception):
            json_result = response.json()
        return json_result
