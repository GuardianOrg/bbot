import asyncio
import hashlib
from contextlib import suppress

from bbot.core.helpers.leak_history import LeakHistory, record_fingerprint
from bbot.core.helpers.observation_dates import indexed_date, indexed_date_tags
from bbot.modules.templates.subdomain_enum import subdomain_enum


class OSINTverseClient:
    """
    Minimal client for the OSINTverse SearchIn API (https://osintverse.com/docs/api/overview).

    Every search is billed from the prepaid OSINTverse wallet, so searches carry an Idempotency-Key
    derived from the scan id: retrying a lost request returns the original search instead of charging twice.
    """

    base_url = "https://apiv1.osintverse.com"
    poll_interval = 2
    # large domains can take several minutes (a Snusbase search for tesla.com took ~335s)
    poll_timeout = 600
    max_attempts = 3

    def __init__(self, module, api_key):
        self.module = module
        self.api_key = str(api_key or "").strip()

    @property
    def headers(self):
        return {"x-api-key": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}

    async def check(self, provider, input_type):
        """
        Validate the API key and wallet balance with a free price quote. Returns a bbot setup() result.
        """
        if not self.api_key:
            return None, "No OSINTverse API key set"
        body = {"provider": provider, "input_type": input_type}
        r = await self.module.helpers.request(
            f"{self.base_url}/v1/search/quote", method="POST", headers=self.headers, json=body
        )
        if r is None:
            return None, "OSINTverse API did not respond"
        j = self._json(r)
        if r.status_code != 200:
            return None, f"OSINTverse API key check failed (status code {r.status_code}): {self._error(r, j)}"
        if not j.get("available", True):
            return None, f'OSINTverse provider "{provider}" is currently unavailable'
        if not j.get("sufficient_balance", False):
            return (
                None,
                f"Insufficient OSINTverse balance (${j.get('balance_usd')}) for {provider} "
                f"(${j.get('unit_cost_usd')} per {input_type} search). Top up at {j.get('top_up_url')}",
            )
        self.module.verbose(
            f"OSINTverse {provider} {input_type} searches cost ${j.get('unit_cost_usd')} (balance ${j.get('balance_usd')})"
        )
        return True, ""

    async def search(self, provider, input_type, query):
        """
        Run a billed search and wait for it to finish. Returns the completed search object, or None.
        """
        body = {"provider": provider, "input_type": input_type, "query": query}
        idempotency_key = hashlib.sha256(
            f"bbot|{self.module.scan.id}|{provider}|{input_type}|{query}".encode()
        ).hexdigest()
        headers = dict(self.headers, **{"Idempotency-Key": idempotency_key})
        r = None
        for attempt in range(self.max_attempts):
            r = await self.module.helpers.request(
                f"{self.base_url}/v1/search", method="POST", headers=headers, json=body
            )
            if r is not None and r.status_code < 500:
                break
            if attempt + 1 < self.max_attempts:
                await asyncio.sleep(self.poll_interval)
        description = f'OSINTverse {provider} search for "{query}"'
        if r is None:
            self.module.warning(f"{description} failed (no response)")
            return None
        j = self._json(r)
        if not 200 <= r.status_code < 300:
            self.module.warning(f"{description} failed (status code {r.status_code}): {self._error(r, j)}")
            return None

        search = await self._wait(j)
        status = search.get("status", "")
        if status != "completed":
            self.module.warning(f"{description} did not complete (status: {status}): {search.get('error')}")
            return None
        self.module.verbose(
            f"{description} cost ${search.get('cost_usd')} (balance after: ${search.get('balance_after')})"
        )
        return search

    async def _wait(self, search):
        elapsed = 0
        while search.get("status") == "running" and search.get("id") and elapsed < self.poll_timeout:
            await asyncio.sleep(self.poll_interval)
            elapsed += self.poll_interval
            r = await self.module.helpers.request(f"{self.base_url}/v1/search/{search['id']}", headers=self.headers)
            if r is not None and r.status_code == 200:
                search = self._json(r) or search
        return search

    @staticmethod
    def results(search):
        result = (search or {}).get("result") or {}
        sources = [s for s in result.get("sources") or [] if isinstance(s, dict)]
        matches = [m for m in result.get("matches") or [] if isinstance(m, dict)]
        return sources, matches

    @staticmethod
    def _json(r):
        try:
            j = r.json()
        except Exception:
            return {}
        return j if isinstance(j, dict) else {}

    @staticmethod
    def _error(r, j):
        error = j.get("error")
        if isinstance(error, dict) and error.get("message"):
            return error["message"]
        return j.get("detail") or getattr(r, "text", "")[:200]


class osintverse_leak(subdomain_enum):
    """
    Base for leak modules that search a domain for exposed credentials.

    Subclasses return records shaped like DeHashed entries (lists under "email", "username", "password",
    "hashed_password", plus "database_name") from fetch_records(); this class handles dedup and emission.

    Every leaked record becomes a LEAKED_CREDENTIAL event holding all of its leak fields, tied to the searched
    domain and parented by the leaked EMAIL_ADDRESS when it belongs to that domain. Personal details found on
    records for an email are merged into one EMAIL_PROFILE per address.
    """

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
    meta = {"description": "Query OSINTverse for exposed credentials", "auth_required": True}
    options = {"osintverse_api_key": "", "history_file": "", "legacy_events": True}
    options_desc = {
        "osintverse_api_key": "OSINTverse API key (billed per search from your OSINTverse wallet)",
        "history_file": "Optional JSON path to persist already-reported leak fingerprints so repeats are not re-emitted on later scans. Leave empty to disable.",
        "legacy_events": "Also emit the flat USERNAME, PASSWORD and HASHED_PASSWORD events next to LEAKED_CREDENTIAL",
    }
    target_only = True
    # leak databases are keyed by email domain, not DNS: wildcard records do not matter
    reject_wildcards = False

    SOURCE = ""
    source_name = ""
    osintverse_provider = ""

    max_field_length = 500
    max_profile_sources = 10
    # EMAIL_PROFILE field -> record fields that may hold it, in order of preference
    profile_fields = {
        "full_name": ("full_name", "fullname", "name"),
        "first_name": ("first_name", "firstname"),
        "last_name": ("last_name", "lastname"),
        "phone_number": ("phone", "phone_number", "telephone", "mobile"),
        "position": ("position", "job_title", "jobtitle", "positionatwork"),
        "company": ("company", "companyname"),
        "address": ("address",),
        "city": ("city",),
        "state": ("state", "region"),
        "country": ("country",),
        "birthdate": ("birthdate", "dob", "bday"),
        "ip_address": ("ip_address", "ip"),
    }

    async def setup(self):
        self.history = LeakHistory(str(self.config.get("history_file", "")).strip(), warn=self.warning)
        self.legacy_events = bool(self.config.get("legacy_events", True))
        self._state_lock = asyncio.Lock()
        self.osintverse = OSINTverseClient(self, self.config.get("osintverse_api_key", ""))
        success, reason = await self.setup_api()
        if not success:
            return success, reason
        return await super().setup()

    async def setup_api(self):
        return await self.osintverse.check(self.osintverse_provider, "domain")

    async def filter_event(self, event):
        # a registrable-domain search already returns the leaks of all its subdomains; never pay twice
        query = self.make_query(event)
        if self.helpers.split_domain(query)[1] != query:
            return False, f'"{query}" is not a registrable domain'
        return await super().filter_event(event)

    async def handle_event(self, event):
        query = self.make_query(event)
        # per-domain state: one EMAIL_ADDRESS event and one merged EMAIL_PROFILE per leaked address
        email_events, profiles = {}, {}
        for entry in await self.fetch_records(query, event):
            await self.emit_leak_record(entry, event, query, email_events, profiles)
        await self.emit_profiles(email_events, profiles)
        await self._save_history()

    async def fetch_records(self, query, event):
        search = await self.osintverse.search(self.osintverse_provider, "domain", query)
        sources, matches = self.osintverse.results(search)
        self.log_truncation(sources, query)
        return [self.normalize_breach_record(m) for m in matches if m.get("type") == "breach_record"]

    def log_truncation(self, sources, query):
        for source in sources:
            returned, total = source.get("returned"), source.get("total")
            if isinstance(returned, int) and isinstance(total, int) and returned < total:
                self.info(
                    f'{self.source_name} through OSINTverse returned only {returned:,} of {total:,} records for "{query}"'
                )

    @classmethod
    def normalize_breach_record(cls, match):
        """
        Convert an OSINTverse breach_record match (scalar fields) into the DeHashed entry shape (list fields).
        """

        def as_list(value):
            if value in (None, ""):
                return []
            return value if isinstance(value, list) else [value]

        entry = {
            "email": as_list(match.get("email")),
            "username": as_list(match.get("username")),
            "password": as_list(match.get("password")),
            "hashed_password": as_list(match.get("hashed_password")),
            "database_name": match.get("database_name") or "",
            "leaked_at": match.get("leaked_at") or "",
        }
        for aliases in cls.profile_fields.values():
            for field in aliases:
                if match.get(field) not in (None, ""):
                    entry[field] = as_list(match[field])
        return entry

    async def emit_leak_record(self, entry, event, query, email_events=None, profiles=None):
        email_events = {} if email_events is None else email_events
        profiles = {} if profiles is None else profiles
        # some providers do a poor job of the email field, so we extract valid addresses from it
        emails = []
        for email in entry.get("email", []):
            email_str = str(email).replace("\\", "")
            found_emails = list(await self.helpers.re.extract_emails(email_str))
            if not found_emails:
                self.debug(f"Invalid email from {self.source_name}: {email_str}")
                continue
            emails += [e for e in found_emails if e not in emails]

        users = [str(u) for u in entry.get("username", []) if u]
        phones = [str(p) for p in entry.get("phone", []) if p]
        pws = [str(p) for p in entry.get("password", []) if p]
        h_pws = [str(h) for h in entry.get("hashed_password", []) if h]
        db_name = entry.get("database_name", "")

        # Skip records already reported on a previous scan (when history_file is set).
        record_fp = record_fingerprint(self.SOURCE, db_name, emails, users or phones, pws, h_pws)
        date_tags = indexed_date_tags(entry)
        if date_tags:
            record_fp += ":" + ":".join(date_tags)
        if self.history.contains(record_fp):
            return
        self.history.add(record_fp)

        tags = list(date_tags) + list(entry.get("tags", []))
        if db_name:
            tags.append(f"db-{db_name}")
        leak_url = entry.get("url", "")
        found_at = f" leaked for {leak_url}" if leak_url else ""

        if emails:
            for email in emails:
                email_event = await self._email_event(email, event, query, tags, email_events)
                if email_event is None:
                    continue
                # an address at another domain (e.g. a customer's gmail) is not this domain's asset
                parent = email_event if self.in_domain(email_event.host, query) else event
                await self._emit_leaks(entry, event, parent, query, tags, email=email_event.data, username=users)
                self._merge_profile(profiles, email_event.data, entry)
                if self.legacy_events:
                    await self._emit_secrets(email_event.data, email_event, users, pws, h_pws, tags, found_at)
        elif users or phones:
            # credentials tied to a bare username or phone number (e.g. stealer logs) rather than an email address
            await self._emit_leaks(entry, event, event, query, tags, username=users)
            if self.legacy_events:
                for user in users or phones:
                    user_event = self.make_event(user, "USERNAME", parent=event, tags=tags)
                    if user_event is None:
                        continue
                    await self.emit_event(
                        user_event,
                        context=f'{{module}} searched {self.source_name} for "{query}" and found {{event.type}}{found_at}: {{event.data}}',
                    )
                    await self._emit_secrets(user, user_event, [], pws, h_pws, tags, found_at)

    async def _email_event(self, email, event, query, tags, email_events):
        if email in email_events:
            return email_events[email]
        email_event = self.make_event(email, "EMAIL_ADDRESS", parent=event, tags=tags)
        if email_event is not None:
            await self.emit_event(
                email_event,
                context=f'{{module}} searched {self.source_name} for "{query}" and found {{event.type}}: {{event.data}}',
            )
        email_events[email] = email_event
        return email_event

    async def _emit_leaks(self, entry, event, parent, query, tags, email=None, username=None):
        """One LEAKED_CREDENTIAL per secret on the record (or one without a secret for exposure-only rows)."""
        secrets = [{"password": p} for p in entry.get("password", []) if p]
        secrets += [{"hashed_password": h} for h in entry.get("hashed_password", []) if h]
        leak_host = await self._leak_host(email, entry.get("url"), event, query)
        base = {
            "host": leak_host,
            "domain": query,
            "provider": self.SOURCE,
            "email": email,
            "username": (username or [None])[0],
            "phone": (entry.get("phone") or [None])[0],
            "hash_type": entry.get("hash_type"),
            "salt": entry.get("salt"),
            "database_name": entry.get("database_name"),
            "database_description": entry.get("database_description"),
            "login_url": entry.get("url"),
            "category": entry.get("category"),
            "password_strength": entry.get("password_strength"),
            "leaked_at": entry.get("leaked_at"),
            "indexed_at": indexed_date(entry),
        }
        for secret in secrets or [{}]:
            data = {}
            for key, value in dict(base, **secret).items():
                if isinstance(value, bool) or value in (None, ""):
                    continue
                data[key] = value if isinstance(value, int) else str(value).strip()[: self.max_field_length]
            if not any(data.get(k) for k in ("email", "username", "phone")):
                continue
            identity = data.get("email") or data.get("username") or data.get("phone")
            kind = "password" if "password" in data else "password hash" if "hashed_password" in data else "record"
            leak_event = self.make_event(data, "LEAKED_CREDENTIAL", parent=parent, tags=tags)
            if leak_event is None:
                continue
            await self.emit_event(
                leak_event,
                context=f'{{module}} searched {self.source_name} for "{query}" and found a leaked {kind} for {identity}',
            )

    async def _leak_host(self, email, url, event, query):
        """
        The subdomain a leak belongs to (the email's domain, else the leaked login URL's host), or the searched
        domain. Subdomains found this way are also reported as DNS_NAME events (bbot dedupes repeats).
        """
        hosts = [str(email).rsplit("@", 1)[-1].lower()] if email else []
        if url:
            with suppress(Exception):
                hosts.append((self.helpers.urlparse(str(url)).hostname or "").lower())
        for host in hosts:
            if host == query or not self.in_domain(host, query):
                continue
            await self.emit_event(
                host,
                "DNS_NAME",
                parent=event,
                abort_if=self.abort_if,
                context=f'{{module}} searched {self.source_name} for "{query}" and found leaked credentials for {{event.type}}: {{event.data}}',
            )
            return host
        return query

    def _merge_profile(self, profiles, email, entry):
        """Null-safe merge: the first non-empty value of each field wins, later records only fill gaps."""
        profile = profiles.setdefault(email, {})
        for field, aliases in self.profile_fields.items():
            if profile.get(field):
                continue
            for alias in aliases:
                values = entry.get(alias)
                for value in values if isinstance(values, list) else [values]:
                    if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
                        profile[field] = str(value).strip()[: self.max_field_length]
                        break
                if profile.get(field):
                    break
        db_name = str(entry.get("database_name") or "").strip()
        sources = profile.setdefault("sources", [])
        if db_name and db_name not in sources and len(sources) < self.max_profile_sources:
            sources.append(db_name)

    async def emit_profiles(self, email_events, profiles):
        for email, profile in profiles.items():
            email_event = email_events.get(email)
            details = {k: v for k, v in profile.items() if k != "sources" and v}
            if email_event is None or not details:
                continue
            data = dict(details, host=email_event.host, email=email, provider=self.SOURCE)
            if profile.get("sources"):
                data["sources"] = profile["sources"]
            await self.emit_event(
                data,
                "EMAIL_PROFILE",
                email_event,
                context=f"{{module}} found personal details {self.source_name} associates with {email}",
            )

    @staticmethod
    def in_domain(host, domain):
        host = str(host or "").lower()
        return host == domain or host.endswith(f".{domain}")

    async def _emit_secrets(self, identity, parent, users, pws, h_pws, tags, found_at=""):
        for event_type, values in (("USERNAME", users), ("PASSWORD", pws), ("HASHED_PASSWORD", h_pws)):
            for value in values:
                await self.emit_event(
                    f"{identity}:{value}",
                    event_type,
                    parent=parent,
                    tags=tags,
                    context=f"{{module}} found {identity} with {{event.type}}{found_at}: {{event.data}}",
                )

    async def _save_history(self):
        async with self._state_lock:
            self.history.save()
