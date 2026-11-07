import asyncio
import json
import ipaddress
import os
import re
from urllib.parse import urlparse

from bbot.core.helpers import shared_infra
from bbot.modules.base import BaseInterceptModule


DNS_SCOPE_EVENT_TYPES = {"DNS_NAME", "DNS_NAME_UNRESOLVED", "RAW_DNS_RECORD"}
IP_RANGE_SCOPE_EVENT_TYPES = {"IP_RANGE"}
WEB_SCOPE_EVENT_TYPES = {
    "WEB_URL_BATCH",
    "URL",
    "URL_UNVERIFIED",
    "URL_HINT",
    "HTTP_RESPONSE",
    "TECHNOLOGY",
    "WAF",
    "TLS_CERTIFICATE",
}
IP_ANALYSIS_EVENT_TYPES = {
    "IP_ADDRESS",
    "OPEN_TCP_PORT",
    "OPEN_UDP_PORT",
    "PROTOCOL",
    "GEOLOCATION",
    "ASN",
}
PORT_SERVICE_EVENT_TYPES = {"OPEN_TCP_PORT", "OPEN_UDP_PORT", "PROTOCOL"}
REPOSITORY_SCOPE_EVENT_TYPES = {"CODE_REPOSITORY", "CODE_REPOSITORY_OWNER"}
REPOSITORY_OWNER_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
REPOSITORY_HOSTS = REPOSITORY_OWNER_HOSTS | {"hub.docker.com"}
EMAIL_SCOPE_EVENT_TYPES = {"EMAIL_ADDRESS", "EMAIL_PROFILE"}
# Facts about one domain or IP. A domain is held to the hostname rule below; an IP must be in scope.
HOST_PROFILE_EVENT_TYPES = {"HOST_REPUTATION"}
# Their host is a provider's by nature (a bucket, a store listing) or they report
# a test of an asset this filter already accepted (a lookalike domain of the
# target, a secret on github.com). Every other event must name in-scope hosts.
REGISTRATION_EVENT_TYPES = {"DOMAIN_WHOIS", "DOMAIN_DNS_CONFIG"}
OFF_DOMAIN_EVENT_TYPES = {"STORAGE_BUCKET", "MOBILE_APP", "OPTIONAL_MOBILE_APP", "FINDING", "VULNERABILITY"}
# Seeded hostnames are resolved before the scan starts; a world can seed hundreds of them.
SEED_RESOLUTION_CONCURRENCY = 20
SEED_RESOLUTION_TIMEOUT_SECONDS = 10
HOSTNAME = re.compile(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}")
GITHUB_SITE_ROUTES = {
    "about",
    "collections",
    "customer-stories",
    "enterprise",
    "explore",
    "features",
    "issues",
    "join",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "resources",
    "search",
    "settings",
    "signup",
    "sponsors",
    "topics",
}
NON_IDENTITY_DOMAIN_LABELS = {
    "admin",
    "api",
    "app",
    "auth",
    "blog",
    "cdn",
    "co",
    "dev",
    "docs",
    "help",
    "login",
    "mail",
    "portal",
    "shop",
    "staging",
    "static",
    "support",
    "www",
}


class offchain_scope_filter(BaseInterceptModule):
    watched_events = ["*"]
    flags = ["passive", "safe"]
    # Intercept every discovery. BBOT forwards events when an intercept module's
    # normal scope-distance postcheck declines them, bypassing handle_event.
    scope_distance_modifier = None
    options = {"scope_targets": []}
    options_desc = {
        "scope_targets": "GuardianSentry effective offchain scope targets, encoded as type:value strings",
    }
    meta = {
        "description": "Drop offchain events outside the seeded GuardianSentry scope",
        "created_date": "2026-05-18",
        "author": "GitHub Copilot",
    }

    _priority = 2
    _disable_auto_module_deps = True

    async def setup(self):
        self.allowed_domain_roots = set()
        self.allowed_email_addresses = set()
        self.allowed_repo_tuples = set()
        self.allowed_repo_owners = set()
        self.allowed_ips = set()
        self.allowed_ip_range_values = set()
        self.allowed_ip_ranges = []
        self.seeded_hostnames = set()
        self._load_config_scope()
        self._load_seed_scope()
        private = await self._private_seed_resolution()
        if private:
            # Setup failing aborts the scan before any module contacts the address.
            return False, f"scan target {private} currently resolves to a non-public IP address"
        return True

    async def _private_seed_resolution(self):
        """The first seeded hostname that resolves to a non-public address, if any."""
        hosts = sorted(self.seeded_hostnames)
        limit = asyncio.Semaphore(SEED_RESOLUTION_CONCURRENCY)

        async def check(host):
            async with limit:
                addresses = await self._resolve_addresses(host)
            return host if any(not self._is_global_ip(address) for address in addresses) else None

        return next((host for host in await asyncio.gather(*(check(host) for host in hosts)) if host), None)

    async def _resolve_addresses(self, host):
        """Every address the system resolver returns for ``host``; none when it does not resolve, since passive
        discovery can still run for an unresolved seed."""
        try:
            answers = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, None), SEED_RESOLUTION_TIMEOUT_SECONDS
            )
        except (OSError, asyncio.TimeoutError, UnicodeError):
            return []
        return [answer[4][0].split("%", 1)[0] for answer in answers]

    async def handle_event(self, event, **kwargs):
        if event.type in DNS_SCOPE_EVENT_TYPES | WEB_SCOPE_EVENT_TYPES | IP_ANALYSIS_EVENT_TYPES:
            if any(not self._is_global_ip(candidate) for candidate in self._event_ip_candidates(event)):
                return False, "event resolves to a non-public IP address"

        shared_frontend = self._shared_frontend_refusal(event)
        if shared_frontend:
            return False, shared_frontend

        if event.type == "WEB_FRONTEND":
            data = self._event_data(event)
            host = self._normalize_domain(data.get("host"))
            if (
                str(getattr(event, "module", "")) == "originfinder"
                and host
                and self._domain_allowed(host)
                and self._extract_url_host(data.get("url")) == host
            ):
                return True
            return False, "frontend event is not for an in-scope website"

        if event.type == "WEB_ORIGIN":
            if self._verified_origin_ip(event):
                return True
            return False, "origin event lacks an in-scope verified direct endpoint"

        if event.type in REPOSITORY_SCOPE_EVENT_TYPES:
            return self._handle_repository_event(event)

        if event.type == "SOCIAL":
            if self._social_profile_allowed(self._event_data(event), event):
                return True
            return False, "social profile has no first-party identity or explicit owner evidence"

        if event.type == "LEAKED_CREDENTIAL":
            # A leak belongs to the domain that was searched (or its subdomain), even
            # when the leaked login is a third-party address such as a customer's gmail.
            data = self._event_data(event)
            if self._event_domain_in_scope(event) or self._domain_allowed(
                self._normalize_domain(data.get("domain")) or ""
            ):
                return True
            if self._event_email_allowed(event):
                return True
            return False, "leaked credential is outside the seeded domain or email scope"

        if event.type in EMAIL_SCOPE_EVENT_TYPES:
            if self._event_email_allowed(event):
                return True
            return False, "email address is outside the seeded email or domain scope"

        if event.type in DNS_SCOPE_EVENT_TYPES:
            if not self._event_domain_in_scope(event):
                return False, "dns event is outside the seeded domain scope"
            self._remember_allowed_ips(event)
            return True

        if event.type in HOST_PROFILE_EVENT_TYPES:
            host = str(self._event_data(event).get("host") or getattr(event, "host", None) or "").strip()
            if self._is_ip(host) and not self._ip_allowed(host):
                return False, "host profile is for an IP address outside the seeded scope"

        if event.type in IP_RANGE_SCOPE_EVENT_TYPES:
            if self._event_ip_range_allowed(event):
                return True
            return False, "IP range event is outside the seeded IP range scope"

        if event.type in WEB_SCOPE_EVENT_TYPES:
            # A shared hosting/CDN IP is not permission to scan another
            # customer's hostname (for example github.com on a linked page).
            host = self._extract_event_url_host(event) or self._normalize_domain(getattr(event, "host", None))
            if not host:
                host = self._normalize_domain(self._event_data(event).get("host"))
            if not host:
                return False, "web event has no host to verify against the seeded scope"
            if self._is_ip(host):
                if self._ip_allowed(host):
                    return True
            elif any(host == root or host.endswith(f".{root}") for root in self.allowed_domain_roots):
                return True
            if event.type == "URL_UNVERIFIED":
                await self._emit_external_social_profile(event)
            return False, "web event host is outside the seeded domain and IP scope"

        if event.type in IP_ANALYSIS_EVENT_TYPES:
            origin_ip = self._verified_origin_ip(event)
            if origin_ip:
                self.allowed_ips.add(origin_ip)
                return True
            if event.type in PORT_SERVICE_EVENT_TYPES:
                if self._event_has_allowed_primary_ip(event):
                    self._remember_allowed_primary_ips(event)
                    return True
                return False, "port/protocol event is not keyed to an allowed IP address"
            if self._event_has_allowed_ip(event) or self._event_is_allowed_domain_resolution_ip(event):
                self._remember_allowed_analysis_ips(event)
                return True
            return False, "IP analysis event is not tied to an allowed IP from seeded domain A/AAAA data"

        # Any other event that names a hostname must name an in-scope one, so new
        # event types and modules cannot add third-party domains (OTX passive DNS
        # on a shared Vercel IP returned hundreds of other customers' hosts).
        if event.type not in OFF_DOMAIN_EVENT_TYPES:
            # WHOIS and DNS configuration describe the registered domain, which is the parent of a seeded subdomain.
            registration = event.type in REGISTRATION_EVENT_TYPES
            if any(
                not self._domain_allowed(host) and not (registration and self._registers_allowed_root(host))
                for host in self._event_hostnames(event)
            ):
                return False, "event names a hostname outside the seeded domain scope"
        return True

    def _shared_frontend_refusal(self, event):
        """Why an event about a shared frontend (CDN, WAF, load balancer, API gateway, shared platform) is dropped.

        Such an address serves every customer of its provider. A port or service on it is the provider's, so no
        module may fingerprint, brute-force or scan it, and its bare address is not a website of the target unless
        the scan was seeded with it. A name behind the frontend stays a website of the target.
        """
        if event.type in PORT_SERVICE_EVENT_TYPES:
            # Port and protocol events are keyed to an address; the rules below drop any keyed to a name.
            address = self._event_primary_ip(event)
            if address and self._address_frontend(event, address):
                return "service on a shared frontend address belongs to the provider, not the target"
            return None
        if event.type in WEB_SCOPE_EVENT_TYPES and "target" not in getattr(event, "tags", ()):
            host = self._extract_event_url_host(event) or self._normalize_domain(getattr(event, "host", None))
            if host and self._is_ip(host) and self._address_frontend(event, host):
                return "bare address of a shared frontend is not a website of the target"
        return None

    def _address_frontend(self, event, address):
        return shared_infra.event_frontend(self.scan, event) or shared_infra.known_frontend(self.scan, address)

    def _event_hostnames(self, event):
        data = self._event_data(event)
        values = (
            getattr(event, "host", None),
            data.get("host"),
            data.get("domain"),
            data.get("hostname"),
            self._extract_event_url_host(event),
        )
        hosts = {self._normalize_domain(str(value)) for value in values if value}
        return {host for host in hosts if host and not self._is_ip(host) and HOSTNAME.fullmatch(host)}

    async def _emit_external_social_profile(self, event):
        """Retain profile discovery without handing its third-party URL to active modules."""
        profile = self._social_profile_data(self._extract_event_url(event))
        if not profile:
            return
        parent = event.get_parent()
        if (
            parent is None
            or (parent.type == "SOCIAL" and parent.data == profile)
            or not self._social_profile_allowed(profile, parent)
        ):
            return
        social = self.make_event(profile, "SOCIAL", parent=parent)
        await self.emit_event(social, context="{module} identified a third-party social profile link")

    def _social_profile_allowed(self, profile, event):
        """A link alone is not evidence that a profile belongs to this scan target."""
        if not isinstance(profile, dict):
            return False
        name = str(profile.get("profile_name") or "").lower()
        platform = str(profile.get("platform") or "").lower()
        if not re.fullmatch(r"[a-z0-9_.-]{1,80}", name) or not platform:
            return False
        canonical = self._social_profile_data(profile.get("url"))
        if not canonical or canonical["platform"] != platform or canonical["profile_name"] != name:
            return False
        host = self._extract_url_host(canonical["url"])
        if platform in {"github", "gitlab", "bitbucket"} and (
            (host, name) in self.allowed_repo_owners or ("*", name) in self.allowed_repo_owners
        ):
            return True
        identity = re.sub(r"[^a-z0-9]", "", name)
        domain_identities = {
            re.sub(r"[^a-z0-9]", "", label)
            for root in self.allowed_domain_roots
            for label in root.split(".")[:-1]
            if label not in NON_IDENTITY_DOMAIN_LABELS
        }
        # The company's own page linking a profile that names it ("halbornsecurity" for halborn.com) is evidence;
        # a profile that only resembles another word is not.
        if not identity or not any(
            identity == known or (len(known) >= 4 and known in identity) for known in domain_identities
        ):
            return False
        observed_response = False
        first_party_page = False
        for ancestor in [event, *self._parent_events(event)][:8]:
            if getattr(ancestor, "type", None) not in WEB_SCOPE_EVENT_TYPES:
                continue
            observed_response |= ancestor.type == "HTTP_RESPONSE"
            host = self._extract_event_url_host(ancestor)
            if host and self._domain_allowed(host):
                first_party_page = True
        return first_party_page and observed_response

    def _social_profile_data(self, value):
        if not isinstance(value, str):
            return None
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            return None
        platform = None
        profile_name = None
        if host in {"github.com", "www.github.com", "gitlab.com", "gitlab.org", "bitbucket.org"}:
            if host.endswith("github.com") and parts[0].lower() in GITHUB_SITE_ROUTES:
                return None
            platform = (
                "github" if host.endswith("github.com") else "gitlab" if host.startswith("gitlab.") else "bitbucket"
            )
            profile_name = parts[0]
        elif host in {"twitter.com", "x.com", "instagram.com", "facebook.com"}:
            platform = "twitter" if host in {"twitter.com", "x.com"} else host.split(".")[0]
            profile_name = parts[0]
        elif host in {"linkedin.com", "www.linkedin.com"} and len(parts) >= 2 and parts[0] in {"in", "company"}:
            platform = "linkedin"
            profile_name = parts[1]
        elif host in {"youtube.com", "www.youtube.com"} and parts[0].startswith("@"):
            platform = "youtube"
            profile_name = parts[0][1:]
        elif host == "hub.docker.com" and len(parts) >= 2 and parts[0] in {"u", "r"}:
            platform = "docker"
            profile_name = parts[1]
        elif host == "huggingface.co":
            platform = "huggingface"
            profile_name = parts[0]
        elif host == "www.postman.com":
            platform = "postman"
            profile_name = parts[0]
        elif host == "linktr.ee":
            platform = "linktree"
            profile_name = parts[0]
        if not profile_name or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", profile_name):
            return None
        profile_name = profile_name.lower()
        canonical_host = "github.com" if platform == "github" else "linkedin.com" if platform == "linkedin" else host
        path = f"/{parts[0]}/{parts[1]}" if platform in {"linkedin", "docker"} else f"/{profile_name}"
        return {"platform": platform, "url": f"https://{canonical_host}{path.lower()}", "profile_name": profile_name}

    def _load_seed_scope(self):
        for seed in self.scan.target.seeds.event_seeds:
            seed_type = getattr(seed, "type", "")
            raw_input = str(getattr(seed, "input", "")).strip()
            seed_data = getattr(seed, "data", None)

            if seed_type == "DNS_NAME":
                domain = self._normalize_domain(seed_data)
                if domain:
                    self.allowed_domain_roots.add(domain)
                    self.seeded_hostnames.add(domain)
                continue

            if seed_type == "EMAIL_ADDRESS":
                email = self._normalize_email(seed_data)
                if email:
                    self.allowed_email_addresses.add(email)
                    self.seeded_hostnames.add(email.rsplit("@", 1)[-1])
                continue

            if seed_type in {"URL", "URL_UNVERIFIED"}:
                host = self._extract_url_host(seed_data)
                normalized = self._normalize_domain(host)
                if normalized and not self._is_ip(normalized):
                    self.allowed_domain_roots.add(normalized)
                    self.seeded_hostnames.add(normalized)
                continue

            if seed_type == "IP_ADDRESS":
                if self._is_global_ip(seed_data):
                    self.allowed_ips.add(str(seed_data))
                continue

            if seed_type == "IP_RANGE":
                self._remember_allowed_ip_range(seed_data)
                continue

            if seed_type == "CODE_REPOSITORY":
                repo = self._parse_repository_scope(self._extract_seed_url(raw_input, seed_data, "CODE_REPOSITORY:"))
                if repo:
                    self.allowed_repo_tuples.add(repo)
                continue

            if seed_type == "CODE_REPOSITORY_OWNER":
                owner = self._parse_repository_owner_scope(
                    self._extract_seed_url(raw_input, seed_data, "CODE_REPOSITORY_OWNER:")
                )
                if owner:
                    self.allowed_repo_owners.add(owner)
                continue

            if seed_type == "ORG_STUB":
                owner_name = str(seed_data if seed_data is not None else raw_input.removeprefix("ORG_STUB:"))
                normalized_owner = owner_name.strip().lower()
                if normalized_owner:
                    self.allowed_repo_owners.add(("*", normalized_owner))

    def _load_config_scope(self):
        scope_targets = self.config.get("scope_targets", [])
        if not scope_targets:
            scope_targets = os.environ.get("GUARDIAN_OFFCHAIN_SCOPE_TARGETS", "")
        if isinstance(scope_targets, str):
            try:
                scope_targets = json.loads(scope_targets)
            except Exception:
                scope_targets = [entry.strip() for entry in scope_targets.split(",") if entry.strip()]

        if not isinstance(scope_targets, list):
            return

        for raw_scope_target in scope_targets:
            if not isinstance(raw_scope_target, str):
                continue

            target_type, _, target_value = raw_scope_target.partition(":")
            target_type = target_type.strip().lower()
            target_value = target_value.strip()
            if not target_type or not target_value:
                continue

            if target_type == "domain":
                normalized = self._normalize_domain(target_value)
                if normalized:
                    self.allowed_domain_roots.add(normalized)
                continue

            if target_type == "url":
                host = self._extract_url_host(target_value)
                normalized = self._normalize_domain(host)
                if normalized and not self._is_ip(normalized):
                    self.allowed_domain_roots.add(normalized)
                continue

            if target_type == "email":
                email = self._normalize_email(target_value)
                if email:
                    self.allowed_email_addresses.add(email)
                continue

            if target_type == "ip_address":
                if self._is_ip(target_value):
                    self.allowed_ips.add(target_value)
                continue

            if target_type == "ip_range":
                self._remember_allowed_ip_range(target_value)
                continue

            if target_type == "code_repository":
                repo = self._parse_repository_scope(target_value)
                if repo:
                    self.allowed_repo_tuples.add(repo)
                continue

            if target_type == "code_repository_owner":
                owner = self._parse_repository_owner_scope(target_value)
                if owner:
                    self.allowed_repo_owners.add(owner)
                continue

            if target_type == "org_stub":
                normalized_owner = target_value.lower()
                if normalized_owner:
                    self.allowed_repo_owners.add(("*", normalized_owner))

    def _handle_repository_event(self, event):
        repo_url = self._extract_event_url(event)
        if not repo_url:
            return False, "repository event is missing a repository URL"

        if event.type == "CODE_REPOSITORY_OWNER":
            owner = self._parse_repository_owner_scope(repo_url)
            if owner and self._owner_allowed(owner):
                return True
            return False, "repository owner is outside the seeded repository scope"

        repo = self._parse_repository_scope(repo_url)
        if not repo:
            return False, "repository event does not contain a supported repository URL"
        if repo in self.allowed_repo_tuples or self._owner_allowed((repo[0], repo[1])):
            return True
        if self._is_discovered_github_org_repository(event, repo):
            return True
        return False, "repository is outside the seeded repository scope"

    @staticmethod
    def _is_discovered_github_org_repository(event, repo):
        if repo[0] != "github.com" or str(getattr(event, "module", "")) != "github_org":
            return False
        if "github-org-scope" not in getattr(event, "tags", ()):
            return False
        get_parent = getattr(event, "get_parent", None)
        parent = get_parent() if callable(get_parent) else getattr(event, "parent", None)
        if getattr(parent, "type", "") != "SOCIAL":
            return False
        profile = getattr(parent, "data", {})
        if not isinstance(profile, dict) or str(profile.get("profile_name", "")).lower() != repo[1]:
            return False
        if "github-org-member" in getattr(parent, "tags", ()):
            if str(getattr(parent, "module", "")) != "github_org":
                return False
            get_grandparent = getattr(parent, "get_parent", None)
            grandparent = get_grandparent() if callable(get_grandparent) else getattr(parent, "parent", None)
            return getattr(grandparent, "type", "") == "SOCIAL" and "github-org" in getattr(grandparent, "tags", ())
        return True

    def _owner_allowed(self, owner_tuple):
        platform, owner = owner_tuple
        return owner_tuple in self.allowed_repo_owners or ("*", owner) in self.allowed_repo_owners

    def _event_domain_in_scope(self, event):
        for domain in self._event_domain_candidates(event):
            if any(domain == root or domain.endswith(f".{root}") for root in self.allowed_domain_roots):
                return True
        return False

    def _event_email_allowed(self, event):
        email = self._event_email_address(event)
        if not email:
            return False
        if email in self.allowed_email_addresses:
            return True
        _, _, domain = email.rpartition("@")
        return bool(
            domain and any(domain == root or domain.endswith(f".{root}") for root in self.allowed_domain_roots)
        )

    def _event_has_allowed_ip(self, event):
        return any(self._ip_allowed(candidate) for candidate in self._event_ip_candidates(event))

    def _event_has_allowed_primary_ip(self, event):
        return any(self._ip_allowed(candidate) for candidate in self._event_primary_ip_candidates(event))

    def _event_is_allowed_domain_resolution_ip(self, event):
        if event.type != "IP_ADDRESS":
            return False

        address = self._event_primary_ip(event)
        if not address or not self._is_global_ip(address):
            return False

        for parent in self._parent_events(event):
            if parent.type not in DNS_SCOPE_EVENT_TYPES:
                continue
            if not self._event_domain_in_scope(parent):
                continue
            if address in self._event_a_aaaa_ip_candidates(parent):
                return True

        return False

    def _domain_allowed(self, host):
        return any(host == root or host.endswith(f".{root}") for root in self.allowed_domain_roots)

    def _registers_allowed_root(self, host):
        return "." in host and any(root.endswith(f".{host}") for root in self.allowed_domain_roots)

    def _verified_origin_ip(self, event):
        for ancestor in [event, *self._parent_events(event)]:
            if getattr(ancestor, "type", None) != "WEB_ORIGIN":
                continue
            if str(getattr(ancestor, "module", "")) != "originfinder":
                continue
            data = self._event_data(ancestor)
            host = self._normalize_domain(data.get("host"))
            ip = data.get("ip")
            try:
                confidence = float(data.get("confidence"))
                port = int(data.get("port"))
            except (TypeError, ValueError):
                continue
            if (
                not host
                or not self._domain_allowed(host)
                or self._extract_url_host(data.get("url")) != host
                or not self._is_global_ip(ip)
                or confidence < 0.88
                or not 1 <= port <= 65535
                or data.get("protocol") not in {"http", "https"}
            ):
                continue
            if event is ancestor or self._event_primary_ip(event) == ip:
                return str(ip)
        return None

    def _remember_allowed_analysis_ips(self, event):
        for candidate in self._event_ip_candidates(event):
            if self._is_global_ip(candidate):
                self.allowed_ips.add(str(candidate).strip())

    def _remember_allowed_primary_ips(self, event):
        for candidate in self._event_primary_ip_candidates(event):
            if self._is_global_ip(candidate):
                self.allowed_ips.add(str(candidate).strip())

    def _event_primary_ip(self, event):
        for candidate in self._event_primary_ip_candidates(event):
            if self._is_ip(candidate):
                return str(candidate).strip()
        return None

    def _event_primary_ip_candidates(self, event):
        data = self._event_data(event)
        candidates = [
            getattr(event, "data", None) if event.type == "IP_ADDRESS" else None,
            getattr(event, "host", None),
            data.get("host"),
            data.get("ip"),
            self._extract_netloc_ip(getattr(event, "data", None)),
            self._extract_netloc_ip(getattr(event, "netloc", None)),
        ]
        return [str(candidate).strip() for candidate in candidates if self._is_ip(candidate)]

    def _parent_events(self, event):
        get_parents = getattr(event, "get_parents", None)
        if callable(get_parents):
            try:
                return list(get_parents())
            except Exception:
                return []

        parents = []
        parent = getattr(event, "parent", None)
        while parent is not None and not isinstance(parent, str):
            parents.append(parent)
            parent = getattr(parent, "parent", None)
        return parents

    def _event_ip_range_allowed(self, event):
        data = self._event_data(event)
        candidates = [
            getattr(event, "data", None) if isinstance(getattr(event, "data", None), str) else None,
            getattr(event, "host", None),
            data.get("subnet"),
            data.get("cidr"),
        ]
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate.strip():
                continue
            try:
                network = ipaddress.ip_network(candidate.strip(), strict=False)
            except ValueError:
                continue
            if str(network) in self.allowed_ip_range_values:
                return True
        return False

    def _remember_allowed_ips(self, event):
        for candidate in self._event_a_aaaa_ip_candidates(event):
            if self._is_global_ip(candidate):
                self.allowed_ips.add(candidate)

    def _event_a_aaaa_ip_candidates(self, event):
        candidates = []
        if event.type == "DNS_NAME":
            candidates.extend(getattr(event, "resolved_hosts", []) or [])
            raw_children = getattr(event, "dns_children", None)
            if isinstance(raw_children, dict):
                for key in ("A", "AAAA", "a", "aaaa"):
                    candidates.extend(raw_children.get(key, []) or [])

        if event.type != "RAW_DNS_RECORD":
            return [str(candidate).strip() for candidate in candidates if self._is_ip(candidate)]

        data = self._event_data(event)
        record_type = str(data.get("type", "")).strip().upper()
        answer = data.get("answer")
        if record_type in {"A", "AAAA"} and self._is_ip(answer):
            candidates.append(answer)

        return [str(candidate).strip() for candidate in candidates if self._is_ip(candidate)]

    def _event_domain_candidates(self, event):
        data = self._event_data(event)
        candidates = [
            self._normalize_domain(event.host),
            self._normalize_domain(data.get("host")),
            self._normalize_domain(data.get("name")),
            self._normalize_domain(self._extract_event_url_host(event)),
        ]

        if event.type in {"DNS_NAME", "DNS_NAME_UNRESOLVED"}:
            candidates.append(self._normalize_domain(getattr(event, "data", None)))

        return [candidate for candidate in candidates if candidate and not self._is_ip(candidate)]

    def _event_ip_candidates(self, event):
        data = self._event_data(event)
        candidates = [
            event.host,
            getattr(event, "netloc", None),
            data.get("host"),
            data.get("ip"),
            self._extract_event_url_host(event),
            getattr(event, "data", None) if event.type == "IP_ADDRESS" else None,
        ]
        if event.type in IP_ANALYSIS_EVENT_TYPES:
            candidates.append(self._extract_netloc_ip(getattr(event, "data", None)))
            candidates.append(self._extract_netloc_ip(getattr(event, "netloc", None)))

        for resolved_host in getattr(event, "resolved_hosts", []) or []:
            candidates.append(resolved_host)

        raw_children = getattr(event, "dns_children", None)
        if isinstance(raw_children, dict):
            for key in ("A", "AAAA", "a", "aaaa"):
                for answer in raw_children.get(key, []) or []:
                    candidates.append(answer)

        normalized = []
        for candidate in candidates:
            if self._is_ip(candidate):
                normalized.append(str(candidate).strip())
        return normalized

    def _event_email_address(self, event):
        data = self._event_data(event)
        candidates = [
            getattr(event, "data", None),
            data.get("email"),
            data.get("email_address"),
            data.get("address"),
        ]
        for candidate in candidates:
            email = self._normalize_email(candidate)
            if email:
                return email
        return None

    def _normalize_email(self, value):
        if not isinstance(value, str):
            return None
        email = value.strip().lower()
        if not email or email.count("@") != 1:
            return None
        local, domain = email.rsplit("@", 1)
        if not local or not self._normalize_domain(domain):
            return None
        return email

    def _extract_netloc_ip(self, value):
        if not isinstance(value, str) or not value.strip():
            return None
        value = value.strip()
        if self._is_ip(value):
            return value
        if value.startswith("["):
            host, separator, _ = value[1:].partition("]")
            return host if separator and self._is_ip(host) else None
        host, separator, port = value.rpartition(":")
        if not separator or not port.isdigit():
            return None
        return host if self._is_ip(host) else None

    def _extract_event_url(self, event):
        data = self._event_data(event)
        if isinstance(getattr(event, "data", None), dict):
            url = data.get("url")
            if isinstance(url, str) and url.strip():
                return url.strip()

        if isinstance(getattr(event, "data", None), str) and str(event.data).startswith(("http://", "https://")):
            return str(event.data).strip()

        return None

    def _extract_event_url_host(self, event):
        return self._extract_url_host(self._extract_event_url(event))

    def _extract_seed_url(self, raw_input, seed_data, prefix):
        if isinstance(seed_data, dict):
            url = seed_data.get("url")
            if isinstance(url, str) and url.strip():
                return url.strip()
        if raw_input.startswith(prefix):
            return raw_input[len(prefix) :].strip()
        if isinstance(seed_data, str) and seed_data.strip():
            return seed_data.strip()
        return None

    def _parse_repository_scope(self, repo_url):
        if not isinstance(repo_url, str) or not repo_url.strip():
            return None

        try:
            parsed = urlparse(repo_url.strip())
        except Exception:
            return None

        host = (parsed.hostname or "").lower()
        if host not in REPOSITORY_HOSTS:
            return None

        segments = [segment for segment in parsed.path.split("/") if segment]
        if host == "hub.docker.com":
            if len(segments) >= 3 and segments[0] == "r":
                return (host, segments[1].lower(), segments[2].removesuffix(".git").lower())
            return None

        if host == "gitlab.com":
            if len(segments) < 2 or "-" in segments:
                return None
            repo_path_segments = segments[1:]
            repo_path_segments[-1] = repo_path_segments[-1].removesuffix(".git")
            repo_path = "/".join(repo_path_segments).lower()
            return (host, segments[0].lower(), repo_path) if repo_path else None

        if len(segments) != 2:
            return None
        return (host, segments[0].lower(), segments[1].removesuffix(".git").lower())

    def _parse_repository_owner_scope(self, owner_url):
        if not isinstance(owner_url, str) or not owner_url.strip():
            return None

        try:
            parsed = urlparse(owner_url.strip())
        except Exception:
            return None

        host = (parsed.hostname or "").lower()
        if host not in REPOSITORY_OWNER_HOSTS:
            return None

        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) != 1:
            return None
        return (host, segments[0].lower())

    def _remember_allowed_ip_range(self, value):
        if not isinstance(value, str) or not value.strip():
            return
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
            if not network.is_global:
                return
            self.allowed_ip_ranges.append(network)
            self.allowed_ip_range_values.add(str(network))
        except ValueError:
            return

    def _ip_allowed(self, candidate):
        try:
            ip_value = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        if not ip_value.is_global:
            return False
        if candidate in self.allowed_ips:
            return True
        return any(ip_value in network for network in self.allowed_ip_ranges)

    def _extract_url_host(self, url_value):
        if not isinstance(url_value, str) or not url_value.strip():
            return None
        try:
            return (urlparse(url_value.strip()).hostname or "").lower() or None
        except Exception:
            return None

    def _event_data(self, event):
        return event.data if isinstance(getattr(event, "data", None), dict) else {}

    def _normalize_domain(self, value):
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower().rstrip(".")
        return normalized or None

    def _is_ip(self, value):
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    def _is_global_ip(self, value):
        try:
            return ipaddress.ip_address(str(value).strip()).is_global
        except ValueError:
            return False
