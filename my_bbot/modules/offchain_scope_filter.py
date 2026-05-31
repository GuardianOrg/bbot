import json
import ipaddress
import os
from urllib.parse import urlparse

from bbot.modules.base import BaseInterceptModule


DNS_SCOPE_EVENT_TYPES = {"DNS_NAME", "DNS_NAME_UNRESOLVED", "RAW_DNS_RECORD"}
IP_RANGE_SCOPE_EVENT_TYPES = {"IP_RANGE"}
WEB_SCOPE_EVENT_TYPES = {
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
EMAIL_SCOPE_EVENT_TYPES = {"EMAIL_ADDRESS"}


class offchain_scope_filter(BaseInterceptModule):
    watched_events = ["*"]
    flags = ["passive", "safe"]
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
        self._load_config_scope()
        self._load_seed_scope()
        return True

    async def handle_event(self, event, **kwargs):
        if event.type in REPOSITORY_SCOPE_EVENT_TYPES:
            return self._handle_repository_event(event)

        if event.type in EMAIL_SCOPE_EVENT_TYPES:
            if self._event_email_allowed(event):
                return True
            return False, "email address is outside the seeded email or domain scope"

        if event.type in DNS_SCOPE_EVENT_TYPES:
            if not self._event_domain_in_scope(event):
                return False, "dns event is outside the seeded domain scope"
            self._remember_allowed_ips(event)
            return True

        if event.type in IP_RANGE_SCOPE_EVENT_TYPES:
            if self._event_ip_range_allowed(event):
                return True
            return False, "IP range event is outside the seeded IP range scope"

        if event.type in WEB_SCOPE_EVENT_TYPES:
            if self._event_domain_in_scope(event):
                return True
            if self._event_has_allowed_ip(event):
                return True
            return False, "web event is outside the seeded domain and IP scope"

        if event.type in IP_ANALYSIS_EVENT_TYPES:
            if event.type in PORT_SERVICE_EVENT_TYPES:
                if self._event_has_allowed_primary_ip(event):
                    self._remember_allowed_primary_ips(event)
                    return True
                return False, "port/protocol event is not keyed to an allowed IP address"
            if self._event_has_allowed_ip(event) or self._event_is_allowed_domain_resolution_ip(event):
                self._remember_allowed_analysis_ips(event)
                return True
            return False, "IP analysis event is not tied to an allowed IP from seeded domain A/AAAA data"

        return True

    def _load_seed_scope(self):
        for seed in self.scan.target.seeds.event_seeds:
            seed_type = getattr(seed, "type", "")
            raw_input = str(getattr(seed, "input", "")).strip()
            seed_data = getattr(seed, "data", None)

            if seed_type == "DNS_NAME":
                domain = self._normalize_domain(seed_data)
                if domain:
                    self.allowed_domain_roots.add(domain)
                continue

            if seed_type == "EMAIL_ADDRESS":
                email = self._normalize_email(seed_data)
                if email:
                    self.allowed_email_addresses.add(email)
                continue

            if seed_type == "URL":
                host = self._extract_url_host(seed_data)
                normalized = self._normalize_domain(host)
                if normalized and not self._is_ip(normalized):
                    self.allowed_domain_roots.add(normalized)
                continue

            if seed_type == "IP_ADDRESS":
                if self._is_ip(seed_data):
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
                owner = self._parse_repository_owner_scope(self._extract_seed_url(raw_input, seed_data, "CODE_REPOSITORY_OWNER:"))
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
        return False, "repository is outside the seeded repository scope"

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
        return bool(domain and any(domain == root or domain.endswith(f".{root}") for root in self.allowed_domain_roots))

    def _event_has_allowed_ip(self, event):
        return any(self._ip_allowed(candidate) for candidate in self._event_ip_candidates(event))

    def _event_has_allowed_primary_ip(self, event):
        return any(self._ip_allowed(candidate) for candidate in self._event_primary_ip_candidates(event))

    def _event_is_allowed_domain_resolution_ip(self, event):
        if event.type != "IP_ADDRESS":
            return False

        address = self._event_primary_ip(event)
        if not address:
            return False

        for parent in self._parent_events(event):
            if parent.type not in DNS_SCOPE_EVENT_TYPES:
                continue
            if not self._event_domain_in_scope(parent):
                continue
            if address in self._event_a_aaaa_ip_candidates(parent):
                return True

        return False

    def _remember_allowed_analysis_ips(self, event):
        for candidate in self._event_ip_candidates(event):
            if self._is_ip(candidate):
                self.allowed_ips.add(str(candidate).strip())

    def _remember_allowed_primary_ips(self, event):
        for candidate in self._event_primary_ip_candidates(event):
            if self._is_ip(candidate):
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
            return raw_input[len(prefix):].strip()
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
            self.allowed_ip_ranges.append(network)
            self.allowed_ip_range_values.add(str(network))
        except ValueError:
            return

    def _ip_allowed(self, candidate):
        if candidate in self.allowed_ips:
            return True
        try:
            ip_value = ipaddress.ip_address(candidate)
        except ValueError:
            return False
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
