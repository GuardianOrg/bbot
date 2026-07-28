import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bbot.core.helpers.whois import normalize_whois_ownership
from bbot.modules.base import BaseModule


class domain_phishing(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "subdomain-enum", "phishing"]
    meta = {
        "description": "Detect likely phishing/typosquat domains using dnstwist permutations + heuristics",
        "created_date": "2026-02-24",
        "author": "@carlospolop + @codex",
    }
    options = {
        "binary": "dnstwist",
        "registered_only": True,
        "fuzzers": [
            "addition",
            "bitsquatting",
            "homoglyph",
            "hyphenation",
            "insertion",
            "omission",
            "replacement",
            "transposition",
            "tld-swap",
        ],
        "nameservers": [],
        "threads": 16,
        "lsh": False,
        "lsh_threshold": 70,
        "young_domain_days": 45,
        "max_candidates": 2000,
        "min_score": 3,
        "history_file": "",
    }
    options_desc = {
        "binary": "Path to dnstwist binary",
        "registered_only": "Only analyze registered permutations",
        "fuzzers": "Subset of dnstwist fuzzers to use",
        "nameservers": "Custom resolvers for dnstwist (comma-separated)",
        "threads": "dnstwist worker threads",
        "lsh": "Enable dnstwist LSH page-similarity checks (slower)",
        "lsh_threshold": "If LSH score >= this threshold, increase confidence",
        "young_domain_days": "Registration age in days considered suspicious",
        "max_candidates": "Maximum permutations to evaluate per root domain",
        "min_score": "Minimum score to emit as finding",
        "history_file": "Optional JSON path to persist already-reported look-alikes + key WHOIS fields (registration date, registrar) so a known domain whose key WHOIS is unchanged is skipped on later scans (no WHOIS lookup, no finding). Leave empty to disable.",
    }
    deps_pip = ["dnstwist", "python-whois~=0.9.5"]
    in_scope_only = True
    per_domain_only = True

    # Ownership-fingerprint keys attached to each emitted finding. These identify the
    # registrant/owner and only change when the look-alike domain is transferred to a
    # different owner, letting downstream consumers suppress repeat alerts for an
    # unchanged domain while re-alerting when it is bought by someone new.
    OWNERSHIP_FINGERPRINT_KEYS = (
        "registrar",
        "registration_date",
        "registrant_org",
        "registrant_email",
        "registrant_name",
        "registrant_country",
    )

    # Permutation techniques that produce a visually deceptive result (harder for a human
    # to spot) are weighted higher than plain typo-class techniques.
    DECEPTIVE_FUZZERS = {"homoglyph", "bitsquatting"}
    VERY_YOUNG_DOMAIN_DAYS = 7
    FINDING_CATEGORY = "phishing-lookalike-domain"
    REDIRECT_TIMEOUT_SECONDS = 5
    MAX_REDIRECTS = 5

    def _pick(self, item, *keys):
        for key in keys:
            if key in item and item.get(key) is not None:
                return item.get(key)
        return None

    def _as_list(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        text = str(value).strip()
        return [text] if text else []

    def _parse_json_output(self, text):
        raw = str(text or "").strip()
        if not raw:
            return []
        # dnstwist might prepend logs, keep only JSON array payload.
        start = raw.find("[")
        end = raw.rfind("]")
        if start == -1 or end == -1 or end <= start:
            return []
        payload = raw[start : end + 1]
        try:
            data = json.loads(payload)
        except Exception:
            return []
        if isinstance(data, list):
            return data
        return []

    def _parse_domain_age_days(self, created):
        if not created:
            return None
        value = str(created).strip()
        if not value:
            return None
        m = re.search(r"(\d{4}-\d{2}-\d{2})", value)
        if m:
            value = m.group(1)
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                return max(0, (datetime.now(timezone.utc) - dt).days)
            except Exception:
                continue
        return None

    def _score_candidate(self, candidate):
        score = 0
        reasons = []

        fuzzer = str(self._pick(candidate, "fuzzer", "fuzz") or "").strip().lower()
        if fuzzer in self.DECEPTIVE_FUZZERS:
            score += 2
            reasons.append(f"visually deceptive permutation ({fuzzer})")
        else:
            score += 1
            reasons.append(f"look-alike permutation ({fuzzer})")

        dns_a = self._as_list(self._pick(candidate, "dns-a", "dns_a"))
        dns_aaaa = self._as_list(self._pick(candidate, "dns-aaaa", "dns_aaaa"))
        dns_mx = self._as_list(self._pick(candidate, "dns-mx", "dns_mx"))
        dns_ns = self._as_list(self._pick(candidate, "dns-ns", "dns_ns"))

        has_web = bool(dns_a or dns_aaaa)
        if has_web:
            score += 1
            reasons.append("active A/AAAA records")
        if dns_mx:
            score += 1
            reasons.append("active MX records")
        if dns_ns:
            score += 1
            reasons.append("delegated NS records")
        if has_web and dns_mx:
            score += 1
            reasons.append("fully operational (web + mail)")

        created = self._pick(candidate, "whois-created", "whois_created", "created")
        age_days = self._parse_domain_age_days(created)
        if age_days is not None and age_days <= self.VERY_YOUNG_DOMAIN_DAYS:
            score += 3
            reasons.append(f"registered within {self.VERY_YOUNG_DOMAIN_DAYS} days ({age_days} days old)")
        elif age_days is not None and age_days <= self.young_domain_days:
            score += 2
            reasons.append(f"newly registered ({age_days} days old)")

        lsh = self._pick(candidate, "lsh")
        try:
            lsh_value = int(float(str(lsh)))
        except Exception:
            lsh_value = None

        if lsh_value is not None and lsh_value >= self.lsh_threshold:
            score += 3
            reasons.append(f"high page similarity (LSH {lsh_value}%)")

        severity = ""
        if score >= 6:
            severity = "HIGH"
        elif score >= 4:
            severity = "MEDIUM"

        return score, severity, reasons

    def _build_evidence(self, candidate, fuzzer, score, reasons):
        evidence_parts = [
            f"Candidate domain: {self._pick(candidate, 'domain')}",
            f"Fuzzer: {fuzzer}",
            f"Score: {score}",
        ]
        if reasons:
            evidence_parts.append(f"Signals: {'; '.join(reasons)}")

        created = self._pick(candidate, "whois-created", "whois_created", "created")
        if created:
            evidence_parts.append(f"Created: {created}")

        for label, keys in (
            ("A", ("dns-a", "dns_a")),
            ("AAAA", ("dns-aaaa", "dns_aaaa")),
            ("MX", ("dns-mx", "dns_mx")),
            ("NS", ("dns-ns", "dns_ns")),
        ):
            values = self._as_list(self._pick(candidate, *keys))
            if values:
                evidence_parts.append(f"{label}: {', '.join(values)}")

        lsh = self._pick(candidate, "lsh")
        if lsh not in (None, ""):
            evidence_parts.append(f"LSH: {lsh}")

        return " | ".join(evidence_parts)

    def _empty_fingerprint(self):
        return {key: None for key in self.OWNERSHIP_FINGERPRINT_KEYS}

    async def _lookup_ownership_fingerprint(self, domain):
        try:
            result = await asyncio.to_thread(self._whois_lookup, domain)
        except Exception:
            self.debug(f"domain_phishing: WHOIS lookup failed for {domain}", trace=True)
            return self._empty_fingerprint()
        if not isinstance(result, dict):
            return self._empty_fingerprint()
        return normalize_whois_ownership(result)

    @staticmethod
    def _whois_lookup(domain):
        import whois

        data = whois.whois(domain)
        if isinstance(data, dict):
            return data
        return dict(data) if data else {}

    @staticmethod
    def _canonical_day(value):
        if not value:
            return None
        m = re.search(r"(\d{4}-\d{2}-\d{2})", str(value))
        if m:
            return m.group(1)
        text = str(value).strip().lower()
        return text or None

    @staticmethod
    def _canonical_text(value):
        if not value:
            return None
        text = re.sub(r"[^a-z0-9\s]+", "", str(value).lower())
        text = re.sub(r"\s+", " ", text).strip()
        return text or None

    def _candidate_change_key(self, candidate):
        # Uses the created date + registrar that dnstwist --whois already fetched, so the
        # change-check needs no extra WHOIS query and is format-stable across scans. Note
        # dnstwist exposes no registrant data, so a registrant-only transfer is not visible
        # here; the Sentry monitor's RDAP fingerprint is the authoritative layer for that.
        created = self._pick(candidate, "whois-created", "whois_created", "created")
        registrar = self._pick(candidate, "whois-registrar", "whois_registrar", "registrar")
        return {"created": self._canonical_day(created), "registrar": self._canonical_text(registrar)}

    def _is_known_unchanged(self, domain, change_key):
        if not self.history_file:
            return False
        # Without a registration date there is no reliable "unchanged" signal (e.g.
        # registered_only=False yields no WHOIS), so never suppress in that case.
        if change_key.get("created") is None:
            return False
        return self.known.get(domain) == change_key

    def _remember_candidate(self, domain, change_key):
        if not self.history_file:
            return
        self.known[domain] = change_key

    async def _redirects_to_protected_domain(self, candidate_domain, root_domain, candidate):
        web_addresses = self._as_list(self._pick(candidate, "dns-a", "dns_a")) + self._as_list(
            self._pick(candidate, "dns-aaaa", "dns_aaaa")
        )
        if not web_addresses or not all(self._is_public_ip(address) for address in web_addresses):
            return False

        normalized_root = str(root_domain or "").strip().lower().rstrip(".")
        normalized_candidate = str(candidate_domain or "").strip().lower().rstrip(".")
        for scheme in ("https", "http"):
            current_url = f"{scheme}://{candidate_domain}/"
            for _redirect_count in range(self.MAX_REDIRECTS + 1):
                try:
                    response = await self.helpers.request(
                        current_url,
                        follow_redirects=False,
                        timeout=self.REDIRECT_TIMEOUT_SECONDS,
                    )
                except Exception:
                    response = None
                if response is None:
                    break

                status_code = int(getattr(response, "status_code", 0) or 0)
                location = response.headers.get("location") if 300 <= status_code < 400 else None
                if not location:
                    return False

                next_url = urljoin(current_url, str(location))
                parsed = urlparse(next_url)
                if parsed.scheme not in ("http", "https"):
                    return False
                next_hostname = str(parsed.hostname or "").strip().lower().rstrip(".")
                if next_hostname == normalized_root or next_hostname.endswith(f".{normalized_root}"):
                    return True
                if not (next_hostname == normalized_candidate or next_hostname.endswith(f".{normalized_candidate}")):
                    return False
                try:
                    redirect_addresses = await self.helpers.resolve(next_hostname, use_cache=False)
                except Exception:
                    return False
                if not redirect_addresses or not all(self._is_public_ip(address) for address in redirect_addresses):
                    return False
                current_url = next_url
            else:
                return False

        return False

    @staticmethod
    def _is_public_ip(address):
        try:
            return ipaddress.ip_address(str(address).strip()).is_global
        except ValueError:
            return False

    def _load_state(self):
        self.known = {}
        if not self.history_file:
            return
        try:
            with open(self.history_file) as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self.known = {str(k): v for k, v in data.items() if isinstance(v, dict)}
        except FileNotFoundError:
            pass
        except Exception:
            self.warning(f"domain_phishing: could not read history_file {self.history_file}", trace=True)

    async def _save_state(self):
        if not self.history_file:
            return
        async with self._state_lock:
            try:
                Path(self.history_file).parent.mkdir(parents=True, exist_ok=True)
                with open(self.history_file, "w") as handle:
                    json.dump(self.known, handle)
            except Exception:
                self.warning(f"domain_phishing: could not write history_file {self.history_file}", trace=True)

    async def setup(self):
        self.binary = str(self.config.get("binary", "dnstwist")).strip()
        self.registered_only = bool(self.config.get("registered_only", True))
        self.fuzzers = list(self.config.get("fuzzers", []))
        self.nameservers = list(self.config.get("nameservers", []))
        self.threads = int(self.config.get("threads", 16))
        self.enable_lsh = bool(self.config.get("lsh", False))
        self.lsh_threshold = int(self.config.get("lsh_threshold", 70))
        self.young_domain_days = int(self.config.get("young_domain_days", 45))
        self.max_candidates = int(self.config.get("max_candidates", 2000))
        self.min_score = int(self.config.get("min_score", 3))
        self.history_file = str(self.config.get("history_file", "")).strip()
        self._state_lock = asyncio.Lock()
        self._load_state()

        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"dnstwist binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'dnstwist binary "{self.binary}" was not found in PATH'

        if self.enable_lsh:
            self.info("domain_phishing: LSH similarity checks enabled (slower).")

        return True

    async def handle_event(self, event):
        input_domain = str(event.data or "").strip().lower().rstrip(".")
        if not input_domain:
            return

        _, root_domain = self.helpers.split_domain(input_domain)
        root_domain = str(root_domain or "").strip().lower()
        if not root_domain or not self.helpers.is_domain(root_domain):
            return

        command = [self.binary, "--format", "json", "--threads", str(self.threads)]

        if self.registered_only:
            command.append("--registered")
            # Bounded by --registered: pre-fills whois-created/registrar so the
            # young-domain scoring signal works and registrar is available cheaply.
            command.append("--whois")

        if self.enable_lsh:
            command += ["--lsh", "ssdeep"]

        if self.fuzzers:
            command += ["--fuzzers", ",".join(self.fuzzers)]

        if self.nameservers:
            command += ["--nameservers", ",".join(self.nameservers)]

        command.append(root_domain)

        process = await self.run_process(command, _log_stderr=False)
        rows = self._parse_json_output(getattr(process, "stdout", ""))
        if not rows:
            self.debug(f"domain_phishing: no candidates returned by dnstwist for {root_domain}")
            return

        emitted = 0
        for idx, candidate in enumerate(rows):
            if idx >= self.max_candidates:
                break
            if not isinstance(candidate, dict):
                continue

            candidate_domain = str(self._pick(candidate, "domain") or "").strip().lower().rstrip(".")
            if not candidate_domain or candidate_domain == root_domain:
                continue

            # Keep scan scope constrained: report risk as finding/vuln without expanding enumeration.
            score, severity, reasons = self._score_candidate(candidate)
            if score < self.min_score:
                continue

            change_key = self._candidate_change_key(candidate)
            if self._is_known_unchanged(candidate_domain, change_key):
                # Known look-alike whose key WHOIS fields are unchanged: no new alert will
                # be generated downstream, so skip the WHOIS enrichment + emit entirely.
                continue

            if await self._redirects_to_protected_domain(candidate_domain, root_domain, candidate):
                self.debug(
                    f"domain_phishing: suppressing {candidate_domain}; it redirects to protected domain {root_domain}"
                )
                continue

            fuzzer = str(self._pick(candidate, "fuzzer", "fuzz") or "unknown").strip()
            fingerprint = await self._lookup_ownership_fingerprint(candidate_domain)
            tags = ["phishing", "typosquatting", f"fuzzer-{fuzzer.lower()}"]
            description = f"Look-alike domain {candidate_domain} was generated from {root_domain} using the {fuzzer} permutation technique."
            if reasons:
                description += f" Suspicious signals: {'; '.join(reasons)}."
            description = (
                f"{description} "
                "This domain visually or linguistically resembles a protected domain and may be used to impersonate the brand. "
                "An attacker could use it for phishing, fake login pages, malicious email, wallet-draining pages, or misleading support flows. "
                "Users, partners, or employees may trust the fake domain, leading to stolen credentials, financial loss, malware delivery, reputational damage, and incident-response costs. "
                "Look-alike domains are especially risky because the attacker does not need to compromise the real organization-owned domain; they only need a name that victims can mistake for it. "
                "The domain should be reviewed for active content, mail records, redirects, certificate issuance, and brand-abuse indicators, then monitored or escalated for takedown when it is clearly malicious."
            )

            payload = {
                "host": candidate_domain,
                "title": f"Potential phishing look-alike domain: {candidate_domain}",
                "category": self.FINDING_CATEGORY,
                "description": description,
                "recommendation": "Review the look-alike domain for brand abuse, monitoring needs, and potential takedown actions.",
                "evidence": self._build_evidence(candidate, fuzzer, score, reasons),
                "command": f"dnstwist --registered --format json {root_domain}",
                "template": "domain-phishing",
                "source-domain": root_domain,
                "fuzzer": fuzzer,
                "probability": score,
                "score": score,
            }
            # Attach the WHOIS ownership fingerprint (registrar + registration date +
            # registrant identity) so Sentry can distinguish a re-registered/newly-bought
            # look-alike from one whose ownership is unchanged.
            payload.update(fingerprint)

            event_type = "FINDING"
            if severity:
                event_type = "VULNERABILITY"
                payload["severity"] = severity

            await self.emit_event(
                payload,
                event_type,
                parent=event,
                tags=tags,
                context=f'{{module}} analyzed "{root_domain}" permutations and found {{event.type}} on look-alike domain "{candidate_domain}"',
            )
            self._remember_candidate(candidate_domain, change_key)
            emitted += 1

        await self._save_state()
        self.info(f"domain_phishing: emitted {emitted} phishing candidate events for {root_domain}")
