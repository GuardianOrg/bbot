from collections import Counter
from urllib.parse import urlsplit

from bbot.modules.base import BaseInterceptModule
from bbot.core.helpers.shared_infra import known_frontend, classify_ip
from bbot.modules.internal.base import BaseInternalModule

# Known library vulnerabilities at high severity remain individual issues.
RETIREJS_GROUPABLE_SEVERITIES = {"", "INFO", "LOW", "MEDIUM"}
SEVERITY_RANK = {"": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
DEFAULT_SEVERITY = "INFO"
# Threat-intelligence reputation is third-party context, not proof of compromise.
REPUTATION_MAX_SEVERITY = "MEDIUM"
REPUTATION_CATEGORIES = {"host-reputation", "indicator-reputation"}

SECURITY_HEADERS_TEMPLATE = "missing-security-headers"
COOKIE_TEMPLATES = {
    "cookies-without-secure": "missing Secure",
    "cookies-without-httponly": "missing HttpOnly",
}
CSP_TEMPLATES = {
    "weak-csp-detect": "weak Content-Security-Policy",
    "csp-script-src-wildcard": "script-src allows any origin",
}
TOMCAT_COOKIE_TEMPLATE = "tomcat-cookie-exposed"
DNS_NUCLEI_TEMPLATES = {"spf-limit-lookup", "spoofable-spf-records-ptr"}
# Templates that extract a disclosed value from responses: one row per value, not per page.
DISCLOSURE_TEMPLATES = {"internal-ip-disclosure"}
# Pages listed for one disclosed value; the rest are counted.
MAX_LOCATIONS_PER_VALUE = 5
DNS_AUDIT_TEMPLATE = "domain-config-dns-audit"
# Takeover scanners report a hostname whose DNS points at a provider resource that is missing
# or unclaimed. As a FINDING (no takeover shown) it is a dangling reference, grouped with the
# others; a VULNERABILITY (a takeover fingerprint with confidence) stays its own issue.
TAKEOVER_CATEGORY = "subdomain-takeover"
GENERIC_SIGNATURE_PREFIX = "_generic_"

# Load balancer stickiness cookies carry a backend-routing token and never a session, so
# the Secure/HttpOnly advice does not apply to them. BIGipServer* is not here on purpose:
# its value encodes the internal pool member address.
STICKINESS_COOKIES = {"awsalb", "awsalbcors", "awsalbapp", "awselb", "awselbcors"}

DNS_AUDIT_CATEGORIES = {"dns", "dnssec", "email", "certificate"}
# A domain whose mail can be forged is a vulnerability of its own, listed apart from the hardening table.
EMAIL_SPOOFING_CATEGORY = "email-spoofing"
# Look-alike domains of the scanned ones: one summary of those that serve a website, one of those that
# receive mail. A domain that does both is listed in both.
PHISHING_MODULE = "domain_phishing"
PHISHING_CATEGORY = "phishing-lookalike-domain"
PHISHING_OWNER_FIELDS = ("registrar", "registration_date", "registrant_org", "registrant_name",
                         "registrant_email", "registrant_country")
DNS_AUDIT_INDIVIDUAL_TITLES = {
    "dns zone transfer enabled", "nsec allows zone walking", "open dns resolver",
}

CATEGORIES = {
    "security_headers": {
        "title": "Missing HTTP security headers",
        "noun": "website",
        "recommendation": (
            "Send the missing security headers on every HTML response, typically from the web server, "
            "load balancer or CDN configuration so that all pages inherit them."
        ),
    },
    "cookies": {
        "title": "Weak HTTP cookie attributes",
        "noun": "issue",
        "recommendation": (
            "Set Secure and HttpOnly on cookies that carry sessions or other secrets."
        ),
    },
    "dns": {
        "title": "DNS and email domain configuration weaknesses",
        "noun": "issue",
        "recommendation": (
            "Review the listed DNS, email-authentication (SPF, DKIM, DMARC, MTA-STS) and CAA records "
            "and tighten them once all legitimate senders and certificate authorities are known."
        ),
    },
    "email_spoofing": {
        "title": "Email spoofing possible for domains without an enforced DMARC policy",
        "noun": "domain",
        "recommendation": (
            "For each listed domain, publish DMARC with p=reject (or p=quarantine while rolling out) and sp=reject "
            "once every legitimate sender passes SPF or DKIM alignment. A domain that sends no mail should publish "
            "v=spf1 -all and v=DMARC1; p=reject."
        ),
    },
    "retirejs": {
        "title": "Outdated JavaScript library {library} with known vulnerabilities",
        "noun": "library version",
        "recommendation": (
            "Upgrade {library} on each listed website to a release without published advisories, or remove it "
            "when it is no longer used."
        ),
    },
    "disclosure": {
        "title": "Internal IP addresses disclosed in HTTP responses",
        "noun": "disclosed address",
        "recommendation": (
            "Stop the listed pages from echoing internal addresses (response headers, error pages, redirects "
            "or bodies), typically by fixing the proxy or application configuration that adds them."
        ),
    },
    "dangling_dns": {
        "title": "Dangling DNS records pointing to missing provider resources",
        "noun": "hostname",
        "recommendation": (
            "For each listed hostname, remove the DNS record when the integration is no longer used, or "
            "recreate or reclaim the provider resource it points to. Until then the hostname does not "
            "resolve, and an account that can create a resource under the same provider name could serve "
            "content under it."
        ),
    },
    "phishing_websites": {
        "title": "Look-alike websites that may impersonate scanned domains",
        "noun": "look-alike website",
        "recommendation": (
            "Open each listed website and compare it with the domain it resembles. Report the ones that copy its "
            "brand, login, product or support pages to the registrar and hosting provider for takedown, and warn "
            "users and staff about them. Keep monitoring the others, as a parked look-alike can be turned into a "
            "phishing page at any time."
        ),
    },
    "phishing_mail": {
        "title": "Look-alike domains with mail servers that may impersonate scanned domains",
        "noun": "look-alike domain",
        "recommendation": (
            "A look-alike domain with mail servers can exchange email under a name mistaken for yours. Check who "
            "owns each listed domain; for the ones not owned by a known, long-established business, warn staff and "
            "partners, block the domain at the mail gateway, and report it to the registrar if it is used for abuse."
        ),
    },
    "reputation": {
        "title": "Reputation observations for scanned assets",
        "noun": "observation",
        "recommendation": "Review the listed threat-intelligence signals and verify ownership and current activity before taking action.",
    },
}

COLUMNS = {
    "cookies": ["Website", "Item", "Problem", "Severity"],
    "dns": ["Domain", "Issue", "Severity"],
    "email_spoofing": ["Domain", "Why it can be spoofed", "SPF", "DMARC", "Severity"],
    "retirejs": ["Website", "Library", "Version", "Max severity", "CVEs"],
    "disclosure": ["Disclosed address", "Found at", "Pages", "Severity"],
    "reputation": ["Asset", "Indicator", "Verdict", "Risk score", "Sources", "Severity"],
    "dangling_dns": ["Hostname", "Points to", "Detected by", "Why it is listed", "Severity"],
    "phishing_websites": ["Look-alike website", "Resembles", "Permutation", "Registrant", "Registered", "Severity"],
    "phishing_mail": ["Look-alike domain", "Resembles", "Permutation", "Mail servers (MX)", "Registrant",
                      "Registered", "Severity"],
}


def url_origin(url):
    """scheme://host[:port] of a URL, with the default port left out."""
    try:
        parsed = urlsplit(str(url or "").strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return ""
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https") or not hostname:
        return ""
    host = f"[{hostname}]" if ":" in hostname else hostname.lower()
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + (f":{port}" if port and port != default_port else "")


def cap_severity(severity, ceiling):
    return ceiling if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK[ceiling] else severity

def highest_severity(severities):
    return max(severities, key=lambda level: SEVERITY_RANK.get(level, 0), default=DEFAULT_SEVERITY) or DEFAULT_SEVERITY

def dangling_reason(targets, signature, confidence):
    """One sentence on why a takeover scanner listed a hostname, for its table row."""
    target = ", ".join(sorted(targets)) or "a provider resource"
    if not signature or signature.startswith(GENERIC_SIGNATURE_PREFIX):
        return (f"The CNAME to {target} does not resolve, so the hostname is a stale or unfinished alias; "
                "the scan did not show that another account can claim the target.")
    level = f" with {confidence.lower()} confidence" if confidence else ""
    return (f"Its DNS to {target} matches the {signature} unclaimed-resource fingerprint{level}; "
            "a takeover was not demonstrated.")


def registrant(owner):
    """Who registered a look-alike domain, from its WHOIS fields."""
    who = owner.get("registrant_org") or owner.get("registrant_name") or "not disclosed"
    country = owner.get("registrant_country")
    registrar = owner.get("registrar")
    return who + (f" ({country})" if country else "") + (f", via {registrar}" if registrar else "")


def endpoint_host(endpoint):
    """Hostname of a website origin, or the endpoint itself when it is already a host."""
    if "://" not in endpoint:
        return endpoint.lower()
    try:
        return (urlsplit(endpoint).hostname or "").lower()
    except ValueError:
        return ""

def extracted_values(data):
    values = data.get("extracted_results")
    if isinstance(values, (list, tuple)):
        return [str(v).strip() for v in values if str(v).strip()]
    for line in str(data.get("poc") or "").splitlines():
        if line.startswith("Extracted Data:"):
            return [v.strip() for v in line.split(":", 1)[1].split(",") if v.strip()]
    return []


class hardening_aggregate(BaseInternalModule, BaseInterceptModule):
    """
    Folds web hardening advice, DNS/email policy, domains whose email can be spoofed, reputation
    observations, outdated JavaScript libraries, and dangling DNS records (takeover leads with no takeover shown) into one summary
    per category before event ingestion. Outdated JavaScript libraries get one summary per library,
    listing every website and version that serves it, so each library is scored on its own advisories.

    The individual findings are held back while the scan runs. Once the scan is finishing
    and no more of them arrive, one summary per category is emitted. A summary is rated
    like the most severe finding it merged (reputation never above MEDIUM) and lists every
    affected asset. Anything that arrives after that is passed on unchanged. Explicit DNS,
    header, cookie and reputation classifications join their summaries at any severity.
    """

    watched_events = ["FINDING", "VULNERABILITY"]
    produced_events = ["VULNERABILITY"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Group low-risk hardening findings into one summary event per category",
        "created_date": "2026-11-02",
        "author": "@carlospolop",
    }
    # run after the tagging intercept modules, right before the event is distributed
    _priority = 5

    async def setup(self):
        self._rows = {category: {} for category in CATEGORIES}
        self._hosts = {category: Counter() for category in CATEGORIES}
        self._held = 0
        self._held_at_last_finish = None
        self._emitted = False
        return True

    async def handle_event(self, event, **kwargs):
        if event.module is self:
            return True
        grouped = self.classify(event)
        if grouped is None:
            return True
        # A look-alike domain can join two summaries; everything else joins one.
        groupings = grouped if isinstance(grouped, list) else [grouped]
        if not any(rows for _, _, rows in groupings):
            return False, "it only reports load balancer stickiness cookies"
        if self._emitted:
            # The summary is already out; a late finding still has to reach the scan.
            return True
        for category, template, rows in groupings:
            for key, values in rows:
                self._merge_row(category, key, values)
                self._record_template(category, key, template)
            if event.host:
                self._hosts[category][str(event.host)] += 1
        self._held += 1
        # Holding an event is activity: ask the scan for one more finish round, or it could
        # end before finish() sees it.
        self.scan._new_activity = True
        categories = " and ".join(category for category, _, _ in groupings)
        return False, f"it is grouped into the {categories} summary"

    async def finish(self):
        if self._emitted:
            return
        if self._held != self._held_at_last_finish:
            # Still changing. Wait for a finish round in which nothing new was held.
            self._held_at_last_finish = self._held
            if self._held:
                self.scan._new_activity = True
            return
        if not self._held:
            return
        self._emitted = True
        for category in CATEGORIES:
            for data in self.summaries(category):
                await self.emit_event(
                data,
                    "VULNERABILITY",
                    parent=self.scan.root_event,
                    tags=["grouped", "grouped-hardening", f"grouped-{category.replace('_', '-')}"],
                    context=f"{{module}} grouped {data['row_count']} {category} rows into one {{event.type}}",
                )

    def classify(self, event):
        """(category, template, [(row key, row values)]) for a groupable event, else None."""
        data = event.data if isinstance(event.data, dict) else {}
        severity = str(data.get("severity") or "").strip().upper()
        module = str(getattr(event, "module", "") or "")
        if module == "host_reputation" and str(data.get("category") or "") in REPUTATION_CATEGORIES:
            return self._classify_reputation(event, data)
        if event.type == "FINDING" and str(data.get("category") or "").strip().lower() == TAKEOVER_CATEGORY:
            return self._classify_dangling_dns(event, data, module)
        if module == PHISHING_MODULE and str(data.get("category") or "").strip().lower() == PHISHING_CATEGORY:
            return self._classify_phishing(event, data, severity)
        template = str(data.get("template") or "")
        if module == "nuclei":
            return self._classify_nuclei(event, data, template, severity)
        if module == "domain_config_dns_audit" and template == DNS_AUDIT_TEMPLATE:
            return self._classify_dns_audit(event, data, severity)
        if module == "retirejs" and severity in RETIREJS_GROUPABLE_SEVERITIES:
            return self._classify_retirejs(event, data, severity)
        return None

    def _event_origin(self, event, data):
        origin = url_origin(data.get("url"))
        if origin:
            return origin
        # Some templates (e.g. JavaScript-protocol ones) report host:port instead of a URL.
        parent = getattr(event, "parent", None)
        if parent is not None and parent is not event and getattr(parent, "type", "") == "URL":
            return url_origin(parent.data)
        return ""

    def _classify_nuclei(self, event, data, template, severity):
        title = str(data.get("title") or "").strip()
        if template == SECURITY_HEADERS_TEMPLATE:
            origin = self._event_origin(event, data)
            if not origin or not title:
                return None
            return "security_headers", template, [((origin, title.lower()), {"problem": "missing", "severity": severity})]
        if template in COOKIE_TEMPLATES:
            origin = self._event_origin(event, data)
            if not origin:
                return None
            names = extracted_values(data)
            if not names:
                return (
                    "cookies",
                    template,
                    [((origin, "(cookie name not reported)"), {"problem": COOKIE_TEMPLATES[template], "severity": severity})],
                )
            names = [name for name in dict.fromkeys(names) if name.lower() not in STICKINESS_COOKIES]
            return (
                "cookies",
                template,
                [((origin, f"cookie {name}"), {"problem": COOKIE_TEMPLATES[template], "severity": severity}) for name in names],
            )
        if template in CSP_TEMPLATES:
            origin = self._event_origin(event, data)
            if not origin:
                return None
            return "security_headers", template, [((origin, "content-security-policy"),
                                                   {"problem": CSP_TEMPLATES[template], "severity": severity})]
        if template == TOMCAT_COOKIE_TEMPLATE:
            origin = self._event_origin(event, data)
            if not origin:
                return None
            item = "Tomcat CookieExample servlet"
            problem = "example servlet exposed; it echoes the request cookies"
            return "cookies", template, [((origin, item), {"problem": problem, "severity": severity})]
        if template in DISCLOSURE_TEMPLATES:
            location = str(data.get("url") or "").strip() or self._event_origin(event, data)
            values = extracted_values(data)
            if not location or not values:
                return None
            return "disclosure", template, [((value,), {"location": location, "severity": severity})
                                            for value in dict.fromkeys(values)]
        if template in DNS_NUCLEI_TEMPLATES:
            domain = str(event.host or "").lower()
            if not domain or not title:
                return None
            return "dns", template, [((domain, title), {"severity": severity or "INFO"})]
        return None

    def _classify_dns_audit(self, event, data, severity):
        title = str(data.get("title") or "").strip()
        category = str(data.get("category") or "").strip().lower()
        domain = str(data.get("host") or event.host or "").lower()
        if not title or not domain:
            return None
        if category == EMAIL_SPOOFING_CATEGORY:
            return "email_spoofing", DNS_AUDIT_TEMPLATE, [((domain,), {
                "reasons": {str(data.get("spoofing_reason") or data.get("description") or title)},
                "spf": {str(data.get("spf") or "none")}, "dmarc": {str(data.get("dmarc") or "none")},
                "severity": severity or "HIGH",
            })]
        if category not in DNS_AUDIT_CATEGORIES or title.lower() in DNS_AUDIT_INDIVIDUAL_TITLES:
            return None
        return "dns", DNS_AUDIT_TEMPLATE, [((domain, title), {"severity": severity or "INFO"})]

    def _classify_reputation(self, event, data):
        asset = str(data.get("host") or event.host or "").strip()
        indicator = str(data.get("indicator") or asset).strip()
        if not asset or not indicator:
            return None
        sources = data.get("sources") or []
        source_names = sorted({str(source.get("source") or source.get("name") or "")[:80]
                               for source in sources if isinstance(source, dict)}) if isinstance(sources, list) else []
        severity = str(data.get("severity") or DEFAULT_SEVERITY).upper()
        return "reputation", "host_reputation", [((asset, indicator), {
            "risk_score": str(data.get("risk_score") or 0), "sources": source_names,
            "malicious": data.get("malicious") is True,
            "severity": cap_severity(severity, REPUTATION_MAX_SEVERITY),
        })]

    def _classify_dangling_dns(self, event, data, module):
        host = str(data.get("host") or event.host or "").strip().rstrip(".").lower()
        if not host:
            return None
        targets = data.get("cname_targets")
        if not isinstance(targets, (list, tuple, set)):
            parent = getattr(event, "parent", None)
            targets = (getattr(parent, "raw_dns_records", None) or {}).get("CNAME", ()) if parent is not event else ()
        targets = {str(target).strip().rstrip(".").lower() for target in targets if str(target).strip()}
        signature = str(data.get("signature") or data.get("template") or "").strip()
        detector = f"{module} ({signature})" if signature else module
        return "dangling_dns", module, [((host,), {
            "targets": targets, "detectors": {detector},
            "reasons": {dangling_reason(targets, signature, str(data.get("confidence") or ""))},
            "severity": DEFAULT_SEVERITY,
        })]

    def _classify_phishing(self, event, data, severity):
        """The website summary for a look-alike that serves a page, the mail summary for one with mail servers."""
        domain = str(data.get("host") or event.host or "").strip().rstrip(".").lower()
        protected = str(data.get("source-domain") or "").strip().rstrip(".").lower()
        if not domain or not protected:
            return None
        mail_servers = data.get("dns_mx") if isinstance(data.get("dns_mx"), (list, tuple)) else []
        mail_servers = {str(server).strip().rstrip(".").lower() for server in mail_servers if str(server).strip()}
        owner = {field: str(data.get(field) or "").strip() for field in PHISHING_OWNER_FIELDS}
        values = {
            "protected": {protected}, "fuzzers": {str(data.get("fuzzer") or "unknown").strip()},
            "mail_servers": mail_servers, "owner": owner, "severity": severity or DEFAULT_SEVERITY,
        }
        groupings = []
        if data.get("web_active") is True:
            groupings.append(("phishing_websites", PHISHING_MODULE, [((domain,), values)]))
        if mail_servers:
            groupings.append(("phishing_mail", PHISHING_MODULE, [((domain,), values)]))
        # domain_phishing reports only look-alikes with a website or mail servers; anything else stays as it is.
        return groupings or None

    def _classify_retirejs(self, event, data, severity):
        component = str(data.get("component") or "").strip()
        if not component:
            return None
        version = str(data.get("version") or "").strip()
        origin = url_origin(data.get("url")) or url_origin(data.get("javascript_url"))
        if not origin:
            return None
        cves = data.get("cves") or []
        if isinstance(cves, str):
            cves = [cves]
        values = {"severity": severity or "INFO", "cves": {str(c).strip() for c in cves if str(c).strip()}}
        return "retirejs", "retirejs", [((origin, component, version), values)]

    def _merge_row(self, category, key, values):
        row = self._rows[category].setdefault(key, {"problems": set(), "severity": "", "cves": set(),
                                                    "templates": set(), "sources": set(), "risk_score": "0",
                                                    "malicious": False, "locations": set(), "targets": set(),
                                                    "detectors": set(), "reasons": set(), "spf": set(),
                                                    "dmarc": set(), "protected": set(), "fuzzers": set(),
                                                    "mail_servers": set(), "owner": {}})
        if values.get("problem"):
            row["problems"].add(values["problem"])
        if SEVERITY_RANK.get(values.get("severity", ""), 0) > SEVERITY_RANK.get(row["severity"], 0):
            row["severity"] = values["severity"]
        row["cves"].update(values.get("cves", ()))
        if values.get("location"):
            row["locations"].add(values["location"])
        row["sources"].update(values.get("sources", ()))
        for field in ("targets", "detectors", "reasons", "spf", "dmarc", "protected", "fuzzers", "mail_servers"):
            row[field].update(values.get(field, ()))
        for field, value in values.get("owner", {}).items():
            if value and not row["owner"].get(field):
                row["owner"][field] = value
        row["malicious"] = row["malicious"] or bool(values.get("malicious"))
        row["risk_score"] = max(row["risk_score"], values.get("risk_score", "0"), key=lambda score: int(score) if score.isdigit() else 0)

    def _record_template(self, category, key, template):
        self._rows[category][key]["templates"].add(template)

    def table(self, category, rows):
        if category == "security_headers":
            headers = sorted({header for _, header in rows})
            missing_by_origin = {}
            for website, header in rows:
                missing_by_origin.setdefault(website, {})[header] = ", ".join(sorted(rows[(website, header)]["problems"]))
            table_rows = [
                [website] + [problems.get(header, "") for header in headers]
                for website, problems in sorted(missing_by_origin.items())
            ]
            return ["Website"] + headers, table_rows, sorted(missing_by_origin)
        if category == "retirejs":
            table_rows = [
                [origin, component, version, row["severity"], ", ".join(sorted(row["cves"]))]
                for (origin, component, version), row in rows.items()
            ]
        elif category == "disclosure":
            return self.disclosure_table(rows)
        elif category == "dns":
            table_rows = [[domain, title, row["severity"]] for (domain, title), row in rows.items()]
        elif category == "email_spoofing":
            table_rows = [[domain, " ".join(sorted(row["reasons"])), ", ".join(sorted(row["spf"])),
                           ", ".join(sorted(row["dmarc"])), row["severity"] or DEFAULT_SEVERITY]
                          for (domain,), row in rows.items()]
        elif category == "dangling_dns":
            table_rows = [[host, ", ".join(sorted(row["targets"])) or "(target not reported)",
                           ", ".join(sorted(row["detectors"])), " ".join(sorted(row["reasons"])),
                           row["severity"] or DEFAULT_SEVERITY]
                          for (host,), row in rows.items()]
        elif category in ("phishing_websites", "phishing_mail"):
            table_rows = [[domain, ", ".join(sorted(row["protected"])), ", ".join(sorted(row["fuzzers"]))]
                          + ([", ".join(sorted(row["mail_servers"]))] if category == "phishing_mail" else [])
                          + [registrant(row["owner"]), row["owner"].get("registration_date") or "unknown",
                             row["severity"] or DEFAULT_SEVERITY]
                          for (domain,), row in rows.items()]
        elif category == "reputation":
            table_rows = [[asset, indicator, "malicious" if row["malicious"] else "not malicious", row["risk_score"],
                           ", ".join(sorted(row["sources"])), row["severity"] or DEFAULT_SEVERITY]
                          for (asset, indicator), row in rows.items()]
        else:
            table_rows = [[origin, item, ", ".join(sorted(row["problems"])), row["severity"] or DEFAULT_SEVERITY]
                          for (origin, item), row in rows.items()]
        return COLUMNS[category], sorted(table_rows), sorted({row[0] for row in table_rows})

    @staticmethod
    def disclosure_table(rows):
        """One row per disclosed value with up to MAX_LOCATIONS_PER_VALUE pages; the endpoints are the pages listed."""
        table_rows, endpoints = [], set()
        for (value,), row in rows.items():
            locations = sorted(row["locations"])
            shown = locations[:MAX_LOCATIONS_PER_VALUE]
            endpoints.update(shown)
            hidden = len(locations) - len(shown)
            found_at = ", ".join(shown) + (f" and {hidden} more" if hidden else "")
            table_rows.append([value, found_at, str(len(locations)), row["severity"] or DEFAULT_SEVERITY])
        return COLUMNS["disclosure"], sorted(table_rows), sorted(endpoints)

    def summaries(self, category):
        """The summaries of one category: one per library for retirejs, else at most one."""
        selected = self._rows[category]
        if category == 'reputation':
            selected = {key: row for key, row in selected.items()
                        if not (known_frontend(self.scan, key[0]) or classify_ip(key[0]))}
        if not selected:
            return []
        if category != "retirejs":
            hosts = Counter(key[0] for key in selected) if category == 'reputation' else self._hosts[category]
            return [self.summary(category, selected, hosts)]
        by_library = {}
        for key, row in selected.items():
            by_library.setdefault(key[1].lower(), {})[key] = row
        return [self.summary(category, rows, self._library_hosts(rows), min(key[1] for key in rows))
                for _, rows in sorted(by_library.items())]

    @staticmethod
    def _library_hosts(rows):
        return Counter(host for host in (endpoint_host(origin) for origin, _, _ in rows) if host)

    def summary(self, category, selected, hosts, library=""):
        meta = CATEGORIES[category]
        columns, rows, endpoints = self.table(category, selected)
        host = sorted(hosts.items(), key=lambda item: (-item[1], item[0]))[0][0] if hosts else None
        place = {"dns": "domain", "email_spoofing": "domain", "reputation": "asset", "disclosure": "page",
                 "dangling_dns": "hostname", "phishing_websites": "look-alike website",
                 "phishing_mail": "look-alike domain"}.get(category, "website")
        places = f"{len(endpoints)} {place}{'' if len(endpoints) == 1 else 's'}"
        # A summary with one row per website counts the websites once, not "N websites across N websites".
        lead = places if meta["noun"] == place else f"{len(rows)} {meta['noun']}{'' if len(rows) == 1 else 's'} across {places}"
        description = (
            f"{lead}: {', '.join(endpoints)}. "
            f"The details for each affected {place} are listed in the table."
        )
        severity = highest_severity(row["severity"] for row in selected.values())
        if category == "reputation":
            severity = cap_severity(severity, REPUTATION_MAX_SEVERITY)
        suffix = library.lower() if library else ""
        data = {
            "severity": severity,
            "title": meta["title"].format(library=library),
            "category": "grouped-hardening",
            "path": f"grouped/{category}" + (f"/{suffix}" if suffix else ""),
            "dedupe_key": f"grouped:{category}" + (f":{suffix}" if suffix else ""),
            "description": description,
            "recommendation": meta["recommendation"].format(library=library),
            "table": {"columns": columns, "rows": rows},
            "affected_endpoints": endpoints,
            "affected_hosts": self.affected_hosts(category, endpoints),
            "row_count": len(rows),
            "source_templates": sorted({template for row in selected.values() for template in row["templates"]}),
        }
        if category in ("phishing_websites", "phishing_mail"):
            # Each look-alike with what resembles it and who owns it, so a reviewer can drop the ones that
            # do not imitate a scanned domain or belong to an established business.
            data["lookalike_domains"] = [
                {"domain": domain, "resembles": sorted(row["protected"]), "permutations": sorted(row["fuzzers"]),
                 "mail_servers": sorted(row["mail_servers"]), **{field: row["owner"].get(field, "")
                                                                  for field in PHISHING_OWNER_FIELDS}}
                for (domain,), row in sorted(selected.items())
            ]
        if host:
            data["host"] = host
        return data

    def affected_hosts(self, category, endpoints):
        """Every host of the summary; a disclosure counts the pages it does not list too."""
        if category == "disclosure":
            endpoints = [location for row in self._rows[category].values() for location in row["locations"]]
        return sorted({host for host in map(endpoint_host, endpoints) if host})
