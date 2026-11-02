from collections import Counter
from urllib.parse import urlsplit

from bbot.modules.base import BaseInterceptModule
from bbot.modules.internal.base import BaseInternalModule

# Only weaknesses that are hardening advice may be folded into a summary. Anything rated
# higher stays an individual finding, whatever produced it.
GROUPABLE_SEVERITIES = {"", "INFO", "LOW", "MEDIUM"}
SEVERITY_RANK = {"": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

SECURITY_HEADERS_TEMPLATE = "naxus-missing-security-headers"
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
DNS_AUDIT_TEMPLATE = "domain-config-dns-audit"

# Load balancer stickiness cookies carry a backend-routing token and never a session, so
# the Secure/HttpOnly advice does not apply to them. BIGipServer* is not here on purpose:
# its value encodes the internal pool member address.
STICKINESS_COOKIES = {"awsalb", "awsalbcors", "awsalbapp", "awselb", "awselbcors"}

# Email and certificate-authority records only express sending and issuance policy.
DNS_AUDIT_GROUPED_CATEGORIES = {"email", "certificate"}
# Zone hardening advice from the DNS and DNSSEC checks. Everything else from those checks
# (zone transfer, zone walking, wildcards, resolver exposure, delegation errors...) is a
# finding in its own right and is never grouped.
DNS_AUDIT_GROUPED_TITLES = {
    "insufficient nameservers",
    "low nameserver diversity",
    "dnssec not enabled",
    "weak dnssec algorithm",
    "ds record uses only sha-1",
    "missing ds record at parent",
    "tld does not support dnssec",
    "multiple dnssec algorithms",
    "soa refresh too short",
    "soa expire too short",
    "very low dns ttl on critical records",
    "no https/svcb service binding records",
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
    "cookies_csp": {
        "title": "Weak cookie attributes and Content-Security-Policy",
        "noun": "issue",
        "recommendation": (
            "Set Secure and HttpOnly on cookies that carry sessions or other secrets, and tighten the "
            "Content-Security-Policy so scripts and objects only load from trusted sources."
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
    "retirejs": {
        "title": "Outdated JavaScript libraries with known vulnerabilities",
        "noun": "library version",
        "recommendation": (
            "Upgrade each listed JavaScript library to a release without published advisories, or remove it "
            "when it is no longer used."
        ),
    },
}

COLUMNS = {
    "cookies_csp": ["Website", "Item", "Problem"],
    "dns": ["Domain", "Issue", "Severity"],
    "retirejs": ["Website", "Library", "Version", "Max severity", "CVEs"],
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
    Folds per-URL hardening advice (missing security headers, cookie flags, weak CSP,
    DNS/email policy, outdated JavaScript libraries) into one summary per category.

    The individual findings are held back while the scan runs. Once the scan is finishing
    and no more of them arrive, one VULNERABILITY per category is emitted carrying a table
    of every affected website or domain. Anything that arrives after that is passed on
    unchanged, and nothing rated HIGH or CRITICAL is ever held back.
    """

    watched_events = ["FINDING", "VULNERABILITY"]
    produced_events = ["VULNERABILITY"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Group low-risk hardening findings into one summary event per category",
        "created_date": "2026-11-02",
        "author": "@naxus",
    }
    # run after the tagging intercept modules, right before the event is distributed
    _priority = 5

    async def setup(self):
        self._rows = {category: {} for category in CATEGORIES}
        self._hosts = {category: Counter() for category in CATEGORIES}
        self._templates = {category: set() for category in CATEGORIES}
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
        category, template, rows = grouped
        if not rows:
            return False, "it only reports load balancer stickiness cookies"
        if self._emitted:
            # The summary is already out; a late finding still has to reach the scan.
            return True
        for key, values in rows:
            self._merge_row(category, key, values)
        self._templates[category].add(template)
        if event.host:
            self._hosts[category][str(event.host)] += 1
        self._held += 1
        # Holding an event is activity: ask the scan for one more finish round, or it could
        # end before finish() sees it.
        self.scan._new_activity = True
        return False, f"it is grouped into the {category} summary"

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
            data = self.summary(category)
            if data is None:
                continue
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
        if severity not in GROUPABLE_SEVERITIES:
            return None
        module = str(getattr(event, "module", "") or "")
        template = str(data.get("template") or "")
        if module == "nuclei":
            return self._classify_nuclei(event, data, template, severity)
        if module == "domain_config_dns_audit" and template == DNS_AUDIT_TEMPLATE:
            return self._classify_dns_audit(event, data, severity)
        if module == "retirejs":
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
            return "security_headers", template, [((origin, title.lower()), {})]
        if template in COOKIE_TEMPLATES:
            origin = self._event_origin(event, data)
            if not origin:
                return None
            names = extracted_values(data)
            if not names:
                return (
                    "cookies_csp",
                    template,
                    [((origin, "(cookie name not reported)"), {"problem": COOKIE_TEMPLATES[template]})],
                )
            names = [name for name in dict.fromkeys(names) if name.lower() not in STICKINESS_COOKIES]
            return (
                "cookies_csp",
                template,
                [((origin, f"cookie {name}"), {"problem": COOKIE_TEMPLATES[template]}) for name in names],
            )
        if template in CSP_TEMPLATES:
            origin = self._event_origin(event, data)
            if not origin:
                return None
            item = f"CSP {title}" if title else "CSP"
            return "cookies_csp", template, [((origin, item), {"problem": CSP_TEMPLATES[template]})]
        if template == TOMCAT_COOKIE_TEMPLATE:
            origin = self._event_origin(event, data)
            if not origin:
                return None
            item = "Tomcat CookieExample servlet"
            problem = "example servlet exposed; it echoes the request cookies"
            return "cookies_csp", template, [((origin, item), {"problem": problem})]
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
        if category not in DNS_AUDIT_GROUPED_CATEGORIES and title.lower() not in DNS_AUDIT_GROUPED_TITLES:
            return None
        return "dns", DNS_AUDIT_TEMPLATE, [((domain, title), {"severity": severity or "INFO"})]

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
        row = self._rows[category].setdefault(key, {"problems": set(), "severity": "", "cves": set()})
        if values.get("problem"):
            row["problems"].add(values["problem"])
        if SEVERITY_RANK.get(values.get("severity", ""), 0) > SEVERITY_RANK.get(row["severity"], 0):
            row["severity"] = values["severity"]
        row["cves"].update(values.get("cves", ()))

    def table(self, category):
        rows = self._rows[category]
        if category == "security_headers":
            headers = sorted({header for _, header in rows})
            missing_by_origin = {}
            for origin, header in rows:
                missing_by_origin.setdefault(origin, set()).add(header)
            table_rows = [
                [origin] + ["missing" if header in missing else "" for header in headers]
                for origin, missing in sorted(missing_by_origin.items())
            ]
            return ["Website"] + headers, table_rows, sorted(missing_by_origin)
        if category == "retirejs":
            table_rows = [
                [origin, component, version, row["severity"], ", ".join(sorted(row["cves"]))]
                for (origin, component, version), row in rows.items()
            ]
        elif category == "dns":
            table_rows = [[domain, title, row["severity"]] for (domain, title), row in rows.items()]
        else:
            table_rows = [[origin, item, ", ".join(sorted(row["problems"]))] for (origin, item), row in rows.items()]
        return COLUMNS[category], sorted(table_rows), sorted({row[0] for row in table_rows})

    def summary(self, category):
        if not self._rows[category]:
            return None
        meta = CATEGORIES[category]
        columns, rows, endpoints = self.table(category)
        hosts = self._hosts[category]
        host = sorted(hosts.items(), key=lambda item: (-item[1], item[0]))[0][0] if hosts else None
        place = "domain" if category == "dns" else "website"
        description = (
            f"{len(rows)} {meta['noun']}{'' if len(rows) == 1 else 's'} across {len(endpoints)} "
            f"{place}{'' if len(endpoints) == 1 else 's'}. The affected {place}s and details are listed in the table."
        )
        data = {
            "severity": "MEDIUM",
            "title": meta["title"],
            "category": "grouped-hardening",
            "path": f"grouped/{category}",
            "dedupe_key": f"grouped:{category}",
            "description": description,
            "recommendation": meta["recommendation"],
            "table": {"columns": columns, "rows": rows},
            "affected_endpoints": endpoints,
            "row_count": len(rows),
            "source_templates": sorted(self._templates[category]),
        }
        if host:
            data["host"] = host
        return data
