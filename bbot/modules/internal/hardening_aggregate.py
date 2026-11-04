from collections import Counter
from hashlib import sha256
from urllib.parse import urlsplit

from bbot.modules.base import BaseInterceptModule
from bbot.modules.internal.base import BaseInternalModule

# Known library vulnerabilities at high severity remain individual issues.
RETIREJS_GROUPABLE_SEVERITIES = {"", "INFO", "LOW", "MEDIUM"}
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

DNS_AUDIT_CATEGORIES = {"dns", "dnssec", "email", "certificate"}
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
    "retirejs": {
        "title": "Outdated JavaScript libraries with known vulnerabilities",
        "noun": "library version",
        "recommendation": (
            "Upgrade each listed JavaScript library to a release without published advisories, or remove it "
            "when it is no longer used."
        ),
    },
    "reputation": {
        "title": "Reputation observations for scanned assets",
        "noun": "observation",
        "recommendation": "Review the listed threat-intelligence signals and verify ownership and current activity before taking action.",
    },
}

COLUMNS = {
    "cookies": ["Website", "Item", "Problem"],
    "dns": ["Domain", "Issue", "Severity"],
    "retirejs": ["Website", "Library", "Version", "Max severity", "CVEs"],
    "reputation": ["Asset", "Indicator", "Risk score", "Sources"],
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
    Folds per-URL hardening advice, DNS/email policy, reputation observations,
    and outdated JavaScript libraries into summaries before event ingestion.

    The individual findings are held back while the scan runs. Once the scan is finishing
    and no more of them arrive, one summary per category and web origin is emitted.
    Anything that arrives after that is passed on unchanged. Explicit DNS, header,
    cookie and reputation classifications join their summaries at any severity.
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
            self._record_template(category, key, template)
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
            origins = (sorted({key[0] for key in self._rows[category]})
                       if category in {"security_headers", "cookies"} else [None])
            for origin in origins:
                data = self.summary(category, origin)
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
        module = str(getattr(event, "module", "") or "")
        if module == "host_reputation" and str(data.get("category") or "") in {"host-reputation", "indicator-reputation"}:
            return self._classify_reputation(event, data)
        template = str(data.get("template") or "")
        if module == "nuclei":
            return self._classify_nuclei(event, data, template, severity)
        if module == "domain_config_dns_audit" and template == DNS_AUDIT_TEMPLATE:
            return self._classify_dns_audit(event, data, severity)
        if module == "dnsresolve" and str(data.get("category") or "") == "domain-classification":
            domain = str(data.get("host") or event.host or "").lower().rstrip(".")
            title = str(data.get("title") or "").strip()
            if domain and title:
                return "dns", "dnsresolve", [((domain, title), {"severity": severity or "INFO"})]
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
        return "reputation", "host_reputation", [((asset, indicator), {
            "risk_score": str(data.get("risk_score") or 0), "sources": source_names,
            "severity": str(data.get("severity") or "INFO").upper(),
        })]

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
                                                    "templates": set(), "sources": set(), "risk_score": "0"})
        if values.get("problem"):
            row["problems"].add(values["problem"])
        if SEVERITY_RANK.get(values.get("severity", ""), 0) > SEVERITY_RANK.get(row["severity"], 0):
            row["severity"] = values["severity"]
        row["cves"].update(values.get("cves", ()))
        row["sources"].update(values.get("sources", ()))
        row["risk_score"] = max(row["risk_score"], values.get("risk_score", "0"), key=lambda score: int(score) if score.isdigit() else 0)

    def _record_template(self, category, key, template):
        self._rows[category][key]["templates"].add(template)

    def table(self, category, origin=None):
        rows = {key: value for key, value in self._rows[category].items()
                if origin is None or key[0] == origin}
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
        elif category == "dns":
            table_rows = [[domain, title, row["severity"]] for (domain, title), row in rows.items()]
        elif category == "reputation":
            table_rows = [[asset, indicator, row["risk_score"], ", ".join(sorted(row["sources"]))]
                          for (asset, indicator), row in rows.items()]
        else:
            table_rows = [[origin, item, ", ".join(sorted(row["problems"]))] for (origin, item), row in rows.items()]
        return COLUMNS[category], sorted(table_rows), sorted({row[0] for row in table_rows})

    def summary(self, category, origin=None):
        selected = {key: value for key, value in self._rows[category].items()
                    if origin is None or key[0] == origin}
        if not selected:
            return None
        meta = CATEGORIES[category]
        columns, rows, endpoints = self.table(category, origin)
        hosts = self._hosts[category]
        host = sorted(hosts.items(), key=lambda item: (-item[1], item[0]))[0][0] if hosts else None
        if origin:
            host = urlsplit(origin).hostname
        place = "domain" if category == "dns" else "asset" if category == "reputation" else "website"
        description = (
            f"{len(rows)} {meta['noun']}{'' if len(rows) == 1 else 's'} across {len(endpoints)} "
            f"{place}{'' if len(endpoints) == 1 else 's'}. The affected {place}s and details are listed in the table."
        )
        data = {
            "severity": (max((row["severity"] for row in selected.values()),
                             key=lambda level: SEVERITY_RANK.get(level, 0))
                         if category == "reputation" else
                         max(["MEDIUM", *(row["severity"] for row in selected.values())],
                             key=lambda level: SEVERITY_RANK.get(level, 0))),
            "title": meta["title"],
            "category": "grouped-hardening",
            "path": f"grouped/{category}" + (f"/{sha256(origin.encode()).hexdigest()[:12]}" if origin else ""),
            "dedupe_key": f"grouped:{category}" + (f":{origin}" if origin else ""),
            "description": description,
            "recommendation": meta["recommendation"],
            "table": {"columns": columns, "rows": rows},
            "affected_endpoints": endpoints,
            "row_count": len(rows),
            "source_templates": sorted({template for row in selected.values() for template in row["templates"]}),
        }
        if host:
            data["host"] = host
        return data
