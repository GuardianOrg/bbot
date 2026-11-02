import random

import pytest

from bbot.modules.internal.hardening_aggregate import hardening_aggregate, url_origin

from ..bbot_fixtures import *


class Harness:
    def __init__(self, scan):
        self.scan = scan
        self.module = hardening_aggregate(scan)
        self.emitted = []
        self.urls = {}

        async def emit_event(data, event_type, parent=None, **kwargs):
            # build the real event so the summary has to pass the VULNERABILITY schema
            event = scan.make_event(data, event_type, parent=parent, tags=kwargs.get("tags"), module=self.module)
            self.emitted.append(event)

        self.module.emit_event = emit_event

    def url(self, url):
        if url not in self.urls:
            self.urls[url] = self.scan.make_event(url, "URL", parent=self.scan.root_event, tags=["status-200"])
        return self.urls[url]

    def nuclei(self, url, template, title, severity="", poc=None, parent_url=None, event_type=None):
        data = {"host": url_host(url or parent_url), "title": title, "template": template, "description": title}
        if url:
            data["url"] = url
        if poc:
            data["poc"] = poc
        if severity:
            data["severity"] = severity
        event_type = event_type or ("VULNERABILITY" if severity not in ("", "INFO") else "FINDING")
        if event_type == "VULNERABILITY" and not severity:
            data["severity"] = "LOW"
        parent = self.url(parent_url or url)
        return self.scan.make_event(data, event_type, parent=parent, module=self.scan._make_dummy_module("nuclei"))

    def dns_audit(self, domain, title, severity, category):
        data = {
            "host": domain,
            "severity": severity,
            "category": category,
            "title": title,
            "description": title,
            "template": "domain-config-dns-audit",
        }
        event_type = "VULNERABILITY" if severity in {"CRITICAL", "HIGH", "MEDIUM"} else "FINDING"
        return self.scan.make_event(
            data,
            event_type,
            parent=self.scan.root_event,
            module=self.scan._make_dummy_module("domain_config_dns_audit"),
        )

    def retire(self, page, component, version, severity, cves):
        data = {
            "host": url_host(page),
            "description": f"{component} {version}",
            "severity": severity,
            "component": component,
            "version": version,
            "cves": cves,
            "javascript_url": f"https://cdn.example.net/{component}-{version}.js",
            "url": page,
        }
        return self.scan.make_event(
            data, "FINDING", parent=self.url(page), module=self.scan._make_dummy_module("retirejs")
        )

    async def feed(self, event):
        result = await self.module.handle_event(event)
        if isinstance(result, tuple):
            result = result[0]
        return result is not False

    async def finish_rounds(self, rounds=3):
        for _ in range(rounds):
            await self.module.finish()

    def by_category(self):
        return {event.data["dedupe_key"]: event for event in self.emitted}


def url_host(url):
    from urllib.parse import urlsplit

    return urlsplit(url).hostname


async def harness(bbot_scanner):
    scan = bbot_scanner("example.com", "app.example.com")
    h = Harness(scan)
    assert await h.module.setup() is True
    return h


def test_url_origin_reduces_to_scheme_host_port():
    assert url_origin("https://App.Example.com:443/a/b?c=1") == "https://app.example.com"
    assert url_origin("http://app.example.com:80/") == "http://app.example.com"
    assert url_origin("https://app.example.com:8443/x") == "https://app.example.com:8443"
    assert url_origin("http://[2001:db8::1]:8080/") == "http://[2001:db8::1]:8080"
    assert url_origin("app.example.com:443") == ""
    assert url_origin("ftp://app.example.com/") == ""
    assert url_origin("") == ""


@pytest.mark.asyncio
async def test_paths_of_one_origin_collapse_into_one_row(bbot_scanner):
    h = await harness(bbot_scanner)
    tpl = "naxus-missing-security-headers"
    for url, header in [
        ("https://app.example.com/", "x-frame-options"),
        ("https://app.example.com/login", "x-frame-options"),
        ("https://app.example.com:443/deep/path?q=1", "content-security-policy"),
        ("http://app.example.com/", "x-frame-options"),
        ("https://app.example.com:8443/", "content-security-policy"),
    ]:
        assert not await h.feed(h.nuclei(url, tpl, header))
    await h.finish_rounds()

    assert list(h.by_category()) == ["grouped:security_headers"]
    event = h.emitted[0]
    assert event.type == "VULNERABILITY"
    assert event.parent is h.scan.root_event
    assert "grouped" in event.tags
    data = event.data
    assert data["table"] == {
        "columns": ["Website", "content-security-policy", "x-frame-options"],
        "rows": [
            ["http://app.example.com", "", "missing"],
            ["https://app.example.com", "missing", "missing"],
            ["https://app.example.com:8443", "missing", ""],
        ],
    }
    assert data["row_count"] == 3
    assert data["affected_endpoints"] == [
        "http://app.example.com",
        "https://app.example.com",
        "https://app.example.com:8443",
    ]
    assert data["severity"] == "MEDIUM"
    assert data["host"] == "app.example.com"
    assert data["path"] == "grouped/security_headers"
    assert data["source_templates"] == [tpl]
    assert "3 websites" in data["description"]


@pytest.mark.asyncio
async def test_severe_and_unrelated_findings_pass_untouched(bbot_scanner):
    h = await harness(bbot_scanner)
    url = "https://app.example.com/"
    passing = [
        h.nuclei(url, "weak-csp-detect", "unsafe-script-src", severity="HIGH"),
        h.nuclei(url, "cookies-without-secure", "Cookies", severity="CRITICAL", poc="Extracted Data: SID"),
        h.nuclei(url, "generic-env", "Env file disclosure", severity="MEDIUM"),
        h.nuclei(url, "robots-txt", "robots.txt"),
        h.nuclei(url, "unknown-severity", "Odd", severity="UNKNOWN"),
        h.retire(url, "jquery", "1.2.3", "high", ["CVE-2020-11022"]),
    ]
    # a module other than nuclei reusing a grouped template id is not grouped either
    other = h.nuclei(url, "naxus-missing-security-headers", "x-frame-options")
    other.module = h.scan._make_dummy_module("some_other_module")
    passing.append(other)
    before = [dict(event.data) for event in passing]
    for event in passing:
        assert await h.feed(event), event.data
    assert [event.data for event in passing] == before
    await h.finish_rounds()
    assert h.emitted == []


@pytest.mark.asyncio
async def test_stickiness_cookies_are_dropped_but_session_cookies_kept(bbot_scanner):
    h = await harness(bbot_scanner)
    url = "https://app.example.com/"
    secure = h.nuclei(
        url,
        "cookies-without-secure",
        "Cookies without Secure attribute - Detect",
        poc="Extracted Data: AWSALB, awsalbcors, SESSIONID, BIGipServerpool_web\nCommand: curl -X GET",
    )
    httponly = h.nuclei(
        "https://app.example.com/account",
        "cookies-without-httponly",
        "Cookies without HttpOnly",
        poc="Extracted Data: SESSIONID",
    )
    only_stickiness = h.nuclei(
        "https://lb.example.com/", "cookies-without-httponly", "Cookies", poc="Extracted Data: AWSELB, AWSALBAPP"
    )
    csp = h.nuclei(url, "csp-script-src-wildcard", 'Content-Security-Policy "script-src" Wildcard Detected')
    assert not await h.feed(secure)
    assert not await h.feed(httponly)
    assert not await h.feed(csp)
    assert not await h.feed(only_stickiness)
    await h.finish_rounds()

    data = h.by_category()["grouped:cookies_csp"].data
    assert data["table"]["columns"] == ["Website", "Item", "Problem"]
    assert data["table"]["rows"] == [
        [
            "https://app.example.com",
            'CSP Content-Security-Policy "script-src" Wildcard Detected',
            "script-src allows any origin",
        ],
        ["https://app.example.com", "cookie BIGipServerpool_web", "missing Secure"],
        ["https://app.example.com", "cookie SESSIONID", "missing HttpOnly, missing Secure"],
    ]
    # the stickiness-only site never shows up
    assert data["affected_endpoints"] == ["https://app.example.com"]
    assert data["source_templates"] == [
        "cookies-without-httponly",
        "cookies-without-secure",
        "csp-script-src-wildcard",
    ]


@pytest.mark.asyncio
async def test_cookie_result_without_url_uses_the_scanned_url(bbot_scanner):
    h = await harness(bbot_scanner)
    # JavaScript-protocol templates report host:port, not a URL
    event = h.nuclei(
        None,
        "cookies-without-secure",
        "Cookies",
        poc="Extracted Data: SID",
        parent_url="https://app.example.com:8443/x",
    )
    assert "url" not in event.data
    assert not await h.feed(event)
    await h.finish_rounds()
    assert h.by_category()["grouped:cookies_csp"].data["table"]["rows"] == [
        ["https://app.example.com:8443", "cookie SID", "missing Secure"]
    ]


@pytest.mark.asyncio
async def test_dns_groups_policy_weaknesses_only(bbot_scanner):
    h = await harness(bbot_scanner)
    grouped = [
        h.dns_audit("example.com", "Missing DMARC Record", "MEDIUM", "Email"),
        h.dns_audit("example.com", "SPF Softfail Policy", "LOW", "Email"),
        h.dns_audit("example.com", "Missing CAA Records", "INFO", "Certificate"),
        h.dns_audit("example.com", "Low Nameserver Diversity", "LOW", "DNS"),
        h.dns_audit("example.com", "DNSSEC Not Enabled", "INFO", "DNSSEC"),
        h.nuclei("https://app.example.com/", "spf-limit-lookup", "SPF record DNS lookup limit"),
    ]
    individual = [
        h.dns_audit("example.com", "DNS zone transfer enabled", "HIGH", "DNS"),
        h.dns_audit("example.com", "NSEC Allows Zone Walking", "INFO", "DNSSEC"),
        h.dns_audit("example.com", "Wildcard DNS Record Detected", "INFO", "DNS"),
        h.dns_audit("example.com", "Open DNS Resolver", "MEDIUM", "DNS"),
        h.dns_audit("example.com", "MX Does Not Resolve", "HIGH", "Email"),
        h.dns_audit("example.com", "RRSIG Signatures Expired", "CRITICAL", "DNSSEC"),
        h.nuclei("https://app.example.com/", "cname-takeover-heroku", "Heroku takeover", severity="MEDIUM"),
    ]
    for event in grouped:
        assert not await h.feed(event), event.data["title"]
    for event in individual:
        assert await h.feed(event), event.data["title"]
    await h.finish_rounds()

    data = h.by_category()["grouped:dns"].data
    assert data["table"] == {
        "columns": ["Domain", "Issue", "Severity"],
        "rows": [
            ["app.example.com", "SPF record DNS lookup limit", "INFO"],
            ["example.com", "DNSSEC Not Enabled", "INFO"],
            ["example.com", "Low Nameserver Diversity", "LOW"],
            ["example.com", "Missing CAA Records", "INFO"],
            ["example.com", "Missing DMARC Record", "MEDIUM"],
            ["example.com", "SPF Softfail Policy", "LOW"],
        ],
    }
    assert data["host"] == "example.com"
    assert data["source_templates"] == ["domain-config-dns-audit", "spf-limit-lookup"]


@pytest.mark.asyncio
async def test_retirejs_rows_merge_advisories_of_one_library(bbot_scanner):
    h = await harness(bbot_scanner)
    for event in [
        h.retire("https://app.example.com/a", "jquery", "1.8.1", "low", ["CVE-2012-6708"]),
        h.retire("https://app.example.com/b", "jquery", "1.8.1", "medium", ["CVE-2020-11022", "CVE-2012-6708"]),
        h.retire("https://app.example.com/b", "jquery", "3.4.0", "medium", []),
        h.retire("https://shop.example.com/", "bootstrap", "3.3.7", "medium", "CVE-2019-8331"),
    ]:
        assert not await h.feed(event)
    await h.finish_rounds()
    data = h.by_category()["grouped:retirejs"].data
    assert data["table"]["rows"] == [
        ["https://app.example.com", "jquery", "1.8.1", "MEDIUM", "CVE-2012-6708, CVE-2020-11022"],
        ["https://app.example.com", "jquery", "3.4.0", "MEDIUM", ""],
        ["https://shop.example.com", "bootstrap", "3.3.7", "MEDIUM", "CVE-2019-8331"],
    ]
    assert data["source_templates"] == ["retirejs"]


@pytest.mark.asyncio
async def test_one_emission_per_category_after_a_quiet_finish_round(bbot_scanner):
    h = await harness(bbot_scanner)
    scan = h.scan
    url = "https://app.example.com/"
    scan._new_activity = False
    assert not await h.feed(h.nuclei(url, "naxus-missing-security-headers", "x-frame-options"))
    # holding an event must keep the scan from ending before finish() sees it
    assert scan._new_activity is True

    scan._new_activity = False
    await h.module.finish()
    assert h.emitted == []
    assert scan._new_activity is True, "a changed buffer must request another finish round"

    # a finding arriving between rounds postpones the emission again
    assert not await h.feed(h.retire(url, "jquery", "1.8.1", "medium", []))
    scan._new_activity = False
    await h.module.finish()
    assert h.emitted == []
    assert scan._new_activity is True

    await h.module.finish()
    assert sorted(h.by_category()) == ["grouped:retirejs", "grouped:security_headers"]
    assert len(h.emitted) == 2
    await h.finish_rounds()
    assert len(h.emitted) == 2

    # after the summary, matching findings are forwarded individually instead of being lost
    late = h.nuclei("https://late.example.com/", "naxus-missing-security-headers", "x-frame-options")
    assert await h.feed(late)
    # stickiness-only cookie results stay dropped after the summary as well
    sticky = h.nuclei("https://late.example.com/", "cookies-without-secure", "Cookies", poc="Extracted Data: AWSALB")
    assert not await h.feed(sticky)
    # our own summaries flow back through the chain and must be forwarded
    assert await h.feed(h.emitted[0])
    await h.finish_rounds()
    assert len(h.emitted) == 2


@pytest.mark.asyncio
async def test_nothing_is_emitted_without_grouped_findings(bbot_scanner):
    h = await harness(bbot_scanner)
    h.scan._new_activity = False
    await h.finish_rounds()
    assert h.emitted == []
    assert h.scan._new_activity is False


@pytest.mark.asyncio
async def test_summary_is_independent_of_arrival_order(bbot_scanner):
    def events(h):
        return [
            h.nuclei("https://b.example.com/x", "naxus-missing-security-headers", "referrer-policy"),
            h.nuclei("https://a.example.com/", "naxus-missing-security-headers", "x-frame-options"),
            h.nuclei("https://a.example.com/y", "naxus-missing-security-headers", "referrer-policy"),
            h.nuclei("https://a.example.com/", "cookies-without-secure", "Cookies", poc="Extracted Data: B, A"),
            h.dns_audit("example.com", "Missing DMARC Record", "MEDIUM", "Email"),
            h.dns_audit("example.com", "SPF Softfail Policy", "LOW", "Email"),
            h.retire("https://a.example.com/", "jquery", "1.8.1", "low", ["CVE-1"]),
            h.retire("https://a.example.com/", "jquery", "1.8.1", "medium", ["CVE-2"]),
        ]

    summaries = []
    for seed in (1, 2, 3):
        h = await harness(bbot_scanner)
        batch = events(h)
        random.Random(seed).shuffle(batch)
        for event in batch:
            await h.feed(event)
        await h.finish_rounds()
        summaries.append({key: (event.id, event.data) for key, event in h.by_category().items()})
    assert summaries[0] == summaries[1] == summaries[2]
    assert sorted(summaries[0]) == [
        "grouped:cookies_csp",
        "grouped:dns",
        "grouped:retirejs",
        "grouped:security_headers",
    ]
    # the event id comes from the stable dedupe key, not from the scanned targets
    other_scan = await harness(bbot_scanner)
    await other_scan.feed(other_scan.dns_audit("example.com", "Missing DMARC Record", "MEDIUM", "Email"))
    await other_scan.finish_rounds()
    assert other_scan.by_category()["grouped:dns"].id == summaries[0]["grouped:dns"][0]
