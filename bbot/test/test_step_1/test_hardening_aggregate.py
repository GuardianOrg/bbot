import random

import pytest

from bbot.modules.internal.hardening_aggregate import SECURITY_HEADERS_TEMPLATE, hardening_aggregate, url_origin

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
async def test_all_header_origins_share_one_summary_with_one_row_each(bbot_scanner):
    h = await harness(bbot_scanner)
    tpl = "missing-security-headers"
    for url, header in [
        ("https://app.example.com/", "x-frame-options"),
        ("https://app.example.com/login", "x-frame-options"),
        ("https://app.example.com:443/deep/path?q=1", "content-security-policy"),
        ("http://app.example.com/", "x-frame-options"),
        ("https://app.example.com:8443/", "content-security-policy"),
    ]:
        assert not await h.feed(h.nuclei(url, tpl, header))
    await h.finish_rounds()

    summaries = h.by_category()
    assert set(summaries) == {"grouped:security_headers"}
    event = summaries["grouped:security_headers"]
    assert event.type == "VULNERABILITY"
    assert event.parent is h.scan.root_event
    assert event.data["table"] == {
        "columns": ["Website", "content-security-policy", "x-frame-options"],
        "rows": [
            ["http://app.example.com", "", "missing"],
            ["https://app.example.com", "missing", "missing"],
            ["https://app.example.com:8443", "missing", ""],
        ],
    }
    assert event.data["affected_endpoints"] == ["http://app.example.com", "https://app.example.com",
                                                 "https://app.example.com:8443"]
    assert event.data["source_templates"] == [tpl]


@pytest.mark.asyncio
async def test_severe_header_and_cookie_findings_group_while_unrelated_findings_pass(bbot_scanner):
    h = await harness(bbot_scanner)
    url = "https://app.example.com/"
    grouped = [
        h.nuclei(url, "weak-csp-detect", "unsafe-script-src", severity="HIGH"),
        h.nuclei(url, "cookies-without-secure", "Cookies", severity="CRITICAL", poc="Extracted Data: SID"),
    ]
    passing = [
        h.nuclei(url, "generic-env", "Env file disclosure", severity="MEDIUM"),
        h.nuclei(url, "robots-txt", "robots.txt"),
        h.nuclei(url, "unknown-severity", "Odd", severity="UNKNOWN"),
        h.retire(url, "jquery", "1.2.3", "high", ["CVE-2020-11022"]),
    ]
    # a module other than nuclei reusing a grouped template id is not grouped either
    other = h.nuclei(url, "missing-security-headers", "x-frame-options")
    other.module = h.scan._make_dummy_module("some_other_module")
    passing.append(other)
    for event in grouped:
        assert not await h.feed(event), event.data
    before = [dict(event.data) for event in passing]
    for event in passing:
        assert await h.feed(event), event.data
    assert [event.data for event in passing] == before
    await h.finish_rounds()
    summaries = h.by_category()
    assert set(summaries) == {"grouped:security_headers", "grouped:cookies"}
    assert summaries["grouped:security_headers"].data["severity"] == "HIGH"
    assert summaries["grouped:cookies"].data["severity"] == "CRITICAL"


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

    data = h.by_category()["grouped:cookies"].data
    assert data["table"]["columns"] == ["Website", "Item", "Problem", "Severity"]
    assert data["table"]["rows"] == [
        ["https://app.example.com", "cookie BIGipServerpool_web", "missing Secure", "INFO"],
        ["https://app.example.com", "cookie SESSIONID", "missing HttpOnly, missing Secure", "INFO"],
    ]
    # the stickiness-only site never shows up
    assert data["affected_endpoints"] == ["https://app.example.com"]
    assert data["source_templates"] == [
        "cookies-without-httponly",
        "cookies-without-secure",
    ]
    headers = h.by_category()["grouped:security_headers"].data
    assert headers["table"]["rows"] == [["https://app.example.com", "script-src allows any origin"]]
    assert headers["source_templates"] == ["csp-script-src-wildcard"]


@pytest.mark.asyncio
async def test_cookie_issues_across_websites_share_one_finding(bbot_scanner):
    h = await harness(bbot_scanner)
    for url, cookie in (("https://app.example.com/account", "SID"),
                        ("https://shop.example.com/cart", "CART")):
        assert not await h.feed(h.nuclei(url, "cookies-without-secure", "Cookies",
                                        poc=f"Extracted Data: {cookie}"))
    await h.finish_rounds()
    assert set(h.by_category()) == {"grouped:cookies"}
    data = h.by_category()["grouped:cookies"].data
    assert data["table"]["rows"] == [
        ["https://app.example.com", "cookie SID", "missing Secure", "INFO"],
        ["https://shop.example.com", "cookie CART", "missing Secure", "INFO"],
    ]
    assert data["affected_endpoints"] == ["https://app.example.com", "https://shop.example.com"]


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
    assert h.by_category()["grouped:cookies"].data["table"]["rows"] == [
        ["https://app.example.com:8443", "cookie SID", "missing Secure", "INFO"]
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
        h.dns_audit("example.com", "MX Does Not Resolve", "HIGH", "Email"),
        h.dns_audit("example.com", "RRSIG Signatures Expired", "CRITICAL", "DNSSEC"),
        h.nuclei("https://app.example.com/", "spf-limit-lookup", "SPF record DNS lookup limit"),
    ]
    individual = [
        h.dns_audit("example.com", "DNS zone transfer enabled", "HIGH", "DNS"),
        h.dns_audit("example.com", "NSEC Allows Zone Walking", "INFO", "DNSSEC"),
        h.dns_audit("example.com", "Open DNS Resolver", "MEDIUM", "DNS"),
        h.nuclei("https://app.example.com/", "cname-takeover-heroku", "Heroku takeover", severity="MEDIUM"),
    ]
    for event in grouped:
        assert not await h.feed(event), event.data["title"]
    wildcard = h.dns_audit("example.com", "Wildcard DNS Record Detected", "INFO", "DNS")
    assert not await h.feed(wildcard)
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
            ["example.com", "MX Does Not Resolve", "HIGH"],
            ["example.com", "Missing CAA Records", "INFO"],
            ["example.com", "Missing DMARC Record", "MEDIUM"],
            ["example.com", "RRSIG Signatures Expired", "CRITICAL"],
            ["example.com", "SPF Softfail Policy", "LOW"],
            ["example.com", "Wildcard DNS Record Detected", "INFO"],
        ],
    }
    assert data["host"] == "example.com"
    assert data["severity"] == "CRITICAL"
    assert data["source_templates"] == ["domain-config-dns-audit", "spf-limit-lookup"]


@pytest.mark.asyncio
async def test_reputation_observations_form_one_scan_finding_never_above_medium(bbot_scanner):
    h = await harness(bbot_scanner)
    for asset, indicator, risk, malicious in (
        ("example.com", "example.com", 80, True),
        ("app.example.com", "CVE-2026-1234", 65, True),
        ("203.0.113.7", "203.0.113.7", 10, False),
    ):
        event = h.scan.make_event(
            {"host": asset, "category": "host-reputation" if asset == indicator else "indicator-reputation",
             "title": f"Reputation of {indicator}", "description": "Threat-intelligence source observation",
             "severity": "HIGH" if malicious else "INFO", "risk_score": risk, "indicator": indicator,
             "malicious": malicious, "sources": [{"source": "MalwareWorld"}]},
            "FINDING", parent=h.scan.root_event, module=h.scan._make_dummy_module("host_reputation"),
        )
        assert not await h.feed(event)
    await h.finish_rounds()
    reputation = h.by_category()["grouped:reputation"].data
    assert reputation["severity"] == "MEDIUM"
    assert reputation["table"] == {
        "columns": ["Asset", "Indicator", "Verdict", "Risk score", "Sources", "Severity"],
        "rows": [["203.0.113.7", "203.0.113.7", "not malicious", "10", "MalwareWorld", "INFO"],
                 ["app.example.com", "CVE-2026-1234", "malicious", "65", "MalwareWorld", "MEDIUM"],
                 ["example.com", "example.com", "malicious", "80", "MalwareWorld", "MEDIUM"]],
    }
    assert reputation["affected_endpoints"] == ["203.0.113.7", "app.example.com", "example.com"]
    assert reputation["affected_hosts"] == ["203.0.113.7", "app.example.com", "example.com"]
    assert "203.0.113.7, app.example.com, example.com" in reputation["description"]


@pytest.mark.asyncio
async def test_summary_is_rated_like_its_most_severe_row_without_a_floor(bbot_scanner):
    h = await harness(bbot_scanner)
    for url in ("https://app.example.com/", "https://shop.example.com:8443/"):
        assert not await h.feed(h.nuclei(url, SECURITY_HEADERS_TEMPLATE, "x-frame-options", severity="INFO"))
    assert not await h.feed(h.dns_audit("example.com", "Missing CAA Records", "INFO", "Certificate"))
    assert not await h.feed(h.dns_audit("example.com", "SPF Softfail Policy", "LOW", "Email"))
    await h.finish_rounds()
    summaries = h.by_category()
    headers = summaries["grouped:security_headers"].data
    assert headers["severity"] == "INFO"
    assert headers["affected_endpoints"] == ["https://app.example.com", "https://shop.example.com:8443"]
    assert headers["affected_hosts"] == ["app.example.com", "shop.example.com"]
    assert "https://app.example.com, https://shop.example.com:8443" in headers["description"]
    assert summaries["grouped:dns"].data["severity"] == "LOW"


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
    assert not await h.feed(h.nuclei(url, "missing-security-headers", "x-frame-options"))
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
    late = h.nuclei("https://late.example.com/", "missing-security-headers", "x-frame-options")
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
            h.nuclei("https://b.example.com/x", "missing-security-headers", "referrer-policy"),
            h.nuclei("https://a.example.com/", "missing-security-headers", "x-frame-options"),
            h.nuclei("https://a.example.com/y", "missing-security-headers", "referrer-policy"),
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
        "grouped:cookies",
        "grouped:dns",
        "grouped:retirejs",
        "grouped:security_headers",
    ]
    # the event id comes from the stable dedupe key, not from the scanned targets
    other_scan = await harness(bbot_scanner)
    await other_scan.feed(other_scan.dns_audit("example.com", "Missing DMARC Record", "MEDIUM", "Email"))
    await other_scan.finish_rounds()
    assert other_scan.by_category()["grouped:dns"].id == summaries[0]["grouped:dns"][0]


@pytest.mark.asyncio
async def test_internal_ip_disclosures_form_one_finding_with_five_pages_per_address(bbot_scanner):
    h = await harness(bbot_scanner)
    tpl = "internal-ip-disclosure"
    pages = [f"https://app.example.com/p{i}" for i in range(7)]
    for page in pages:
        assert not await h.feed(h.nuclei(page, tpl, "Internal IP Disclosure", poc="Extracted Data: 10.0.0.5"))
    assert not await h.feed(h.nuclei("https://example.com/", tpl, "Internal IP Disclosure",
                                     poc="Extracted Data: 10.0.0.5, 192.168.1.9"))
    assert not await h.feed(h.nuclei("https://example.com/login", tpl, "Internal IP Disclosure",
                                     poc="Extracted Data: 192.168.1.9"))
    # A finding without an extracted address is not merged into the summary.
    assert await h.feed(h.nuclei("https://example.com/x", tpl, "Internal IP Disclosure"))
    await h.finish_rounds()

    summaries = h.by_category()
    assert set(summaries) == {"grouped:disclosure"}
    data = summaries["grouped:disclosure"].data
    ten_rows = [row for row in data["table"]["rows"] if row[0] == "10.0.0.5"]
    assert len(ten_rows) == 1
    listed = sorted(["https://example.com/"] + pages)[:5]
    assert ten_rows[0] == ["10.0.0.5", ", ".join(listed) + " and 3 more", "8", "INFO"]
    assert ["192.168.1.9", "https://example.com/, https://example.com/login", "2", "INFO"] in data["table"]["rows"]
    assert data["affected_endpoints"] == sorted(set(listed) | {"https://example.com/", "https://example.com/login"})
    assert data["affected_hosts"] == ["app.example.com", "example.com"]
    assert data["row_count"] == 2
