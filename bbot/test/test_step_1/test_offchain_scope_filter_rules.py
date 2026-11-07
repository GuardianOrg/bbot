"""Scope rules of the offchain scope filter, checked event by event without a running scan."""

import asyncio
import json
import types
import unittest
from unittest import mock

from bbot.core.helpers import shared_infra
from bbot.modules.offchain_scope_filter import offchain_scope_filter


def make_scan(seeds=()):
    return types.SimpleNamespace(
        config={"modules": {"offchain_scope_filter": {}}, "web": {}},
        web_config={},
        helpers=None,
        target=types.SimpleNamespace(seeds=types.SimpleNamespace(event_seeds=list(seeds))),
    )


def make_filter(scan=None):
    scan = scan or make_scan()
    module = offchain_scope_filter(scan)
    module._name = "offchain_scope_filter"
    return module


class Event:
    def __init__(self, type_, data, host, resolved_hosts=(), parent=None, tags=(), source_module=None):
        self.type = type_
        self.data = data
        self.host = host
        self.resolved_hosts = resolved_hosts
        self.dns_children = {}
        self.parent = parent
        self.tags = set(tags)
        self.module = source_module

    def get_parent(self):
        return self.parent

    def get_parents(self, include_self=False):
        parents, parent = ([self] if include_self else []), self.parent
        while parent is not None:
            parents.append(parent)
            parent = parent.parent
        return parents


class ScopeFilterTests(unittest.TestCase):
    def setUp(self):
        self.filter = make_filter()
        self.filter.allowed_domain_roots = {"guardianaudits.com"}
        self.filter.allowed_ips = {"8.8.8.8"}
        self.filter.allowed_ip_ranges = []
        self.filter.allowed_repo_tuples = set()
        self.filter.allowed_repo_owners = set()
        self.filter.allowed_mobile_app_ids = set()
        self.filter.allowed_org_stubs = set()
        self.filter.seeded_hostnames = set()
        self.emitted = []
        self.filter.make_event = lambda data, event_type, parent: (data, event_type, parent)

        async def emit(event, **_):
            self.emitted.append(event)

        self.filter.emit_event = emit

    def check(self, event):
        result = asyncio.run(self.filter.handle_event(event))
        return (result[0] if isinstance(result, tuple) else result) is True

    def test_out_of_scope_hostname_is_rejected_even_on_allowed_ip(self):
        event = Event("URL", "https://github.com/guardianaudits", "github.com", ["8.8.8.8"])
        self.assertFalse(self.check(event))
        self.assertFalse(
            self.check(Event("HTTP_RESPONSE", {"url": "https://github.com/guardianaudits"}, "github.com", ["8.8.8.8"]))
        )

    def test_seeded_domains_and_allowed_ip_urls_are_accepted(self):
        self.assertTrue(self.check(Event("URL", "https://lab.guardianaudits.com/path", "lab.guardianaudits.com")))
        self.assertTrue(self.check(Event("URL", "https://8.8.8.8/", "8.8.8.8")))

    def test_url_unverified_seed_authorizes_its_website_host(self):
        self.filter.allowed_domain_roots.clear()
        seed = Event("URL_UNVERIFIED", "https://hacktricks-training.com/", "hacktricks-training.com")
        seed.input = seed.data
        self.filter.scan = make_scan([seed])
        self.filter._load_seed_scope()
        self.assertEqual(self.filter.allowed_domain_roots, {"hacktricks-training.com"})
        self.assertTrue(self.check(seed))
        self.assertFalse(self.check(Event("URL_UNVERIFIED", "https://other.example/", "other.example")))

    def test_outbound_profile_is_recorded_as_social_without_scanning_its_website(self):
        response = Event("HTTP_RESPONSE", {"url": "https://guardianaudits.com/"}, "guardianaudits.com")
        parent = Event("URL", "https://guardianaudits.com/", "guardianaudits.com", parent=response)
        self.assertFalse(
            self.check(Event("URL_UNVERIFIED", "https://github.com/GuardianAudits", "github.com", parent=parent))
        )
        self.assertEqual(len(self.emitted), 1)
        self.assertEqual(self.emitted[0][1], "SOCIAL")
        self.assertEqual(self.emitted[0][0]["url"], "https://github.com/guardianaudits")
        self.assertIs(self.emitted[0][2], parent)
        self.assertFalse(
            self.check(Event("URL_UNVERIFIED", "https://github.com/marketplace", "github.com", parent=parent))
        )
        self.assertEqual(len(self.emitted), 1)

    def test_third_party_profile_mentioned_on_scoped_site_is_not_attributed(self):
        parent = Event("URL", "https://guardianaudits.com/blog/go", "guardianaudits.com")
        link = Event("URL_UNVERIFIED", "https://github.com/golang", "github.com", parent=parent)
        self.assertFalse(self.check(link))
        self.assertEqual(self.emitted, [])
        self.assertFalse(
            self.check(
                Event(
                    "SOCIAL",
                    {
                        "platform": "github",
                        "profile_name": "golang",
                        "url": "https://github.com/golang",
                    },
                    "github.com",
                    parent=link,
                    source_module="social",
                )
            )
        )

    def test_matching_profile_needs_first_party_provenance(self):
        profile = {"platform": "github", "profile_name": "GuardianAudits", "url": "https://github.com/GuardianAudits"}
        linked = Event(
            "URL_UNVERIFIED",
            profile["url"],
            "github.com",
            parent=Event(
                "URL",
                "https://guardianaudits.com/",
                "guardianaudits.com",
                parent=Event("HTTP_RESPONSE", {"url": "https://guardianaudits.com/"}, "guardianaudits.com"),
            ),
        )
        self.assertTrue(self.check(Event("SOCIAL", profile, "github.com", parent=linked, source_module="social")))
        self.assertFalse(self.check(Event("SOCIAL", profile, "github.com", source_module="social")))
        self.assertFalse(
            self.check(
                Event(
                    "SOCIAL",
                    profile,
                    "github.com",
                    parent=Event("URL", "https://guardianaudits.com/", "guardianaudits.com"),
                    source_module="social",
                )
            )
        )

    def test_company_page_linking_a_profile_that_names_the_company_keeps_the_profile_not_its_repositories(self):
        page = Event(
            "URL",
            "https://guardianaudits.com/",
            "guardianaudits.com",
            parent=Event("HTTP_RESPONSE", {"url": "https://guardianaudits.com/"}, "guardianaudits.com"),
        )

        def linked(name):
            url = f"https://github.com/{name}"
            return Event(
                "SOCIAL",
                {"platform": "github", "profile_name": name, "url": url},
                "github.com",
                parent=Event("URL_UNVERIFIED", url, "github.com", parent=page),
                source_module="social",
            )

        account = linked("GuardianAuditsSecurity")
        self.assertTrue(self.check(account))
        repo = Event(
            "CODE_REPOSITORY",
            {"url": "https://github.com/GuardianAuditsSecurity/reports"},
            "github.com",
            parent=account,
            tags={"git", "github", "github-org-scope"},
            source_module="github_org",
        )
        # The profile is the company's, but its repositories were not seeded, so they are not scanned.
        self.assertFalse(self.check(repo))
        # A linked profile that does not name the company is still a third party.
        self.assertFalse(self.check(linked("golang")))
        # A short domain label is too generic to identify a longer profile name.
        self.filter.allowed_domain_roots = {"ab.io"}
        self.assertFalse(self.check(linked("abfan")))

    def test_explicit_repository_owner_keeps_its_profile(self):
        self.filter.allowed_repo_owners.add(("github.com", "differentname"))
        profile = {"platform": "github", "profile_name": "differentname", "url": "https://github.com/differentname"}
        self.assertTrue(self.check(Event("SOCIAL", profile, "github.com", source_module="github_org")))
        self.assertFalse(
            self.check(
                Event("SOCIAL", {**profile, "url": "https://github.com/other"}, "github.com", source_module="social")
            )
        )
        self.filter.allowed_repo_owners.add(("gitlab.org", "differentname"))
        self.assertTrue(
            self.check(
                Event(
                    "SOCIAL",
                    {
                        "platform": "gitlab",
                        "profile_name": "differentname",
                        "url": "https://gitlab.org/differentname",
                    },
                    "gitlab.org",
                    source_module="social",
                )
            )
        )

    def test_interceptor_evaluates_events_beyond_bbot_search_distance(self):
        self.assertIsNone(self.filter.scope_distance_modifier)

    def test_verified_origin_expands_only_its_public_ip_and_port(self):
        self.filter.allowed_ips.clear()
        origin = Event(
            "WEB_ORIGIN",
            {
                "host": "www.guardianaudits.com",
                "url": "https://www.guardianaudits.com/",
                "ip": "8.8.8.8",
                "port": 8443,
                "protocol": "https",
                "confidence": 0.95,
            },
            "www.guardianaudits.com",
            source_module="originfinder",
        )
        address = Event("IP_ADDRESS", "8.8.8.8", "8.8.8.8", parent=origin)
        port = Event("OPEN_TCP_PORT", "8.8.8.8:8443", "8.8.8.8", parent=address)
        unrelated = Event("OPEN_TCP_PORT", "8.8.4.4:8443", "8.8.4.4", parent=address)
        self.assertTrue(self.check(origin))
        self.assertTrue(self.check(address))
        self.assertTrue(self.check(port))
        self.assertFalse(self.check(unrelated))
        origin.module = "untrusted_module"
        self.assertFalse(self.check(origin))

    def test_repositories_of_a_discovered_github_org_or_its_members_are_not_scanned(self):
        org = Event("SOCIAL", {"profile_name": "company"}, "github.com", tags={"github-org"})
        member = Event(
            "SOCIAL",
            {"profile_name": "employee"},
            "github.com",
            parent=org,
            tags={"github-org-member"},
            source_module="github_org",
        )
        repo = Event(
            "CODE_REPOSITORY",
            {"url": "https://github.com/employee/project"},
            "github.com",
            parent=member,
            tags={"git", "github", "github-org-scope"},
            source_module="github_org",
        )
        self.assertFalse(self.check(repo))
        repo.data = {"url": "https://github.com/company/project"}
        repo.parent = org
        self.assertFalse(self.check(repo))
        self.filter.allowed_repo_owners.add(("github.com", "company"))
        self.assertTrue(self.check(repo))

    def test_in_scope_names_that_resolve_to_internal_addresses_are_never_scanned(self):
        for event in (
            Event("DNS_NAME", "internal.guardianaudits.com", "internal.guardianaudits.com", ["10.0.0.5"]),
            Event("URL", "https://app.guardianaudits.com/", "app.guardianaudits.com", ["8.8.8.8", "127.0.0.1"]),
            Event("URL", "http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
            Event("OPEN_TCP_PORT", "[::1]:22", "::1"),
            Event("IP_ADDRESS", "192.168.1.10", "192.168.1.10"),
        ):
            with self.subTest(event=event.data):
                self.assertFalse(self.check(event))

    def test_only_true_subdomains_of_a_seeded_root_are_in_scope(self):
        self.assertTrue(self.check(Event("DNS_NAME", "A.Lab.GuardianAudits.com.", "a.lab.guardianaudits.com.")))
        for host in ("evilguardianaudits.com", "guardianaudits.com.attacker.net", "guardianaudits.co"):
            with self.subTest(host=host):
                self.assertFalse(self.check(Event("DNS_NAME", host, host)))
                self.assertFalse(self.check(Event("URL", f"https://{host}/", host)))

    def test_in_scope_resolution_authorizes_only_the_ips_it_returned(self):
        self.filter.allowed_ips.clear()
        dns = Event("DNS_NAME", "www.guardianaudits.com", "www.guardianaudits.com", ["1.1.1.1"])
        self.assertTrue(self.check(dns))
        self.assertTrue(self.check(Event("IP_ADDRESS", "1.1.1.1", "1.1.1.1", parent=dns)))
        self.assertTrue(self.check(Event("OPEN_TCP_PORT", "1.1.1.1:443", "1.1.1.1", parent=dns)))
        self.assertFalse(self.check(Event("IP_ADDRESS", "1.0.0.1", "1.0.0.1", parent=dns)))
        self.assertFalse(self.check(Event("OPEN_TCP_PORT", "1.0.0.1:443", "1.0.0.1", parent=dns)))
        # An out-of-scope name never contributes its addresses.
        other = Event("DNS_NAME", "cdn.example.net", "cdn.example.net", ["9.9.9.9"])
        self.assertFalse(self.check(other))
        self.assertFalse(self.check(Event("IP_ADDRESS", "9.9.9.9", "9.9.9.9", parent=other)))

    def test_cve_candidates_follow_the_scope_of_their_address(self):
        candidates = {"source": "Shodan InternetDB", "cves": ["CVE-2021-26855"]}
        self.assertTrue(self.check(Event("CVE_CANDIDATES", {"host": "8.8.8.8", **candidates}, "8.8.8.8")))
        self.assertFalse(self.check(Event("CVE_CANDIDATES", {"host": "9.9.9.9", **candidates}, "9.9.9.9")))

    def test_email_and_ip_range_events_follow_their_seeded_scope(self):
        self.filter.allowed_email_addresses = {"owner@gmail.com"}
        self.filter.allowed_ip_range_values = set()
        self.filter._remember_allowed_ip_range("1.2.3.0/24")
        self.filter._remember_allowed_ip_range("10.0.0.0/8")
        self.assertTrue(
            self.check(Event("EMAIL_ADDRESS", "Security@Lab.GuardianAudits.com", "lab.guardianaudits.com"))
        )
        self.assertTrue(self.check(Event("EMAIL_ADDRESS", "owner@gmail.com", "gmail.com")))
        self.assertFalse(self.check(Event("EMAIL_ADDRESS", "someone@gmail.com", "gmail.com")))
        self.assertTrue(
            self.check(Event("EMAIL_PROFILE", {"email": "jon@lab.guardianaudits.com"}, "lab.guardianaudits.com"))
        )
        self.assertFalse(self.check(Event("EMAIL_PROFILE", {"email": "someone@gmail.com"}, "gmail.com")))
        # A seeded third-party address keeps its profile, like the address itself.
        self.assertTrue(self.check(Event("EMAIL_PROFILE", {"email": "owner@gmail.com"}, "gmail.com")))
        self.assertTrue(self.check(Event("IP_RANGE", "1.2.3.0/24", "1.2.3.0/24")))
        self.assertFalse(self.check(Event("IP_RANGE", "1.2.0.0/16", "1.2.0.0/16")))
        self.assertFalse(self.check(Event("IP_RANGE", "10.0.0.0/8", "10.0.0.0/8")))
        self.assertTrue(self.check(Event("URL", "https://1.2.3.77/", "1.2.3.77")))

    def test_leaked_credentials_follow_the_searched_domain_scope(self):
        def leak(host, domain, email):
            return Event("LEAKED_CREDENTIAL", {"host": host, "domain": domain, "email": email, "password": "x"}, host)

        self.filter.allowed_email_addresses = set()
        # A customer's third-party address leaked for an in-scope login stays with that domain.
        self.assertTrue(self.check(leak("guardianaudits.com", "guardianaudits.com", "someone@gmail.com")))
        self.assertTrue(self.check(leak("lab.guardianaudits.com", "guardianaudits.com", "jon@lab.guardianaudits.com")))
        self.assertFalse(self.check(leak("other.com", "other.com", "someone@other.com")))
        self.filter.allowed_email_addresses = {"owner@gmail.com"}
        self.assertTrue(self.check(leak("gmail.com", "gmail.com", "owner@gmail.com")))

    def test_unlisted_event_types_cannot_carry_third_party_hostnames(self):
        # OTX passive DNS on an in-scope name's shared CDN IP lists other customers' hosts.
        address = Event("IP_ADDRESS", "8.8.8.8", "8.8.8.8")

        def history(host):
            return Event("DOMAIN_DNS_HISTORY", {"host": host, "records": [{"ip": "8.8.8.8"}]}, host, parent=address)

        self.assertFalse(self.check(history("006tc.orphiq.com")))
        self.assertTrue(self.check(history("one.staging.guardianaudits.com")))
        for event in (
            Event("DOMAIN_WHOIS", {"host": "orphiq.com", "registrar": "x"}, "orphiq.com"),
            Event("DOMAIN_CERTIFICATE_HISTORY", {"host": "evilguardianaudits.com"}, "evilguardianaudits.com"),
            Event(
                "VHOST", {"host": "guardianaudits.com.attacker.net", "vhost": "a"}, "guardianaudits.com.attacker.net"
            ),
            Event("WEBSCREENSHOT", {"url": "https://orphiq.com/", "path": "/tmp/a.png"}, None),
            # A dict whose host field disagrees with the event host is judged on both.
            Event("DOMAIN_DNS_CONFIG", {"host": "orphiq.com"}, "guardianaudits.com"),
            # Event types BBOT has no host for still name their domain in the data.
            Event("DOMAIN_REGISTRATION", {"domain": "orphiq.com"}, None),
            Event("DOMAIN_REGISTRATION", {"hostname": "006tc.orphiq.com."}, None),
        ):
            with self.subTest(event=event.type):
                self.assertFalse(self.check(event))
        self.assertTrue(self.check(Event("DOMAIN_WHOIS", {"host": "guardianaudits.com"}, "guardianaudits.com")))

    def test_host_reputation_and_workspace_providers_are_kept_only_for_in_scope_assets(self):
        def reputation(host, kind):
            return Event(
                "HOST_REPUTATION",
                {"host": host, "kind": kind, "risk_score": 70, "malicious": True, "sources": []},
                host,
            )

        def provider(host):
            return Event(
                "WORKSPACE_PROVIDER",
                {
                    "host": host,
                    "provider": "google_workspace",
                    "name": "Google Workspace",
                    "services": ["email"],
                    "signals": ["mx"],
                },
                host,
            )

        self.assertTrue(self.check(reputation("lab.guardianaudits.com", "domain")))
        self.assertTrue(self.check(reputation("8.8.8.8", "ip")))
        self.assertTrue(self.check(provider("guardianaudits.com")))
        self.assertFalse(self.check(reputation("orphiq.com", "domain")))
        self.assertFalse(self.check(reputation("1.1.1.1", "ip")))
        self.assertFalse(self.check(provider("orphiq.com")))

    def test_registration_records_of_a_seeded_subdomain_name_its_registered_domain(self):
        self.filter.allowed_domain_roots = {"app.example.com"}
        for event_type in ("DOMAIN_WHOIS", "DOMAIN_DNS_CONFIG"):
            with self.subTest(event_type=event_type):
                self.assertTrue(self.check(Event(event_type, {"domain": "example.com"}, "example.com")))
                self.assertFalse(self.check(Event(event_type, {"domain": "other.com"}, "other.com")))
        # Other records about the parent domain stay out: they could list the parent's other subdomains.
        self.assertFalse(self.check(Event("DOMAIN_DNS_HISTORY", {"domain": "example.com"}, "example.com")))

    def test_off_domain_assets_findings_and_hostless_events_still_pass(self):
        for event in (
            Event(
                "STORAGE_BUCKET",
                {"name": "guardianaudits", "url": "https://guardianaudits.s3.amazonaws.com/"},
                "guardianaudits.s3.amazonaws.com",
            ),
            # A same-named store app kept only for the user to review; no module consumes it.
            Event(
                "OPTIONAL_MOBILE_APP",
                {
                    "url": "https://play.google.com/store/apps/details?id=com.lookalike.guardianaudits",
                    "reason": "Package name matches",
                },
                "play.google.com",
            ),
            Event(
                "VULNERABILITY",
                {"host": "guardianaudits.co", "category": "phishing-lookalike-domain"},
                "guardianaudits.co",
            ),
            Event(
                "FINDING", {"host": "github.com", "url": "https://github.com/guardianaudits/app/blob/x"}, "github.com"
            ),
            Event("USERNAME", "admin", None),
            Event("SCAN", {"name": "62aca233-3372-47d8-93c4-6257784bac44", "id": "SCAN:1"}, None),
            Event("ORG_STUB", "guardianaudits", None),
        ):
            with self.subTest(event=event.type):
                self.assertTrue(self.check(event))

    def store_search_app(self, org_stub, app_id="com.guardianaudits.wallet"):
        stub = Event("ORG_STUB", org_stub, None)
        url = f"https://play.google.com/store/apps/details?id={app_id}"
        app = Event(
            "MOBILE_APP",
            {"id": app_id, "url": url, "platform": "android"},
            "play.google.com",
            parent=stub,
            tags={"android"},
            source_module="google_playstore",
        )
        return stub, app

    def test_store_apps_found_from_a_seeded_domain_are_only_suggested(self):
        # bbot names an org stub after every seeded domain; a store search for it is not the user naming an app.
        stub, app = self.store_search_app("guardianaudits")
        self.assertFalse(self.check(app))
        self.assertEqual(len(self.emitted), 1)
        data, event_type, parent = self.emitted[0]
        self.assertEqual(event_type, "OPTIONAL_MOBILE_APP")
        self.assertIs(parent, stub)
        self.assertEqual(data["id"], "com.guardianaudits.wallet")
        self.assertEqual(data["platform"], "android")
        self.assertIn("not in the scan's scope", data["reason"])

    def test_seeded_apps_and_apps_of_a_seeded_organisation_are_scanned(self):
        self.filter.allowed_mobile_app_ids = {"com.guardianaudits.wallet"}
        self.filter.allowed_org_stubs = set()
        self.assertTrue(self.check(self.store_search_app("guardianaudits")[1]))
        self.filter.allowed_mobile_app_ids = set()
        self.filter.allowed_org_stubs = {"guardianaudits"}
        self.assertTrue(self.check(self.store_search_app("guardianaudits")[1]))
        self.assertFalse(self.check(self.store_search_app("guardian")[1]))
        self.assertEqual([event_type for _, event_type, _ in self.emitted], ["OPTIONAL_MOBILE_APP"])

    def test_seeded_mobile_app_targets_are_read_by_id_or_store_url(self):
        seed = Event(
            "MOBILE_APP",
            {"id": "com.Seeded.App", "url": "https://play.google.com/store/apps/details?id=com.Seeded.App"},
            "play.google.com",
        )
        seed.input = "MOBILE_APP:https://play.google.com/store/apps/details?id=com.Seeded.App"
        org = Event("ORG_STUB", "Acme", None)
        org.input = "ORG_STUB:Acme"
        targets = [
            "mobile_app:com.config.app",
            "mobile_app:https://play.google.com/store/apps/details?id=com.config.url&hl=en",
            "mobile_app:https://apps.apple.com/us/app/wallet/id123456789",
            "org_stub:ConfigOrg",
        ]
        with mock.patch.dict("os.environ", {"GUARDIAN_OFFCHAIN_SCOPE_TARGETS": json.dumps(targets)}):
            scope = make_filter(make_scan([seed, org]))
            self.assertTrue(asyncio.run(scope.setup()))
        self.assertEqual(
            scope.allowed_mobile_app_ids, {"com.seeded.app", "com.config.app", "com.config.url", "123456789"}
        )
        self.assertEqual(scope.allowed_org_stubs, {"acme", "configorg"})
        self.assertTrue(asyncio.run(scope.handle_event(seed)))

    def test_seeded_mobile_apps_given_as_plain_store_urls_are_scanned(self):
        play = Event("MOBILE_APP", "https://play.google.com/store/apps/details?id=com.Plain.App", "play.google.com")
        play.input = "MOBILE_APP:https://play.google.com/store/apps/details?id=com.Plain.App"
        apple = Event("MOBILE_APP", "https://apps.apple.com/us/app/wallet/id987654321", "apps.apple.com")
        apple.input = "MOBILE_APP:https://apps.apple.com/us/app/wallet/id987654321"
        scope = make_filter(make_scan([play, apple]))
        self.assertTrue(asyncio.run(scope.setup()))

        self.assertEqual(scope.allowed_mobile_app_ids, {"com.plain.app", "987654321"})
        found = Event(
            "MOBILE_APP",
            {"id": "987654321", "url": "https://apps.apple.com/gb/app/wallet/id987654321"},
            "acme.com",
        )
        self.assertTrue(asyncio.run(scope.handle_event(found)))

    def test_setup_reads_scope_targets_from_json_or_comma_separated_environment(self):
        scan = make_scan()
        targets = [
            "domain:Example.COM.",
            "ip_address:1.1.1.1",
            "ip_range:192.168.0.0/16",
            "code_repository:https://github.com/Org/Repo.git",
            "org_stub:MyOrg",
            "bogus",
            "email:",
        ]
        for raw in (json.dumps(targets), ",".join(targets)):
            with self.subTest(raw=raw[:20]), mock.patch.dict("os.environ", {"GUARDIAN_OFFCHAIN_SCOPE_TARGETS": raw}):
                scope = make_filter(scan)
                self.assertTrue(asyncio.run(scope.setup()))
                self.assertEqual(scope.allowed_domain_roots, {"example.com"})
                self.assertEqual(scope.allowed_ips, {"1.1.1.1"})
                self.assertEqual(scope.allowed_ip_ranges, [])
                self.assertEqual(scope.allowed_repo_tuples, {("github.com", "org", "repo")})
                self.assertEqual(scope.allowed_repo_owners, {("*", "myorg")})
                self.assertEqual(scope.allowed_email_addresses, set())


CDN_IP = "104.16.1.1"


class SharedFrontendTests(unittest.TestCase):
    """A CDN, WAF, load balancer or shared platform address is never network-scanned, and its bare address is not a
    website; the target's names behind it remain websites."""

    def setUp(self):
        self.filter = make_filter()
        self.filter.allowed_domain_roots = {"guardianaudits.com"}
        self.filter.allowed_ips = {"8.8.8.8", CDN_IP}
        self.filter.allowed_ip_ranges = []
        shared_infra.remember_frontend(self.filter.scan, CDN_IP, "cdn", "cloudflare")

    def verdict(self, event):
        result = asyncio.run(self.filter.handle_event(event))
        return result if isinstance(result, tuple) else (result, None)

    def test_ports_and_services_on_a_shared_frontend_address_are_dropped(self):
        for event in (
            Event("OPEN_TCP_PORT", f"{CDN_IP}:22", CDN_IP),
            Event("OPEN_TCP_PORT", f"{CDN_IP}:443", CDN_IP),
            Event("OPEN_UDP_PORT", f"{CDN_IP}:53", CDN_IP),
            Event("PROTOCOL", {"host": CDN_IP, "port": 22, "protocol": "SSH"}, CDN_IP),
        ):
            with self.subTest(event=event.data):
                allowed, reason = self.verdict(event)
                self.assertFalse(allowed)
                self.assertIn("shared frontend", reason)

    def test_dedicated_address_ports_are_kept(self):
        self.assertTrue(self.verdict(Event("OPEN_TCP_PORT", "8.8.8.8:22", "8.8.8.8"))[0])
        self.assertTrue(
            self.verdict(Event("PROTOCOL", {"host": "8.8.8.8", "port": 22, "protocol": "SSH"}, "8.8.8.8"))[0]
        )

    def test_bare_shared_frontend_address_is_not_a_website_unless_seeded(self):
        self.assertFalse(self.verdict(Event("URL", f"https://{CDN_IP}/", CDN_IP))[0])
        self.assertFalse(self.verdict(Event("URL_UNVERIFIED", f"http://{CDN_IP}:2095/", CDN_IP))[0])
        self.assertTrue(self.verdict(Event("URL", f"https://{CDN_IP}/", CDN_IP, tags={"target"}))[0])

    def test_names_behind_a_shared_frontend_remain_websites(self):
        name = "www.guardianaudits.com"
        self.assertTrue(self.verdict(Event("URL", f"https://{name}/", name, [CDN_IP]))[0])
        self.assertTrue(self.verdict(Event("HTTP_RESPONSE", {"url": f"https://{name}/"}, name, [CDN_IP]))[0])

    def test_alias_to_a_managed_frontend_marks_the_address_but_not_a_verified_origin_behind_it(self):
        self.filter.allowed_ips.add("8.8.4.4")
        name = Event("DNS_NAME", "app.guardianaudits.com", "app.guardianaudits.com", ["8.8.4.4"])
        name.dns_children = {"CNAME": ["d111.cloudfront.net"]}
        address = Event("IP_ADDRESS", "8.8.4.4", "8.8.4.4", parent=name)
        self.assertFalse(self.verdict(Event("OPEN_TCP_PORT", "8.8.4.4:22", "8.8.4.4", parent=address))[0])
        origin = Event(
            "WEB_ORIGIN",
            {
                "host": "app.guardianaudits.com",
                "url": "https://app.guardianaudits.com/",
                "ip": "8.8.8.8",
                "port": 443,
                "protocol": "https",
                "confidence": 0.95,
            },
            "app.guardianaudits.com",
            parent=name,
            source_module="originfinder",
        )
        origin_address = Event("IP_ADDRESS", "8.8.8.8", "8.8.8.8", parent=origin)
        self.assertTrue(self.verdict(Event("OPEN_TCP_PORT", "8.8.8.8:22", "8.8.8.8", parent=origin_address))[0])


class Seed:
    def __init__(self, type_, data):
        self.type = type_
        self.data = data
        self.input = data


class PrivateTargetResolutionTests(unittest.TestCase):
    """A seeded target that currently points at a non-public address stops the scan before any module contacts it."""

    def setup_with(self, seeds, answers):
        async def resolve(host):
            return answers.get(host, [])

        module = make_filter(make_scan(seeds))
        with mock.patch.object(module, "_resolve_addresses", side_effect=resolve):
            return asyncio.run(module.setup())

    def test_seeded_name_url_or_email_domain_resolving_privately_fails_setup(self):
        for seed in (
            Seed("DNS_NAME", "internal.example.com"),
            Seed("URL", "https://internal.example.com/login"),
            Seed("EMAIL_ADDRESS", "admin@internal.example.com"),
        ):
            with self.subTest(seed=seed.type):
                status = self.setup_with([seed], {"internal.example.com": ["93.184.216.34", "10.0.0.5"]})
                self.assertIsInstance(status, tuple)
                self.assertIs(status[0], False)
                self.assertIn("non-public", status[1])

    def test_loopback_and_link_local_answers_are_refused_too(self):
        for address in ("127.0.0.1", "169.254.169.254", "fd00::1"):
            with self.subTest(address=address):
                status = self.setup_with([Seed("DNS_NAME", "example.com")], {"example.com": [address]})
                self.assertIs(status[0], False)

    def test_public_and_unresolved_seeds_start_the_scan(self):
        status = self.setup_with(
            [Seed("DNS_NAME", "example.com"), Seed("DNS_NAME", "not-registered-yet.example")],
            {"example.com": ["93.184.216.34", "2606:2800:220:1::1"]},
        )
        self.assertIs(status, True)
