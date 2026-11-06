import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from bbot.core.helpers.dns.helpers import extract_targets
from bbot.modules.base import BaseModule
from bbot.modules.templates.takeover import is_aws_elb_cname, takeover_finding_title


# A Vercel rewrite can proxy an external upstream, passing its body and status through, so a live
# Vercel deployment only disproves takeovers that the deployment itself rules out:
# - Vercel: the hostname is assigned to a deployment (unassigned ones answer 404 DEPLOYMENT_NOT_FOUND);
# - Gemfury: its fingerprint is Next.js's not-found text, which every Next.js page embeds, while the
#   unclaimed Gemfury page is that same Next.js 404 and is never served with a 200.
VERCEL_DISPROVED_ENGINES = frozenset({"vercel", "gemfury"})
NON_CARGO_CNAME_SUFFIXES = ("sendgrid.net", "readmessl.com", "ghost.io")
NON_INTERCOM_CNAME_SUFFIXES = ("ghost.io",)


# subzy matches bodies against can-i-take-over-xyz's fingerprints but ignores their status and
# CNAMEs, so a page quoting a provider's error text is reported as that provider's takeover.
VULNERABLE_FINGERPRINT_STATUS = "vulnerable"
MAX_CNAME_HOPS = 5
# Provider domains for vulnerable fingerprints that list no CNAME.
ENGINE_CNAME_DOMAINS = {
    "campaign monitor": ("createsend.com",),
    "canny": ("canny.io",),
    "cargo collective": ("cargocollective.com", "cargo.site"),
    "pantheon": ("pantheonsite.io",),
    "pingdom": ("stats.pingdom.com",),
    "readthedocs": ("readthedocs.io",),
    "smugsmug": ("domains.smugmug.com",),
}
# Buckets are also addressed through regional and website endpoints.
ENGINE_CNAME_PATTERNS = {
    "aws/s3": re.compile(r"(?:^|\.)s3[.-](?:[a-z0-9-]+\.)*amazonaws\.com$"),
}


def cname_has_suffix(target, suffixes):
    return any(target == suffix or target.endswith(f".{suffix}") for suffix in suffixes)


def normalize_dns_name(name):
    return str(name).strip().rstrip(".").lower()


def fingerprint_targets(engine, entry):
    """Split a fingerprint's CNAME list, plus the known provider domains, into hostnames and IPs."""
    names, ips = set(), set()
    for target in [*(entry.get("cname") or ()), *ENGINE_CNAME_DOMAINS.get(engine, ())]:
        target = str(target).strip()
        if "://" in target:
            target = urlparse(target).hostname or ""
        target = normalize_dns_name(target)
        if not target:
            continue
        try:
            ips.add(str(ipaddress.ip_address(target)))
        except ValueError:
            names.add(target)
    return names, ips


class subzy(BaseModule):
    fatal_on_error = True
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["VULNERABILITY"]
    flags = ["active", "safe", "subdomain-hijack"]
    meta = {
        "description": "Check potential subdomain takeovers from stale or unclaimed DNS records",
        "created_date": "2026-02-20",
        "author": "@carlospolop",
    }
    options = {
        "binary": "subzy",
        "concurrency": 25,
        "timeout": 10,
        "https": False,
        "verify_ssl": False,
        "check_unresolved": False,
        "fingerprints": "",
    }
    options_desc = {
        "binary": "Path to subzy executable",
        "concurrency": "Concurrent checks for subzy",
        "timeout": "Request timeout in seconds",
        "https": "Use HTTPS when protocol is not supplied",
        "verify_ssl": "Only check sites with valid SSL certs",
        "check_unresolved": "Also check DNS_NAME_UNRESOLVED events",
        "fingerprints": "Path to the fingerprints.json subzy uses (default: ~/subzy/fingerprints.json)",
    }
    deps_apt = ["golang-go"]
    deps_ansible = [
        {
            "name": "Install subzy",
            "shell": "GOBIN=#{BBOT_TOOLS} go install github.com/PentestPad/subzy@latest",
            "args": {"creates": "#{BBOT_TOOLS}/subzy"},
        },
        {
            "name": "Ensure subzy executable mode",
            "file": {"path": "#{BBOT_TOOLS}/subzy", "mode": "0755"},
        },
    ]
    _batch_size = 500
    in_scope_only = True
    domain_seed_scope_only = True

    async def setup(self):
        if self.scan.custom_http_headers:
            # Its HTTP fingerprint requests would go out without the headers every scan request must carry.
            return None, "subzy has no option to send the scan's custom HTTP headers"
        self.binary = str(self.config.get("binary", "subzy")).strip()
        self.concurrency = int(self.config.get("concurrency", 25))
        self.timeout = int(self.config.get("timeout", 10))
        self.https = bool(self.config.get("https", False))
        self.verify_ssl = bool(self.config.get("verify_ssl", False))
        self.check_unresolved = bool(self.config.get("check_unresolved", False))
        fingerprints = str(self.config.get("fingerprints", "") or "").strip()
        self.fingerprints_path = (
            Path(fingerprints).expanduser() if fingerprints else Path.home() / "subzy" / "fingerprints.json"
        )
        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return False, f"subzy binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return False, f'subzy binary "{self.binary}" was not found in PATH'
        return True

    async def filter_event(self, event):
        if event.type == "DNS_NAME_UNRESOLVED" and not self.check_unresolved:
            return False, "unresolved DNS takeover checks are disabled"
        return True

    @staticmethod
    def is_provider_mismatch(engine, raw_dns_records=None):
        """A direct CNAME to another provider cannot be claimed through this engine."""
        cname_targets = {
            str(target).lower().rstrip(".") for target in (raw_dns_records or {}).get("CNAME", ())
        }
        if not cname_targets:
            return False
        engine = str(engine).lower()
        if engine == "cargo collective":
            return all(
                is_aws_elb_cname(target) or cname_has_suffix(target, NON_CARGO_CNAME_SUFFIXES)
                for target in cname_targets
            )
        if engine == "intercom":
            return all(cname_has_suffix(target, NON_INTERCOM_CNAME_SUFFIXES) for target in cname_targets)
        return False

    @staticmethod
    def is_claimed_provider_response(response, engine, raw_dns_records=None, host=None):
        """
        subzy matches response bodies only, so generic text matches live sites. A 200 carrying a
        hosting provider's claimed-site headers proves the host is served by a site someone owns:
        - GitBook (X-GitBook-Route-Site / X-GitBook-Target), which serves only its own sites;
        - Vercel (x-vercel-id without x-vercel-error), for the engines in VERCEL_DISPROVED_ENGINES.
        """
        if subzy.is_provider_mismatch(engine, raw_dns_records):
            return True
        if response is None:
            return False
        # Subzy's Cargo fingerprint also matches stock nginx/openresty ingress 404s.
        # A direct ingress address plus that exact generic page is not Cargo routing.
        # A CNAME to a known other provider likewise disproves the Cargo match.
        # Unknown DNS state and Cargo's own CNAME retain the alert.
        dns_records = raw_dns_records or {}
        engine = str(engine).lower()
        cname_targets = {str(target).lower().rstrip(".") for target in dns_records.get("CNAME", ())}
        if engine == "cargo collective":
            # A host that CNAMEs to its own parent domain and receives that
            # domain's stock Varnish 404 is not routed through Cargo.
            parent_domain = str(host or "").lower().partition(".")[2]
            if (
                parent_domain in cname_targets
                and parent_domain
                and (dns_records.get("A") or dns_records.get("AAAA"))
                and response.status_code == 404
                and str(getattr(response, "text", "") or "").strip().lower() == "404 not found"
                and any(
                    str(key).lower() == "server" and str(value).lower() == "varnish"
                    for key, value in response.headers.items()
                )
            ):
                return True
            if response.status_code == 404 and not dns_records.get("CNAME"):
                body = str(getattr(response, "text", "") or "").lower()
                if (
                    (dns_records.get("A") or dns_records.get("AAAA"))
                    and "<title>404 not found</title>" in body
                    and any(f"<center>{server}</center>" in body for server in ("nginx", "openresty"))
                ):
                    return True
        # Subzy's Uptimerobot fingerprint is the generic "page not found".
        # Cloudflare's own default 404 includes that phrase on directly
        # addressed hosts, but is not an Uptimerobot unclaimed-site response.
        if engine == "uptimerobot" and response.status_code == 404:
            server = str(next((value for key, value in response.headers.items() if str(key).lower() == "server"), ""))
            if (
                server.lower() == "cloudflare"
                and str(getattr(response, "text", "") or "").strip().lower() == "404 page not found"
                and (dns_records.get("A") or dns_records.get("AAAA"))
                and not dns_records.get("CNAME")
            ):
                return True
        if response.status_code != 200:
            return False
        # A live Next.js page can embed the default 404 text in its script data even when
        # served by a provider other than Vercel. Gemfury's unclaimed response is an error,
        # so an HTTP 200 containing that generic fingerprint is not a Gemfury takeover.
        body = str(getattr(response, "text", "") or "").lower()
        if engine == "gemfury" and "404: this page could not be found." in body:
            return True
        headers = {str(key).lower() for key in response.headers.keys()}
        if "x-gitbook-route-site" in headers or "x-gitbook-target" in headers:
            return True
        vercel_deployment = "x-vercel-id" in headers and "x-vercel-error" not in headers
        return vercel_deployment and engine in VERCEL_DISPROVED_ENGINES

    async def is_claimed_provider_host(self, host, engine, raw_dns_records=None):
        dns_records = dict(raw_dns_records or {})
        if str(engine).lower() in {"cargo collective", "intercom"} and not dns_records.get("CNAME"):
            # DNS metadata can be absent from a replayed event. Recheck only the
            # hostname's direct CNAME; an inconclusive lookup keeps the alert.
            try:
                answers, _errors = await self.helpers.resolve_raw(host, type="CNAME")
                cname_targets = {answer for rdtype, answer in answers if str(rdtype).upper() == "CNAME"}
                if cname_targets:
                    dns_records["CNAME"] = cname_targets
            except Exception:
                pass
        if self.is_provider_mismatch(engine, dns_records):
            return True
        for scheme in ("https", "http"):
            try:
                response = await self.helpers.request(f"{scheme}://{host}")
            except Exception:
                continue
            if self.is_claimed_provider_response(response, engine, dns_records, host=host):
                return True
        return False

    def load_fingerprints(self):
        """subzy downloads its fingerprints before a run; read the same file to know each engine's status and CNAMEs."""
        try:
            entries = json.loads(Path(self.fingerprints_path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"could not read subzy fingerprints at {self.fingerprints_path}: {exc}") from exc
        return {str(entry.get("service", "")).strip().lower(): entry for entry in entries if isinstance(entry, dict)}

    async def resolve_records(self, name, rdtype):
        """Return the record values for name, or None when the lookup is inconclusive."""
        try:
            answers, errors = await self.helpers.resolve_raw(name, type=rdtype)
        except Exception:
            return None
        values = {
            normalize_dns_name(value)
            for answer in answers
            for answer_type, value in extract_targets(answer)
            if answer_type == rdtype
        }
        if not values and errors:
            return None
        return values

    async def points_elsewhere(self, host, engine, entry, raw_dns_records=None):
        """
        True when DNS proves the host is not routed to the fingerprint's provider: its CNAME chain
        reaches none of the provider's domains and its addresses none of the provider's IPs.
        Engines without known provider domains, and inconclusive lookups, keep the result.
        """
        names, ips = fingerprint_targets(engine, entry)
        pattern = ENGINE_CNAME_PATTERNS.get(engine)
        if not names and not ips and pattern is None:
            return False

        def matches(target):
            return cname_has_suffix(target, names) or bool(pattern and pattern.search(target))

        dns_records = raw_dns_records or {}
        if ips:
            addresses = {normalize_dns_name(a) for a in dns_records.get("A", ())}
            if not addresses:
                addresses = await self.resolve_records(host, "A")
                if addresses is None:
                    return False
            if addresses & ips:
                return False
        if not names and pattern is None:
            return True

        chain = set()
        frontier = {normalize_dns_name(target) for target in dns_records.get("CNAME", ())}
        if not frontier:
            frontier = await self.resolve_records(host, "CNAME")
            if frontier is None:
                return False
        for _ in range(MAX_CNAME_HOPS):
            frontier -= chain
            if not frontier:
                break
            if any(matches(target) for target in frontier):
                return False
            chain |= frontier
            next_hops = set()
            for target in frontier:
                next_hops |= await self.resolve_records(target, "CNAME") or set()
            frontier = next_hops
        return True

    async def handle_batch(self, *events):
        targets = []
        parent_by_host = {}
        for event in events:
            host = str(event.host or "").strip().rstrip(".").lower()
            if not host:
                continue
            if host not in parent_by_host:
                parent_by_host[host] = event
                targets.append(host)

        if not targets:
            return

        targets_file = self.helpers.tempfile(targets, pipe=False)
        output_file = self.helpers.tempfile("", pipe=False)
        try:
            command = [
                self.binary,
                "run",
                "--targets",
                str(targets_file),
                "--output",
                str(output_file),
                "--vuln",
                "--hide_fails",
                "--concurrency",
                str(self.concurrency),
                "--timeout",
                str(self.timeout),
            ]
            if self.https:
                command.append("--https")
            if self.verify_ssl:
                command.append("--verify_ssl")

            result = await self.run_process(command, _log_stderr=False)
            if getattr(result, "returncode", 0) != 0:
                raise RuntimeError(
                    f"subzy failed for batch of {len(targets)} targets "
                    f"(exit {result.returncode}): {str(getattr(result, 'stderr', '') or '').strip()}"
                )

            output_raw = Path(output_file).read_text(errors="ignore").strip()
            if not output_raw:
                return
            try:
                results = json.loads(output_raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError("subzy returned invalid JSON") from exc
            # subzy encodes a batch with no vulnerable hosts as `null` (an unset Go slice under --vuln).
            if results is None:
                return
            if not isinstance(results, list):
                raise RuntimeError("subzy returned a non-list JSON result")

            fingerprints = None
            for result in results:
                if not isinstance(result, dict):
                    continue
                if str(result.get("status", "")).lower() != "vulnerable":
                    continue

                host = str(result.get("subdomain", "")).strip().rstrip(".").lower()
                if not host:
                    continue
                parent_event = parent_by_host.get(host)
                if parent_event is None:
                    continue

                engine = result.get("engine") or result.get("service") or "subzy"
                if fingerprints is None:
                    fingerprints = self.load_fingerprints()
                entry = fingerprints.get(str(engine).strip().lower())
                if entry is None:
                    raise RuntimeError(f'subzy reported engine "{engine}", which is not in {self.fingerprints_path}')
                if str(entry.get("status", "")).strip().lower() != VULNERABLE_FINGERPRINT_STATUS:
                    self.debug(
                        f'Suppressing {engine} takeover result for {host}: the fingerprint status is "{entry.get("status")}"'
                    )
                    continue
                if await self.points_elsewhere(
                    host, str(engine).strip().lower(), entry, getattr(parent_event, "raw_dns_records", None)
                ):
                    self.debug(f"Suppressing {engine} takeover result for {host}: its DNS does not point to {engine}")
                    continue
                if await self.is_claimed_provider_host(host, engine, getattr(parent_event, "raw_dns_records", None)):
                    self.debug(f"Suppressing {engine} takeover result for {host}: the response proves a claimed site")
                    continue

                discussion = result.get("discussion", "")
                documentation = result.get("documentation", "")
                description = (
                    f"{host} may be vulnerable to subdomain takeover because it matches the {engine} service fingerprint. "
                    "Subdomain takeover can happen when DNS still points a hostname to an external provider resource that the organization no longer owns, has not claimed, or has not finished configuring. "
                    "The attacker does not need to compromise DNS or the main application; they may only need to claim the missing provider-side resource. "
                    "If confirmed, they can publish content under a trusted hostname, enabling phishing, malicious redirects, fake login pages, cookie or token exposure, content spoofing, and reputational damage. "
                    "Reclaim the external resource, complete the provider configuration, or remove the stale DNS record."
                )
                if discussion:
                    description += f" Discussion: [{discussion}]."
                if documentation:
                    description += f" Documentation: [{documentation}]."
                poc_parts = [f"Engine: {engine}"]
                if discussion:
                    poc_parts.append(f"Discussion: {discussion}")
                if documentation:
                    poc_parts.append(f"Documentation: {documentation}")

                await self.emit_event(
                    {
                        "severity": "MEDIUM",
                        "title": takeover_finding_title(host, engine),
                        "category": "subdomain-takeover",
                        "description": description,
                        "recommendation": (
                            "Validate the dangling DNS target and either reclaim the third-party resource "
                            "or remove the stale DNS entry before it can be taken over."
                        ),
                        "host": host,
                        "poc": "\n".join(poc_parts),
                    },
                    "VULNERABILITY",
                    parent_event,
                    tags=["takeover", "subzy"],
                    context=f'{{module}} checked "{host}" with subzy and found {{event.type}}',
                )
        finally:
            targets_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)
