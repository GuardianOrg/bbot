import json
from pathlib import Path

from bbot.modules.base import BaseModule


# A Vercel rewrite can proxy an external upstream, passing its body and status through, so a live
# Vercel deployment only disproves takeovers that the deployment itself rules out:
# - Vercel: the hostname is assigned to a deployment (unassigned ones answer 404 DEPLOYMENT_NOT_FOUND);
# - Gemfury: its fingerprint is Next.js's not-found text, which every Next.js page embeds, while the
#   unclaimed Gemfury page is that same Next.js 404 and is never served with a 200.
VERCEL_DISPROVED_ENGINES = frozenset({"vercel", "gemfury"})
NON_CARGO_CNAME_SUFFIXES = ("sendgrid.net", "readmessl.com")


class subzy(BaseModule):
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
    }
    options_desc = {
        "binary": "Path to subzy executable",
        "concurrency": "Concurrent checks for subzy",
        "timeout": "Request timeout in seconds",
        "https": "Use HTTPS when protocol is not supplied",
        "verify_ssl": "Only check sites with valid SSL certs",
        "check_unresolved": "Also check DNS_NAME_UNRESOLVED events",
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
        self.binary = str(self.config.get("binary", "subzy")).strip()
        self.concurrency = int(self.config.get("concurrency", 25))
        self.timeout = int(self.config.get("timeout", 10))
        self.https = bool(self.config.get("https", False))
        self.verify_ssl = bool(self.config.get("verify_ssl", False))
        self.check_unresolved = bool(self.config.get("check_unresolved", False))
        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"subzy binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'subzy binary "{self.binary}" was not found in PATH'
        return True

    async def filter_event(self, event):
        if event.type == "DNS_NAME_UNRESOLVED" and not self.check_unresolved:
            return False, "unresolved DNS takeover checks are disabled"
        return True

    @staticmethod
    def is_claimed_provider_response(response, engine, raw_dns_records=None, host=None):
        """
        subzy matches response bodies only, so generic text matches live sites. A 200 carrying a
        hosting provider's claimed-site headers proves the host is served by a site someone owns:
        - GitBook (X-GitBook-Route-Site / X-GitBook-Target), which serves only its own sites;
        - Vercel (x-vercel-id without x-vercel-error), for the engines in VERCEL_DISPROVED_ENGINES.
        """
        if response is None:
            return False
        # Subzy's Cargo fingerprint also matches stock nginx/openresty ingress 404s.
        # A direct ingress address plus that exact generic page is not Cargo routing.
        # A CNAME to a known other provider likewise disproves the Cargo match.
        # Unknown DNS state and Cargo's own CNAME retain the alert.
        dns_records = raw_dns_records or {}
        if str(engine).lower() == "cargo collective":
            cname_targets = {str(target).lower().rstrip(".") for target in dns_records.get("CNAME", ())}
            if any(
                target == suffix or target.endswith(f".{suffix}")
                for target in cname_targets
                for suffix in NON_CARGO_CNAME_SUFFIXES
            ):
                return True
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
        if str(engine).lower() == "uptimerobot" and response.status_code == 404:
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
        headers = {str(key).lower() for key in response.headers.keys()}
        if "x-gitbook-route-site" in headers or "x-gitbook-target" in headers:
            return True
        vercel_deployment = "x-vercel-id" in headers and "x-vercel-error" not in headers
        return vercel_deployment and str(engine).lower() in VERCEL_DISPROVED_ENGINES

    async def is_claimed_provider_host(self, host, engine, raw_dns_records=None):
        for scheme in ("https", "http"):
            try:
                response = await self.helpers.request(f"{scheme}://{host}")
            except Exception:
                continue
            if self.is_claimed_provider_response(response, engine, raw_dns_records, host=host):
                return True
        return False

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

            await self.run_process(command, _log_stderr=False)

            output_raw = Path(output_file).read_text(errors="ignore").strip()
            if not output_raw:
                return
            try:
                results = json.loads(output_raw)
            except Exception:
                return
            if not isinstance(results, list):
                return

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
                        "title": f"Potential subdomain takeover on {host}",
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
