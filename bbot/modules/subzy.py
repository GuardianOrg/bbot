import json
from pathlib import Path

from bbot.modules.base import BaseModule


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
    # subzy downloads its fingerprints here; reading the same file keeps our CNAME check in
    # lockstep with the fingerprint that produced the match.
    fingerprints_path = Path.home() / "subzy" / "fingerprints.json"
    max_cname_hops = 10
    in_scope_only = True
    domain_seed_scope_only = True

    async def setup(self):
        self.binary = str(self.config.get("binary", "subzy")).strip()
        self.concurrency = int(self.config.get("concurrency", 25))
        self.timeout = int(self.config.get("timeout", 10))
        self.https = bool(self.config.get("https", False))
        self.verify_ssl = bool(self.config.get("verify_ssl", False))
        self.check_unresolved = bool(self.config.get("check_unresolved", False))
        self.service_cnames = None
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
    def is_claimed_provider_response(response):
        if response is None or response.status_code != 200:
            return False
        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        return "x-gitbook-route-site" in headers or "x-gitbook-target" in headers

    async def is_claimed_provider_host(self, host):
        for scheme in ("https", "http"):
            try:
                response = await self.helpers.request(f"{scheme}://{host}")
            except Exception:
                continue
            if self.is_claimed_provider_response(response):
                return True
        return False

    @staticmethod
    def load_service_cnames(fingerprints_path):
        """Maps each subzy engine name to the CNAME suffixes its fingerprint declares."""
        try:
            fingerprints = json.loads(Path(fingerprints_path).read_text())
        except (OSError, ValueError):
            return {}
        return {
            str(entry.get("service", "")): [str(cname).lower().rstrip(".") for cname in entry.get("cname") or []]
            for entry in fingerprints
            if isinstance(entry, dict)
        }

    @staticmethod
    def routes_to_other_provider(cname_chain, service_cnames):
        """
        subzy matches response bodies only and never checks the CNAMEs a fingerprint declares, so
        generic text (e.g. Next.js's "404: This page could not be found." for Gemfury) matches
        unrelated providers. A match is contradicted only when the fingerprint declares CNAMEs and
        the host is CNAMEd somewhere none of them cover: its traffic then goes to that other
        provider, where the fingerprinted resource cannot be claimed. Hosts without a CNAME (apex
        A records to the provider) and fingerprints without CNAMEs stay reported.
        """
        if not service_cnames or not cname_chain:
            return False
        return not any(
            target == cname or target.endswith(f".{cname}") for target in cname_chain for cname in service_cnames
        )

    async def resolve_cname_chain(self, host):
        chain = []
        current = host
        for _ in range(self.max_cname_hops):
            targets = sorted(await self.helpers.dns.resolve(current, type="CNAME"))
            if not targets:
                break
            current = str(targets[0]).lower().rstrip(".")
            if current in chain:
                break
            chain.append(current)
        return chain

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

                if await self.is_claimed_provider_host(host):
                    self.debug(f"Suppressing takeover result for {host}: provider response confirms an active claimed site")
                    continue

                engine = result.get("engine") or result.get("service") or "subzy"
                if self.service_cnames is None:
                    self.service_cnames = self.load_service_cnames(self.fingerprints_path)
                cname_chain = await self.resolve_cname_chain(host)
                if self.routes_to_other_provider(cname_chain, self.service_cnames.get(engine)):
                    self.debug(
                        f"Suppressing {engine} takeover result for {host}: CNAME chain {cname_chain} "
                        f"does not reach {self.service_cnames.get(engine)}"
                    )
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
