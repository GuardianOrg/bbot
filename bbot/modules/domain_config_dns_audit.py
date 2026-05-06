import asyncio
import json
import uuid
from collections.abc import Iterable
from pathlib import Path

import dns.resolver
import dns.query
import dns.zone

from bbot.modules.base import BaseModule


class domain_config_dns_audit(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING", "VULNERABILITY", "DOMAIN_DNS_CONFIG"]
    flags = ["active", "safe", "subdomain-enum"]
    meta = {
        "description": "Audit DNS/domain security configuration using domain-config-dns-audit",
        "created_date": "2026-02-26",
        "author": "@carlospolop + @codex",
    }
    options = {
        "version": "main",
        "binary": "domain-config-dns-audit",
        "workers": 8,
        "quick": False,
        "zone_transfer_lifetime": 5,
        "wildcard_nameservers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "wildcard_probe_count": 2,
        "wildcard_resolver_timeout": 4,
    }
    options_desc = {
        "version": "Git branch/tag/commit of domain-config-dns-audit",
        "binary": "Path to domain-config-dns-audit executable wrapper",
        "workers": "Parallel workers used by the DNS audit tool",
        "quick": "Skip slow checks in DNS audit tool when explicitly enabled",
        "zone_transfer_lifetime": "Timeout in seconds for each AXFR attempt",
        "wildcard_nameservers": "At least 3 DNS resolver IPs used to recheck wildcard DNS status",
        "wildcard_probe_count": "How many random wildcard probes to send per resolver and candidate parent",
        "wildcard_resolver_timeout": "Timeout in seconds for each wildcard DNS resolver query",
    }
    deps_ansible = [
        {
            "name": "Clone domain-config-dns-audit repository",
            "git": {
                "repo": "https://github.com/carlospolop/domain-config-dns-audit",
                "dest": "#{BBOT_TEMP}/domain-config-dns-audit",
                "version": "#{BBOT_MODULES_DOMAIN_CONFIG_DNS_AUDIT_VERSION}",
            },
        },
        {
            "name": "Create domain-config-dns-audit venv",
            "command": {
                "cmd": "python3 -m venv .venv",
                "chdir": "#{BBOT_TEMP}/domain-config-dns-audit",
                "creates": "#{BBOT_TEMP}/domain-config-dns-audit/.venv/bin/python",
            },
        },
        {
            "name": "Install domain-config-dns-audit requirements",
            "command": {
                "cmd": ".venv/bin/pip install -r dns-audit/requirements.txt",
                "chdir": "#{BBOT_TEMP}/domain-config-dns-audit",
            },
        },
        {
            "name": "Install domain-config-dns-audit wrapper",
            "copy": {
                "dest": "#{BBOT_TOOLS}/domain-config-dns-audit",
                "mode": "u+x,g+x,o+x",
                "content": "#!/usr/bin/env bash\nexec \"#{BBOT_TEMP}/domain-config-dns-audit/.venv/bin/python\" \"#{BBOT_TEMP}/domain-config-dns-audit/dns-audit/dns_audit.py\" \"$@\"\n",
            },
        },
    ]

    _batch_size = 150
    in_scope_only = True
    per_host_only = True

    SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    CATEGORIES = {
        "DNS": {"maxPenalty": 30},
        "DNSSEC": {"maxPenalty": 25},
        "Email": {"maxPenalty": 20},
        "HTTP": {"maxPenalty": 25},
        "TLS": {"maxPenalty": 30},
    }

    async def setup(self):
        self.binary = str(self.config.get("binary", "domain-config-dns-audit")).strip()
        self.workers = max(1, int(self.config.get("workers", 8)))
        self.quick = bool(self.config.get("quick", False))
        self.zone_transfer_lifetime = max(1, int(self.config.get("zone_transfer_lifetime", 5)))
        self.wildcard_nameservers = self._coerce_string_list(
            self.config.get("wildcard_nameservers", ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        )
        self.wildcard_probe_count = max(1, int(self.config.get("wildcard_probe_count", 2)))
        self.wildcard_resolver_timeout = max(1, int(self.config.get("wildcard_resolver_timeout", 4)))
        if len(self.wildcard_nameservers) < 3:
            return None, "domain-config-dns-audit requires at least 3 wildcard_nameservers"
        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"domain-config-dns-audit binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'domain-config-dns-audit binary "{self.binary}" was not found in PATH'
        return True

    def _coerce_string_list(self, value):
        if isinstance(value, str):
            items = value.split(",")
        elif isinstance(value, Iterable) and not isinstance(value, (bytes, dict)):
            items = value
        else:
            items = []
        return [str(item).strip() for item in items if str(item).strip()]

    async def filter_event(self, event):
        host = str(event.host or "").strip().rstrip(".").lower()
        if not host:
            return False, "event host is empty"
        if "_wildcard" in host.split("."):
            return False, "event is wildcard"
        if not self.helpers.is_domain(host):
            return False, "host is not a domain"
        return True

    def _parse_json_output(self, text):
        raw = str(text or "").strip()
        if not raw:
            return []
        for parser in (lambda x: json.loads(x), self._parse_embedded_json):
            try:
                parsed = parser(raw)
            except Exception:
                continue
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        return []

    def _parse_embedded_json(self, raw):
        candidates = []
        for idx, char in enumerate(raw):
            if char not in "[{":
                continue
            prev = raw[idx - 1] if idx > 0 else "\n"
            if idx == 0 or prev in "\r\n":
                candidates.append(idx)

        for start in candidates:
            end_list = raw.rfind("]")
            end_obj = raw.rfind("}")
            possible_ends = [end for end in (end_list, end_obj) if end > start]
            for end in sorted(possible_ends, reverse=True):
                try:
                    return json.loads(raw[start : end + 1])
                except Exception:
                    continue
        return []

    def _map_category(self, category):
        cat = str(category or "").strip()
        if cat == "DNSSEC":
            return "DNSSEC"
        if cat == "DNS" or "DNS" in cat:
            return "DNS"
        if cat in {"Email", "SPF", "DMARC", "DKIM", "MTA-STS"}:
            return "Email"
        if cat in {"HTTP", "Headers"}:
            return "HTTP"
        if cat in {"TLS", "SSL", "Certificate"}:
            return "TLS"
        if cat == "WHOIS":
            return "DNS"
        return ""

    def _grade_from_score(self, score):
        if score >= 90:
            return "A+"
        if score >= 80:
            return "A"
        if score >= 60:
            return "B"
        if score >= 40:
            return "C"
        if score >= 20:
            return "D"
        return "F"

    def _calculate_grade(self, findings):
        category_penalties = {k: 0 for k in self.CATEGORIES.keys()}
        for finding in findings:
            sev = str(finding.get("severity", "info")).lower().strip()
            mapped = self._map_category(finding.get("category", ""))
            if not mapped:
                continue
            category_penalties[mapped] += self.SEVERITY_POINTS.get(sev, 0)

        total_penalty = 0
        category_scores = {}
        for category, meta in self.CATEGORIES.items():
            max_penalty = int(meta["maxPenalty"])
            penalty = min(category_penalties.get(category, 0), max_penalty)
            total_penalty += penalty
            category_scores[category] = max(0, 100 - round((penalty / max_penalty) * 100))

        max_total_penalty = sum(int(v["maxPenalty"]) for v in self.CATEGORIES.values())
        overall = max(0, round(100 - (total_penalty / max_total_penalty) * 100))
        return overall, self._grade_from_score(overall), category_scores

    def _short(self, value, limit=200):
        text = str(value or "").strip().replace("\n", " ")
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    async def check_zone_transfer(self, host):
        nameservers = []
        ns_results = await self.helpers.resolve_raw(host, type="NS")
        if ns_results:
            raw_results, _errors = ns_results
            for answer in raw_results:
                value = answer.to_text().strip().rstrip(".").lower()
                if value and value not in nameservers:
                    nameservers.append(value)

        for nameserver in nameservers:
            if await self._try_zone_transfer(nameserver, host):
                return {"zone_transfer_possible": True, "zone_transfer_nameservers": [nameserver]}

        return {"zone_transfer_possible": False, "zone_transfer_nameservers": nameservers}

    async def check_wildcard(self, host):
        nameservers = self.wildcard_nameservers[:3]
        host_ips_by_nameserver = {}
        for nameserver in nameservers:
            host_ips = await self._resolve_ip_records(host, nameserver)
            if host_ips:
                host_ips_by_nameserver[nameserver] = set(host_ips)

        if len(host_ips_by_nameserver) < 3:
            return {"is_wildcard": False, "wildcard_ips": []}

        for parent in self._wildcard_candidate_parents(host):
            matching_ips_by_nameserver = {}
            for nameserver in nameservers:
                baseline_ips = host_ips_by_nameserver.get(nameserver)
                if not baseline_ips:
                    continue

                wildcard_probe_ips = set()
                for _ in range(self.wildcard_probe_count):
                    probe_host = f"{uuid.uuid4().hex[:12]}.{parent}"
                    wildcard_probe_ips.update(await self._resolve_ip_records(probe_host, nameserver))

                overlap = sorted(baseline_ips.intersection(wildcard_probe_ips))
                if overlap:
                    matching_ips_by_nameserver[nameserver] = overlap

            if len(matching_ips_by_nameserver) >= 3:
                wildcard_ips = sorted({ip for ips in matching_ips_by_nameserver.values() for ip in ips})
                return {"is_wildcard": True, "wildcard_ips": wildcard_ips}

        return {"is_wildcard": False, "wildcard_ips": []}

    def _wildcard_candidate_parents(self, host):
        labels = [label for label in str(host or "").split(".") if label]
        return [".".join(labels[index:]) for index in range(1, max(len(labels) - 1, 1)) if len(labels[index:]) >= 2]

    async def _resolve_ip_records(self, host, nameserver):
        return await asyncio.to_thread(self._sync_resolve_ip_records, host, nameserver)

    def _sync_resolve_ip_records(self, host, nameserver):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = self.wildcard_resolver_timeout
        resolver.lifetime = self.wildcard_resolver_timeout

        results = set()
        for rdtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(host, rdtype)
            except Exception:
                continue
            for answer in answers:
                value = answer.to_text().strip()
                if value:
                    results.add(value)

        return sorted(results)

    async def _try_zone_transfer(self, nameserver, host):
        try:
            zone = await asyncio.to_thread(self._sync_zone_transfer, nameserver, host)
        except Exception:
            return False
        return zone is not None

    def _sync_zone_transfer(self, nameserver, host):
        transfer = dns.query.xfr(nameserver, host, lifetime=self.zone_transfer_lifetime)
        return dns.zone.from_xfr(transfer)

    async def emit_dns_config_status(self, parent_event, host):
        zone_status = await self.check_zone_transfer(host)
        wildcard_status = await self.check_wildcard(host)
        payload = {
            "host": host,
            "zone_transfer_possible": zone_status["zone_transfer_possible"],
            "zone_transfer_nameservers": zone_status["zone_transfer_nameservers"],
            "is_wildcard": wildcard_status["is_wildcard"],
            "wildcard_ips": wildcard_status["wildcard_ips"],
        }

        await self.emit_event(
            payload,
            "DOMAIN_DNS_CONFIG",
            parent_event,
            context=f'{{module}} checked DNS configuration for "{host}"',
        )

        if not zone_status["zone_transfer_possible"]:
            return

        nameservers = zone_status["zone_transfer_nameservers"]
        nameserver_text = ", ".join(nameservers) if nameservers else "one of the authoritative nameservers"
        await self.emit_event(
            {
                "host": host,
                "severity": "HIGH",
                "category": "DNS",
                "title": "DNS zone transfer enabled",
                "description": f'DNS zone transfer (AXFR) is enabled for {host}.',
                "evidence": f'AXFR succeeded against {nameserver_text}.',
                "recommendation": "Disable public AXFR and restrict zone transfers to authorized secondary name servers only.",
                "template": "domain-config-dns-audit",
                "zone_transfer_possible": True,
                "zone_transfer_nameservers": nameservers,
            },
            "VULNERABILITY",
            parent_event,
            tags=["dns-audit", "domain-config-dns-audit", "dns-audit-zone-transfer"],
            context=f'{{module}} found an exposed DNS zone transfer on "{host}"',
        )

    async def handle_batch(self, *events):
        parent_by_host = {}
        targets = []
        for event in events:
            host = str(event.host or "").strip().rstrip(".").lower()
            if not host or not self.helpers.is_domain(host):
                continue
            if host not in parent_by_host:
                parent_by_host[host] = event
                targets.append(host)
        if not targets:
            return

        targets_file = self.helpers.tempfile(targets, pipe=False)
        try:
            command = [self.binary, "--file", str(targets_file), "--json", "--workers", str(self.workers)]
            if self.quick:
                command.append("--quick")
            process = await self.run_process(command, _log_stderr=False)
            results = self._parse_json_output(getattr(process, "stdout", ""))
            for result in results:
                if not isinstance(result, dict):
                    continue
                host = str(result.get("domain", "")).strip().rstrip(".").lower()
                if not host:
                    continue
                parent_event = parent_by_host.get(host)
                if parent_event is None:
                    continue

                findings = result.get("findings", [])
                if not isinstance(findings, list):
                    findings = []

                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    title = self._short(finding.get("title", "Domain configuration finding"), limit=120)
                    severity = str(finding.get("severity", "info")).strip().upper()
                    category = self._short(finding.get("category", "General"), limit=60)
                    raw_description = self._short(finding.get("description", "Domain configuration finding"), limit=400)
                    evidence = self._short(finding.get("evidence", ""), limit=180)
                    recommendation = self._short(finding.get("recommendation", ""), limit=180)
                    command_txt = self._short(finding.get("command", ""), limit=140)

                    payload = {
                        "title": title,
                        "category": category,
                        "description": raw_description,
                        "host": host,
                        "evidence": evidence,
                        "recommendation": recommendation,
                        "command": command_txt,
                        "template": "domain-config-dns-audit",
                    }
                    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                        payload["severity"] = severity
                    event_type = "VULNERABILITY" if severity in {"CRITICAL", "HIGH", "MEDIUM"} else "FINDING"

                    await self.emit_event(
                        payload,
                        event_type,
                        parent_event,
                        tags=["dns-audit", "domain-config-dns-audit", f"dns-audit-{severity.lower()}"],
                        context=f'{{module}} audited "{host}" and produced {{event.type}}',
                    )

                score, grade, category_scores = self._calculate_grade(findings)
                grade_description = (
                    "template: [domain-config-dns-audit-grade], name: [Domain security grade], "
                    f"score: [{score}], grade: [{grade}], dns: [{category_scores.get('DNS', 0)}], "
                    f"dnssec: [{category_scores.get('DNSSEC', 0)}], email: [{category_scores.get('Email', 0)}], "
                    f"http: [{category_scores.get('HTTP', 0)}], tls: [{category_scores.get('TLS', 0)}]"
                )

                await self.emit_event(
                    {"description": grade_description, "host": host},
                    "FINDING",
                    parent_event,
                    tags=["dns-audit", "domain-config-dns-audit", "dns-audit-grade"],
                    context=f'{{module}} calculated a domain-security grade for "{host}"',
                )

            for host, parent_event in parent_by_host.items():
                await self.emit_dns_config_status(parent_event, host)
        finally:
            targets_file.unlink(missing_ok=True)
