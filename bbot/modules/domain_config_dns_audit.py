import json
from pathlib import Path

from bbot.modules.base import BaseModule


class domain_config_dns_audit(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING", "VULNERABILITY"]
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
        "quick": True,
    }
    options_desc = {
        "version": "Git branch/tag/commit of domain-config-dns-audit",
        "binary": "Path to domain-config-dns-audit executable wrapper",
        "workers": "Parallel workers used by the DNS audit tool",
        "quick": "Skip slow checks in DNS audit tool",
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
        self.quick = bool(self.config.get("quick", True))
        if "/" in self.binary:
            if not Path(self.binary).is_file():
                return None, f"domain-config-dns-audit binary not found at path: {self.binary}"
        elif not self.helpers.which(self.binary):
            return None, f'domain-config-dns-audit binary "{self.binary}" was not found in PATH'
        return True

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
        finally:
            targets_file.unlink(missing_ok=True)
