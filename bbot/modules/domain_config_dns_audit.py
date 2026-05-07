import asyncio
import http.client
import re
import socket
import ssl
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.zone

from bbot.modules.base import BaseModule


@dataclass
class AuditFinding:
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    command: str = ""


class domain_config_dns_audit(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["FINDING", "VULNERABILITY", "DOMAIN_DNS_CONFIG"]
    flags = ["active", "safe", "subdomain-enum"]
    meta = {
        "description": "Audit DNS, DNSSEC, email-DNS, CAA, and MX domain configuration without external scripts.",
        "created_date": "2026-02-26",
        "author": "@carlospolop + @codex",
    }
    options = {
        "quick": False,
        "zone_transfer_lifetime": 5,
        "dns_timeout": 5,
        "wildcard_nameservers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "wildcard_probe_count": 2,
        "wildcard_resolver_timeout": 4,
        "dkim_selectors": [
            "google",
            "selector1",
            "selector2",
            "default",
            "mail",
            "dkim",
            "k1",
            "k2",
            "s1",
            "s2",
            "smtp",
            "email",
            "mx",
            "postfix",
            "mailjet",
            "sendgrid",
            "mandrill",
            "amazonses",
            "cm",
            "protonmail",
        ],
    }
    options_desc = {
        "quick": "Skip slower checks such as AXFR, PTR, DANE, SPF include-depth, MX STARTTLS, and open-resolver checks.",
        "zone_transfer_lifetime": "Timeout in seconds for each AXFR attempt.",
        "dns_timeout": "Timeout in seconds for direct DNS queries.",
        "wildcard_nameservers": "At least 3 resolver IPs used to recheck wildcard DNS status.",
        "wildcard_probe_count": "How many random wildcard probes to send per resolver and candidate parent.",
        "wildcard_resolver_timeout": "Timeout in seconds for each wildcard DNS resolver query.",
        "dkim_selectors": "Common DKIM selectors to test through DNS TXT records.",
    }

    _batch_size = 150
    in_scope_only = True
    per_domain_only = True

    async def setup(self):
        self.quick = bool(self.config.get("quick", False))
        self.zone_transfer_lifetime = max(1, int(self.config.get("zone_transfer_lifetime", 5)))
        self.dns_timeout = max(1, int(self.config.get("dns_timeout", 5)))
        self.wildcard_nameservers = self._coerce_string_list(
            self.config.get("wildcard_nameservers", ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        )
        self.wildcard_probe_count = max(1, int(self.config.get("wildcard_probe_count", 2)))
        self.wildcard_resolver_timeout = max(1, int(self.config.get("wildcard_resolver_timeout", 4)))
        self.dkim_selectors = self._coerce_string_list(self.config.get("dkim_selectors", []))
        self.dns_cache = {}
        self.dns_ttl_cache = {}
        self.dns_full_cache = {}
        if len(self.wildcard_nameservers) < 3:
            return None, "domain_config_dns_audit requires at least 3 wildcard_nameservers"
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

    async def handle_batch(self, *events):
        parent_by_domain = {}
        for event in events:
            host = str(event.host or "").strip().rstrip(".").lower()
            if not host or not self.helpers.is_domain(host):
                continue
            _, registered_domain = self.helpers.split_domain(host)
            audit_domain = (registered_domain or host).lower().rstrip(".")
            parent_by_domain.setdefault(audit_domain, event)

        for domain, parent_event in parent_by_domain.items():
            await self.audit_domain(parent_event, domain)

    async def audit_domain(self, parent_event, domain):
        records = await self.collect_basic_dns(domain)
        findings = []
        dns_config = {
            "host": domain,
            "zone_transfer_possible": False,
            "zone_transfer_nameservers": records.get("NS", []),
            "is_wildcard": False,
            "wildcard_ips": [],
        }

        checks = [
            self.check_basic_dns,
            self.check_ns_delegation_integrity,
            self.check_https_svcb_records,
            self.check_dns_edns_resilience,
            self.check_dns_low_ttl_hints,
            self.check_cname_at_apex,
            self.check_wildcard_dns,
            self.check_deprecated_record_types,
            self.check_soa_values,
            self.check_dnssec,
            self.check_dnssec_lifecycle,
            self.check_dnssec_negative_validation,
            self.check_dnssec_algorithm_rollover,
            self.check_doh_dot,
            self.check_spf,
            self.check_spf_include_depth,
            self.check_dmarc,
            self.check_dkim,
            self.check_mta_sts,
            self.check_tls_rpt,
            self.check_tls_rpt_destinations,
            self.check_bimi,
            self.check_caa,
            self.check_caa_policy_quality,
            self.check_dane,
            self.check_mx_security,
            self.check_mx_starttls,
            self.check_ptr_records,
            self.check_dns_version,
            self.check_open_resolver,
        ]

        for check in checks:
            try:
                if self.quick and check.__name__ in {
                    "check_spf_include_depth",
                    "check_dane",
                    "check_mx_starttls",
                    "check_ptr_records",
                    "check_open_resolver",
                }:
                    continue
                await check(domain, records, findings)
            except Exception:
                self.verbose(f"{check.__name__} failed for {domain}", trace=True)

        try:
            zone_status = await self.check_zone_transfer(domain, records)
            dns_config["zone_transfer_possible"] = zone_status["zone_transfer_possible"]
            dns_config["zone_transfer_nameservers"] = zone_status["zone_transfer_nameservers"]
            if zone_status["zone_transfer_possible"]:
                findings.append(self.zone_transfer_finding(domain, zone_status["zone_transfer_nameservers"]))
        except Exception:
            self.verbose(f"check_zone_transfer failed for {domain}", trace=True)

        try:
            wildcard_status = await self.check_wildcard(domain)
            dns_config["is_wildcard"] = wildcard_status["is_wildcard"]
            dns_config["wildcard_ips"] = wildcard_status["wildcard_ips"]
        except Exception:
            self.verbose(f"check_wildcard failed for {domain}", trace=True)

        await self.emit_event(
            dns_config,
            "DOMAIN_DNS_CONFIG",
            parent_event,
            context=f'{{module}} checked DNS configuration for "{domain}"',
        )

        seen = set()
        for finding in findings:
            key = (finding.title, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            await self.emit_finding(parent_event, domain, finding)

    async def emit_finding(self, parent_event, domain, finding):
        severity = finding.severity.upper()
        payload = {
            "host": domain,
            "severity": severity,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "command": finding.command,
            "template": "domain-config-dns-audit",
        }
        event_type = "VULNERABILITY" if severity in {"CRITICAL", "HIGH", "MEDIUM"} else "FINDING"
        await self.emit_event(
            payload,
            event_type,
            parent_event,
            tags=["dns-audit", "domain-config-dns-audit", f"dns-audit-{severity.lower()}"],
            context=f'{{module}} audited "{domain}" and produced {{event.type}}',
        )

    async def collect_basic_dns(self, domain):
        records = {}
        for rdtype in ("A", "AAAA", "NS", "MX", "TXT", "SOA"):
            success, answers = await self.query_dns(domain, rdtype)
            if success:
                if rdtype == "NS":
                    answers = [answer.rstrip(".").lower() for answer in answers]
                records[rdtype] = answers
        if records.get("SOA"):
            records["SOA"] = records["SOA"][0]
        return records

    async def query_dns(self, domain, rdtype, nameserver=None, raise_on_nxdomain=False):
        key = (str(domain).lower(), str(rdtype).upper(), str(nameserver or "").lower(), bool(raise_on_nxdomain))
        if key not in self.dns_cache:
            self.dns_cache[key] = await asyncio.to_thread(self._sync_query_dns, domain, rdtype, nameserver, raise_on_nxdomain)
        success, answers = self.dns_cache[key]
        return success, list(answers)

    def _sync_query_dns(self, domain, rdtype, nameserver=None, raise_on_nxdomain=False):
        resolver = self.get_resolver(nameserver)
        try:
            answers = resolver.resolve(domain, rdtype)
            return True, [str(rdata).strip() for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return (False, ["NXDOMAIN"]) if raise_on_nxdomain else (True, [])
        except dns.resolver.NoAnswer:
            return True, []
        except dns.resolver.NoNameservers:
            return False, ["No nameservers available"]
        except dns.exception.Timeout:
            return False, ["timeout"]
        except Exception as e:
            return False, [str(e)]

    async def query_dns_with_ttl(self, domain, rdtype, nameserver=None):
        key = (str(domain).lower(), str(rdtype).upper(), str(nameserver or "").lower())
        if key not in self.dns_ttl_cache:
            self.dns_ttl_cache[key] = await asyncio.to_thread(self._sync_query_dns_with_ttl, domain, rdtype, nameserver)
        success, entries = self.dns_ttl_cache[key]
        return success, list(entries)

    def _sync_query_dns_with_ttl(self, domain, rdtype, nameserver=None):
        resolver = self.get_resolver(nameserver)
        try:
            answers = resolver.resolve(domain, rdtype)
            ttl = int(getattr(answers.rrset, "ttl", 0) or 0)
            return True, [(str(rdata).strip(), ttl) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return True, []
        except dns.resolver.NoAnswer:
            return True, []
        except Exception:
            return False, []

    async def query_dns_full(self, domain, rdtype, nameserver=None):
        key = (str(domain).lower(), str(rdtype).upper(), str(nameserver or "").lower())
        if key not in self.dns_full_cache:
            self.dns_full_cache[key] = await asyncio.to_thread(self._sync_query_dns_full, domain, rdtype, nameserver)
        return self.dns_full_cache[key]

    def _sync_query_dns_full(self, domain, rdtype, nameserver=None):
        try:
            ns = nameserver or "8.8.8.8"
            q = dns.message.make_query(domain, rdtype, want_dnssec=True)
            response = dns.query.udp(q, ns, timeout=self.dns_timeout)
            return True, response
        except Exception:
            return False, None

    def get_resolver(self, nameserver=None):
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        if nameserver:
            resolver.nameservers = [nameserver]
        return resolver

    def is_apex_domain(self, domain):
        _, registered_domain = self.helpers.split_domain(domain)
        return not registered_domain or domain.rstrip(".").lower() == registered_domain.lower()

    def get_tld(self, domain):
        parts = str(domain or "").rstrip(".").split(".")
        return parts[-1] if parts else ""

    async def check_basic_dns(self, domain, records, findings):
        a_records = records.get("A", [])
        aaaa_records = records.get("AAAA", [])
        ns_records = records.get("NS", [])
        if not a_records:
            findings.append(AuditFinding(
                "No A Record",
                "INFO",
                "DNS",
                "Domain has no IPv4 address (A record) configured.",
                f"DNS query for {domain} A returned empty",
                "Add an A record if the domain should be directly reachable over IPv4.",
                f"dig {domain} A +short",
            ))
        if a_records and not aaaa_records:
            findings.append(AuditFinding(
                "No IPv6 (AAAA) Record",
                "INFO",
                "DNS",
                "Domain has IPv4 connectivity but no IPv6 address.",
                f"DNS query for {domain} AAAA returned empty",
                "Add an AAAA record if the service supports IPv6.",
                f"dig {domain} AAAA +short",
            ))
        if len(ns_records) < 2:
            findings.append(AuditFinding(
                "Insufficient Nameservers",
                "MEDIUM",
                "DNS",
                "Fewer than two nameservers are configured, reducing DNS redundancy.",
                f"NS records: {', '.join(ns_records) or '<none>'}",
                "Configure at least two authoritative nameservers, ideally across different networks/providers.",
                f"dig {domain} NS +short",
            ))
        await self.check_nameserver_diversity(domain, ns_records, findings)

    async def check_nameserver_diversity(self, domain, ns_records, findings):
        ns_ips = []
        for ns in ns_records:
            success, ips = await self.query_dns(ns, "A")
            if success and ips:
                ns_ips.append(ips[0])
        if len(ns_ips) < 2:
            return
        prefixes = {".".join(ip.split(".")[:2]) for ip in ns_ips if len(ip.split(".")) >= 2}
        if len(prefixes) == 1:
            findings.append(AuditFinding(
                "Low Nameserver Diversity",
                "LOW",
                "DNS",
                "All checked nameservers resolve inside the same IPv4 /16, which reduces provider/network redundancy.",
                f"NS IPs: {', '.join(ns_ips)}",
                "Use nameservers from at least two different networks/providers where possible.",
                f"dig {domain} NS +short | xargs -I{{}} dig {{}} A +short",
            ))

    async def check_zone_transfer(self, domain, records):
        if not self.is_apex_domain(domain) or self.quick:
            return {"zone_transfer_possible": False, "zone_transfer_nameservers": records.get("NS", [])}
        ns_records = records.get("NS", [])
        for ns in ns_records:
            ns_ips = []
            for rdtype in ("A", "AAAA"):
                success, answers = await self.query_dns(ns, rdtype)
                if success:
                    ns_ips.extend(answers)
            for ns_ip in dict.fromkeys(ns_ips):
                if await self._try_zone_transfer(ns_ip, domain):
                    return {"zone_transfer_possible": True, "zone_transfer_nameservers": [ns]}
        return {"zone_transfer_possible": False, "zone_transfer_nameservers": ns_records}

    def zone_transfer_finding(self, domain, nameservers):
        nameserver_text = ", ".join(nameservers) if nameservers else "one authoritative nameserver"
        return AuditFinding(
            "DNS zone transfer enabled",
            "HIGH",
            "DNS",
            f"DNS zone transfer (AXFR) is enabled for {domain}.",
            f"AXFR succeeded against {nameserver_text}.",
            "Disable public AXFR and restrict zone transfers to authorized secondary name servers only.",
            f"dig @{nameserver_text.split(',')[0]} {domain} AXFR",
        )

    async def _try_zone_transfer(self, nameserver, domain):
        try:
            zone = await asyncio.to_thread(self._sync_zone_transfer, nameserver, domain)
        except Exception:
            return False
        return zone is not None

    def _sync_zone_transfer(self, nameserver, domain):
        transfer = dns.query.xfr(nameserver, domain, lifetime=self.zone_transfer_lifetime)
        return dns.zone.from_xfr(transfer)

    async def check_wildcard(self, domain):
        nameservers = self.wildcard_nameservers[:3]
        baseline_by_nameserver = {}
        for nameserver in nameservers:
            ips = await self._resolve_ip_records(domain, nameserver)
            if ips:
                baseline_by_nameserver[nameserver] = set(ips)
        if len(baseline_by_nameserver) < 3:
            return {"is_wildcard": False, "wildcard_ips": []}
        for parent in self.wildcard_candidate_parents(domain):
            matching = {}
            for nameserver in nameservers:
                wildcard_ips = set()
                for _ in range(self.wildcard_probe_count):
                    wildcard_ips.update(await self._resolve_ip_records(f"{uuid.uuid4().hex[:12]}.{parent}", nameserver))
                overlap = sorted(baseline_by_nameserver.get(nameserver, set()).intersection(wildcard_ips))
                if overlap:
                    matching[nameserver] = overlap
            if len(matching) >= 3:
                return {"is_wildcard": True, "wildcard_ips": sorted({ip for ips in matching.values() for ip in ips})}
        return {"is_wildcard": False, "wildcard_ips": []}

    def wildcard_candidate_parents(self, domain):
        labels = [label for label in str(domain or "").split(".") if label]
        return [".".join(labels[index:]) for index in range(0, max(len(labels) - 1, 1)) if len(labels[index:]) >= 2]

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

    async def check_dnssec(self, domain, records, findings):
        if not self.is_apex_domain(domain):
            return
        tld = self.get_tld(domain)
        success, dnskey_records = await self.query_dns(domain, "DNSKEY")
        if not success or not dnskey_records:
            findings.append(AuditFinding(
                "DNSSEC Not Enabled",
                "MEDIUM",
                "DNSSEC",
                "Domain does not publish DNSKEY records, so DNSSEC is not enabled.",
                "No DNSKEY records found",
                "Enable DNSSEC through the registrar or DNS provider.",
                f"dig {domain} DNSKEY +short",
            ))
            return
        records["DNSKEY"] = dnskey_records
        dnskey_text = " ".join(dnskey_records)
        for weak_alg, name in {"5": "RSASHA1", "7": "RSASHA1-NSEC3-SHA1", "10": "RSASHA512"}.items():
            if re.search(rf"\s{weak_alg}\s", dnskey_text):
                findings.append(AuditFinding(
                    "Weak DNSSEC Algorithm",
                    "MEDIUM",
                    "DNSSEC",
                    f"DNSSEC uses weak or deprecated algorithm {name}.",
                    f"DNSKEY algorithm: {weak_alg}",
                    "Migrate to a modern DNSSEC algorithm such as ECDSAP256SHA256 or ED25519.",
                    f"dig {domain} DNSKEY +short",
                ))
        success, ds_records = await self.query_dns(domain, "DS")
        if success and ds_records:
            records["DS"] = ds_records
            if any(len(ds.split()) >= 3 and ds.split()[2] == "1" for ds in ds_records) and not any(
                len(ds.split()) >= 3 and ds.split()[2] == "2" for ds in ds_records
            ):
                findings.append(AuditFinding(
                    "DS Record Uses Only SHA-1",
                    "MEDIUM",
                    "DNSSEC",
                    "DS record uses SHA-1 without a SHA-256 digest.",
                    f"DS: {ds_records[0]}",
                    "Publish a SHA-256 DS record at the parent zone.",
                    f"dig {domain} DS +short",
                ))
        else:
            findings.append(AuditFinding(
                "Missing DS Record at Parent",
                "HIGH",
                "DNSSEC",
                "Zone is signed but no DS record exists at the parent zone, breaking the chain of trust.",
                "DNSKEY present but no DS record found",
                "Publish the matching DS record through the registrar.",
                f"dig {domain} DS +short",
            ))
        try:
            success, tld_ds = await self.query_dns(f"{tld}.", "DS", nameserver="198.41.0.4")
            if success and not tld_ds:
                findings.append(AuditFinding(
                    "TLD Does Not Support DNSSEC",
                    "HIGH",
                    "DNSSEC",
                    f"The .{tld} TLD has no DS record in the root zone, so DNSSEC chain of trust cannot be established.",
                    f"Query for {tld}. DS at root returned no DS",
                    "DNSSEC is ineffective for this TLD; monitor for TLD DNSSEC enablement.",
                    f"dig @198.41.0.4 {tld}. DS +short",
                ))
        except Exception:
            pass
        await self.check_rrsig_expiration(domain, findings)
        await self.check_nsec_records(domain, findings)
        await self.check_dnssec_validation(domain, records, findings)

    async def check_rrsig_expiration(self, domain, findings):
        success, response = await self.query_dns_full(domain, "SOA")
        if not success or not response:
            return
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for rrsig in rrset:
                exp_date = datetime.fromtimestamp(rrsig.expiration, tz=timezone.utc)
                days_left = (exp_date - datetime.now(tz=timezone.utc)).days
                if days_left < 0:
                    findings.append(AuditFinding(
                        "RRSIG Signatures Expired",
                        "CRITICAL",
                        "DNSSEC",
                        "DNSSEC signatures have expired.",
                        f"RRSIG expiry: {exp_date.isoformat()}",
                        "Re-sign the zone immediately.",
                        f"dig {domain} SOA +dnssec | grep RRSIG",
                    ))
                elif days_left < 14:
                    findings.append(AuditFinding(
                        "RRSIG Expiration Approaching",
                        "MEDIUM" if days_left >= 7 else "HIGH",
                        "DNSSEC",
                        f"DNSSEC signatures expire in {days_left} days.",
                        f"RRSIG expiry: {exp_date.isoformat()}",
                        "Verify automated DNSSEC re-signing.",
                        f"dig {domain} SOA +dnssec | grep RRSIG",
                    ))
                return

    async def check_nsec_records(self, domain, findings):
        success, nsec_records = await self.query_dns(domain, "NSEC")
        if success and nsec_records:
            findings.append(AuditFinding(
                "NSEC Allows Zone Walking",
                "MEDIUM",
                "DNSSEC",
                "Zone uses NSEC denial-of-existence records, which can expose domain names through zone walking.",
                f"NSEC: {nsec_records[0][:100]}",
                "Use NSEC3 if zone-walking resistance is required.",
                f"dig {domain} NSEC +short",
            ))
        success, nsec3param = await self.query_dns(domain, "NSEC3PARAM")
        if success and nsec3param:
            parts = nsec3param[0].split()
            if len(parts) >= 3 and parts[2].isdigit():
                iterations = int(parts[2])
                if iterations == 0:
                    findings.append(AuditFinding(
                        "NSEC3 Without Iterations",
                        "LOW",
                        "DNSSEC",
                        "NSEC3 uses zero iterations, making hashes easier to reverse.",
                        f"NSEC3PARAM: {nsec3param[0]}",
                        "Use a modest NSEC3 iteration count if zone-walking resistance is required.",
                        f"dig {domain} NSEC3PARAM +short",
                    ))
                elif iterations > 150:
                    findings.append(AuditFinding(
                        "Excessive NSEC3 Iterations",
                        "MEDIUM",
                        "DNSSEC",
                        f"NSEC3 uses {iterations} iterations, which can cause resolver CPU pressure.",
                        f"NSEC3PARAM: {nsec3param[0]}",
                        "Reduce NSEC3 iterations to a safer range.",
                        f"dig {domain} NSEC3PARAM +short",
                    ))

    async def check_dnssec_validation(self, domain, records, findings):
        if not records.get("DNSKEY"):
            return
        success, response = await self.query_dns_full(domain, "A", nameserver="8.8.8.8")
        if success and response and not (response.flags & dns.flags.AD):
            findings.append(AuditFinding(
                "DNSSEC Validation Failing",
                "HIGH",
                "DNSSEC",
                "Zone is signed but a validating resolver did not return the AD flag.",
                "Query to 8.8.8.8 does not return AD flag",
                "Check DS/DNSKEY consistency, valid signatures, and DNSSEC chain health.",
                f"dig @8.8.8.8 {domain} A +dnssec +noall +comments | grep flags",
            ))

    async def check_dnssec_lifecycle(self, domain, records, findings):
        if not self.is_apex_domain(domain) or not records.get("DNSKEY"):
            return
        success_ds, ds_records = await self.query_dns(domain, "DS")
        success_cds, cds_records = await self.query_dns(domain, "CDS")
        success_cdnskey, cdnskey_records = await self.query_dns(domain, "CDNSKEY")
        if success_cds and cds_records and not (success_cdnskey and cdnskey_records):
            findings.append(AuditFinding(
                "DNSSEC Rollover Signal Incomplete (CDS without CDNSKEY)",
                "MEDIUM",
                "DNSSEC",
                "CDS records are published but CDNSKEY records are missing.",
                f"CDS: {cds_records}",
                "Publish both CDS and CDNSKEY consistently during rollover.",
                f"dig {domain} CDS +short && dig {domain} CDNSKEY +short",
            ))
        if success_cdnskey and cdnskey_records and not (success_cds and cds_records):
            findings.append(AuditFinding(
                "DNSSEC Rollover Signal Incomplete (CDNSKEY without CDS)",
                "LOW",
                "DNSSEC",
                "CDNSKEY records are published but CDS records are missing.",
                f"CDNSKEY: {cdnskey_records[:2]}",
                "Publish CDS records alongside CDNSKEY when using automated DS management.",
                f"dig {domain} CDNSKEY +short && dig {domain} CDS +short",
            ))
        if success_ds and ds_records and success_cds and cds_records:
            ds_keytags = {parts[0] for parts in (r.split() for r in ds_records) if parts}
            cds_keytags = {parts[0] for parts in (r.split() for r in cds_records) if parts}
            if ds_keytags and cds_keytags and ds_keytags.isdisjoint(cds_keytags):
                findings.append(AuditFinding(
                    "DNSSEC Parent/Child Key Tag Mismatch",
                    "HIGH",
                    "DNSSEC",
                    "CDS key tags do not match parent DS key tags.",
                    f"DS key tags: {sorted(ds_keytags)}; CDS key tags: {sorted(cds_keytags)}",
                    "Synchronize child CDS/CDNSKEY with parent DS records before retiring old keys.",
                    f"dig {domain} DS +short && dig {domain} CDS +short",
                ))

    async def check_dnssec_negative_validation(self, domain, records, findings):
        if not self.is_apex_domain(domain) or not records.get("DNSKEY"):
            return
        random_label = f"_dnssec-negative-{uuid.uuid4().hex[:8]}.{domain}"
        try:
            q = dns.message.make_query(random_label, dns.rdatatype.A, want_dnssec=True)
            response = await asyncio.to_thread(dns.query.udp, q, "8.8.8.8", timeout=self.dns_timeout)
        except Exception:
            return
        if response.rcode() == dns.rcode.NXDOMAIN and not (response.flags & dns.flags.AD):
            findings.append(AuditFinding(
                "DNSSEC Negative Response Not Validated",
                "MEDIUM",
                "DNSSEC",
                "Signed zone returned NXDOMAIN without AD flag from a validating resolver.",
                f"Query: {random_label} A, rcode={dns.rcode.to_text(response.rcode())}",
                "Verify DS/DNSKEY consistency and validate the zone with DNSViz.",
                f"dig @8.8.8.8 {random_label} A +dnssec",
            ))
        has_nsec_proof = any(rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3) for rrset in (response.authority or []))
        if response.rcode() == dns.rcode.NXDOMAIN and not has_nsec_proof:
            findings.append(AuditFinding(
                "DNSSEC Denial-of-Existence Proof Not Observed",
                "LOW",
                "DNSSEC",
                "NXDOMAIN response did not include visible NSEC/NSEC3 proof records in the authority section.",
                f"Query: {random_label} A, authority_rrsets={len(response.authority or [])}",
                "Check authoritative DNSSEC signer output and denial-of-existence records.",
                f"dig @8.8.8.8 {random_label} A +dnssec +multi",
            ))

    async def check_dnssec_algorithm_rollover(self, domain, records, findings):
        dnskey_records = records.get("DNSKEY", [])
        algorithms = set()
        for key in dnskey_records:
            parts = key.split()
            if len(parts) >= 3 and parts[2].isdigit():
                algorithms.add(parts[2])
        if len(algorithms) > 1:
            findings.append(AuditFinding(
                "Multiple DNSSEC Algorithms",
                "INFO",
                "DNSSEC",
                f"Zone uses multiple DNSSEC algorithms: {sorted(algorithms)}.",
                f"Algorithms: {', '.join(sorted(algorithms))}",
                "Multiple algorithms may indicate rollover; verify this is intentional.",
                f"dig DNSKEY {domain} +short",
            ))

    async def check_doh_dot(self, domain, records, findings):
        ns_records = records.get("NS", [])
        if not ns_records:
            return
        has_doh = False
        has_dot = False
        doh_servers = []
        dot_servers = []
        for ns in ns_records[:2]:
            ns_clean = ns.rstrip(".")
            for path in ("/dns-query", "/resolve"):
                if await asyncio.to_thread(self._sync_check_doh, ns_clean, path):
                    has_doh = True
                    doh_servers.append(f"{ns_clean}{path}")
                    break
            success, ns_ips = await self.query_dns(ns_clean, "A")
            if success and ns_ips and await asyncio.to_thread(self._sync_check_dot, ns_ips[0], ns_clean):
                has_dot = True
                dot_servers.append(f"{ns_clean}:853")
        if has_doh:
            records["DoH_nameservers"] = doh_servers
        if has_dot:
            records["DoT_nameservers"] = dot_servers
        if not has_doh and not has_dot:
            findings.append(AuditFinding(
                "DNS-over-HTTPS/TLS Not Supported",
                "INFO",
                "DNS",
                "Checked authoritative nameservers do not appear to support DNS-over-HTTPS or DNS-over-TLS.",
                f"Tested nameservers: {', '.join(ns_records[:2])}",
                "Consider whether encrypted DNS support is required for this DNS provider or deployment.",
                f"kdig -d @{ns_records[0]} +tls {domain}",
            ))

    def _sync_check_doh(self, host, path):
        connection = None
        try:
            connection = http.client.HTTPSConnection(host, timeout=3, context=ssl.create_default_context())
            connection.request("GET", f"{path}?name=example.com&type=A", headers={"Accept": "application/dns-json"})
            response = connection.getresponse()
            response.read(512)
            return response.status == 200
        except Exception:
            return False
        finally:
            try:
                connection.close()
            except Exception:
                pass

    def _sync_check_dot(self, ip, server_hostname):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 853), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=server_hostname):
                    return True
        except Exception:
            return False

    async def check_spf(self, domain, records, findings):
        txt_records = records.get("TXT", [])
        spf_records = [r.strip('"') for r in txt_records if "v=spf1" in r.lower()]
        if not spf_records:
            if records.get("MX"):
                findings.append(AuditFinding(
                    "Missing SPF Record",
                    "MEDIUM",
                    "Email",
                    "Domain accepts email but does not publish an SPF record.",
                    "No TXT record starting with v=spf1",
                    "Publish an SPF TXT record listing authorized outbound mail sources.",
                    f"dig {domain} TXT +short | grep spf",
                ))
            return
        if len(spf_records) > 1:
            findings.append(AuditFinding(
                "Multiple SPF Records",
                "MEDIUM",
                "Email",
                "Multiple SPF records are invalid and cause SPF PermError.",
                f"Found {len(spf_records)} SPF records",
                "Merge SPF mechanisms into a single v=spf1 TXT record.",
                f"dig {domain} TXT +short | grep spf",
            ))
        spf = spf_records[0]
        records["SPF"] = spf
        lowered = spf.lower()
        if lowered.endswith("+all"):
            severity, title = "HIGH", "SPF Allows All Senders"
        elif lowered.endswith("?all"):
            severity, title = "MEDIUM", "SPF Neutral Policy"
        elif lowered.endswith("~all"):
            severity, title = "LOW", "SPF Softfail Policy"
        else:
            severity, title = None, None
        if title:
            findings.append(AuditFinding(
                title,
                severity,
                "Email",
                "SPF terminal policy is weaker than hardfail.",
                f"SPF: {spf}",
                "Use -all after confirming legitimate senders are included.",
                f"dig {domain} TXT +short | grep spf",
            ))
        if "ptr" in lowered:
            findings.append(AuditFinding(
                "SPF Uses Deprecated PTR Mechanism",
                "LOW",
                "Email",
                "SPF uses the deprecated and slow ptr mechanism.",
                f"SPF: {spf}",
                "Replace ptr with explicit ip4/ip6/a/mx/include mechanisms.",
                f"dig {domain} TXT +short | grep spf",
            ))
        lookups = re.findall(r"(include:|a:|mx:|ptr:|exists:|redirect=)", spf, re.I)
        if len(lookups) > 10:
            findings.append(AuditFinding(
                "SPF Exceeds DNS Lookup Limit",
                "MEDIUM",
                "Email",
                f"SPF has {len(lookups)} DNS lookup mechanisms; the limit is 10.",
                f"Mechanisms: {lookups}",
                "Reduce lookups by flattening SPF or removing unnecessary includes.",
                f"dig {domain} TXT +short | grep spf",
            ))

    async def check_spf_include_depth(self, domain, records, findings):
        spf = records.get("SPF")
        if not spf:
            return
        includes = re.findall(r"include:([^\s]+)", spf, re.I)
        redirects = re.findall(r"redirect=([^\s]+)", spf, re.I)
        total = len(includes) + len(redirects)
        for include in includes[:5]:
            success, txt_records = await self.query_dns(include, "TXT")
            if success:
                total += sum(len(re.findall(r"include:|redirect=", rec, re.I)) for rec in txt_records if "v=spf1" in rec.lower())
        if total > 8:
            findings.append(AuditFinding(
                "SPF Approaching Lookup Limit",
                "LOW",
                "Email",
                f"SPF include chain uses approximately {total}+ DNS lookups.",
                f"Includes: {', '.join(includes[:5])}",
                "SPF has a 10 DNS lookup limit; consider flattening.",
                f"dig TXT {domain} +short | grep spf",
            ))

    async def check_dmarc(self, domain, records, findings):
        success, dmarc_records = await self.query_dns(f"_dmarc.{domain}", "TXT")
        dmarc = next((rec.strip('"') for rec in dmarc_records if "v=dmarc1" in rec.lower()), None) if success else None
        if not dmarc:
            if records.get("MX"):
                findings.append(AuditFinding(
                    "Missing DMARC Record",
                    "MEDIUM",
                    "Email",
                    "Domain accepts email but no valid DMARC record was found.",
                    f"_dmarc.{domain} has no valid DMARC TXT record",
                    "Publish a DMARC record and progress policy toward quarantine/reject.",
                    f"dig _dmarc.{domain} TXT +short",
                ))
            return
        records["DMARC"] = dmarc
        lowered = dmarc.lower()
        policy = re.search(r"p\s*=\s*(none|quarantine|reject)", lowered)
        if policy and policy.group(1) in {"none", "quarantine"}:
            findings.append(AuditFinding(
                f"DMARC Policy Set to {policy.group(1).capitalize()}",
                "MEDIUM" if policy.group(1) == "none" else "LOW",
                "Email",
                "DMARC policy does not fully reject failing messages.",
                f"DMARC: {dmarc}",
                "Move to p=reject once legitimate sending paths are aligned.",
                f"dig _dmarc.{domain} TXT +short",
            ))
        for tag, title, recommendation in (
            ("sp=", "DMARC Missing Subdomain Policy", "Add sp=reject or another explicit subdomain policy."),
            ("rua=", "DMARC Missing Aggregate Reports", "Add rua=mailto:... to receive aggregate reports."),
            ("adkim=s", "DMARC DKIM Alignment Not Strict", "Use adkim=s after validating legitimate senders."),
            ("aspf=s", "DMARC SPF Alignment Not Strict", "Use aspf=s after validating legitimate senders."),
            ("fo=", "DMARC Forensic Reporting Not Configured", "Consider adding fo=1 if your reporting pipeline can handle forensic reports."),
        ):
            if tag not in lowered:
                severity = "INFO" if tag == "fo=" else "LOW"
                findings.append(AuditFinding(title, severity, "Email", title, f"DMARC: {dmarc}", recommendation, f"dig _dmarc.{domain} TXT +short"))
        pct = re.search(r"pct\s*=\s*(\d+)", lowered)
        if pct and int(pct.group(1)) < 100:
            findings.append(AuditFinding(
                "DMARC Not Applied to All Email",
                "LOW",
                "Email",
                f"DMARC pct={pct.group(1)} only applies policy to part of mail flow.",
                f"DMARC: {dmarc}",
                "Increase pct to 100 after validating legitimate mail.",
                f"dig _dmarc.{domain} TXT +short",
            ))

    async def check_dkim(self, domain, records, findings):
        found = []
        for selector in self.dkim_selectors:
            success, dkim_records = await self.query_dns(f"{selector}._domainkey.{domain}", "TXT")
            if not success or not dkim_records:
                continue
            dkim = " ".join(dkim_records)
            if "v=dkim1" not in dkim.lower():
                continue
            found.append(selector)
            if "k=rsa" in dkim.lower() or "k=" not in dkim.lower():
                match = re.search(r"p=([A-Za-z0-9+/=]+)", dkim)
                if match and len(match.group(1)) * 6 < 1024:
                    findings.append(AuditFinding(
                        "Weak DKIM Key Size",
                        "MEDIUM",
                        "Email",
                        f"DKIM selector {selector} appears to use a small RSA key.",
                        f"Key appears to be about {len(match.group(1)) * 6} bits",
                        "Use at least 2048-bit RSA keys or modern DKIM key types.",
                        f"dig TXT {selector}._domainkey.{domain}",
                    ))
        if found:
            records["DKIM_selectors"] = found
        elif records.get("MX"):
            findings.append(AuditFinding(
                "No DKIM Records Found",
                "LOW",
                "Email",
                "No DKIM records found for common selectors.",
                f"Checked selectors: {', '.join(self.dkim_selectors[:10])}",
                "Ensure DKIM is configured with the mail provider.",
                f"dig TXT selector._domainkey.{domain}",
            ))

    async def check_mta_sts(self, domain, records, findings):
        success, mta_records = await self.query_dns(f"_mta-sts.{domain}", "TXT")
        mta = next((rec for rec in mta_records if "v=stsv1" in rec.lower()), None) if success else None
        if mta:
            records["MTA-STS"] = mta
        elif records.get("MX"):
            findings.append(AuditFinding(
                "Missing MTA-STS",
                "LOW",
                "Email",
                "No MTA-STS TXT record was found for a mail-receiving domain.",
                f"_mta-sts.{domain} has no STSv1 TXT record",
                "Publish an MTA-STS TXT record if inbound SMTP transport hardening is required.",
                f"dig TXT _mta-sts.{domain}",
            ))

    async def check_tls_rpt(self, domain, records, findings):
        success, tls_records = await self.query_dns(f"_smtp._tls.{domain}", "TXT")
        tls_rpt = next((rec for rec in tls_records if "v=tlsrptv1" in rec.lower()), None) if success else None
        if tls_rpt:
            records["TLS-RPT"] = tls_rpt
        elif records.get("MX"):
            findings.append(AuditFinding(
                "Missing TLS-RPT",
                "INFO",
                "Email",
                "No SMTP TLS reporting record is configured.",
                f"_smtp._tls.{domain} has no TLS-RPT record",
                "Add TLS-RPT to receive SMTP TLS failure reports.",
                f"dig TXT _smtp._tls.{domain}",
            ))

    async def check_tls_rpt_destinations(self, domain, records, findings):
        tls_rpt = records.get("TLS-RPT")
        if not tls_rpt:
            return
        match = re.search(r"rua\s*=\s*([^;]+)", tls_rpt, re.I)
        if not match:
            findings.append(AuditFinding(
                "TLS-RPT Missing rua Destinations",
                "LOW",
                "Email",
                "TLS-RPT exists but has no rua destinations.",
                f"TLS-RPT: {tls_rpt}",
                "Add rua=mailto:... or rua=https://... destination(s).",
                f"dig TXT _smtp._tls.{domain} +short",
            ))
            return
        invalid = []
        weak = []
        for destination in [item.strip() for item in match.group(1).split(",") if item.strip()]:
            if destination.startswith("mailto:"):
                address = destination.removeprefix("mailto:")
                if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", address):
                    invalid.append(destination)
                    continue
                report_domain = address.split("@", 1)[1]
                ok_mx, mx = await self.query_dns(report_domain, "MX")
                ok_a, a = await self.query_dns(report_domain, "A")
                if (ok_mx and not mx) and (ok_a and not a):
                    weak.append(destination)
            elif destination.startswith("https://"):
                if len(destination) <= len("https://"):
                    invalid.append(destination)
            else:
                invalid.append(destination)
        if invalid:
            findings.append(AuditFinding(
                "Invalid TLS-RPT Destination",
                "MEDIUM",
                "Email",
                "One or more TLS-RPT rua destinations are malformed.",
                f"Invalid destinations: {invalid}",
                "Use valid mailto: or https: URIs in rua.",
                f"dig TXT _smtp._tls.{domain} +short",
            ))
        if weak:
            findings.append(AuditFinding(
                "Potentially Undeliverable TLS-RPT Destination",
                "LOW",
                "Email",
                "Some mailto TLS-RPT destinations may be undeliverable due to missing MX/A records.",
                f"Destinations: {weak}",
                "Ensure report destination domains have working MX or A records.",
                f"dig TXT _smtp._tls.{domain} +short",
            ))

    async def check_bimi(self, domain, records, findings):
        success, bimi_records = await self.query_dns(f"default._bimi.{domain}", "TXT")
        if not success:
            return
        bimi = next((rec for rec in bimi_records if "v=bimi1" in rec.lower()), None)
        if bimi:
            records["BIMI"] = bimi
            if "a=" not in bimi.lower():
                findings.append(AuditFinding(
                    "BIMI Without VMC",
                    "INFO",
                    "Email",
                    "BIMI record exists but no VMC certificate is specified.",
                    f"BIMI: {bimi}",
                    "Add a VMC certificate URL when using BIMI for verified brand display.",
                    f"dig TXT default._bimi.{domain}",
                ))

    async def check_caa(self, domain, records, findings):
        success, caa_records = await self.query_dns(domain, "CAA")
        if not success or not caa_records:
            findings.append(AuditFinding(
                "Missing CAA Records",
                "MEDIUM",
                "Certificate",
                "No CAA records are configured, so any CA may issue certificates for the domain.",
                f"DNS query for {domain} CAA returned empty",
                "Add CAA records restricting certificate issuance to approved CAs.",
                f"dig CAA {domain}",
            ))
            return
        records["CAA"] = caa_records
        if "iodef" not in " ".join(caa_records).lower():
            findings.append(AuditFinding(
                "CAA Missing Incident Reporting",
                "INFO",
                "Certificate",
                "CAA record has no iodef tag for incident reporting.",
                f"CAA: {caa_records}",
                "Add iodef to receive certificate issuance violation reports.",
                f"dig CAA {domain}",
            ))

    async def check_caa_policy_quality(self, domain, records, findings):
        caa_records = records.get("CAA", [])
        if not caa_records:
            return
        issue_values = []
        issuewild_values = []
        for rec in caa_records:
            rec_l = rec.lower()
            match = re.search(r'issuewild\s+"?([^";\s]+)', rec_l)
            if match:
                issuewild_values.append(match.group(1))
            match = re.search(r'issue\s+"?([^";\s]+)', rec_l)
            if match:
                issue_values.append(match.group(1))
        allowed = {value for value in issue_values + issuewild_values if value and value != ";"}
        if "*" in allowed:
            findings.append(AuditFinding(
                "CAA Wildcard Authorization Is Overly Broad",
                "HIGH",
                "Certificate",
                "CAA authorization includes wildcard issuer value.",
                f"CAA records: {caa_records}",
                "Replace wildcard CA authorization with a tight allow-list.",
                f"dig CAA {domain}",
            ))
        if len(allowed) > 3:
            findings.append(AuditFinding(
                "CAA Authorizes Many Certificate Authorities",
                "LOW",
                "Certificate",
                f"CAA authorizes {len(allowed)} different CAs.",
                f"Authorized issuers: {sorted(allowed)}",
                "Reduce authorized CAs to the minimal operational set.",
                f"dig CAA {domain}",
            ))
        if issue_values and not issuewild_values:
            findings.append(AuditFinding(
                "CAA Missing Explicit issuewild Policy",
                "INFO",
                "Certificate",
                "CAA has issue tags but no explicit issuewild policy.",
                f"CAA records: {caa_records}",
                "Add explicit issuewild policy or issuewild \";\" to deny wildcard issuance.",
                f"dig CAA {domain}",
            ))

    async def check_dane(self, domain, records, findings):
        for mx in records.get("MX", [])[:2]:
            mx_host = self.mx_host(mx)
            if not mx_host:
                continue
            success, tlsa_records = await self.query_dns(f"_25._tcp.{mx_host}", "TLSA")
            if success and tlsa_records:
                records["DANE"] = tlsa_records
                return

    async def check_mx_security(self, domain, records, findings):
        mx_records = records.get("MX", [])
        if not mx_records:
            return
        null_mx = any(mx.strip() == "0 ." for mx in mx_records)
        if null_mx and len(mx_records) == 1:
            findings.append(AuditFinding(
                "Null MX Record (RFC 7505)",
                "INFO",
                "Email",
                "Domain explicitly declares it does not accept email.",
                f"MX: {mx_records[0]}",
                "This is valid if the domain should not receive email.",
                f"dig MX {domain}",
            ))
            return
        if null_mx and len(mx_records) > 1:
            findings.append(AuditFinding(
                "Null MX Mixed With Other MX Records",
                "MEDIUM",
                "Email",
                "RFC 7505 null MX is present alongside other MX records.",
                f"MX records: {mx_records}",
                "Use either null MX alone or remove it when accepting mail.",
                f"dig MX {domain} +short",
            ))
        priorities = []
        for mx in mx_records:
            parts = mx.split()
            if parts and parts[0].isdigit():
                priorities.append(int(parts[0]))
            mx_host = self.mx_host(mx)
            if not mx_host:
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", mx_host):
                findings.append(AuditFinding(
                    "MX Points to IP Address",
                    "MEDIUM",
                    "Email",
                    "MX record points directly to an IP address instead of a hostname.",
                    f"MX: {mx}",
                    "Point MX records to hostnames, not IP addresses.",
                    f"dig MX {domain}",
                ))
                continue
            if mx_host in {"localhost", "localhost.localdomain"} or mx_host.endswith(".local"):
                findings.append(AuditFinding(
                    "MX Points to Localhost/Internal",
                    "HIGH",
                    "Email",
                    "MX record points to localhost or an internal-only domain.",
                    f"MX: {mx}",
                    "Use an externally resolvable mail server hostname, or a null MX record if the domain should not receive mail.",
                    f"dig MX {domain}",
                ))
            success_a, mx_a = await self.query_dns(mx_host, "A")
            success_aaaa, mx_aaaa = await self.query_dns(mx_host, "AAAA")
            if success_a and success_aaaa and not mx_a and not mx_aaaa:
                findings.append(AuditFinding(
                    "MX Does Not Resolve",
                    "HIGH",
                    "Email",
                    f"Mail server {mx_host} has no A or AAAA record and cannot receive email.",
                    f"MX: {mx}",
                    "Ensure the MX hostname resolves to valid public IP addresses.",
                    f"dig A {mx_host} && dig AAAA {mx_host}",
                ))
        if len(priorities) != len(set(priorities)) and len(priorities) > 1:
            findings.append(AuditFinding(
                "Duplicate MX Priorities",
                "INFO",
                "Email",
                "Multiple MX records share the same priority.",
                f"MX priorities: {priorities}",
                "Verify duplicate priorities are intentional for load-balancing.",
                f"dig MX {domain} +short",
            ))
        if len(mx_records) == 1:
            findings.append(AuditFinding(
                "No Backup MX Server",
                "INFO",
                "Email",
                "Only one MX record is configured.",
                f"MX: {mx_records[0]}",
                "Consider adding a backup MX with a higher priority number if inbound email continuity requires it.",
                f"dig MX {domain}",
            ))

    async def check_mx_starttls(self, domain, records, findings):
        mx_records = records.get("MX", [])
        if not mx_records:
            return
        summaries = []
        cert_errors = []
        starttls_supported = 0
        for mx in mx_records[:2]:
            mx_host = self.mx_host(mx)
            if not mx_host:
                continue
            try:
                summary = await asyncio.to_thread(self._sync_check_mx_starttls, mx_host)
            except Exception:
                continue
            if not summary:
                continue
            summaries.append(summary)
            if summary.get("starttls"):
                starttls_supported += 1
            elif summary.get("ehlo_lines") is not None:
                findings.append(AuditFinding(
                    "MX Server Without STARTTLS",
                    "HIGH",
                    "Email",
                    f"Mail server {mx_host} does not advertise STARTTLS.",
                    f"EHLO capabilities: {' | '.join(summary.get('ehlo_lines', [])[:8]) or 'no EHLO response'}",
                    "Enable STARTTLS on MX servers and pair it with MTA-STS and TLS-RPT monitoring.",
                    f"openssl s_client -starttls smtp -connect {mx_host}:25 -servername {mx_host}",
                ))
            if summary.get("starttls_error"):
                findings.append(AuditFinding(
                    "MX STARTTLS Negotiation Failure",
                    "MEDIUM",
                    "Email",
                    f"{mx_host} advertises STARTTLS but did not successfully switch to TLS.",
                    f"STARTTLS reply: {summary['starttls_error']}",
                    "Validate SMTP TLS configuration and certificate chain on this MX host.",
                    f"openssl s_client -starttls smtp -connect {mx_host}:25 -servername {mx_host}",
                ))
            if summary.get("cert_error"):
                cert_errors.append(f"{mx_host}: {summary['cert_error']}")
        if summaries:
            records["MX_STARTTLS"] = [{"mx": item["mx"], "starttls": item.get("starttls", False)} for item in summaries]
        if summaries and starttls_supported == 0:
            findings.append(AuditFinding(
                "No MX Server Supports STARTTLS",
                "HIGH",
                "Email",
                "None of the tested MX servers supported STARTTLS.",
                f"Tested MX hosts: {[item.get('mx') for item in summaries]}",
                "Enable STARTTLS across all MX endpoints and pair it with MTA-STS and TLS-RPT monitoring.",
                f"for mx in $(dig +short MX {domain} | awk '{{print $2}}'); do openssl s_client -starttls smtp -connect ${{mx%?}}:25 -servername ${{mx%?}} </dev/null; done",
            ))
        if cert_errors:
            findings.append(AuditFinding(
                "MX STARTTLS Certificate Issues",
                "MEDIUM",
                "Email",
                "One or more MX servers have TLS certificate validation issues during STARTTLS negotiation.",
                "; ".join(cert_errors[:4]),
                "Install valid public certificates with correct SANs, full chains, and current validity on all MX servers.",
                "openssl s_client -starttls smtp -connect <mx-host>:25 -servername <mx-host>",
            ))

    def _sync_check_mx_starttls(self, mx_host):
        try:
            with socket.create_connection((mx_host, 25), timeout=5) as sock:
                self._recv_smtp_reply(sock)
                sock.sendall(b"EHLO dns-audit.local\r\n")
                ehlo_lines = self._recv_smtp_reply(sock)
                supports_starttls = any("STARTTLS" in line.upper() for line in ehlo_lines)
                summary = {"mx": mx_host, "starttls": supports_starttls, "ehlo_lines": ehlo_lines}
                if not supports_starttls:
                    return summary
                sock.sendall(b"STARTTLS\r\n")
                starttls_lines = self._recv_smtp_reply(sock)
                if not any(line.startswith("220") for line in starttls_lines):
                    summary["starttls_error"] = " | ".join(starttls_lines[:5]) or "empty response"
                    return summary
                context = ssl.create_default_context()
                try:
                    with context.wrap_socket(sock, server_hostname=mx_host) as tls_sock:
                        if not tls_sock.getpeercert():
                            summary["cert_error"] = "empty certificate"
                except ssl.SSLError as e:
                    summary["cert_error"] = f"TLS certificate validation failed ({e})"
                return summary
        except (socket.timeout, socket.error, OSError):
            return None

    def _recv_smtp_reply(self, sock, timeout=5):
        sock.settimeout(timeout)
        chunks = b""
        while b"\n" not in chunks:
            part = sock.recv(4096)
            if not part:
                break
            chunks += part
            if len(chunks) > 32768:
                break
        lines = chunks.decode(errors="ignore").splitlines()
        if not lines:
            return []
        code = lines[0][:3] if len(lines[0]) >= 3 else ""
        if code.isdigit() and any(line.startswith(code + "-") for line in lines):
            while not any(line.startswith(code + " ") for line in lines):
                part = sock.recv(4096)
                if not part:
                    break
                lines.extend(part.decode(errors="ignore").splitlines())
                if len(lines) > 200:
                    break
        return lines

    async def check_ptr_records(self, domain, records, findings):
        for mx in records.get("MX", [])[:2]:
            mx_host = self.mx_host(mx)
            if not mx_host:
                continue
            success, ips = await self.query_dns(mx_host, "A")
            if not success or not ips:
                continue
            ip = ips[0]
            octets = ip.split(".")
            if len(octets) != 4:
                continue
            ptr_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
            success, ptr_records = await self.query_dns(ptr_name, "PTR")
            if success and not ptr_records:
                findings.append(AuditFinding(
                    "Missing PTR Record for Mail Server",
                    "LOW",
                    "Email",
                    f"Mail server {mx_host} has no reverse DNS.",
                    f"No PTR record for {ip}",
                    "Add PTR/rDNS for mail server IPs to improve deliverability.",
                    f"dig -x {ip}",
                ))
            elif success and ptr_records and ptr_records[0].rstrip(".").lower() != mx_host.lower():
                findings.append(AuditFinding(
                    "PTR/Forward DNS Mismatch",
                    "LOW",
                    "Email",
                    "Mail server PTR does not match MX hostname.",
                    f"PTR: {ptr_records[0]}, MX: {mx_host}",
                    "Align PTR and forward DNS where possible for mail deliverability.",
                    f"dig -x {ip} && dig A {mx_host}",
                ))
            return

    def mx_host(self, mx):
        parts = str(mx or "").split()
        if not parts:
            return None
        host = parts[-1].rstrip(".").lower()
        return host if host and host != "." else None

    async def check_wildcard_dns(self, domain, records, findings):
        detected = {}
        for _ in range(2):
            probe = f"audit-{uuid.uuid4().hex[:12]}.{domain}"
            for rdtype in ("A", "AAAA", "CNAME", "MX", "TXT"):
                success, answers = await self.query_dns(probe, rdtype, raise_on_nxdomain=True)
                if success and answers:
                    detected.setdefault(rdtype, []).append((probe, answers))
        if detected:
            evidence = []
            for rdtype, observations in detected.items():
                probe, answers = observations[0]
                evidence.append(f"{probe} {rdtype} -> {', '.join(answers[:5])}")
            findings.append(AuditFinding(
                "Wildcard DNS Record Detected",
                "INFO",
                "DNS",
                "Arbitrary subdomains appear to resolve instead of returning NXDOMAIN.",
                "; ".join(evidence),
                "Verify wildcard DNS is intentional and unknown subdomains are handled safely.",
                f"dig A random-test-subdomain.{domain}",
            ))

    async def check_ns_delegation_integrity(self, domain, records, findings):
        if not self.is_apex_domain(domain):
            return
        ns_records = records.get("NS", [])
        soa_serials = {}
        unresolved = []
        lame = []
        for ns in ns_records[:4]:
            success, ips = await self.query_dns(ns, "A")
            if not success or not ips:
                success, ips = await self.query_dns(ns, "AAAA")
            if not success or not ips:
                unresolved.append(ns)
                continue
            success, soa = await self.query_dns(domain, "SOA", nameserver=ips[0])
            if not success or not soa:
                lame.append(f"{ns} ({ips[0]})")
                continue
            parts = soa[0].split()
            if len(parts) >= 3 and parts[2].isdigit():
                soa_serials[ns] = parts[2]
        if unresolved:
            findings.append(AuditFinding(
                "Delegated Nameserver Hostname Does Not Resolve",
                "HIGH",
                "DNS",
                "One or more delegated NS hostnames do not resolve.",
                f"Unresolved NS: {unresolved}",
                "Ensure every delegated NS hostname has valid A/AAAA/glue records.",
                f"dig {domain} NS +short",
            ))
        if lame:
            findings.append(AuditFinding(
                "Potential Lame Delegation",
                "HIGH",
                "DNS",
                "Some delegated nameservers did not return authoritative SOA answers.",
                f"Non-authoritative/unresponsive NS: {lame}",
                "Fix parent delegation to only include authoritative nameservers.",
                f"for ns in $(dig +short {domain} NS); do dig @${{ns%?}} {domain} SOA +short; done",
            ))
        if len(set(soa_serials.values())) > 1:
            findings.append(AuditFinding(
                "Authoritative Nameservers Out of Sync",
                "MEDIUM",
                "DNS",
                "Authoritative nameservers return different SOA serials.",
                f"SOA serials per NS: {soa_serials}",
                "Synchronize zone replication across authoritative nameservers.",
                f"for ns in $(dig +short {domain} NS); do dig @${{ns%?}} {domain} SOA +short; done",
            ))

    async def check_https_svcb_records(self, domain, records, findings):
        https_found = []
        svcb_found = []
        for target in (domain, f"www.{domain}"):
            success, answers = await self.query_dns(target, "HTTPS")
            if success and answers:
                https_found.extend([f"{target}: {answer}" for answer in answers[:3]])
            success, answers = await self.query_dns(target, "SVCB")
            if success and answers:
                svcb_found.extend([f"{target}: {answer}" for answer in answers[:3]])
        if https_found:
            records["HTTPS"] = https_found
        if svcb_found:
            records["SVCB"] = svcb_found
        if (records.get("A") or records.get("AAAA")) and not https_found and not svcb_found:
            findings.append(AuditFinding(
                "No HTTPS/SVCB Service Binding Records",
                "INFO",
                "DNS",
                "Domain has web-address records but does not publish HTTPS/SVCB records.",
                f"Checked: {domain}, www.{domain}",
                "Consider HTTPS/SVCB records if your DNS provider and stack support them.",
                f"dig {domain} HTTPS +short && dig {domain} SVCB +short",
            ))

    async def check_dns_edns_resilience(self, domain, records, findings):
        if not self.is_apex_domain(domain):
            return
        try:
            q = dns.message.make_query(domain, dns.rdatatype.DNSKEY, use_edns=True, payload=1232, want_dnssec=True)
            udp_resp = await asyncio.to_thread(dns.query.udp, q, "8.8.8.8", timeout=self.dns_timeout)
        except Exception:
            return
        if not (udp_resp.flags & dns.flags.TC):
            return
        try:
            tcp_resp = await asyncio.to_thread(dns.query.tcp, q, "8.8.8.8", timeout=self.dns_timeout)
            if not (tcp_resp.answer or tcp_resp.authority):
                raise dns.exception.DNSException("empty TCP response")
        except Exception as e:
            findings.append(AuditFinding(
                "DNS TCP Fallback Failed After Truncation",
                "HIGH",
                "DNS",
                "UDP DNS response was truncated and TCP fallback failed.",
                f"Domain={domain}, error={type(e).__name__}: {str(e)}",
                "Allow and validate TCP/53 on authoritative DNS infrastructure.",
                f"dig {domain} DNSKEY +dnssec +bufsize=1232 && dig {domain} DNSKEY +dnssec +tcp",
            ))

    async def check_dns_low_ttl_hints(self, domain, records, findings):
        low = []
        very_low = []
        for rdtype in ("A", "AAAA", "MX", "NS"):
            success, entries = await self.query_dns_with_ttl(domain, rdtype)
            if not success or not entries:
                continue
            ttls = sorted({ttl for _, ttl in entries if ttl > 0})
            if not ttls:
                continue
            min_ttl = ttls[0]
            records[f"{rdtype}_TTL"] = min_ttl
            if min_ttl <= 60:
                very_low.append(f"{rdtype}:{min_ttl}")
            elif min_ttl < 300:
                low.append(f"{rdtype}:{min_ttl}")
        if very_low or low:
            findings.append(AuditFinding(
                "Very Low DNS TTL on Critical Records" if very_low else "Low DNS TTL on Critical Records",
                "MEDIUM" if very_low else "LOW",
                "DNS",
                "Critical DNS records use low TTL values.",
                f"TTLs: {very_low or low}",
                "Review whether low TTLs are required; raise TTLs for stable records.",
                f"dig {domain} A +ttlid && dig {domain} MX +ttlid && dig {domain} NS +ttlid",
            ))

    async def check_soa_values(self, domain, records, findings):
        if not self.is_apex_domain(domain):
            return
        soa = records.get("SOA")
        if not soa:
            return
        parts = soa.split()
        if len(parts) < 7:
            return
        try:
            serial, refresh, _retry, expire = int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5])
        except ValueError:
            return
        if refresh < 300:
            findings.append(AuditFinding(
                "SOA Refresh Too Short",
                "INFO",
                "DNS",
                f"SOA refresh interval is very short ({refresh}s).",
                f"SOA: {soa}",
                "Review SOA refresh to avoid excessive secondary polling.",
                f"dig SOA {domain} +short",
            ))
        if expire < 604800:
            findings.append(AuditFinding(
                "SOA Expire Too Short",
                "LOW",
                "DNS",
                f"SOA expire ({expire}s) is less than one week.",
                f"SOA: {soa}",
                "Use an expire value that tolerates primary DNS outages.",
                f"dig SOA {domain} +short",
            ))
        serial_text = str(serial)
        if len(serial_text) == 10 and not serial_text.startswith(("19", "20")):
            findings.append(AuditFinding(
                "Non-Standard SOA Serial Format",
                "INFO",
                "DNS",
                "SOA serial does not look date-based.",
                f"Serial: {serial}",
                "Consider date-based serials for easier operational tracking.",
                f"dig SOA {domain} +short",
            ))

    async def check_cname_at_apex(self, domain, records, findings):
        if not self.is_apex_domain(domain):
            return
        success, cnames = await self.query_dns(domain, "CNAME")
        if success and cnames:
            findings.append(AuditFinding(
                "CNAME at Zone Apex",
                "HIGH",
                "DNS",
                "CNAME exists at the zone apex, which cannot coexist with SOA/NS/MX records.",
                f"CNAME: {cnames[0]}",
                "Use ALIAS/ANAME flattening or A/AAAA records instead of apex CNAME.",
                f"dig CNAME {domain}",
            ))

    async def check_deprecated_record_types(self, domain, records, findings):
        for rdtype, title in (("HINFO", "HINFO Record Present"), ("WKS", "WKS Record Present (Deprecated)")):
            success, answers = await self.query_dns(domain, rdtype)
            if success and answers:
                findings.append(AuditFinding(
                    title,
                    "INFO",
                    "DNS",
                    f"{rdtype} record is present and may disclose unnecessary information or rely on deprecated DNS behavior.",
                    f"{rdtype}: {answers[0]}",
                    f"Remove {rdtype} unless it is intentionally required.",
                    f"dig {rdtype} {domain}",
                ))

    async def check_dns_version(self, domain, records, findings):
        for ns in records.get("NS", [])[:2]:
            success, ns_ips = await self.query_dns(ns, "A")
            if not success or not ns_ips:
                continue
            try:
                answers = await asyncio.to_thread(self._sync_version_bind, ns_ips[0])
            except Exception:
                continue
            if answers:
                version = str(answers[0]).strip('"')
                findings.append(AuditFinding(
                    "DNS Version Disclosure",
                    "INFO",
                    "DNS",
                    f"Nameserver {ns} discloses software version through CHAOS TXT.",
                    f"version.bind: {version}",
                    "Hide DNS version information where supported.",
                    f"dig @{ns} version.bind chaos txt",
                ))
                return

    def _sync_version_bind(self, nameserver):
        resolver = self.get_resolver(nameserver)
        return list(resolver.resolve("version.bind", "TXT", rdclass=dns.rdataclass.CH))

    async def check_open_resolver(self, domain, records, findings):
        for ns in records.get("NS", [])[:2]:
            success, ns_ips = await self.query_dns(ns, "A")
            if not success or not ns_ips:
                continue
            success, response = await self.query_dns_full("google.com", "A", nameserver=ns_ips[0])
            if success and response and (response.flags & dns.flags.RA):
                findings.append(AuditFinding(
                    "Open DNS Resolver",
                    "MEDIUM",
                    "DNS",
                    f"Nameserver {ns} appears to allow recursion.",
                    "RA flag observed when querying external domain",
                    "Disable public recursion on authoritative nameservers.",
                    f"dig @{ns_ips[0]} google.com +recurse",
                ))
                return
