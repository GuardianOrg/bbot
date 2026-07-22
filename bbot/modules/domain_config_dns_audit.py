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
from bbot.core.event.base import _normalize_event_description


@dataclass
class AuditFinding:
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    command: str = ""

    def __post_init__(self):
        self.description = self._normalize_description(self.description)

    @staticmethod
    def _normalize_description(description: str) -> str:
        return _normalize_event_description(description)


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
            "key1",
            "key2",
            "key3",
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
        "managed_authoritative_ns_suffixes": [
            "cloudflare.com",
            "awsdns-",
            "googledomains.com",
            "domaincontrol.com",
            "dnsimple.com",
            "dns-parking.com",
        ],
        "managed_mx_suffixes": [
            "aspmx.l.google.com",
            "googlemail.com",
            "smtp.google.com",
            "protection.outlook.com",
            "migadu.com",
            "protonmail.ch",
            "protonmail.com",
            "mailgun.org",
            "sendgrid.net",
            "amazonses.com",
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
        "managed_authoritative_ns_suffixes": "Authoritative DNS provider suffixes where provider-owned operational INFO checks are suppressed.",
        "managed_mx_suffixes": "Hosted mail provider suffixes where provider-owned MX redundancy/PTR findings are suppressed.",
    }

    _batch_size = 150
    in_scope_only = True
    per_domain_only = False

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
        self.managed_authoritative_ns_suffixes = [
            suffix.lower() for suffix in self._coerce_string_list(self.config.get("managed_authoritative_ns_suffixes", []))
        ]
        self.managed_mx_suffixes = [
            suffix.lower() for suffix in self._coerce_string_list(self.config.get("managed_mx_suffixes", []))
        ]
        self.dns_cache = {}
        self.dns_ttl_cache = {}
        self.dns_full_cache = {}
        self.audited_domains = set()
        self.wildcard_checked_hosts = set()
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
        if not self.helpers.is_dns_name(host):
            return False, "host is not a DNS name"
        return True

    async def handle_batch(self, *events):
        parent_by_domain = {}
        target_hosts = {}
        for event in events:
            host = str(event.host or "").strip().rstrip(".").lower()
            if not host or not self.helpers.is_dns_name(host):
                continue
            _, registered_domain = self.helpers.split_domain(host)
            audit_domain = (registered_domain or host).lower().rstrip(".")
            parent_by_domain.setdefault(audit_domain, event)
            if "target" in event.tags and "wildcard-child" not in event.tags:
                target_hosts.setdefault(host, event)

        for domain, parent_event in parent_by_domain.items():
            if domain in self.audited_domains:
                continue
            self.audited_domains.add(domain)
            await self.audit_domain(parent_event, domain)

        for host, parent_event in target_hosts.items():
            if host in self.wildcard_checked_hosts or host in self.audited_domains:
                continue
            self.wildcard_checked_hosts.add(host)
            await self.emit_wildcard_dns_config(parent_event, host)

    async def audit_domain(self, parent_event, domain):
        records = await self.collect_basic_dns(domain)
        findings = []
        dns_config = {
            "host": domain,
            "zone_transfer_possible": False,
            "zone_transfer_nameservers": records.get("NS", []),
            "is_wildcard": False,
            "wildcard_ips": [],
            "wildcard_records": {},
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
            dns_config["wildcard_records"] = wildcard_status["wildcard_records"]
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

    async def emit_wildcard_dns_config(self, parent_event, domain):
        try:
            wildcard_status = await self.check_wildcard(domain)
        except Exception:
            self.verbose(f"check_wildcard failed for {domain}", trace=True)
            return

        await self.emit_event(
            {
                "host": domain,
                "is_wildcard": wildcard_status["is_wildcard"],
                "wildcard_ips": wildcard_status["wildcard_ips"],
                "wildcard_records": wildcard_status["wildcard_records"],
            },
            "DOMAIN_DNS_CONFIG",
            parent_event,
            context=f'{{module}} checked wildcard DNS configuration for "{domain}"',
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
                (
                    "Domain has no IPv4 address (A record) configured."
                    ' An A record is the DNS entry that maps a name to an IPv4 address. If this domain is'
                    ' expected to host a website, API, VPN endpoint, mail-related hostname, or any other internet-facing service'
                    ' over IPv4, clients will not know which IPv4 server to contact. Some domains intentionally have no A record'
                    ' because they only use subdomains, redirects, IPv6, or email-only records, so this is informational rather than'
                    ' automatically dangerous. The value should still be confirmed because an accidental missing A record can cause'
                    ' downtime, failed monitoring checks, broken links, and confusion during incident response.'
                ),
                f"DNS query for {domain} A returned empty",
                "Add an A record if the domain should be directly reachable over IPv4.",
                f"dig {domain} A +short",
            ))
        if a_records and not aaaa_records:
            findings.append(AuditFinding(
                "No IPv6 (AAAA) Record",
                "INFO",
                "DNS",
                (
                    f"{domain} resolves over IPv4 but has no AAAA record. IPv6-only clients and networks will not be able to reach this host directly, which can reduce availability and user reachability as IPv6 adoption increases."
                    ' An AAAA record is the DNS entry that maps a name to an IPv6 address. IPv6 is'
                    ' increasingly common on mobile networks, cloud environments, corporate networks, and regions where IPv4'
                    ' addresses are scarce. When a service only has IPv4 records, IPv6-only users must rely on translation gateways'
                    ' or may not reach the service at all. This is usually an availability and future-readiness issue rather than an'
                    ' immediate security flaw. It should be reviewed when the application, CDN, load balancer, or hosting provider'
                    ' already supports IPv6, because adding the record can improve reachability without changing the application'
                    ' itself.'
                ),
                f"DNS query for {domain} AAAA returned empty",
                "Add an AAAA record if the service supports IPv6.",
                f"dig {domain} AAAA +short",
            ))
        if len(ns_records) < 2:
            findings.append(AuditFinding(
                "Insufficient Nameservers",
                "MEDIUM",
                "DNS",
                (
                    "The domain has fewer than two authoritative nameservers. A single nameserver creates a DNS availability risk because maintenance, provider failure, routing issues, or DDoS against that server can make the domain unreachable."
                    ' Authoritative nameservers are the systems that answer DNS questions for the domain.'
                    ' Having fewer than two means there is little redundancy at the DNS layer. If the only nameserver is down,'
                    ' unreachable, misconfigured, rate limited, or under attack, users may be unable to resolve the domain even if'
                    ' the website, mail server, or application is healthy. Good DNS design normally uses multiple authoritative'
                    ' nameservers, preferably operated on separate networks or providers. This reduces the chance that one provider'
                    ' incident or routing problem takes the whole domain offline.'
                ),
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
                (
                    "All checked nameservers resolve inside the same IPv4 /16. This concentrates authoritative DNS in one network area, so a provider or routing incident can affect every nameserver at once."
                    ' Multiple nameservers only improve resilience when they are not all dependent on the'
                    ' same network path or infrastructure. If every authoritative nameserver resolves into the same broad IPv4'
                    ' network, a provider outage, routing leak, firewall mistake, or denial-of-service event affecting that network'
                    ' can impact all of them together. The domain may look redundant on paper but still fail like a single-provider'
                    ' deployment. This is usually an availability risk rather than a direct compromise risk, and it should be fixed'
                    ' by using nameservers distributed across independent networks, regions, or DNS providers where operationally'
                    ' possible.'
                ),
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
            (
                f"{domain} allows DNS zone transfers over AXFR. Anyone who can query the exposed nameserver can download the zone contents and quickly map hostnames, mail systems, staging assets, and other infrastructure that may not be meant for easy discovery."
                ' A DNS zone transfer is a mechanism used by DNS servers to copy an entire zone from a'
                ' primary server to authorized secondary servers. It should not normally be available to the public. When public'
                ' zone transfer is enabled, anyone can download a full list of DNS records and quickly learn about internal'
                ' naming patterns, staging systems, mail infrastructure, forgotten hosts, and other targets that may not be'
                ' obvious from normal browsing. This does not directly grant access to those systems, but it gives attackers a'
                ' high-quality map of the environment and can make phishing, takeover research, and targeted vulnerability'
                ' hunting much easier.'
            ),
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
        wildcard_domains = await self.helpers.is_wildcard_domain(domain, rdtypes=("A", "AAAA", "CNAME"))
        wildcard_records = wildcard_domains.get(domain, {})
        wildcard_ips = set()
        normalized_records = {}
        for rdtype, (wildcard_results, wildcard_results_raw) in wildcard_records.items():
            normalized_values = set()
            for value in set(wildcard_results).union(wildcard_results_raw):
                if self.helpers.is_ip(value):
                    wildcard_ips.add(value)
                if rdtype == "CNAME":
                    normalized_value = str(value).strip().rstrip(".").lower()
                    if normalized_value:
                        normalized_values.add(normalized_value)
                elif rdtype in ("A", "AAAA") and self.helpers.is_ip(value):
                    normalized_values.add(value)
            if normalized_values:
                normalized_records[rdtype] = sorted(normalized_values)
        return {
            "is_wildcard": bool(wildcard_records),
            "wildcard_ips": sorted(wildcard_ips),
            "wildcard_records": normalized_records,
        }

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
                (
                    "Domain does not publish DNSKEY records, so DNSSEC is not enabled."
                    ' DNSSEC is a DNS security extension that lets resolvers verify that DNS answers were'
                    ' signed by the legitimate zone owner and were not modified in transit. Without DNSSEC, users still receive DNS'
                    ' answers, but those answers are protected mainly by resolver behavior, network trust, and provider controls'
                    ' rather than cryptographic validation. This can matter if an attacker can tamper with DNS traffic, compromise'
                    ' an upstream resolver, or exploit cache-poisoning weaknesses. Not every organization enables DNSSEC, and it'
                    ' must be operated carefully, but the absence means the domain does not provide this extra protection against'
                    ' forged DNS answers.'
                ),
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
                    (
                        f"DNSSEC uses weak or deprecated algorithm {name}."
                        ' DNSSEC relies on cryptographic algorithms to sign DNS data. If the zone uses an'
                        ' algorithm that is deprecated, weak, or no longer recommended, the signatures may provide less protection than'
                        ' expected over time. This does not always mean the domain is immediately exploitable, but it reduces confidence'
                        ' in the long-term integrity of DNS answers and can create compatibility or audit issues. DNSSEC should use'
                        ' modern algorithms supported by the DNS provider, registrar, and validating resolvers. A planned rollover is'
                        ' needed because changing DNSSEC keys or algorithms incorrectly can break validation and make the domain appear'
                        ' unreachable to security-aware resolvers.'
                    ),
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
                    (
                        "The parent zone publishes only a SHA-1 DS digest for this DNSSEC delegation. SHA-1 is deprecated, and relying on it weakens the integrity guarantees DNSSEC is meant to provide."
                        ' A DS record sits at the parent zone, such as the TLD, and points resolvers to the'
                        ' DNSSEC key used by this domain. If the only DS digest uses SHA-1, the delegation depends on a hash algorithm'
                        ' that is widely considered obsolete. This weakens the assurance that the parent and child DNSSEC data are tied'
                        ' together safely. It is not the same as a missing DS record, but it is below modern expectations. Publishing a'
                        ' SHA-256 DS record gives validating resolvers a stronger path to verify the domain and reduces the chance that'
                        ' future resolver policy changes treat the delegation as weak or unacceptable.'
                    ),
                    f"DS: {ds_records[0]}",
                    "Publish a SHA-256 DS record at the parent zone.",
                    f"dig {domain} DS +short",
                ))
        else:
            findings.append(AuditFinding(
                "Missing DS Record at Parent",
                "HIGH",
                "DNSSEC",
                (
                    "The zone publishes DNSSEC keys but the parent zone has no matching DS record. Resolvers cannot build a chain of trust, so clients receive little to no DNSSEC protection despite the zone being signed."
                    ' DNSSEC only works end to end when the parent zone publishes a DS record that points'
                    " to the child zone's DNSSEC key. The DNSKEY records in the child zone show that the zone is signed, but without"
                    ' the matching parent DS record, validating resolvers cannot build a trusted chain from the root down to this'
                    ' domain. In plain terms, the domain may look partially configured for DNSSEC but does not receive the full'
                    ' protection. This can create a false sense of security and may also indicate an unfinished or failed DNSSEC'
                    ' rollout. The DS record should be published through the registrar before relying on DNSSEC validation.'
                ),
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
                    (
                        f"The .{tld} TLD has no DS record in the root zone. DNSSEC validation cannot establish a chain of trust for this domain, so DNS spoofing protection cannot work end to end."
                        ' DNSSEC validation depends on a chain of trust from the DNS root, through the'
                        ' top-level domain, and then to the specific domain. If the top-level domain does not publish the needed DS'
                        ' information in the root zone, that chain cannot be completed for domains under it. The domain owner may still'
                        ' publish DNSSEC-looking records, but validating resolvers cannot fully prove the answers came from the rightful'
                        " source. This is usually outside the domain owner's direct control. The practical impact is that DNS spoofing"
                        ' protection cannot work end to end until the TLD itself supports DNSSEC delegation.'
                    ),
                    f"Query for {tld}. DS at root returned no DS",
                    "DNSSEC is ineffective for this TLD; monitor for TLD DNSSEC enablement.",
                    f"dig @198.41.0.4 {tld}. DS +short",
                ))
        except Exception:
            pass
        await self.check_rrsig_expiration(domain, records, findings)
        await self.check_nsec_records(domain, findings)
        await self.check_dnssec_validation(domain, records, findings)

    async def check_rrsig_expiration(self, domain, records, findings):
        success, response = await self.query_dns_full(domain, "SOA")
        if not success or not response:
            return
        suppress_managed_warning = self.has_managed_authoritative_ns(records)
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
                        (
                            "The DNSSEC signatures for this zone have expired. Validating resolvers may reject answers for the domain, causing outages for users and services that rely on DNSSEC validation."
                            ' DNSSEC signatures are time-limited proofs attached to DNS records. They must be'
                            ' refreshed before they expire, much like certificates need renewal before their expiration date. If signatures'
                            ' are already expired, validating resolvers may reject otherwise correct DNS answers because they can no longer'
                            ' prove the data is current and trusted. Users behind validating resolvers can see lookup failures, application'
                            ' outages, mail delivery issues, or intermittent behavior depending on resolver policy. This is a high-priority'
                            ' operational problem because the fix is usually to re-sign the zone or repair the automated signing process'
                            ' immediately.'
                        ),
                        f"RRSIG expiry: {exp_date.isoformat()}",
                        "Re-sign the zone immediately.",
                        f"dig {domain} SOA +dnssec | grep RRSIG",
                    ))
                elif days_left < 14 and not suppress_managed_warning:
                    findings.append(AuditFinding(
                        "RRSIG Expiration Approaching",
                        "MEDIUM" if days_left >= 7 else "HIGH",
                        "DNSSEC",
                (
                    f"DNSSEC signatures expire in {days_left} days. If automated resigning fails or is not monitored, validating resolvers may soon start rejecting DNS answers for this zone."
                    ' DNSSEC signatures have expiration times so old DNS data cannot be replayed forever.'
                    ' If signatures are close to expiring, the domain is approaching a point where validating resolvers may stop'
                    ' trusting the answers. This often means automated signing, key management, or publication monitoring needs'
                    ' attention. The domain may still work right now, but the safety margin is shrinking. Teams should confirm that'
                    ' the DNS provider is refreshing signatures on schedule and that monitoring will alert before expiration. Treat'
                            ' this like an expiring production certificate: it may not be broken yet, but waiting too long can cause visible'
                            ' outages.'
                        ),
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
                (
                    "The zone uses NSEC denial-of-existence records. NSEC can allow zone walking, letting an attacker enumerate valid hostnames and use that list for reconnaissance and targeted attacks."
                    ' NSEC records are used by DNSSEC to prove that a requested name does not exist. A'
                    ' side effect is that they can reveal the next valid name in the zone, allowing someone to walk through the zone'
                    ' and enumerate many real hostnames. This does not give direct access to systems, but it can expose staging'
                    ' hosts, admin names, forgotten services, naming conventions, and other reconnaissance value. Some zones accept'
                    ' this tradeoff because NSEC is simple and standards-compliant. If hostname privacy matters, NSEC3 or other'
                    ' operational controls should be considered, while remembering that DNS should not be the only place sensitive'
                    ' systems are hidden.'
                ),
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
                        (
                            "NSEC3 is enabled with zero iterations. This lowers the cost of reversing hashed names and weakens the protection NSEC3 is intended to provide against zone enumeration."
                            ' NSEC3 is designed to make DNSSEC denial-of-existence records less directly'
                            ' enumerable by using hashed names instead of plain names. When it is configured with zero iterations, reversing'
                            ' or guessing those hashed names becomes cheaper for attackers, especially if hostnames follow predictable'
                            ' patterns such as admin, vpn, dev, or staging. This is usually a reconnaissance issue rather than an immediate'
                            ' compromise. It means the protection expected from NSEC3 is weaker than intended. The setting should be'
                            ' reviewed with the DNS provider, balancing privacy benefits against resolver performance and current DNSSEC'
                            ' guidance.'
                        ),
                        f"NSEC3PARAM: {nsec3param[0]}",
                        "Use a modest NSEC3 iteration count if zone-walking resistance is required.",
                        f"dig {domain} NSEC3PARAM +short",
                    ))
                elif iterations > 150:
                    findings.append(AuditFinding(
                        "Excessive NSEC3 Iterations",
                        "MEDIUM",
                        "DNSSEC",
                        (
                            f"NSEC3 uses {iterations} iterations. Excessive iteration counts can increase CPU load for authoritative servers and validating resolvers, creating unnecessary availability risk."
                            ' NSEC3 iterations make each proof more computationally expensive. A modest value can'
                            ' slow down zone enumeration, but a very high value can also increase work for authoritative DNS servers and'
                            ' validating resolvers. That extra CPU cost may become visible during traffic spikes, attacks, or normal'
                            ' high-volume resolution, turning a privacy feature into an availability risk. Modern guidance often favors'
                            ' conservative NSEC3 settings because high iteration counts provide limited real-world protection against'
                            ' determined enumeration. The configuration should be reduced to a safe range that preserves compatibility and'
                            ' keeps DNS responses fast and reliable.'
                        ),
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
                (
                    "The zone appears signed, but a validating resolver did not mark the answer as authenticated. This usually means the DNSSEC chain, signatures, or key material is inconsistent and clients may not receive trusted answers."
                    ' The zone appears to have DNSSEC data, but a validating resolver did not mark the'
                    ' answer as authenticated. For a non-specialist, this means the resolver could not prove that the DNS answer was'
                    ' correctly signed and linked to the parent DNS chain. Common causes include mismatched DS and DNSKEY records,'
                    ' expired signatures, missing records, algorithm problems, or an incomplete key rollover. The domain may still'
                    ' resolve for users whose resolvers do not validate DNSSEC, which can hide the issue. Users behind validating'
                    ' resolvers may see failures or distrust the answers, so the DNSSEC chain should be checked end to end.'
                ),
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
                (
                    "The child zone publishes CDS rollover records without matching CDNSKEY records. Automated parent DS updates may fail or apply incomplete key information during DNSSEC rollover."
                    ' CDS and CDNSKEY records are signals a child zone can publish to help the parent zone'
                    ' update DNSSEC delegation information during key rollover. Publishing one without the other can confuse or'
                    ' block automated parent updates, depending on registrar and registry behavior. For someone unfamiliar with'
                    ' DNSSEC, this is like sending only part of the paperwork needed to rotate a signing key. The current domain may'
                    ' still work, but the next rollover could fail or leave old and new keys out of sync. That can eventually break'
                    ' validation and make the domain fail for resolvers that enforce DNSSEC.'
                ),
                f"CDS: {cds_records}",
                "Publish both CDS and CDNSKEY consistently during rollover.",
                f"dig {domain} CDS +short && dig {domain} CDNSKEY +short",
            ))
        if success_cdnskey and cdnskey_records and not (success_cds and cds_records):
            findings.append(AuditFinding(
                "DNSSEC Rollover Signal Incomplete (CDNSKEY without CDS)",
                "LOW",
                "DNSSEC",
                (
                    "The child zone publishes CDNSKEY records without CDS records. Registrars or parent zones that expect both signals may not update DS records reliably during DNSSEC rollover."
                    ' CDNSKEY records can help automate DNSSEC key changes by advertising key material'
                    ' from the child zone to the parent. If CDNSKEY exists without corresponding CDS records, some parent or'
                    ' registrar workflows may not have enough information to safely update the DS record. The result can be a'
                    ' stalled or partially completed rollover. This is usually an operational hygiene issue today, but it becomes'
                    ' important when keys are replaced, compromised, or retired. The safest approach is to publish rollover signals'
                    ' consistently and verify that the registrar supports the exact automation process being used.'
                ),
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
                (
                    "The child zone's CDS key tags do not match the DS key tags currently published at the parent. This indicates a DNSSEC rollover or delegation mismatch that can break validation if old keys are retired."
                    ' DNSSEC depends on the parent zone and child zone agreeing about which key should be'
                    ' trusted. A key tag mismatch means the child is advertising rollover information that does not line up with the'
                    ' DS records currently published by the parent. In plain language, the parent may be pointing resolvers to one'
                    ' key while the child is preparing or using another. If old keys are removed before the parent is updated,'
                    " validating resolvers may reject the domain's DNS answers. This should be treated carefully because DNSSEC"
                    ' rollover mistakes can cause real outages even when the underlying web and mail services are healthy.'
                ),
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
                (
                    "A validating resolver returned NXDOMAIN for a signed zone without authentication data. Negative answers may not be cryptographically validated, weakening protection against spoofed nonexistent-domain responses."
                    ' A negative DNS answer means the resolver is saying a requested name does not exist.'
                    ' With DNSSEC, even that negative answer should be provable so attackers cannot easily forge nonexistent-domain'
                    ' responses. If a validating resolver returns NXDOMAIN without authentication data, it may be unable to prove'
                    " the denial came from the legitimate zone. This weakens one of DNSSEC's protections and can indicate a signer,"
                    ' delegation, or resolver compatibility problem. The impact is subtle but important: forged negative answers can'
                    ' disrupt access, hide real records, or interfere with services that depend on DNS lookups.'
                ),
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
                (
                    "An NXDOMAIN response did not include visible NSEC or NSEC3 proof records in the authority section. This may indicate incomplete denial-of-existence handling or signer behavior that should be verified."
                    ' When DNSSEC is working correctly, a response for a nonexistent name normally'
                    ' includes NSEC or NSEC3 proof showing why the name does not exist. If that proof is missing from the authority'
                    ' section, the negative response may not be fully verifiable by clients or diagnostic tools. This may be caused'
                    ' by signer behavior, resolver behavior, or incomplete DNSSEC configuration. It is not always a confirmed'
                    ' outage, but it should be checked because denial-of-existence is part of what prevents attackers from forging'
                    ' negative DNS answers. Broken proof can reduce trust in the zone and create hard-to-debug resolution failures.'
                ),
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
                (
                    f"The zone publishes DNSKEY records using multiple DNSSEC algorithms: {sorted(algorithms)}. This can be normal during rollover, but it should be intentional and monitored to avoid validation failures."
                    ' A zone can publish DNSSEC keys using more than one algorithm during a planned'
                    ' migration, but it should not happen accidentally. Multiple algorithms increase the number of moving parts that'
                    ' must remain synchronized between DNSKEY, DS records, signatures, and resolver support. If the configuration is'
                    ' not carefully managed, one group of resolvers may validate successfully while another fails. This finding is'
                    ' informational because it can be normal during a rollover. The important point is to confirm there is an'
                    ' intentional migration plan, clear monitoring, and a safe point where obsolete algorithms will be removed.'
                ),
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
                (
                    "The domain accepts email but does not publish SPF, the DNS rule that lists which servers may send mail for the domain. Without SPF, receivers have less evidence that a message using the domain is legitimate."
                    ' SPF is one of the basic anti-spoofing controls for email. If it is missing, receiving mail systems have less'
                    ' information to decide whether a message claiming to come from the domain is legitimate. Attackers can more'
                    " easily send spoofed messages that appear to use the organization's domain, especially when other controls such"
                    ' as DKIM and DMARC are also missing or weak. SPF alone does not stop all phishing, but it is a basic control that supports DMARC enforcement and improves'
                    ' receiver confidence. The record should include every legitimate outbound mail service and end with an'
                    ' appropriate enforcement policy.'
                ),
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
                (
                    "The domain publishes multiple SPF records. SPF permits only one record, so receivers can return PermError and skip SPF evaluation, weakening spoofing protection."
                    ' SPF requires exactly one TXT record beginning with v=spf1 for a domain. If multiple'
                    ' SPF records exist, many receivers treat the result as a permanent error and may skip SPF evaluation entirely.'
                    ' This can accidentally remove a major anti-spoofing control even though each individual record looks'
                    ' reasonable. The issue often appears after adding a new mail provider without merging it into the existing SPF'
                    " policy. The fix is to combine all legitimate senders into one record while staying under SPF's DNS lookup"
                    ' limit. Until fixed, spoofed messages may be harder for receivers to identify and DMARC alignment may fail'
                    ' unpredictably.'
                ),
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
                (
                    f"The SPF record ends with a weak terminal policy ({spf.split()[-1]}). Mail that fails SPF may still be accepted or treated ambiguously, which reduces protection against forged sender domains."
                    ' SPF terminal policies decide what receivers should do when a sending server is not'
                    ' authorized. A strong -all policy says unauthorized senders should fail, while ~all, ?all, or +all are weaker'
                    ' and may let forged mail pass or be treated ambiguously. Weak endings are sometimes used during rollout, but'
                    ' leaving them in place long term reduces anti-spoofing value and can undermine DMARC. The domain owner should'
                    ' first confirm that all legitimate mail providers are included in SPF, then move toward -all so receivers have'
                    ' a clear signal to reject unauthorized senders.'
                ),
                f"SPF: {spf}",
                "Use -all after confirming legitimate senders are included.",
                f"dig {domain} TXT +short | grep spf",
            ))
        if "ptr" in lowered:
            findings.append(AuditFinding(
                "SPF Uses Deprecated PTR Mechanism",
                "LOW",
                "Email",
                (
                    "The SPF record uses the deprecated ptr mechanism. PTR checks are slow, unreliable, and discouraged because they can increase DNS lookup cost and produce inconsistent authorization decisions."
                    ' The SPF ptr mechanism asks receivers to perform reverse DNS checks as part of'
                    ' deciding whether a sender is authorized. This mechanism is deprecated because it is slow, unreliable, and can'
                    ' require extra DNS lookups that make SPF evaluation fragile. Different receivers may handle the lookup chain'
                    ' differently, so authorization decisions can become inconsistent. It can also push a record closer to SPF\'s'
                    ' strict DNS lookup limit, causing permanent errors. The safer approach is to explicitly list trusted sending'
                    ' sources with ip4, ip6, a, mx, include, or redirect mechanisms maintained by the mail providers that actually'
                    ' send messages for the domain.'
                ),
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
                (
                    f"The SPF record uses {len(lookups)} DNS lookup mechanisms, exceeding the SPF limit of 10. Receivers may return PermError and ignore SPF, allowing spoofed messages to bypass this control."
                    ' SPF has a hard limit of 10 DNS lookups during evaluation. Includes, redirects, mx,'
                    ' a, ptr, exists, and similar mechanisms can all count toward that limit. When the limit is exceeded, receivers'
                    ' may return a permanent error and stop using SPF for the message. That means a record intended to prevent'
                    ' spoofing may fail open or become unreliable, especially after a mail provider changes its own SPF includes.'
                    ' This is common in organizations that use many email platforms. The record should be simplified, flattened'
                    ' carefully, or split by subdomain so legitimate senders remain authorized without breaking the lookup limit.'
                ),
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
                (
                    f"The SPF include/redirect chain uses approximately {total}+ DNS lookups. It is close to the SPF limit of 10, so one provider-side include change can break SPF validation unexpectedly."
                    ' This SPF policy is close to the 10-lookup limit even if it has not clearly exceeded'
                    ' it yet. That is risky because the domain owner may not control every included provider record. A provider can'
                    ' add one include or redirect later and suddenly push the domain over the limit, causing SPF to fail with a'
                    ' permanent error. The result can be weaker spoofing protection, failed DMARC alignment, or legitimate mail'
                    ' being treated suspiciously. This should be handled proactively by reducing unnecessary includes, using'
                    ' provider-specific subdomains where appropriate, or carefully flattening stable IP ranges while keeping the'
                    ' policy maintainable.'
                ),
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
                    (
                        "The domain accepts email but does not publish a valid DMARC policy. DMARC is the DNS policy that tells receivers what to do when mail using the domain fails SPF or DKIM alignment checks."
                        ' Without DMARC, receivers may still perform SPF or DKIM checks, but they do not have a clear domain-owner'
                        ' policy saying whether failed messages should be rejected, quarantined, or only monitored. This makes'
                        ' direct domain spoofing easier and reduces visibility into abuse. DMARC also'
                        ' provides reporting that helps identify misconfigured legitimate senders. A safe rollout usually starts with'
                        ' monitoring, fixes legitimate mail alignment, then moves toward quarantine or reject once the organization is'
                        ' confident normal mail will not be blocked.'
                    ),
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
                (
                    f"The DMARC policy is set to p={policy.group(1)}. DMARC is the domain-owner rule for how receivers treat mail that fails SPF or DKIM alignment, and this setting stops short of full rejection."
                    ' A monitoring-only or partial policy can be useful while legitimate senders are'
                    ' being fixed, but it does not fully stop spoofed mail from reaching recipients. Attackers can take advantage of'
                    ' weak enforcement because the domain still appears in the visible From address. The policy should move'
                    ' gradually from monitoring to quarantine and then reject after reports show that normal mail flows pass SPF or'
                    ' DKIM alignment reliably.'
                ),
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
                descriptions = {
                    "DMARC Missing Subdomain Policy": (
                        "The DMARC record does not define a subdomain policy. Subdomains may inherit a weaker policy than intended, leaving forgotten or unused subdomains easier to spoof. "
                        "DMARC is the email control that tells receivers how to handle messages that claim to come from the domain but fail authentication checks. A subdomain policy, written as sp=, makes that instruction explicit for names below the main domain. Without it, old campaign domains, test systems, regional subdomains, or abandoned hosts may not receive the same protection as the parent domain. This can let attackers choose a less protected subdomain for phishing while still looking related to the organization."
                    ),
                    "DMARC Missing Aggregate Reports": (
                        "The DMARC record has no aggregate report destination. The domain owner will not receive regular visibility into spoofing attempts, authentication failures, or misconfigured legitimate senders. "
                        "Aggregate reports are summaries sent by participating mail providers that show who is sending mail using the domain and whether those messages pass SPF, DKIM, and DMARC alignment. Without these reports, teams have much less evidence when deciding whether it is safe to strengthen policy to quarantine or reject. Missing reports can also hide a broken mail provider setup until legitimate messages start failing or spoofed messages reach users."
                    ),
                    "DMARC DKIM Alignment Not Strict": (
                        "DMARC does not require strict DKIM alignment. Related but different domains may satisfy DKIM alignment, which can be less precise than strict organizational control. "
                        "DKIM is an email signature, and DMARC checks whether that signature aligns with the visible From domain users see. Relaxed alignment can be valid for organizations that intentionally send through related domains, but it widens what receivers may accept as aligned. Strict alignment requires the DKIM signing domain to match more closely, reducing ambiguity and making abuse harder. This should be changed only after confirming all legitimate mail providers sign with the expected domain."
                    ),
                    "DMARC SPF Alignment Not Strict": (
                        "DMARC does not require strict SPF alignment. Related but different domains may satisfy SPF alignment, reducing precision in anti-spoofing enforcement. "
                        "SPF checks whether the sending server is allowed to send for a domain, while DMARC checks whether that domain aligns with the visible From address. Relaxed alignment can be useful during complex mail-provider setups, but it may allow mail authenticated for a related domain to satisfy DMARC for this domain. Strict alignment narrows that relationship and provides clearer control. Before enabling it, legitimate senders should be reviewed so normal mail does not fail unexpectedly."
                    ),
                    "DMARC Forensic Reporting Not Configured": (
                        "The DMARC record does not request forensic failure reports. This limits detailed visibility into individual spoofing or authentication-failure events. "
                        "Forensic reports can provide more specific examples of failed messages than aggregate reports, helping teams investigate active phishing campaigns or misconfigured senders. Not every mailbox provider sends them, and they can contain sensitive message information, so they require careful handling and privacy review. This is not always a must-have setting, but the absence means incident responders may have fewer details when abuse happens. If used, reports should go to a controlled mailbox or processing service."
                    ),
                }
                findings.append(AuditFinding(title, severity, "Email", descriptions[title], f"DMARC: {dmarc}", recommendation, f"dig _dmarc.{domain} TXT +short"))
        pct = re.search(r"pct\s*=\s*(\d+)", lowered)
        if pct and int(pct.group(1)) < 100:
            findings.append(AuditFinding(
                "DMARC Not Applied to All Email",
                "LOW",
                "Email",
                (
                    f"The DMARC record uses pct={pct.group(1)}, so enforcement applies only to part of the mail flow. Some messages that fail DMARC may avoid quarantine or rejection during this partial rollout."
                    ' The DMARC pct tag applies enforcement to only a percentage of messages. This is'
                    ' useful during a gradual rollout, but leaving it below 100 means some messages that fail DMARC may avoid the'
                    ' intended quarantine or reject action. Attackers do not need every spoofed message to land; even partial'
                    ' delivery can be enough for phishing campaigns. If legitimate senders are already aligned, the percentage'
                    ' should be increased until the policy covers all mail. If the percentage is intentionally low, it should have'
                    ' an owner, a timeline, and monitoring so the domain does not remain permanently in a partial-protection state.'
                ),
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
                        (
                            f"DKIM selector {selector} appears to use a small RSA key. Weak DKIM keys can be easier to crack or abuse, reducing confidence that signed mail really came from an authorized sender."
                            ' DKIM uses cryptographic signatures so receivers can verify that a message was'
                            ' authorized by the domain or a related mail provider and was not modified in transit. If the DKIM key is too'
                            ' small, it may be easier to attack over time and may fail modern provider requirements. Weak DKIM does not'
                            ' automatically mean messages can be forged today, but it lowers the assurance that signed mail is trustworthy.'
                            ' Many mail providers now recommend 2048-bit RSA keys or modern alternatives. Rotating DKIM keys should be'
                            ' coordinated with the mail provider so old and new selectors overlap long enough to avoid breaking legitimate'
                            ' mail delivery.'
                        ),
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
                (
                    "No DKIM records were found for common selectors on a domain that accepts email. Without DKIM signatures, receivers have less evidence that messages were authorized and unmodified."
                    ' DKIM records publish public keys that let receivers verify signatures on outgoing'
                    ' email. If no DKIM records are found for common selectors on a domain that accepts mail, messages may be'
                    ' unsigned or signed with selectors not checked here. Without DKIM, receivers have less evidence that a message'
                    ' was authorized by the domain and not changed after sending. DKIM is also important for DMARC because a message'
                    ' can pass DMARC through aligned DKIM even when SPF fails due to forwarding. The domain owner should confirm'
                    ' with each mail provider which selectors are used and whether DKIM signing is enabled for all legitimate'
                    ' outbound mail.'
                ),
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
                (
                    "The domain receives email but does not publish MTA-STS. Sending mail servers cannot learn a strict TLS policy for this domain, so SMTP delivery may remain more exposed to downgrade or interception attempts."
                    ' MTA-STS is a policy that lets a domain tell other mail servers to use encrypted SMTP'
                    ' connections when delivering mail to it. Without MTA-STS, many senders will still try STARTTLS, but SMTP'
                    ' encryption can be downgraded or skipped more easily because there is no published strict policy for the'
                    ' domain. This matters for inbound email confidentiality and resistance to man-in-the-middle downgrade attacks.'
                    ' MTA-STS should be deployed carefully with valid certificates on all MX servers, because a strict policy'
                    ' combined with broken TLS can cause mail delivery failures. TLS-RPT reporting is useful alongside it for'
                    ' monitoring problems.'
                ),
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
                (
                    "The domain does not publish TLS-RPT for SMTP. Mail transport TLS failures, downgrade attempts, and MTA-STS problems may go unnoticed because receivers have no reporting destination."
                    ' TLS-RPT is a reporting mechanism for SMTP transport security problems. It lets other'
                    ' mail systems send reports when they cannot deliver mail securely, when MTA-STS validation fails, or when'
                    ' downgrade-like behavior is observed. Without TLS-RPT, the domain owner may not notice that inbound mail'
                    ' encryption is failing for some senders, especially if delivery falls back to plaintext or intermittent errors'
                    ' are hidden in remote systems. This is mostly a visibility issue rather than a direct vulnerability. It becomes'
                    ' more important when MTA-STS is enabled, because strict TLS policies need reporting to detect certificate,'
                    ' policy, and delivery issues quickly.'
                ),
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
                (
                    "The TLS-RPT record exists but does not include a rua reporting destination. SMTP TLS reports cannot be delivered, so the record provides little operational visibility."
                    ' A TLS-RPT record without a rua destination tells senders that reporting exists but'
                    ' gives them nowhere useful to send reports. In practice, the domain owner receives little or no visibility into'
                    ' SMTP TLS failures, downgrade attempts, or MTA-STS problems. This can leave mail security issues unresolved for'
                    ' long periods because normal users may only see delayed or missing mail, not the underlying TLS cause. The'
                    ' destination can be an email mailbox or HTTPS endpoint that is monitored and able to process reports. If the'
                    ' organization does not consume these reports, the record should still be corrected or removed to avoid a false'
                    ' sense of monitoring.'
                ),
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
                (
                    "One or more TLS-RPT rua destinations are malformed. Mail systems may be unable to deliver TLS failure reports, leaving transport-security issues hidden."
                    ' TLS-RPT reporting destinations must be valid mailto or HTTPS URIs. If the'
                    ' destination is malformed, sending mail systems may ignore it or fail to deliver reports. The result is lost'
                    ' operational visibility into mail transport encryption problems. This is especially risky when the domain also'
                    ' uses MTA-STS, because strict mail TLS policies can break delivery if certificates, MX names, or policy files'
                    ' are wrong. A valid destination should point to a monitored mailbox or service that can receive aggregate'
                    ' reports. Fixing the syntax is usually straightforward, but the destination should also be tested so reports'
                    ' are actually received and reviewed.'
                ),
                f"Invalid destinations: {invalid}",
                "Use valid mailto: or https: URIs in rua.",
                f"dig TXT _smtp._tls.{domain} +short",
            ))
        if weak:
            findings.append(AuditFinding(
                "Potentially Undeliverable TLS-RPT Destination",
                "LOW",
                "Email",
                (
                    "Some mailto TLS-RPT destinations appear undeliverable because their domains lack MX or A records. TLS reports may be silently lost instead of reaching monitoring systems."
                    ' The TLS-RPT record points to a mail reporting address whose domain does not appear'
                    ' to have working mail or address records. Even if the syntax is correct, reports may never arrive. That means'
                    ' problems such as TLS negotiation failures, invalid certificates, or MTA-STS policy conflicts can remain'
                    ' invisible to the domain owner. This is a monitoring reliability issue: the security control may exist on paper'
                    ' but not provide useful feedback. The reporting domain should have valid MX or A records, the mailbox should'
                    ' accept reports, and the team should confirm that report processing or alerting is actually in place.'
                ),
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
                (
                    "The domain publishes BIMI but does not specify a Verified Mark Certificate. Brand logos may not be displayed by mailbox providers that require a VMC, reducing the value of the BIMI deployment."
                    ' BIMI is an email branding standard that can let mailbox providers display a verified'
                    ' logo next to authenticated messages. Many providers require a Verified Mark Certificate before showing the'
                    ' logo. If the BIMI record exists without a certificate reference, the deployment may not produce the expected'
                    ' visible branding benefit. This is not usually a security vulnerability by itself, but it can create a false'
                    ' assumption that recipients will see a trusted brand indicator. BIMI also depends on strong email'
                    ' authentication, especially DMARC enforcement. The domain owner should confirm whether BIMI is intended,'
                    ' whether the logo and certificate requirements are met, and whether DMARC is strong enough for provider'
                    ' requirements.'
                ),
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
                (
                    "The domain has no CAA records. CAA is the DNS policy that tells publicly trusted certificate authorities which companies may issue TLS certificates for the domain."
                    ' Without CAA, any publicly trusted CA can issue a certificate if its normal validation process succeeds. That'
                    ' does not mean certificates are currently compromised, but it increases the number of organizations whose'
                    ' mistakes or account compromises could affect the domain. CAA is mainly a governance and damage-reduction'
                    ' control: it narrows the allowed issuers and can provide incident reporting for unauthorized'
                    ' issuance attempts. The policy should include the CAs actually used by the organization and be updated when'
                    ' certificate providers change.'
                ),
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
                (
                    "The CAA policy does not include an iodef reporting destination. Certificate issuance violations may not be reported to the domain owner."
                    ' The CAA iodef tag provides a place for certificate authorities to send reports when'
                    " certificate issuance violates the domain's CAA policy. Without it, an unauthorized or mistaken issuance"
                    " attempt may fail silently from the domain owner's perspective. The core CAA restrictions can still work, but"
                    ' the organization loses a useful early-warning signal about certificate abuse, provider misconfiguration, or'
                    ' forgotten validation paths. This is usually a visibility and governance issue rather than an immediate'
                    ' compromise. The destination should be a monitored mailbox or incident handling endpoint that can route'
                    ' certificate-related reports to the right team.'
                ),
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
                (
                    "The CAA policy authorizes wildcard certificate issuance too broadly. Overly broad CA authorization increases the chance that unexpected providers can issue certificates for subdomains."
                    ' Wildcard certificates can cover many subdomains at once, such as every name under a'
                    ' domain. If CAA authorizes wildcard issuance too broadly, a mistake or compromise at an allowed certificate'
                    ' authority can have a larger impact because one certificate may be valid for many hosts. This does not prove'
                    ' that a bad certificate has been issued, but it weakens the guardrails around certificate governance. Wildcard'
                    ' issuance should be limited to the providers that truly need it, and some domains may choose to deny wildcard'
                    ' certificates entirely. A tighter issuewild policy reduces the chance of unexpected certificates being issued'
                    ' for sensitive subdomains.'
                ),
                f"CAA records: {caa_records}",
                "Replace wildcard CA authorization with a tight allow-list.",
                f"dig CAA {domain}",
            ))
        if len(allowed) > 3:
            findings.append(AuditFinding(
                "CAA Authorizes Many Certificate Authorities",
                "LOW",
                "Certificate",
                (
                    f"The CAA policy authorizes {len(allowed)} different certificate authorities. A large issuer allow-list weakens the control CAA provides and makes certificate governance harder to audit."
                    ' CAA is most useful when it narrows certificate issuance to a small, intentional set'
                    ' of providers. If many certificate authorities are authorized, the policy becomes harder to understand and'
                    ' offers less reduction in risk. Each additional CA represents another account, validation workflow, and'
                    ' operational relationship that could issue certificates for the domain. This may be necessary in complex'
                    ' environments, but it should be deliberate and documented. The list should be reviewed against actual'
                    ' certificate inventory, removed providers should be deleted, and separate subdomain policies can be used when'
                    ' different business units need different issuers.'
                ),
                f"Authorized issuers: {sorted(allowed)}",
                "Reduce authorized CAs to the minimal operational set.",
                f"dig CAA {domain}",
            ))
        if issue_values and not issuewild_values:
            findings.append(AuditFinding(
                "CAA Missing Explicit issuewild Policy",
                "INFO",
                "Certificate",
                (
                    "The CAA policy restricts normal certificate issuance but does not explicitly define wildcard issuance. Wildcard certificate behavior may not match the intended policy."
                    ' The CAA issue tag controls normal certificate issuance, while issuewild controls'
                    ' wildcard certificates specifically. If normal issuance is restricted but wildcard issuance is not explicitly'
                    ' defined, the resulting behavior can be misunderstood by operators and auditors. Wildcard certificates are'
                    ' powerful because one certificate can authenticate many subdomains, so their policy should be intentional.'
                    ' Adding issuewild either allows only approved wildcard issuers or denies wildcard issuance entirely. This makes'
                    " the domain's certificate governance easier to reason about and reduces surprises when a provider or automation"
                    ' system tries to request a wildcard certificate.'
                ),
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
                (
                    "The domain publishes a null MX record, explicitly declaring that it does not accept email. This is valid when intentional and helps receivers reject mail quickly."
                    ' A null MX record is a standards-based way to say that a domain does not accept'
                    ' email. This can be good security hygiene for domains that should never receive mail, because it helps senders'
                    ' fail quickly and reduces backscatter or pointless delivery attempts. It also makes the domain\'s intent clearer'
                    ' than simply having no MX record. This finding is informational because the configuration is valid when'
                    ' intentional. The important review question is whether the domain truly should not receive email. If users,'
                    ' applications, password resets, or vendors expect to send mail to this domain, the null MX record will prevent'
                    ' normal delivery.'
                ),
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
                (
                    "The domain publishes a null MX record alongside normal MX records. This is contradictory: some senders may treat the domain as not accepting mail while others try delivery, causing unreliable inbound email behavior."
                    ' A null MX record means the domain does not accept email, while normal MX records'
                    ' tell senders where to deliver email. Publishing both sends contradictory instructions. Some senders may treat'
                    ' the domain as mail-disabled, while others may attempt delivery to the listed servers, creating inconsistent'
                    ' and hard-to-debug mail behavior. This can cause lost messages, delayed messages, or different outcomes between'
                    ' mail providers. From a security perspective, confusion around mail routing can also hide spoofing or delivery'
                    ' problems. The domain should choose one clear posture: either null MX alone for no inbound mail, or normal MX'
                    ' records when inbound mail is expected.'
                ),
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
                    (
                        "An MX record points directly to an IP address instead of a hostname. This violates normal mail-routing expectations and can cause delivery failures or inconsistent sender behavior."
                        ' MX records are supposed to point to hostnames, not directly to IP addresses. Mail'
                        ' systems then resolve those hostnames to A or AAAA records. Using an IP address in an MX record violates normal'
                        ' DNS mail-routing expectations and can cause different senders to behave inconsistently. Some systems may'
                        ' reject the record, fail delivery, or skip expected checks such as forward and reverse DNS validation. This is'
                        ' primarily a reliability and standards-compliance issue, but it can affect security controls tied to mail'
                        ' identity and reputation. The fix is to create a proper mail hostname and point the MX record to that name.'
                    ),
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
                    (
                        "An MX record points to localhost or an internal-only domain. External senders cannot deliver mail reliably, and misrouted mail may bounce, queue, or be delivered to the wrong local system."
                        ' An MX record pointing to localhost, a .local name, or another internal-only hostname'
                        ' cannot be used reliably by external senders on the public internet. Senders may try to deliver mail to'
                        ' themselves, fail resolution, queue messages, or bounce messages unexpectedly. This often happens when internal'
                        ' test configuration leaks into public DNS. The impact can include complete inbound mail failure, lost security'
                        ' notifications, failed account recovery emails, and confusion during incidents. If the domain should receive'
                        ' email, the MX host must be a public, resolvable mail server. If it should not receive email, a null MX record'
                        ' is clearer and safer.'
                    ),
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
                (
                        f"Mail server {mx_host} has no A or AAAA record and cannot receive email."
                        ' An MX record tells other mail systems which host should receive mail for the domain.'
                        ' If that MX hostname has no A or AAAA address, senders cannot turn the mail-server name into an IP address and'
                        ' therefore cannot deliver messages. This can break inbound email completely or cause long delays while senders'
                        ' retry. The problem may be caused by a removed DNS record, a typo, an expired provider setup, or a migration'
                        ' that did not finish. The security impact is indirect but important: missed password resets, alerts, invoices,'
                        ' abuse reports, or incident messages can affect operations and response. The MX hostname should resolve to'
                        ' valid public addresses.'
                    ),
                    f"MX: {mx}",
                    "Ensure the MX hostname resolves to valid public IP addresses.",
                    f"dig A {mx_host} && dig AAAA {mx_host}",
                ))
        duplicate_priorities = {priority for priority in priorities if priorities.count(priority) > 1}
        duplicate_hosts = [
            self.mx_host(mx)
            for mx in mx_records
            if self.mx_priority(mx) in duplicate_priorities
        ]
        managed_provider_load_balancing = bool(duplicate_hosts) and all(
            self.is_managed_mx_host(host) for host in duplicate_hosts
        )
        if duplicate_priorities and not managed_provider_load_balancing:
            findings.append(AuditFinding(
                "Duplicate MX Priorities",
                "INFO",
                "Email",
                (
                    "Multiple MX records share the same priority. This can be intentional load balancing, but if accidental it may send mail to unexpected servers or make failover behavior harder to predict."
                    ' MX priority values tell senders which mail servers to try first. Duplicate'
                    ' priorities can be valid when they are intentionally used for load balancing across equivalent mail servers. If'
                    ' they are accidental, senders may distribute mail across systems that are not equally configured, leading to'
                    ' inconsistent spam filtering, TLS behavior, mailbox routing, or delivery reliability. This is not automatically'
                    ' a vulnerability, but it should be reviewed because mail issues often appear only for some senders. Confirm'
                    ' that each server with the same priority is intended to receive the same traffic and has equivalent security'
                    ' controls, certificates, and anti-abuse configuration.'
                ),
                f"MX priorities: {priorities}",
                "Verify duplicate priorities are intentional for load-balancing.",
                f"dig MX {domain} +short",
            ))
        if len(mx_records) == 1 and not self.is_managed_mx_host(self.mx_host(mx_records[0])):
            findings.append(AuditFinding(
                "No Backup MX Server",
                "INFO",
                "Email",
                (
                    "Only one MX record is configured. If that mail server or provider is unavailable, inbound email has no DNS-level backup route and may be delayed or rejected."
                    ' A single MX record means there is only one DNS-level destination for inbound mail.'
                    ' If that provider or server is unavailable, senders may queue mail for a while, but there is no alternate MX'
                    ' route advertised in DNS. Modern cloud mail providers may already provide redundancy behind one hostname, so'
                    ' this is not always a problem. The finding should be interpreted in the context of the provider. For'
                    ' self-hosted or single-server deployments, however, lack of a backup MX can increase the chance of delayed or'
                    ' rejected mail during outages. Organizations that depend heavily on inbound email should confirm the provider\'s'
                    ' redundancy model or add a properly configured backup.'
                ),
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
                    (
                        f"Mail server {mx_host} does not advertise STARTTLS. Other mail servers may deliver messages in plaintext, exposing email content and metadata to network interception."
                        ' STARTTLS lets mail servers upgrade an SMTP connection from plaintext to TLS'
                        ' encryption. If an MX server does not advertise STARTTLS, other mail servers may deliver inbound messages'
                        ' without transport encryption. Email is often relayed between multiple systems, and plaintext SMTP can expose'
                        ' message contents, sender and recipient addresses, and metadata to networks on the delivery path. This does not'
                        ' mean mailbox login is affected, but it weakens confidentiality for mail in transit. The server should support'
                        ' STARTTLS with a valid certificate, and domains with higher security needs should combine it with MTA-STS and'
                        ' TLS-RPT monitoring.'
                    ),
                    f"EHLO capabilities: {' | '.join(summary.get('ehlo_lines', [])[:8]) or 'no EHLO response'}",
                    "Enable STARTTLS on MX servers and pair it with MTA-STS and TLS-RPT monitoring.",
                    f"openssl s_client -starttls smtp -connect {mx_host}:25 -servername {mx_host}",
                ))
            if summary.get("starttls_error"):
                findings.append(AuditFinding(
                    "MX STARTTLS Negotiation Failure",
                    "MEDIUM",
                    "Email",
                (
                        f"{mx_host} advertises STARTTLS but failed to complete the TLS negotiation. Senders may fall back to plaintext, defer delivery, or treat the server as unreliable."
                        ' This mail server advertises STARTTLS but fails when the TLS handshake is attempted.'
                        ' That is worse than simply not supporting encryption because senders may make different decisions depending on'
                        ' their policy: some may fall back to plaintext, some may retry later, and strict senders may fail delivery. The'
                        ' result can be inconsistent mail behavior and reduced confidentiality. Common causes include broken'
                        ' certificates, protocol mismatch, middleboxes, old TLS versions, or server configuration errors. The server'
                        ' should be tested from outside the network and fixed so STARTTLS completes reliably with a valid certificate'
                        ' chain and hostname.'
                    ),
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
                (
                    "None of the tested MX servers supported STARTTLS. Inbound email can be delivered without transport encryption, exposing messages and metadata to passive network observers."
                    ' None of the tested inbound mail servers offered STARTTLS, so mail sent to the domain'
                    ' can be delivered over unencrypted SMTP. This exposes message content and metadata to anyone able to observe'
                    ' traffic along the delivery path. While SMTP encryption between mail servers is opportunistic by default, most'
                    ' modern mail infrastructure supports STARTTLS, and lack of support is below current expectations. This can also'
                    ' prevent stronger controls such as MTA-STS from being deployed safely. The organization should enable STARTTLS'
                    ' on all MX endpoints, use valid certificates, and monitor delivery with TLS-RPT if inbound email'
                    ' confidentiality matters.'
                ),
                f"Tested MX hosts: {[item.get('mx') for item in summaries]}",
                "Enable STARTTLS across all MX endpoints and pair it with MTA-STS and TLS-RPT monitoring.",
                f"for mx in $(dig +short MX {domain} | awk '{{print $2}}'); do openssl s_client -starttls smtp -connect ${{mx%?}}:25 -servername ${{mx%?}} </dev/null; done",
            ))
        if cert_errors:
            findings.append(AuditFinding(
                "MX STARTTLS Certificate Issues",
                "MEDIUM",
                "Email",
                (
                    "One or more MX servers present invalid or untrusted TLS certificates during STARTTLS. Senders that validate certificates may reject encrypted delivery, and others may fall back to weaker behavior."
                    ' The MX server supports STARTTLS but presents a certificate that is invalid,'
                    ' untrusted, expired, incomplete, or not valid for the mail hostname. Some sending mail systems may ignore'
                    ' certificate problems and continue, while stricter systems may refuse encrypted delivery or fail delivery'
                    ' entirely. This creates inconsistent behavior and weakens confidence that mail is being encrypted to the right'
                    ' server. Certificate problems also block safe deployment of MTA-STS, which depends on valid TLS. Each MX'
                    ' hostname should present a publicly trusted certificate with the correct subject alternative names, complete'
                    ' chain, and current validity period.'
                ),
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
            if self.is_managed_mx_host(mx_host):
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
                    (
                        f"Mail server {mx_host} has no reverse DNS for {ip}. Missing PTR records can reduce deliverability because many receivers treat mail from hosts without reverse DNS as suspicious."
                        ' PTR records provide reverse DNS, allowing an IP address to map back to a hostname.'
                        ' Many mail receivers use reverse DNS as a basic reputation and anti-abuse signal. If a mail server IP has no'
                        ' PTR record, receiving systems may treat messages from it as suspicious, score them as spam, throttle delivery,'
                        ' or reject them outright. This does not directly expose the server, but it can damage mail deliverability and'
                        ' make legitimate messages less trustworthy. The PTR record usually must be configured by the IP address owner'
                        " or hosting provider, and it should align with the mail server's forward DNS where possible."
                    ),
                    f"No PTR record for {ip}",
                    "Add PTR/rDNS for mail server IPs to improve deliverability.",
                    f"dig -x {ip}",
                ))
            elif success and ptr_records and not self.ptr_matches_mx(ptr_records[0], mx_host):
                findings.append(AuditFinding(
                    "PTR/Forward DNS Mismatch",
                    "LOW",
                    "Email",
                    (
                        "The mail server PTR record does not match the MX hostname. This mismatch can reduce mail deliverability and make the server look less trustworthy to receivers."
                        ' Forward DNS maps a hostname to an IP address, while PTR or reverse DNS maps the IP'
                        ' address back to a hostname. For mail servers, many receivers expect these values to be consistent or at least'
                        ' clearly related. A mismatch can make the server look misconfigured or suspicious, reducing deliverability and'
                        ' reputation. This is especially important for self-hosted mail and transactional mail systems. The mismatch'
                        ' does not prove abuse, but it can cause legitimate messages to land in spam or be rejected by stricter'
                        ' receivers. The IP owner should configure reverse DNS to a stable mail hostname that resolves back to the same'
                        ' address.'
                    ),
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

    def mx_priority(self, mx):
        parts = str(mx or "").split()
        return int(parts[0]) if parts and parts[0].isdigit() else None

    def is_managed_mx_host(self, host):
        host = str(host or "").rstrip(".").lower()
        if not host:
            return False
        return any(host == suffix or host.endswith(f".{suffix}") for suffix in self.managed_mx_suffixes)

    def is_managed_authoritative_ns(self, host):
        host = str(host or "").rstrip(".").lower()
        if not host:
            return False
        for suffix in self.managed_authoritative_ns_suffixes:
            if suffix.endswith("-"):
                if suffix in host:
                    return True
                continue
            if host == suffix or host.endswith(f".{suffix}"):
                return True
        return False

    def has_managed_authoritative_ns(self, records):
        return any(self.is_managed_authoritative_ns(ns) for ns in records.get("NS", []))

    def ptr_matches_mx(self, ptr_record, mx_host):
        ptr = str(ptr_record or "").rstrip(".").lower()
        mx = str(mx_host or "").rstrip(".").lower()
        if not ptr or not mx:
            return False
        if ptr == mx:
            return True
        success, ptr_root = self.helpers.split_domain(ptr)
        mx_success, mx_root = self.helpers.split_domain(mx)
        return bool(success and mx_success and ptr_root and mx_root and ptr_root == mx_root)

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
                (
                    "Arbitrary subdomains resolve instead of returning NXDOMAIN. Wildcard DNS can hide typos, route unexpected hostnames into applications, and make it harder to distinguish real assets from generated names."
                    ' Wildcard DNS means that random, nonexistent subdomains still resolve instead of'
                    ' returning a clear does-not-exist answer. This can be intentional for catch-all hosting, tenant routing, or'
                    ' marketing systems, but it can also create confusion. Security tools, asset inventories, and users may treat'
                    ' generated names as real hosts. Applications behind the wildcard may receive unexpected hostnames, which can'
                    ' interact badly with virtual hosting, cookies, redirects, password reset links, or tenant isolation. The domain'
                    ' owner should confirm the wildcard is intentional and ensure unknown hostnames are handled safely, with no'
                    ' default sensitive application or misleading content exposed.'
                ),
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
                (
                    "One or more delegated nameserver hostnames do not resolve. Resolvers may waste time querying unusable authoritative servers, reducing DNS reliability and increasing lookup latency."
                    ' The parent zone delegates this domain to nameserver hostnames, but one or more of'
                    ' those hostnames cannot be resolved to an IP address. Resolvers may still try to use them, wasting time and'
                    ' increasing DNS lookup latency. If enough delegated nameservers are broken, the domain can become'
                    ' intermittently or completely unreachable. This can happen after provider migrations, removed glue records,'
                    ' expired nameserver domains, or typos in delegation. Every delegated nameserver should have working A or AAAA'
                    ' records, and glue records should be correct when the nameserver is inside the delegated domain itself.'
                ),
                f"Unresolved NS: {unresolved}",
                "Ensure every delegated NS hostname has valid A/AAAA/glue records.",
                f"dig {domain} NS +short",
            ))
        if lame:
            findings.append(AuditFinding(
                "Potential Lame Delegation",
                "HIGH",
                "DNS",
                (
                    "Some delegated nameservers did not return authoritative SOA answers for the domain. Parent delegation points clients to servers that may not actually serve the zone, causing intermittent DNS failures."
                    ' A lame delegation occurs when the parent zone points resolvers to a nameserver that'
                    ' does not actually serve authoritative answers for the domain. To users, this can look like intermittent DNS'
                    ' failure because some resolvers hit working nameservers while others hit the lame one. It often appears after'
                    ' DNS provider migrations where old nameservers remain listed at the registrar, or when a provider has removed'
                    ' the zone. This is primarily an availability risk, but it can also complicate incident response because DNS'
                    ' behavior differs depending on which server is queried. The parent delegation should list only nameservers that'
                    ' are authoritative for the zone.'
                ),
                f"Non-authoritative/unresponsive NS: {lame}",
                "Fix parent delegation to only include authoritative nameservers.",
                f"for ns in $(dig +short {domain} NS); do dig @${{ns%?}} {domain} SOA +short; done",
            ))
        if len(set(soa_serials.values())) > 1:
            findings.append(AuditFinding(
                "Authoritative Nameservers Out of Sync",
                "MEDIUM",
                "DNS",
                (
                    "Authoritative nameservers return different SOA serials. Zone data is not synchronized, so users may receive different DNS answers depending on which nameserver they query."
                    ' Authoritative nameservers should serve the same zone data. Different SOA serial'
                    ' numbers indicate that at least some nameservers have different versions of the zone. Users may receive'
                    ' different DNS answers depending on resolver choice, geography, cache state, or random nameserver selection.'
                    ' This can cause confusing behavior during migrations, certificate validation, mail delivery, and incident'
                    ' response. It may also mean a secondary server is not receiving updates from the primary. The DNS provider or'
                    ' zone transfer configuration should be checked so all authoritative servers converge on the same records before'
                    ' old data causes outages or stale exposure.'
                ),
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
                (
                    "The domain has web-address records but does not publish HTTPS/SVCB records. Clients cannot use DNS service hints for HTTPS parameters, alternative endpoints, or future protocol optimization."
                    ' HTTPS and SVCB records are newer DNS record types that can advertise service'
                    ' parameters such as preferred protocols, alternative endpoints, and HTTPS connection hints before a client'
                    ' connects. They are not required for normal websites to work, so this finding is informational. The absence'
                    ' means clients cannot use DNS-level service hints that may improve performance, protocol negotiation, or future'
                    ' deployment patterns. For many domains this is acceptable, especially when a CDN or provider does not require'
                    ' them. The domain owner should consider these records only if the web platform supports them and there is a'
                    ' clear operational benefit.'
                ),
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
                (
                    "A DNS response was truncated over UDP and the TCP retry failed. Large DNSSEC or DNS responses may become unreachable to resolvers that correctly retry over TCP."
                    ' DNS normally uses UDP first, but large answers can be truncated and require the'
                    ' resolver to retry over TCP on port 53. This is common for DNSSEC data and other large responses. If UDP'
                    ' truncation occurs and TCP fallback fails, standards-compliant resolvers may be unable to get the full answer.'
                    ' Users can see intermittent lookup failures, especially for validating DNSSEC resolvers or networks that block'
                    ' fragmented UDP. The fix is to ensure authoritative DNS infrastructure allows TCP/53, handles larger responses'
                    ' correctly, and is not blocked by firewalls, load balancers, or provider security rules.'
                ),
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
        if very_low:
            findings.append(AuditFinding(
                "Very Low DNS TTL on Critical Records",
                "MEDIUM",
                "DNS",
                (
                    "Critical DNS records use unusually low TTL values. This can increase resolver load, amplify provider outages, and make DNS behavior more sensitive to transient authoritative-server issues. "
                    "TTL means time to live: the amount of time other DNS resolvers are allowed to cache an answer before asking again. Low TTLs are useful during planned migrations because changes take effect faster, but they are not free. If stable records such as A, AAAA, MX, or NS expire from caches very quickly, more users depend on the authoritative DNS provider being reachable at every moment. A short provider outage, rate limit, or routing issue can therefore affect more users. Low TTLs should be intentional, temporary when possible, and raised after migrations are complete."
                ),
                f"TTLs: {very_low}",
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
                (
                    f"The SOA refresh interval is very short ({refresh}s). Secondary nameservers may poll the primary too frequently, increasing unnecessary DNS control-plane load."
                    ' The SOA refresh value tells secondary nameservers how often to check the primary'
                    ' nameserver for zone updates. If it is extremely short, secondary servers may poll more often than necessary,'
                    ' creating extra control-plane traffic and load. This usually is not a direct security issue, but it can make'
                    ' DNS operations noisier and less efficient, especially for large zones or providers with many secondaries. A'
                    ' short refresh may be intentional during active changes, but it should not remain low without a reason. The'
                    ' value should balance timely propagation with stable, low-overhead zone replication.'
                ),
                f"SOA: {soa}",
                "Review SOA refresh to avoid excessive secondary polling.",
                f"dig SOA {domain} +short",
            ))
        if expire < 604800:
            findings.append(AuditFinding(
                "SOA Expire Too Short",
                "LOW",
                "DNS",
                (
                    f"The SOA expire value ({expire}s) is less than one week. Secondary nameservers may stop serving the zone quickly during a primary DNS outage, reducing resilience."
                    ' The SOA expire value tells secondary nameservers how long they may continue serving'
                    ' the zone if they cannot reach the primary server. If this value is too short, a primary DNS outage can cause'
                    ' secondaries to stop answering sooner than necessary, even if their cached zone data is still useful. That'
                    ' reduces resilience during provider, network, or maintenance incidents. This is mostly an availability issue.'
                    ' The value should be long enough to tolerate realistic primary outages while still preventing very old zone'
                    ' data from being served indefinitely. Many deployments use an expire period of at least a week.'
                ),
                f"SOA: {soa}",
                "Use an expire value that tolerates primary DNS outages.",
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
                (
                    "A CNAME exists at the zone apex. Apex CNAMEs cannot coexist correctly with required SOA, NS, and MX records, which can break DNS behavior for the domain."
                    ' The zone apex is the bare domain, such as example.com. DNS standards require'
                    ' important records like SOA and NS to exist at the apex, and many domains also need MX or TXT records there. A'
                    ' true CNAME says the name is only an alias and should not have other records, which conflicts with those'
                    ' required apex records. Some providers offer ALIAS, ANAME, or CNAME-flattening features that look similar but'
                    ' behave differently. If a real apex CNAME is present, DNS behavior can break or vary between providers. The'
                    ' domain should use provider-supported flattening or direct A/AAAA records instead.'
                ),
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
                    (
                        f"A {rdtype} record is present. This record type may disclose unnecessary system information or rely on deprecated DNS behavior that modern deployments generally avoid."
                        ' Older or uncommon DNS record types can reveal details that are not useful to normal'
                        ' users and may confuse modern tooling. HINFO can disclose host or operating-system hints, while WKS is obsolete'
                        ' and rarely needed. These records usually do not create direct compromise by themselves, but they add'
                        ' reconnaissance value and increase the amount of legacy behavior the zone must carry. If there is no documented'
                        ' business or protocol requirement for the record, removing it reduces unnecessary exposure and keeps the public'
                        ' DNS zone focused on records that actively support current services.'
                    ),
                    f"{rdtype}: {answers[0]}",
                    f"Remove {rdtype} unless it is intentionally required.",
                    f"dig {rdtype} {domain}",
                ))

    async def check_dns_version(self, domain, records, findings):
        for ns in records.get("NS", [])[:2]:
            if self.is_managed_authoritative_ns(ns):
                continue
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
                    (
                        f"Nameserver {ns} discloses its DNS software version through CHAOS TXT. Attackers can use this information to identify known server-specific vulnerabilities or tailor exploitation attempts."
                        ' Some DNS servers answer a special CHAOS TXT query called version.bind with their'
                        ' software name or version. This information is not usually sensitive by itself, but it helps attackers and'
                        ' researchers identify exactly which DNS software may be running and compare it against known vulnerabilities or'
                        ' configuration weaknesses. Hiding the version does not replace patching, but it reduces unnecessary'
                        ' fingerprinting. The best fix is to keep DNS software current and, where supported, disable or customize public'
                        ' version disclosure. This is an information disclosure issue with low direct impact but useful reconnaissance'
                        ' value.'
                    ),
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
                    (
                        f"Nameserver {ns} appears to allow public recursion. Open resolvers can be abused for DNS amplification attacks and may expose internal resolver behavior if authoritative and recursive roles are mixed."
                        ' An authoritative nameserver should normally answer for zones it hosts, not perform'
                        ' recursive lookups for the public internet. If it allows public recursion, other people can use it as an open'
                        ' resolver. Open resolvers are commonly abused in DNS amplification attacks, where small spoofed queries trigger'
                        ' larger responses toward a victim. Mixing authoritative and recursive roles can also expose internal resolver'
                        ' behavior or cache state. This does not mean the domain itself is compromised, but it creates abuse and'
                        ' availability risk for the DNS infrastructure. Public recursion should be disabled or restricted to trusted'
                        ' networks only.'
                    ),
                    "RA flag observed when querying external domain",
                    "Disable public recursion on authoritative nameservers.",
                    f"dig @{ns_ips[0]} google.com +recurse",
                ))
                return
