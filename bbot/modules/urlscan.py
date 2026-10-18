import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from bbot.modules.templates.subdomain_enum import subdomain_enum


class urlscan(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED", "DOMAIN_DNS_HISTORY", "DOMAIN_CERTIFICATE_HISTORY"]
    meta = {
        "description": "Query urlscan.io for subdomains",
        "created_date": "2022-06-09",
        "author": "@TheTechromancer",
    }
    options = {"urls": True, "api_key": "", "max_pages": 3, "page_size": 100, "max_certificate_results": 50}
    options_desc = {
        "urls": "Emit URLs in addition to DNS_NAMEs",
        "max_pages": "Maximum historical website scan result pages per domain",
        "page_size": "Website scan results per page",
        "api_key": "Optional urlscan.io API key for broader history and higher limits",
        "max_certificate_results": "Maximum distinct historical certificate result pages fetched per domain",
    }

    base_url = "https://urlscan.io/api/v1"

    async def setup(self):
        self.urls = self.config.get("urls", False)
        self.max_pages = max(1, min(10, int(self.config.get("max_pages", 3))))
        self.page_size = max(1, min(1000, int(self.config.get("page_size", 100))))
        self.max_certificate_results = max(0, min(200, int(self.config.get("max_certificate_results", 50))))
        api_key = str(self.config.get("api_key", "")).strip()
        self.request_headers = {"api-key": api_key} if api_key else {}
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        results, histories, certificate_candidates = await self.query(query)
        for domain, url in results:
            parent_event = event
            if domain and domain != query:
                domain_event = self.make_event(domain, "DNS_NAME", parent=event)
                if domain_event:
                    if str(domain_event.host).endswith(f".{query}") and not str(domain_event.host) == str(event.host):
                        await self.emit_event(
                            domain_event,
                            abort_if=self.abort_if,
                            context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.data}}',
                        )
                        parent_event = domain_event
            if url:
                url_event = self.make_event(url, "URL_UNVERIFIED", parent=parent_event)
                if url_event:
                    if str(url_event.host) == query or str(url_event.host).endswith(f".{query}"):
                        if self.urls:
                            await self.emit_event(
                                url_event,
                                abort_if=self.abort_if,
                                context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.data}}',
                            )
                        else:
                            await self.emit_event(
                                str(url_event.host),
                                "DNS_NAME",
                                parent=event,
                                abort_if=self.abort_if,
                                context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.data}}',
                            )
                    else:
                        self.debug(f"{url_event.host} does not match {query}")

        for host, records in histories.items():
            await self.emit_event(
                {"host": host, "records": list(records.values())},
                "DOMAIN_DNS_HISTORY",
                parent=event,
                context=f'{{module}} found historical website scan addresses for "{host}" in {{event.type}}',
            )

        for certificate in await self.certificate_history(certificate_candidates):
            await self.emit_event(
                certificate,
                "DOMAIN_CERTIFICATE_HISTORY",
                parent=event,
                context=f'{{module}} found a historical TLS certificate for "{certificate["host"]}" in {{event.type}}',
            )

    async def query(self, query):
        results = set()
        histories = defaultdict(dict)
        certificate_candidates = {}
        cursor = None
        for _ in range(self.max_pages):
            url = f"{self.base_url}/search/?q={self.helpers.quote(f'page.domain:{query}')}&size={self.page_size}"
            if cursor:
                url += f"&search_after={self.helpers.quote(cursor)}"
            response = await self.helpers.request(url, headers=self.request_headers)
            if response is None or response.status_code != 200:
                break
            try:
                response_data = response.json()
            except ValueError:
                self.verbose(f'Invalid urlscan response for "{query}"')
                break
            if not isinstance(response_data, dict):
                break
            page_results = response_data.get("results")
            if not isinstance(page_results, list):
                break
            for result in page_results:
                if not isinstance(result, dict):
                    continue
                task = result.get("task") if isinstance(result.get("task"), dict) else {}
                page = result.get("page") if isinstance(result.get("page"), dict) else {}
                for item in (task, page):
                    domain, page_url = item.get("domain", ""), item.get("url", "")
                    if domain or page_url:
                        results.add((domain, page_url))
                host = str(page.get("domain", "")).lower().rstrip(".")
                if host == query or host.endswith(f".{query}"):
                    self.collect_certificate_candidate(certificate_candidates, host, result, task, page)
                    try:
                        ip = ipaddress.ip_address(page.get("ip", ""))
                    except ValueError:
                        continue
                    record = {"ip": str(ip), "record_type": "A" if ip.version == 4 else "AAAA", "source": "urlscan"}
                    observed_at = task.get("time")
                    if isinstance(observed_at, str) and observed_at:
                        record["first_seen"] = observed_at
                        record["last_seen"] = observed_at
                    histories[host][(record["ip"], observed_at)] = record
            sort = page_results[-1].get("sort") if page_results and isinstance(page_results[-1], dict) else None
            next_cursor = ",".join(map(str, sort)) if isinstance(sort, list) and len(sort) == 2 else None
            if len(page_results) < self.page_size or not next_cursor or next_cursor == cursor:
                break
            cursor = next_cursor
        return results, histories, certificate_candidates

    @staticmethod
    def valid_time(value):
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        except ValueError:
            return None

    @staticmethod
    def cert_time(value):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
        except (ValueError, TypeError, OverflowError):
            return None

    def collect_certificate_candidate(self, candidates, host, result, task, page):
        if self.max_certificate_results == 0:
            return
        page_url = page.get("url", "")
        scan_id = task.get("uuid") or result.get("_id")
        if not isinstance(page_url, str) or not page_url.startswith("https://"):
            return
        if not isinstance(scan_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", scan_id):
            return
        if not page.get("tlsIssuer") and not page.get("tlsValidFrom"):
            return
        observed = self.valid_time(task.get("time"))
        key = (host, str(page.get("tlsIssuer")), str(page.get("tlsValidFrom")), str(page.get("tlsValidDays")))
        existing = candidates.get(key)
        if existing:
            if observed:
                existing["first_seen"] = min(existing["first_seen"], observed) if existing["first_seen"] else observed
                existing["last_seen"] = max(existing["last_seen"], observed) if existing["last_seen"] else observed
            if page.get("ip"):
                existing["ips"].add(page["ip"])
            return
        candidates[key] = {
            "host": host,
            "scan_id": scan_id,
            "first_seen": observed,
            "last_seen": observed,
            "ips": {page["ip"]} if page.get("ip") else set(),
        }

    async def certificate_history(self, candidates):
        observations = {}
        for candidate in list(candidates.values())[: self.max_certificate_results]:
            scan_id = candidate["scan_id"]
            result_url = f"{self.base_url}/result/{scan_id}/"
            response = await self.helpers.request(result_url, headers=self.request_headers)
            if response is None or response.status_code != 200:
                continue
            try:
                result = response.json()
            except ValueError:
                continue
            if not isinstance(result, dict):
                continue
            host = candidate["host"]
            data = result.get("data")
            lists = result.get("lists")
            requests = data.get("requests", []) if isinstance(data, dict) else []
            if not isinstance(requests, list):
                continue
            matched = []
            for item in requests:
                if not isinstance(item, dict):
                    continue
                request_part = item.get("request")
                response_part = item.get("response")
                request = request_part.get("request", {}) if isinstance(request_part, dict) else {}
                received = response_part.get("response", {}) if isinstance(response_part, dict) else {}
                if not isinstance(request, dict) or not isinstance(received, dict):
                    continue
                requested_url = request.get("url", "")
                try:
                    parsed = urlparse(requested_url) if isinstance(requested_url, str) else None
                    in_scope = parsed is not None and parsed.scheme == "https" and parsed.hostname == host
                except ValueError:
                    in_scope = False
                if not in_scope:
                    continue
                security = received.get("securityDetails")
                if not isinstance(security, dict) or not security.get("subjectName"):
                    continue
                matched.append((security, received.get("remoteIPAddress")))
            # lists.certificates is a page-wide list, including third-party resources.
            # Use it only when the certificate subject itself identifies this host.
            if not matched and isinstance(lists, dict):
                certificates = lists.get("certificates", [])
                if isinstance(certificates, list):
                    matched = [
                        (certificate, None)
                        for certificate in certificates
                        if isinstance(certificate, dict)
                        and self.certificate_subject_matches(host, certificate.get("subjectName"))
                    ]
            for security, remote_ip in matched:
                subject = security["subjectName"]
                issuer = security.get("issuer")
                valid_from = self.cert_time(security.get("validFrom"))
                valid_to = self.cert_time(security.get("validTo"))
                raw_sans = security.get("sanList")
                sans = (
                    sorted({name for name in raw_sans if isinstance(name, str)}) if isinstance(raw_sans, list) else []
                )
                identity = (host, subject, issuer, valid_from, valid_to, tuple(sans))
                record = observations.get(identity)
                if record is None:
                    record = {
                        "host": host,
                        "source": "urlscan",
                        "subject_name": subject,
                        "issuer": issuer,
                        "san_domains": sans,
                        "valid_from": valid_from,
                        "valid_to": valid_to,
                        "first_seen": candidate["first_seen"],
                        "last_seen": candidate["last_seen"],
                        "observed_ips": [],
                        "result_urls": [],
                    }
                    observations[identity] = record
                for field, fn in (("first_seen", min), ("last_seen", max)):
                    current, incoming = record[field], candidate[field]
                    if incoming:
                        record[field] = fn(current, incoming) if current else incoming
                ips = set(candidate["ips"])
                if remote_ip:
                    ips.add(remote_ip)
                for ip in ips:
                    try:
                        normalized = str(ipaddress.ip_address(ip))
                    except ValueError:
                        continue
                    if normalized not in record["observed_ips"]:
                        record["observed_ips"].append(normalized)
                if result_url not in record["result_urls"] and len(record["result_urls"]) < 5:
                    record["result_urls"].append(result_url)
        return list(observations.values())

    @staticmethod
    def certificate_subject_matches(host, subject):
        if not isinstance(subject, str):
            return False
        subject = subject.lower().rstrip(".")
        if subject == host:
            return True
        if subject.startswith("*."):
            suffix = subject[2:]
            return host.endswith(f".{suffix}") and host.count(".") == suffix.count(".") + 1
        return False
