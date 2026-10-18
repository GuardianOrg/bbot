"""Verify direct website origins after passive discovery has completed."""

import asyncio
import base64
import hashlib
import html
import ipaddress
import re
import socket
import ssl
import zlib
from collections import defaultdict
from difflib import SequenceMatcher
from urllib.parse import urlencode, urlparse

import mmh3

from bbot.modules.base import BaseModule
from bbot.modules.internal.cloudcheck import cloud_ip_metadata, frontend_cname_evidence


COMMON_HTTP_PORTS = (80, 443, 8080, 8443, 8000, 8888, 8081, 3000, 8008, 9443)
HTTP_PORTS = tuple((port, port in {443, 8443, 9443}) for port in COMMON_HTTP_PORTS)
ORIGIN_NAMES = ("origin", "direct", "api", "staging", "admin", "mail", "backend", "app")
FRONTEND_TAGS = {"cdn", "waf", "load-balancer", "fronted-proxy"}
MAX_API_PAGES = 5
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TEXT_RE = re.compile(r"<script\b.*?</script>|<style\b.*?</style>|<[^>]+>", re.I | re.S)
RESOURCE_RE = re.compile(r"<(?:script|link|img)\b[^>]*?\b(?:src|href)\s*=\s*['\"]([^'\"]+)", re.I)
MAX_BODY_BYTES = 65536


def public_ip(value):
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def website_text(body):
    value = html.unescape(TEXT_RE.sub(" ", body.decode("utf-8", errors="replace")))
    return " ".join(value.lower().split())[:24000]


def website_title(body):
    match = TITLE_RE.search(body.decode("utf-8", errors="replace"))
    return " ".join(html.unescape(match.group(1)).lower().split())[:250] if match else ""


def website_resources(body):
    page = body.decode("utf-8", errors="replace")
    paths = set()
    for value in RESOURCE_RE.findall(page):
        path = urlparse(html.unescape(value)).path.lower().rstrip("/")
        if len(path) >= 12:
            paths.add(path)
    return paths


def decode_http_body(headers, body):
    """Normalize wire framing and compression before comparing website content."""
    if re.search(r"(?im)^transfer-encoding:\s*[^\r\n]*\bchunked\b", headers):
        decoded = bytearray()
        offset = 0
        while offset < len(body) and len(decoded) < MAX_BODY_BYTES:
            line_end = body.find(b"\r\n", offset)
            if line_end < 0:
                break
            try:
                chunk_size = int(body[offset:line_end].split(b";", 1)[0], 16)
            except ValueError:
                break
            offset = line_end + 2
            if chunk_size == 0 or offset + chunk_size + 2 > len(body):
                break
            decoded.extend(body[offset : offset + chunk_size])
            offset += chunk_size
            if body[offset : offset + 2] != b"\r\n":
                break
            offset += 2
        body = bytes(decoded)
    encoding = re.search(r"(?im)^content-encoding:\s*(gzip|deflate)\s*$", headers)
    if encoding:
        try:
            wbits = 16 + zlib.MAX_WBITS if encoding.group(1).lower() == "gzip" else zlib.MAX_WBITS
            body = zlib.decompressobj(wbits).decompress(body, MAX_BODY_BYTES)
        except zlib.error:
            return b""
    return body[:MAX_BODY_BYTES]


def same_host_redirect_path(response, host):
    if response is None or response["status"] not in {301, 302, 307, 308}:
        return None
    match = re.search(r"(?im)^location:\s*(\S+)", response["headers"])
    if not match:
        return None
    destination = urlparse(match.group(1).strip())
    if destination.hostname and destination.hostname.lower() != host:
        return None
    path = destination.path or "/"
    if path == "/" and not destination.query:
        return None
    return path + (f"?{destination.query}" if destination.query else "")


def similarity(reference, candidate):
    if reference["status"] != 200 or candidate["status"] != 200:
        return 0.0
    first, second = website_text(reference["body"]), website_text(candidate["body"])
    if hashlib.sha256(reference["body"]).digest() == hashlib.sha256(candidate["body"]).digest():
        return 1.0
    reference_title, candidate_title = website_title(reference["body"]), website_title(candidate["body"])
    if not reference_title or reference_title != candidate_title:
        return 0.0
    if len(first) >= 160 and len(second) >= 160:
        tokens_a, tokens_b = set(first.split()), set(second.split())
        if len(tokens_a) >= 20 and len(tokens_b) >= 20:
            overlap = len(tokens_a & tokens_b) / len(tokens_a | tokens_b)
            if overlap >= 0.82:
                text_score = min(overlap, SequenceMatcher(None, first, second, autojunk=True).ratio())
                if text_score >= 0.88:
                    return text_score
    # Single-page apps can have almost no visible HTML text. Matching several
    # distinctive asset paths plus the exact title is a stronger fallback than
    # matching a short placeholder such as "Loading...".
    resources_a, resources_b = website_resources(reference["body"]), website_resources(candidate["body"])
    if min(len(resources_a), len(resources_b)) < 8:
        return 0.0
    overlap = len(resources_a & resources_b) / len(resources_a | resources_b)
    return overlap if overlap >= 0.90 else 0.0


async def fetch_website(address, host, port, tls, path="/", timeout=4):
    """Connect to an IP while sending the real Host and TLS SNI; never follow redirects."""
    context = None
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, ssl=context, server_hostname=host if tls else None), timeout
        )
        host_header = host if port in (80, 443) else f"{host}:{port}"
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Mozilla/5.0 "
            "(compatible; GuardianOriginFinder/1.0)\r\nAccept: text/html,*/*\r\n"
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout)
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        body = bytearray()
        while len(body) < 131072:
            chunk = await asyncio.wait_for(reader.read(min(16384, 131072 - len(body))), timeout)
            if not chunk:
                break
            body.extend(chunk)
        status = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", header)
        if not status:
            return None
        cert = writer.get_extra_info("ssl_object")
        cert_der = cert.getpeercert(binary_form=True) if cert else None
        return {
            "status": int(status.group(1)),
            "body": decode_http_body(header.decode("latin-1"), bytes(body)),
            "headers": header.decode("latin-1"),
            "cert_sha256": hashlib.sha256(cert_der).hexdigest() if cert_der else None,
            "cert_sha1": hashlib.sha1(cert_der).hexdigest() if cert_der else None,
        }
    except (
        OSError,
        asyncio.TimeoutError,
        asyncio.IncompleteReadError,
        asyncio.LimitOverrunError,
        ssl.SSLError,
        UnicodeError,
    ):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


class originfinder(BaseModule):
    watched_events = [
        "DNS_NAME",
        "URL",
        "HTTP_RESPONSE",
        "GEOLOCATION",
        "DOMAIN_DNS_HISTORY",
        "DOMAIN_CERTIFICATE_HISTORY",
        "RAW_DNS_RECORD",
        "OPEN_TCP_PORT",
    ]
    produced_events = ["WEB_FRONTEND", "WEB_ORIGIN", "IP_ADDRESS", "OPEN_TCP_PORT", "FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Find and verify public website origins behind managed frontends",
        "created_date": "2026-10-18",
        "author": "@carlospolop",
    }
    options = {"shodan_api_key": "", "censys_api_key": "", "censys_organization_id": ""}
    options_desc = {
        "shodan_api_key": "Optional Shodan key for certificate and favicon pivots",
        "censys_api_key": "Optional Censys Platform PAT for certificate pivots",
        "censys_organization_id": "Censys Starter or paid organization UUID required for API search",
    }
    _qsize = 100

    async def setup(self):
        self.websites = {}
        self.host_events = {}
        self.ip_frontends = {}
        self.ip_classifications = {}
        self.histories = defaultdict(dict)
        self.ports = defaultdict(set)
        self.certificates = defaultdict(set)
        self.api_cache = {}
        self.processed_hosts = {}
        self.reported_origins = set()
        self.shodan_key = str(self.config.get("shodan_api_key", "") or "").strip()
        self.censys_key = str(self.config.get("censys_api_key", "") or "").strip()
        self.censys_organization_id = str(self.config.get("censys_organization_id", "") or "").strip()
        return True

    async def filter_event(self, event):
        if event.scope_distance != 0:
            return False, "origin discovery only uses in-scope evidence"
        return True

    def add_candidate(self, host, value, source, port=None):
        ip = public_ip(value)
        if ip:
            item = self.histories[host].setdefault(ip, {"sources": set(), "ports": set()})
            item["sources"].add(source)
            try:
                numeric_port = int(port)
            except (TypeError, ValueError):
                numeric_port = 0
            if 1 <= numeric_port <= 65535:
                item["ports"].add(numeric_port)

    async def handle_event(self, event):
        data = event.data
        if event.type == "DNS_NAME":
            host = str(data).lower().rstrip(".")
            self.host_events[host] = event
            for ip in (
                set(event.resolved_hosts)
                | set(event.dns_children.get("A", ()))
                | set(event.dns_children.get("AAAA", ()))
            ):
                self.add_candidate(host, ip, "current-dns")
            return
        if event.type == "GEOLOCATION" and isinstance(data, dict):
            ip = public_ip(data.get("ip"))
            if ip and data.get("isFrontedProxy") is True:
                self.ip_frontends[ip] = data
            return
        if event.type == "DOMAIN_DNS_HISTORY" and isinstance(data, dict):
            host = str(data.get("host") or "").lower().rstrip(".")
            for record in data.get("records") or []:
                if isinstance(record, dict):
                    self.add_candidate(
                        host, record.get("ip"), f"historical-dns:{record.get('source') or event.module}"
                    )
            return
        if event.type == "DOMAIN_CERTIFICATE_HISTORY" and isinstance(data, dict):
            host = str(data.get("host") or "").lower().rstrip(".")
            for ip in data.get("observed_ips") or []:
                self.add_candidate(host, ip, f"certificate-history:{data.get('source') or event.module}")
            fingerprint = str(data.get("fingerprint_sha256") or "").lower()
            if re.fullmatch(r"[a-f0-9]{64}", fingerprint):
                self.certificates[host].add(fingerprint)
            return
        if event.type == "RAW_DNS_RECORD" and isinstance(data, dict):
            host = str(data.get("host") or "").lower().rstrip(".")
            if str(data.get("type") or "").upper() in {"A", "AAAA"}:
                self.add_candidate(host, data.get("answer"), "dns-record")
            return
        if event.type == "OPEN_TCP_PORT":
            match = re.match(r"^\[?([0-9a-f:.]+)\]?:([0-9]{1,5})$", str(data), re.I)
            if match and public_ip(match.group(1)):
                self.ports[public_ip(match.group(1))].add(int(match.group(2)))
            return
        if event.type in {"URL", "HTTP_RESPONSE"}:
            url = str(data.get("url") if isinstance(data, dict) else data)
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if not host or public_ip(host) or parsed.scheme not in {"http", "https"} or parsed.path not in {"", "/"}:
                return
            website = self.websites.setdefault(host, {"urls": {}, "ips": set(), "cnames": set(), "certs": set()})
            website["urls"][f"{parsed.scheme}://{parsed.netloc}/"] = event
            website["ips"].update(filter(None, (public_ip(ip) for ip in event.resolved_hosts)))
            website["cnames"].update(str(name) for name in event.dns_children.get("CNAME", ()))
            website["certs"].update(self.certificates.get(host, ()))
            if isinstance(data, dict):
                for key in ("certFingerprintSha256", "cert_fingerprint_sha256"):
                    fingerprint = str(data.get(key) or "").lower()
                    if re.fullmatch(r"[a-f0-9]{64}", fingerprint):
                        website["certs"].add(fingerprint)

    async def finish(self):
        # Classify every known managed-frontend DNS answer before testing any
        # candidate. A load balancer can use an ordinary cloud IP range, so a
        # range lookup alone would not exclude its address as another origin.
        for domain_event in self.host_events.values():
            cname_frontend = frontend_cname_evidence(domain_event.dns_children.get("CNAME", ()))
            if cname_frontend:
                for raw_ip in (
                    set(domain_event.resolved_hosts)
                    | set(domain_event.dns_children.get("A", ()))
                    | set(domain_event.dns_children.get("AAAA", ()))
                ):
                    ip = public_ip(raw_ip)
                    if ip:
                        self.ip_frontends.setdefault(ip, cloud_ip_metadata(ip, None, (), cname_frontend))
        for host, website in sorted(self.websites.items()):
            current = website["ips"]
            domain_event = self.host_events.get(host)
            if domain_event is not None:
                current.update(filter(None, (public_ip(ip) for ip in domain_event.resolved_hosts)))
                current.update(filter(None, (public_ip(ip) for ip in domain_event.dns_children.get("A", ()))))
                current.update(filter(None, (public_ip(ip) for ip in domain_event.dns_children.get("AAAA", ()))))
                website["cnames"].update(str(name) for name in domain_event.dns_children.get("CNAME", ()))
            cname_frontend = frontend_cname_evidence(website["cnames"])
            if current and not cname_frontend:
                await asyncio.gather(*(self.is_frontend_ip(ip) for ip in current if ip not in self.ip_frontends))
            frontend_ips = {ip for ip in current if ip in self.ip_frontends}
            if not current or not (frontend_ips == current or cname_frontend):
                continue
            signature = self.evidence_signature(host, website)
            if self.processed_hosts.get(host) == signature:
                continue
            parent = self.host_events.get(host) or next(iter(website["urls"].values()))
            url = next((url for url in website["urls"] if url.startswith("https://")), next(iter(website["urls"])))
            frontend_evidence = (
                f"DNS CNAME indicates {cname_frontend[1]} {cname_frontend[0]}"
                if cname_frontend
                else "Current IPs belong to managed frontend ranges"
            )
            frontend = await self.emit_event(
                {
                    "host": host,
                    "url": url,
                    "frontend_ips": sorted(current),
                    "frontend_type": (cname_frontend or ("cdn", "cloudcheck"))[0],
                    "evidence": frontend_evidence,
                },
                "WEB_FRONTEND",
                parent,
                context=f"{{module}} confirmed that {host} resolves through a managed frontend",
            )
            await self.find_origins(host, url, website, frontend or parent)
            # Other modules can emit more passive evidence in later BBOT
            # finishing rounds. Only rerun this website if that input changes.
            self.processed_hosts[host] = self.evidence_signature(host, website)

    def evidence_signature(self, host, website):
        domain = self.helpers.parent_domain(host)
        names = {host, domain}
        names.update(f"{prefix}.{domain}" for prefix in ORIGIN_NAMES)
        if host != domain:
            names.update(f"{prefix}.{host}" for prefix in ORIGIN_NAMES)
        histories = []
        for name in sorted(names):
            for ip, item in sorted(self.histories.get(name, {}).items()):
                histories.append(
                    (
                        name,
                        ip,
                        tuple(sorted(item["sources"])),
                        tuple(sorted(item["ports"])),
                        tuple(sorted(self.ports.get(ip, ()))),
                    )
                )
        return (
            tuple(sorted(website["urls"])),
            tuple(sorted(website["ips"])),
            tuple(sorted(website["cnames"])),
            tuple(sorted(website["certs"])),
            tuple(histories),
        )

    async def find_origins(self, host, url, website, parent):
        baseline = None
        probe_path = "/"
        # Prefer HTTPS, but a stale or broken HTTPS endpoint must not hide a
        # working HTTP website that BBOT discovered on the same hostname.
        for website_url in sorted(website["urls"], key=lambda item: not item.startswith("https://")):
            parsed = urlparse(website_url)
            baseline_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            candidate_baseline = await fetch_website(host, host, baseline_port, parsed.scheme == "https")
            candidate_path = same_host_redirect_path(candidate_baseline, host) or "/"
            if candidate_path != "/":
                candidate_baseline = await fetch_website(
                    host, host, baseline_port, parsed.scheme == "https", candidate_path
                )
            if candidate_baseline is not None and candidate_baseline["status"] == 200:
                baseline = candidate_baseline
                probe_path = candidate_path
                break
        if baseline is None:
            self.verbose(f"No comparable public website response for {host}")
            return
        domain = self.helpers.parent_domain(host)
        if domain != host:
            for ip, item in list(self.histories.get(domain, {}).items()):
                for source in tuple(item["sources"]):
                    self.add_candidate(host, ip, f"root-domain:{source}")
        sibling_names = {f"{name}.{domain}" for name in ORIGIN_NAMES}
        if host != domain:
            sibling_names.update(f"{name}.{host}" for name in ORIGIN_NAMES)
        for sister in sibling_names:
            if sister == host:
                continue
            for ip, item in list(self.histories.get(sister, {}).items()):
                for source in tuple(item["sources"]):
                    self.add_candidate(host, ip, f"sibling:{sister}:{source}")
                for port in item["ports"]:
                    self.add_candidate(host, ip, f"sibling:{sister}", port)
        await self.query_sibling_dns(host, domain)
        website["certs"].update(self.certificates.get(host, ()))
        if baseline.get("cert_sha256"):
            website["certs"].add(baseline["cert_sha256"])
        for ip, port, source in await self.api_candidates(host, website["certs"], baseline):
            self.add_candidate(host, ip, source, port)
        candidates = dict(self.histories.get(host, {}))
        semaphore = asyncio.Semaphore(16)

        async def check(ip, evidence):
            async with semaphore:
                if (host, ip) in self.reported_origins or ip in website["ips"] or await self.is_frontend_ip(ip):
                    return
                observed_ports = sorted(evidence["ports"] | self.ports.get(ip, set()))
                usual_schemes = dict(HTTP_PORTS)
                ports = []
                for port in observed_ports:
                    if port in usual_schemes:
                        ports.append((port, usual_schemes[port]))
                    else:
                        ports.extend(((port, False), (port, True)))
                ports.extend(item for item in HTTP_PORTS if item not in ports)

                async def probe(port, tls):
                    candidate = await fetch_website(ip, host, port, tls, probe_path)
                    score = similarity(baseline, candidate) if candidate else 0.0
                    return score, candidate, port, tls

                # A small per-IP batch is faster than serial timeouts without
                # flooding a single endpoint with all ten requests at once.
                for offset in range(0, len(ports), 3):
                    group = await asyncio.gather(*(probe(port, tls) for port, tls in ports[offset : offset + 3]))
                    for score, candidate, port, tls in sorted(group, key=lambda item: item[0], reverse=True):
                        if score < 0.88:
                            continue
                        control_host = f"no-such-host-{hashlib.sha256(host.encode()).hexdigest()[:12]}.invalid"
                        control = await fetch_website(ip, control_host, port, tls, probe_path)
                        if control is not None and similarity(candidate, control) >= 0.65:
                            continue
                        await self.report_origin(host, url, ip, port, tls, score, candidate, evidence, parent)
                        return
                # The ten common ports are checked with their usual scheme
                # first. A non-standard HTTP/TLS pairing can still be found.
                for offset in range(0, len(HTTP_PORTS), 3):
                    alternatives = [(port, not tls) for port, tls in HTTP_PORTS[offset : offset + 3]]
                    group = await asyncio.gather(*(probe(port, tls) for port, tls in alternatives))
                    for score, candidate, port, tls in sorted(group, key=lambda item: item[0], reverse=True):
                        if score < 0.88:
                            continue
                        control_host = f"no-such-host-{hashlib.sha256(host.encode()).hexdigest()[:12]}.invalid"
                        control = await fetch_website(ip, control_host, port, tls, probe_path)
                        if control is not None and similarity(candidate, control) >= 0.65:
                            continue
                        await self.report_origin(host, url, ip, port, tls, score, candidate, evidence, parent)
                        return

        await asyncio.gather(*(check(ip, item) for ip, item in candidates.items()))

    async def query_sibling_dns(self, host, domain):
        loop = asyncio.get_running_loop()

        async def resolve(name):
            try:
                answers = await asyncio.wait_for(loop.getaddrinfo(name, 443, type=socket.SOCK_STREAM), 3)
            except (OSError, asyncio.TimeoutError):
                return
            for answer in answers:
                self.add_candidate(host, answer[4][0], f"direct-dns:{name}")

        names = {f"{prefix}.{domain}" for prefix in ORIGIN_NAMES}
        if host != domain:
            names.update(f"{prefix}.{host}" for prefix in ORIGIN_NAMES)
        await asyncio.gather(*(resolve(name) for name in names))

    async def is_frontend_ip(self, ip):
        if ip in self.ip_frontends:
            return True
        if ip in self.ip_classifications:
            return self.ip_classifications[ip]
        try:
            providers = await self.helpers.cloudcheck.lookup(ip)
        except Exception as exc:
            self.verbose(f"Could not classify origin candidate {ip}: {type(exc).__name__}")
            return False
        for provider in providers:
            data = cloud_ip_metadata(ip, provider.get("name"), provider.get("tags", ()))
            if data.get("isFrontedProxy"):
                self.ip_frontends[ip] = data
                self.ip_classifications[ip] = True
                return True
        self.ip_classifications[ip] = False
        return False

    async def api_candidates(self, host, fingerprints, baseline):
        results = []
        queries = [f"hostname:{host}"]
        # Shodan's ssl.cert.fingerprint filter is SHA-1; Censys uses SHA-256.
        # Historical BBOT events currently preserve SHA-256 only, so the
        # Shodan certificate pivot uses the live certificate bytes instead.
        if baseline.get("cert_sha1"):
            queries.append(f"ssl.cert.fingerprint:{baseline['cert_sha1']}")
        censys_queries = [f'host.dns.names = "{host}"'] + [
            f'host.services.cert.fingerprint_sha256 = "{fingerprint}"' for fingerprint in fingerprints
        ]
        if len(baseline.get("body", b"")) >= 160:
            body_hash = hashlib.sha256(baseline["body"][:65536]).hexdigest()
            censys_queries.append(f'host.services.endpoints.http.body_hash_sha256 = "{body_hash}"')
        # Shodan indexes favicons by Murmur3 of base64-encoded bytes.
        favicon = await fetch_website(host, host, 443, True, "/favicon.ico")
        if (
            favicon
            and favicon["status"] == 200
            and 8 < len(favicon["body"]) <= 65536
            and b"<html" not in favicon["body"].lower()
        ):
            favicon_hash = mmh3.hash(base64.encodebytes(favicon["body"]))
            queries.append(f"http.favicon.hash:{favicon_hash}")
            favicon_sha256 = hashlib.sha256(favicon["body"]).hexdigest()
            censys_queries.append(f'host.services.endpoints.http.favicons.hash_sha256 = "{favicon_sha256}"')
        if self.shodan_key:
            for query in queries:
                cache_key = ("shodan", query)
                if cache_key in self.api_cache:
                    results.extend(self.api_cache[cache_key])
                    continue
                matches = []
                for page in range(1, MAX_API_PAGES + 1):
                    url = "https://api.shodan.io/shodan/host/search?" + urlencode(
                        {"key": self.shodan_key, "query": query, "page": page}
                    )
                    try:
                        response = await self.helpers.request(url)
                        if response and response.status_code == 200:
                            body = response.json()
                            for hit in body.get("matches", []):
                                ip = public_ip(hit.get("ip_str"))
                                if ip:
                                    matches.append((ip, hit.get("port"), f"shodan:{query.split(':', 1)[0]}"))
                            if page * 100 >= int(body.get("total") or 0) or not body.get("matches"):
                                break
                            if page == MAX_API_PAGES:
                                self.warning(f"Shodan origin pivot truncated after {MAX_API_PAGES} pages: {query}")
                        elif response and response.status_code in {401, 402, 403, 429}:
                            self.warning(f"Shodan origin pivot unavailable (HTTP {response.status_code})")
                            break
                        else:
                            break
                    except Exception as exc:
                        self.verbose(f"Shodan origin pivot failed: {type(exc).__name__}")
                        break
                self.api_cache[cache_key] = matches
                results.extend(matches)
        if self.censys_key and self.censys_organization_id:
            for query in censys_queries:
                cache_key = ("censys", query)
                if cache_key in self.api_cache:
                    results.extend(self.api_cache[cache_key])
                    continue
                matches = []
                page_token = None
                for page in range(MAX_API_PAGES):
                    payload = {
                        "query": query,
                        "page_size": 100,
                        "fields": ["host.ip", "host.services.port", "host.services.protocol"],
                    }
                    if page_token:
                        payload["page_token"] = page_token
                    try:
                        response = await self.helpers.request(
                            "https://api.platform.censys.io/v3/global/search/query?"
                            + urlencode({"organization_id": self.censys_organization_id}),
                            method="POST",
                            headers={
                                "Authorization": f"Bearer {self.censys_key}",
                                "User-Agent": "Mozilla/5.0 (compatible; GuardianOriginFinder/1.0)",
                                "Content-Type": "application/json",
                            },
                            json=payload,
                        )
                        if response and response.status_code == 200:
                            data = response.json().get("result", {})
                            for hit in data.get("hits", []):
                                candidate = hit.get("host_v1", {}).get("resource", {})
                                ip = public_ip(candidate.get("ip"))
                                if ip:
                                    ports = [service.get("port") for service in candidate.get("services", [])]
                                    for port in ports or [None]:
                                        source = (
                                            "favicon"
                                            if "favicons" in query
                                            else "content"
                                            if "body_hash" in query
                                            else "dns-name"
                                            if "host.dns.names" in query
                                            else "certificate"
                                        )
                                        matches.append((ip, port, f"censys:{source}"))
                            page_token = data.get("next_page_token")
                            if not page_token:
                                break
                            if page + 1 == MAX_API_PAGES:
                                self.warning(f"Censys origin pivot truncated after {MAX_API_PAGES} pages: {query}")
                        elif response and response.status_code in {401, 402, 403, 429}:
                            self.warning(f"Censys origin pivot unavailable (HTTP {response.status_code})")
                            break
                        else:
                            break
                    except Exception as exc:
                        self.verbose(f"Censys origin pivot failed: {type(exc).__name__}")
                        break
                self.api_cache[cache_key] = matches
                results.extend(matches)
        return results

    async def report_origin(self, host, url, ip, port, tls, score, response, evidence, parent):
        if (host, ip) in self.reported_origins:
            return
        endpoint = f"{ip}:{port}/tcp" if ":" not in ip else f"[{ip}]:{port}/tcp"
        scheme = "https" if tls else "http"
        sources = sorted(evidence["sources"])
        proof = (
            f"A direct {scheme.upper()} request to {ip}:{port} with Host and TLS SNI set to {host} "
            f"returned HTTP 200 and matched the public website (similarity {score:.2f}; "
            f"title {website_title(response['body'])!r}). A random Host/SNI did not return the same page. "
            f"Candidate sources: {', '.join(sources)}."
        )
        origin = await self.emit_event(
            {
                "host": host,
                "url": url,
                "ip": ip,
                "port": port,
                "protocol": scheme,
                "confidence": round(score, 3),
                "sources": sources,
                "evidence": proof,
            },
            "WEB_ORIGIN",
            parent,
            context=f"{{module}} verified a direct origin IP for {host} at {ip}:{port}",
        )
        # A verified origin is intentionally in scope even though its address is
        # not in the current DNS RRset. Make this explicit before dispatch so
        # the remaining BBOT modules can inspect it during the finishing cycle.
        ip_event = self.make_event(
            ip,
            "IP_ADDRESS",
            origin or parent,
            context=f"{{module}} added verified website origin {ip} to scope",
        )
        if ip_event is not None:
            ip_event.scope_distance = 0
            await self.emit_event(ip_event)
        await self.emit_event(
            f"{ip}:{port}" if ":" not in ip else f"[{ip}]:{port}",
            "OPEN_TCP_PORT",
            ip_event or origin or parent,
            context=f"{{module}} verified HTTP on website origin {ip}:{port}",
        )
        await self.emit_event(
            {
                "host": host,
                "url": url,
                "ip": ip,
                "port": port,
                "affected_endpoints": [endpoint],
                "category": "origin-ip-exposure",
                "title": f"Public origin IP exposed for {host}",
                "description": proof,
                "evidence": proof,
                "sources": sources,
                "dedupe_key": f"origin-ip-exposure:{host}:{ip}:{port}",
            },
            "FINDING",
            origin or parent,
            context=f"{{module}} found {{event.type}} for {host} at {ip}:{port}",
        )
        self.reported_origins.add((host, ip))
