from bbot.modules.base import BaseModule
import time


class shodan_idb(BaseModule):
    """
    Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities

    InternetDB is especially nice because it doesn't require an API key

    API reference: https://internetdb.shodan.io/docs

    Example API response:

    {
        "cpes": [
            "cpe:/a:microsoft:internet_information_services",
            "cpe:/a:microsoft:outlook_web_access:15.0.1367",
        ],
        "hostnames": [
            "autodiscover.evilcorp.com",
            "mail.evilcorp.com",
        ],
        "ip": "1.2.3.4",
        "ports": [
            25,
            80,
            443,
        ],
        "tags": [
            "starttls",
            "self-signed",
            "eol-os"
        ],
        "vulns": [
            "CVE-2021-26857",
            "CVE-2021-26855"
        ]
    }
    """

    watched_events = ["DNS_NAME", "IP_ADDRESS", "IP_RANGE"]
    produced_events = [
        "IP_ADDRESS",
        "TECHNOLOGY",
        "VULNERABILITY",
        "FINDING",
        "OPEN_TCP_PORT",
        "OPEN_UDP_PORT",
        "PROTOCOL",
        "DNS_NAME",
        "GEOLOCATION",
    ]
    flags = ["passive", "safe", "portscan", "ip-enum"]
    meta = {
        "description": "Query Shodan's InternetDB for open ports, hostnames, technologies, and vulnerabilities",
        "created_date": "2023-12-22",
        "author": "@TheTechromancer",
    }
    options = {"retries": None, "api_key": "", "full_host": True, "max_range_pages": 3, "max_open_ports_per_ip": 70}
    options_desc = {
        "retries": "How many times to retry API requests (e.g. after a 429 error). Overrides the global web.api_retries setting.",
        "api_key": "Optional Shodan API key. If present, shodan_idb also queries /shodan/host/{ip} for OS/provider metadata.",
        "full_host": "Use the authenticated Shodan host API when an API key is available.",
        "max_range_pages": "Maximum authenticated /shodan/host/search result pages to fetch for an IP range target.",
        "max_open_ports_per_ip": "Discard this module's OPEN_TCP_PORT/OPEN_UDP_PORT results for an IP when more than this many ports are found",
    }

    # we typically don't want to abort this module
    _api_failure_abort_threshold = 9999999999

    # since there are rate limits, we set a lower qsize
    # this way when our queue is full, we can give the API a break
    _qsize = 100
    scope_distance_modifier = 1

    base_url = "https://internetdb.shodan.io"

    async def setup(self):
        await super().setup()
        self.last_request_time = 0
        self.queried_ips = set()
        self.queried_ranges = set()
        self.reported_vulnerabilities = set()
        self.full_host = bool(self.config.get("full_host", True))
        self.max_range_pages = max(1, int(self.config.get("max_range_pages", 3)))
        self.max_open_ports_per_ip = max(1, int(self.config.get("max_open_ports_per_ip", 70)))
        self.api_key = self.get_shodan_api_keys()
        return True

    async def filter_event(self, event):
        if event.type == "DNS_NAME" and event.scope_distance > 0:
            return False, "only querying Shodan IDB for in-scope DNS names"
        return True

    def get_shodan_api_keys(self):
        api_keys = set()
        for module_name in ("shodan", "shodan_dns", "shodan_port", "shodan_idb"):
            module_config = self.scan.config.get("modules", {}).get(module_name, {})
            api_key = module_config.get("api_key", "")
            if isinstance(api_key, str):
                api_key = [api_key]
            elif api_key is None:
                api_key = []
            for key in api_key:
                key = self.clean_api_key(key)
                if key:
                    api_keys.add(key)
        return list(api_keys)

    def clean_api_key(self, key):
        key = str(key or "").strip()
        if "#" in key:
            key = key.split("#", 1)[0].strip()
        return key.strip("\"'")

    def _incoming_dedup_hash(self, event):
        ip = self.get_ip(event)
        return hash(str(ip or event.data).strip().lower())

    @property
    def api_retries(self):
        # allow the module to override global retry setting
        return self.config.get("retries", None) or super().api_retries

    async def handle_event(self, event):
        if event.type == "IP_RANGE":
            await self.handle_range_event(event)
            return

        ip = self.get_ip(event)
        if ip is None:
            return
        ip = str(ip).strip()
        if ip in self.queried_ips:
            return
        self.queried_ips.add(ip)
        url = f"{self.base_url}/{ip}"

        # Rate limiting: ensure at least 1 second between requests
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < 1:
            await self.helpers.sleep(1 - time_since_last)

        # Update the last request time
        self.last_request_time = time.time()

        r = await self.helpers.request(url)
        if r is None:
            self.debug(f"No response for {event.data}")
            return
        try:
            data = r.json()
        except Exception as e:
            self.verbose(f"Error parsing JSON response from {url}: {e}")
            self.trace()
            return
        if data:
            if r.status_code == 200:
                await self._parse_response(data=data, event=event, ip=ip)
                await self._parse_host_response(data=data, event=event, ip=ip, source="InternetDB")
            elif r.status_code == 404:
                detail = data.get("detail", "")
                if detail:
                    self.debug(f"404 response for {url}: {detail}")
            else:
                err_data = data.get("type", "")
                err_msg = data.get("msg", "")
                self.verbose(f"Shodan error for {ip}: {err_data}: {err_msg}")

        if self.full_host and self.api_key:
            await self.query_full_host(event, ip)

    async def handle_range_event(self, event):
        cidr = str(event.data).strip()
        if not cidr or cidr in self.queried_ranges:
            return
        self.queried_ranges.add(cidr)

        if not self.api_key:
            self.debug(f"Skipping authenticated Shodan range search for {cidr}: no API key configured")
            return

        seen_matches = 0
        for page in range(1, self.max_range_pages + 1):
            url = (
                f"https://api.shodan.io/shodan/host/search?key={self.api_key}"
                f"&query={self.helpers.quote(f'net:{cidr}')}&page={page}&minify=false"
            )
            r = await self.helpers.request(url)
            if r is None:
                self.cycle_api_key()
                continue
            try:
                data = r.json()
            except Exception as e:
                self.verbose(f"Error parsing JSON response from Shodan host search for {cidr}: {e}")
                self.trace()
                return

            if r.status_code == 200 and isinstance(data, dict):
                matches = data.get("matches", [])
                if not isinstance(matches, list) or not matches:
                    return
                for match in matches:
                    if isinstance(match, dict):
                        await self.emit_range_match(match, event, cidr)
                        seen_matches += 1
                total = data.get("total")
                if not isinstance(total, int) or seen_matches >= total:
                    return
                continue

            if r.status_code in (401, 402, 403, 404):
                return

            err_data = data.get("error", data.get("type", "")) if isinstance(data, dict) else ""
            err_msg = data.get("msg", "") if isinstance(data, dict) else ""
            self.verbose(f"Shodan host search error for {cidr}: {err_data}: {err_msg}")
            self.cycle_api_key()

    async def emit_range_match(self, data, event, cidr):
        ip = self.clean_string(data.get("ip_str") or data.get("ip"))
        if not ip:
            return

        ip_event = self.make_event(ip, "IP_ADDRESS", parent=event)
        if ip_event is None:
            return

        self.queried_ips.add(ip)
        await self.emit_event(
            ip_event,
            context=f'{{module}} queried Shodan host search for "net:{cidr}" and found {{event.type}}: {{event.data}}',
        )
        await self._parse_response(data=data, event=ip_event, ip=ip)
        await self._parse_host_response(data=data, event=ip_event, ip=ip, source=f"Shodan host search net:{cidr}")

    async def query_full_host(self, event, ip):
        for _ in range(self.api_retries):
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
            r = await self.helpers.request(url)
            if r is None:
                self.cycle_api_key()
                continue
            try:
                data = r.json()
            except Exception as e:
                self.verbose(f"Error parsing JSON response from Shodan host API for {ip}: {e}")
                self.trace()
                return
            if r.status_code == 200 and isinstance(data, dict):
                await self._parse_host_response(data=data, event=event, ip=ip, source="Shodan host API")
                return
            if r.status_code in (401, 402, 403, 404):
                return
            err_data = data.get("error", data.get("type", "")) if isinstance(data, dict) else ""
            err_msg = data.get("msg", "") if isinstance(data, dict) else ""
            self.verbose(f"Shodan host API error for {ip}: {err_data}: {err_msg}")
            self.cycle_api_key()

    async def _parse_response(self, data: dict, event, ip):
        """Handles emitting events from returned JSON"""
        data: dict  # has keys: cpes, hostnames, ip, ports, tags, vulns
        ip = str(ip)
        query_host = ip if event.data == ip else f"{event.data} ({ip})"
        # ip is a string, ports is a list of ports, the rest is a list of strings
        for hostname in data.get("hostnames", []):
            if hostname != event.data:
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    parent=event,
                    context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.data}}',
                )
        for cpe in data.get("cpes", []):
            await self.emit_event(
                {"technology": cpe, "host": str(event.host)},
                "TECHNOLOGY",
                parent=event,
                context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.data}}',
            )
        ports = sorted({port for port in data.get("ports", []) if isinstance(port, int)})
        if len(ports) > self.max_open_ports_per_ip:
            self.warning(
                f"shodan_idb found {len(ports):,} open TCP ports on {ip}; discarding this module's port results for that IP because the limit is {self.max_open_ports_per_ip:,}"
            )
        else:
            for port in ports:
                await self.emit_event(
                    self.helpers.make_netloc(event.data, port),
                    "OPEN_TCP_PORT",
                    parent=event,
                    context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.data}}',
                )
        await self.emit_vulnerability_events(data=data, event=event, ip=ip, query_host=query_host, source="Shodan InternetDB")

    async def _parse_host_response(self, data: dict, event, ip, source):
        tags = self.normalize_string_list(data.get("tags", []))
        hostnames = self.normalize_string_list(data.get("hostnames", []))
        services = data.get("data", [])
        service_os = self.first_service_os(services)
        os_name = self.clean_os(data.get("os")) or service_os
        org = self.clean_string(data.get("org"))
        isp = self.clean_string(data.get("isp")) or org
        asn = self.clean_asn(data.get("asn"))
        provider = self.detect_cloud_provider(data)
        is_cdn, cdn_name = self.detect_cdn(data, tags)
        privacy_flags = self.detect_privacy_flags(tags)

        geo_data = {
            "ip": str(ip),
            "country": self.clean_string(data.get("country_name")),
            "region": self.clean_string(data.get("region_code")),
            "city": self.clean_string(data.get("city")),
            "latitude": data.get("latitude") if isinstance(data.get("latitude"), (int, float)) else None,
            "longitude": data.get("longitude") if isinstance(data.get("longitude"), (int, float)) else None,
            "asn": asn,
            "isp": isp,
            "reverseDns": hostnames,
            "os": os_name,
            "cloudProvider": provider,
            "providerType": self.provider_type(provider=provider, cdn_name=cdn_name, privacy_flags=privacy_flags, tags=tags),
            "isCdn": True if is_cdn else None,
            "cdnName": cdn_name,
            **privacy_flags,
        }
        geo_data = {k: v for k, v in geo_data.items() if v not in (None, "", [])}
        if len(geo_data) > 1:
            await self.emit_event(
                geo_data,
                "GEOLOCATION",
                parent=event,
                context=f'{{module}} queried {source} for "{ip}" and found {{event.type}} metadata',
            )

        await self.emit_protocol_events(services, event, ip, source)
        await self.emit_vulnerability_events(data=data, event=event, ip=ip, query_host=ip, source=source)

    async def emit_protocol_events(self, services, event, ip, source):
        if not isinstance(services, list):
            return

        service_ports = {
            (service.get("port"), self.clean_string(service.get("transport")) or "tcp")
            for service in services
            if isinstance(service, dict) and isinstance(service.get("port"), int)
        }
        if len(service_ports) > self.max_open_ports_per_ip:
            self.warning(
                f"shodan_idb found {len(service_ports):,} service ports on {ip}; discarding this module's service results for that IP because the limit is {self.max_open_ports_per_ip:,}"
            )
            return

        for service in services:
            if not isinstance(service, dict):
                continue
            port = service.get("port")
            if not isinstance(port, int):
                continue

            transport = self.clean_string(service.get("transport")) or "tcp"
            await self.emit_event(
                self.helpers.make_netloc(event.data, port),
                "OPEN_UDP_PORT" if transport.lower() == "udp" else "OPEN_TCP_PORT",
                parent=event,
                context=f'{{module}} queried {source} for "{ip}" and found {{event.type}}: {{event.data}}',
            )

            protocol = self.service_protocol(service)
            if not protocol:
                continue

            protocol_data = {
                "host": str(event.host or event.data or ip),
                "ip": ip,
                "port": port,
                "transport": transport.lower(),
                "protocol": protocol,
                "banner": self.clean_string(service.get("data")),
                "product": self.clean_string(service.get("product")),
                "version": self.clean_string(service.get("version")),
                "os": self.clean_os(service.get("os")),
                "tls_version": self.service_tls_version(service),
                "cipher_suite": self.service_cipher_suite(service),
                "cpes": self.service_cpes(service),
            }
            protocol_data = {k: v for k, v in protocol_data.items() if v not in (None, "", [])}
            await self.emit_event(
                protocol_data,
                "PROTOCOL",
                parent=event,
                context=f'{{module}} queried {source} for "{ip}" and found {{event.type}} details on port {port}',
            )

    async def emit_vulnerability_events(self, data, event, ip, query_host, source):
        tags = self.normalize_string_list(data.get("tags", []))
        is_cdn, cdn_name = self.detect_cdn(data, tags)
        if is_cdn:
            provider = cdn_name or "shared CDN"
            self.debug(
                f"Suppressing Shodan vulnerability attribution for {ip}: the address belongs to {provider} infrastructure"
            )
            return

        for vuln in self.iter_vulnerabilities(data):
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue
            dedupe_key = (str(ip), str(vuln_id))
            if dedupe_key in self.reported_vulnerabilities:
                continue
            self.reported_vulnerabilities.add(dedupe_key)

            await self.emit_event(
                {
                    "host": str(ip),
                    "severity": self.vulnerability_severity(vuln.get("cvss")),
                    "title": f"Shodan detected {vuln_id}",
                    "category": "Shodan",
                    "description": self.vulnerability_description(vuln_id, vuln.get("summary"), query_host, source),
                    "recommendation": "Validate the exposed service, confirm the fingerprint, and remediate or patch the affected software if the issue is present.",
                    "evidence": self.vulnerability_evidence(vuln_id, source, vuln.get("cvss")),
                    "cve": vuln_id,
                },
                "VULNERABILITY",
                parent=event,
                context=f'{{module}} queried {source} for "{query_host}" and found {{event.type}}: {vuln_id}',
            )

    def detect_privacy_flags(self, tags):
        normalized = {tag.lower() for tag in tags}
        flags = {}
        if "tor" in normalized:
            flags["isTor"] = True
        if "proxy" in normalized:
            flags["isProxy"] = True
        if "vpn" in normalized:
            flags["isVpn"] = True
        return flags

    def detect_cloud_provider(self, data):
        provider = self.extract_cloud_provider(data)
        if provider:
            return self.normalize_cloud_provider(provider)
        services = data.get("data", [])
        if isinstance(services, list):
            for service in services:
                if not isinstance(service, dict):
                    continue
                provider = self.extract_cloud_provider(service)
                if provider:
                    return self.normalize_cloud_provider(provider)
        return None

    def extract_cloud_provider(self, data):
        cloud = data.get("cloud") if isinstance(data, dict) else None
        if not isinstance(cloud, dict):
            return None
        return self.clean_string(cloud.get("provider"))

    def normalize_cloud_provider(self, provider):
        provider = provider.strip().lower()
        return {
            "amazon": "aws",
            "aws": "aws",
            "microsoft": "azure",
            "azure": "azure",
            "google": "gcp",
            "gcp": "gcp",
        }.get(provider, provider)

    def detect_cdn(self, data, tags):
        text = self.enrichment_text(data, tags)
        cdns = {
            "cloudflare": "cloudflare",
            "cloudfront": "cloudfront",
            "akamai": "akamai",
            "fastly": "fastly",
            "imperva": "imperva",
            "stackpath": "stackpath",
            "bunny": "bunny",
            "edgio": "edgio",
            "limelight": "limelight",
        }
        for marker, cdn in cdns.items():
            if marker in text:
                return True, cdn
        return (True, None) if "cdn" in {tag.lower() for tag in tags} else (False, None)

    def enrichment_text(self, data, tags):
        values = list(tags)
        for key in ("org", "isp", "asn", "as", "country_name"):
            values.append(data.get(key, ""))
        values.extend(data.get("hostnames", []) or [])
        return " ".join(str(value or "").lower() for value in values)

    def provider_type(self, provider, cdn_name, privacy_flags, tags):
        if privacy_flags.get("isTor"):
            return "tor"
        if privacy_flags.get("isVpn"):
            return "vpn"
        if privacy_flags.get("isProxy"):
            return "proxy"
        if cdn_name:
            return "cdn"
        if provider:
            return "cloud"
        if "cloud" in {tag.lower() for tag in tags}:
            return "cloud"
        return None

    def first_service_os(self, services):
        if not isinstance(services, list):
            return None
        for service in services:
            if not isinstance(service, dict):
                continue
            os_name = self.clean_os(service.get("os"))
            if os_name:
                return os_name
        return None

    def normalize_string_list(self, value):
        if not isinstance(value, list):
            return []
        return sorted({str(item).strip() for item in value if str(item).strip()})

    def clean_string(self, value):
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def clean_os(self, value):
        os_name = self.clean_string(value)
        if os_name and os_name.lower() not in ("unknown", "none"):
            return os_name
        return None

    def clean_asn(self, value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            value = value.strip().upper()
            if value.startswith("AS"):
                value = value[2:]
            if value.isdigit():
                return int(value)
        return None

    def get_ip(self, event):
        """
        Get the first available IP address from an event (IP_ADDRESS or DNS_NAME)
        """
        if event.type == "IP_ADDRESS":
            return event.host
        for host in sorted(getattr(event, "resolved_hosts", set())):
            if self.helpers.is_ip(host):
                return host
        return None

    def service_protocol(self, service):
        module = service.get("_shodan", {}) if isinstance(service.get("_shodan"), dict) else {}
        protocol = (
            self.clean_protocol(module.get("module"))
            or self.clean_protocol(service.get("service"))
            or self.protocol_from_banner(service.get("data"))
        )
        return protocol.upper() if protocol else None

    def clean_protocol(self, value):
        protocol = self.clean_string(value)
        if protocol and protocol.lower() not in ("auto", "nodata-tcp", "unknown", "none"):
            return protocol
        return None

    def protocol_from_banner(self, value):
        banner = self.clean_string(value)
        if not banner:
            return None
        banner = banner.lstrip().lower()
        if banner.startswith("http/"):
            return "http"
        if banner.startswith("ssh-"):
            return "ssh"
        if banner.startswith("smtp") or " esmtp" in banner:
            return "smtp"
        if banner.startswith("+ok"):
            return "pop3"
        if banner.startswith("* ok"):
            return "imap"
        return None

    def service_tls_version(self, service):
        ssl_info = service.get("ssl") if isinstance(service.get("ssl"), dict) else {}
        versions = ssl_info.get("versions", []) if isinstance(ssl_info.get("versions", []), list) else []
        for version in versions:
            cleaned = self.clean_string(version)
            if cleaned:
                return cleaned
        return None

    def service_cipher_suite(self, service):
        ssl_info = service.get("ssl") if isinstance(service.get("ssl"), dict) else {}
        cipher = ssl_info.get("cipher") if isinstance(ssl_info.get("cipher"), dict) else {}
        return self.clean_string(cipher.get("name"))

    def service_cpes(self, service):
        cpes = []
        for key in ("cpe23", "cpe", "cpes"):
            value = service.get(key)
            if isinstance(value, list):
                cpes.extend(self.normalize_string_list(value))
            elif isinstance(value, str):
                cleaned = self.clean_string(value)
                if cleaned:
                    cpes.append(cleaned)
        normalized = self.normalize_string_list(cpes)
        return normalized or None

    def iter_vulnerabilities(self, data):
        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        if isinstance(vulns, list):
            for vuln in vulns:
                vuln_id = self.clean_string(vuln)
                if vuln_id:
                    yield {"id": vuln_id, "summary": None, "cvss": None}
            return

        if isinstance(vulns, dict):
            for vuln_id, details in vulns.items():
                cleaned_id = self.clean_string(vuln_id)
                if not cleaned_id:
                    continue
                details = details if isinstance(details, dict) else {}
                yield {
                    "id": cleaned_id,
                    "summary": self.clean_string(details.get("summary") or details.get("description")),
                    "cvss": self.to_float(details.get("cvss") or details.get("cvss_score")),
                }

    def vulnerability_severity(self, cvss):
        if isinstance(cvss, (int, float)):
            if cvss >= 7:
                return "HIGH"
            if cvss >= 4:
                return "MEDIUM"
            return "LOW"
        return "MEDIUM"

    def vulnerability_description(self, vuln_id, summary, query_host, source):
        prefix = f"The exposed host or service at {query_host} is associated with {vuln_id}."
        description = f"{prefix} {summary}" if summary else prefix
        return (
            f"{description} "
            "A public exposure intelligence source associated the host or service with a known vulnerability. "
            "Attackers may be able to use public exploit techniques if the exposed service and version are truly affected. "
            "Depending on the CVE, exploitation can lead to data exposure, authentication bypass, remote code execution, service compromise, or useful reconnaissance for further attacks. "
            "This should be treated as a validation task rather than blind proof of compromise: confirm the listening service, product, version, and exposure path, then compare them with the vulnerability details. "
            "If the match is correct, patch or disable the affected service, restrict access with firewall rules or VPN controls, and review logs for exploitation attempts around the period the service was exposed."
        )

    def vulnerability_evidence(self, vuln_id, source, cvss):
        evidence = f"{source} listed {vuln_id} on the scanned host"
        if isinstance(cvss, (int, float)):
            evidence += f" with CVSS {cvss}"
        return evidence

    def to_float(self, value):
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return None
        return None
