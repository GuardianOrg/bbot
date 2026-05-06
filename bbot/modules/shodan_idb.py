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

    watched_events = ["DNS_NAME", "IP_ADDRESS"]
    produced_events = ["TECHNOLOGY", "VULNERABILITY", "FINDING", "OPEN_TCP_PORT", "DNS_NAME", "GEOLOCATION"]
    flags = ["passive", "safe", "portscan"]
    meta = {
        "description": "Query Shodan's InternetDB for open ports, hostnames, technologies, and vulnerabilities",
        "created_date": "2023-12-22",
        "author": "@TheTechromancer",
    }
    options = {"retries": None, "api_key": "", "full_host": True}
    options_desc = {
        "retries": "How many times to retry API requests (e.g. after a 429 error). Overrides the global web.api_retries setting.",
        "api_key": "Optional Shodan API key. If present, shodan_idb also queries /shodan/host/{ip} for OS/provider metadata.",
        "full_host": "Use the authenticated Shodan host API when an API key is available.",
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
        self.full_host = bool(self.config.get("full_host", True))
        self.api_key = self.get_shodan_api_keys()
        return True

    def get_shodan_api_keys(self):
        api_keys = set()
        for module_name in ("shodan", "shodan_dns", "shodan_port", "shodan_idb"):
            module_config = self.scan.config.get("modules", {}).get(module_name, {})
            api_key = module_config.get("api_key", "")
            if isinstance(api_key, str):
                api_key = [api_key]
            for key in api_key:
                key = str(key).strip()
                if key:
                    api_keys.add(key)
        return list(api_keys)

    def _incoming_dedup_hash(self, event):
        ip = self.get_ip(event)
        return hash(str(ip or event.data).strip().lower())

    @property
    def api_retries(self):
        # allow the module to override global retry setting
        return self.config.get("retries", None) or super().api_retries

    async def handle_event(self, event):
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
        for port in data.get("ports", []):
            await self.emit_event(
                self.helpers.make_netloc(event.data, port),
                "OPEN_TCP_PORT",
                parent=event,
                context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found {{event.type}}: {{event.data}}',
            )
        vulns = data.get("vulns", [])
        if vulns:
            vulns_str = ", ".join([str(v) for v in vulns])
            await self.emit_event(
                {"description": f"Shodan reported possible vulnerabilities: {vulns_str}", "host": str(event.host)},
                "FINDING",
                parent=event,
                context=f'{{module}} queried Shodan\'s InternetDB API for "{query_host}" and found potential {{event.type}}: {vulns_str}',
            )

    async def _parse_host_response(self, data: dict, event, ip, source):
        tags = self.normalize_string_list(data.get("tags", []))
        hostnames = self.normalize_string_list(data.get("hostnames", []))
        service_os = self.first_service_os(data.get("data", []))
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
            "os": os_name,
            "cloudProvider": provider,
            "providerType": self.provider_type(provider=provider, cdn_name=cdn_name, privacy_flags=privacy_flags, tags=tags),
            "isCdn": True if is_cdn else None,
            "cdnName": cdn_name,
            **privacy_flags,
        }
        geo_data = {k: v for k, v in geo_data.items() if v not in (None, "", [])}
        if len(geo_data) <= 1:
            return

        await self.emit_event(
            geo_data,
            "GEOLOCATION",
            parent=event,
            context=f'{{module}} queried {source} for "{ip}" and found {{event.type}} metadata',
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
        if "cdn" not in {tag.lower() for tag in tags}:
            return False, None
        text = self.enrichment_text(data, tags)
        cdns = {
            "cloudflare": "cloudflare",
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
        return True, None

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
