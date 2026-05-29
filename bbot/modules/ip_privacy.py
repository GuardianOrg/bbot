import asyncio
import ipaddress
import ast
from urllib.parse import urlparse

from bbot.modules.base import BaseModule


class ip_privacy(BaseModule):
    """
    Classify IPs using free text/netset feeds. No paid API key required.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["passive", "safe", "ip-enum"]
    meta = {
        "description": "Classify IPs as Tor/proxy/VPN using free public IP list feeds.",
        "created_date": "2026-05-06",
        "author": "@carlospolop",
    }
    options = {
        "tor_urls": [
            "https://check.torproject.org/torbulkexitlist",
            "https://opendbl.net/tor-exit.list",
            "https://raw.githubusercontent.com/alireza-rezaee/tor-nodes/master/tor_exit_nodes_ip.txt",
        ],
        "proxy_urls": [
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt",
        ],
        "vpn_urls": [
            "https://raw.githubusercontent.com/X4BNet/lists_vpn/master/output/vpn/ipv4.txt",
            "https://raw.githubusercontent.com/NazgulCoder/IPLists/main/vpn/ipv4.txt",
            "https://raw.githubusercontent.com/az0/vpn_ip/master/ip.txt",
            "https://raw.githubusercontent.com/TN3W/ProtonVPN-IPs/main/protonvpn_ips.txt",
            "https://raw.githubusercontent.com/TN3W/Windscribe-IPs/main/windscribe_ips.txt",
        ],
        "cache_for": 86400,
    }
    options_desc = {
        "tor_urls": "Comma-separated free Tor exit-node list URLs.",
        "proxy_urls": "Comma-separated free proxy/anonymizer IP or CIDR list URLs.",
        "vpn_urls": "Comma-separated free VPN IP or CIDR list URLs.",
        "cache_for": "Seconds to cache downloaded lists.",
    }
    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    async def setup(self):
        self.cache_for = max(0, int(self.config.get("cache_for", 86400)))
        self.feed_urls = {
            "isTor": self.parse_urls(self.config.get("tor_urls", "")),
            "isProxy": self.parse_urls(self.config.get("proxy_urls", "")),
            "isVpn": self.parse_urls(self.config.get("vpn_urls", "")),
        }
        self._feeds = None
        self._feeds_lock = asyncio.Lock()
        return True

    async def handle_event(self, event):
        ip = ipaddress.ip_address(str(event.data))
        feeds = await self.load_feeds()
        matches = {
            field: self.ip_in_feed(ip, feed)
            for field, feed in feeds.items()
        }
        positive_matches = {field: True for field, matched in matches.items() if matched is True}
        if not positive_matches:
            return

        await self.emit_event(
            {
                "ip": str(ip),
                **positive_matches,
                "providerType": self.provider_type(positive_matches),
            },
            "GEOLOCATION",
            event,
            context=f"{{module}} matched {ip} against free IP privacy feeds and found {{event.type}}",
        )

    def parse_urls(self, value):
        if isinstance(value, list):
            raw_urls = value
        else:
            raw_value = str(value or "").strip()
            if raw_value.startswith("[") and raw_value.endswith("]"):
                try:
                    parsed = ast.literal_eval(raw_value)
                except (SyntaxError, ValueError):
                    parsed = None
                raw_urls = parsed if isinstance(parsed, list) else raw_value.split(",")
            else:
                raw_urls = raw_value.split(",")
        return [str(url).strip() for url in raw_urls if url and str(url).strip()]

    async def load_feeds(self):
        async with self._feeds_lock:
            if self._feeds is not None:
                return self._feeds

            self._feeds = {}
            for field, urls in self.feed_urls.items():
                self._feeds[field] = await self.load_feed_urls(urls)
            return self._feeds

    async def load_feed_urls(self, urls):
        networks = []
        for url in urls:
            try:
                response = await self.helpers.request(url, cache_for=self.cache_for)
                if not response:
                    continue
                networks.extend(self.parse_feed(response.text or ""))
            except Exception:
                self.verbose(f"Error loading IP privacy feed {url}", trace=True)
        return networks

    def parse_feed(self, text):
        networks = []
        for line in text.splitlines():
            networks.extend(self.parse_feed_line(line))
        return networks

    def parse_feed_line(self, line):
        value = line.strip()
        if not value or value.startswith("#") or value.startswith(";"):
            return []

        value = value.split("#", 1)[0].strip()
        if not value:
            return []

        candidates = [value]
        parsed = urlparse(value)
        if parsed.hostname:
            candidates.append(parsed.hostname)

        if "/" not in value and ":" in value:
            candidates.append(value.rsplit(":", 1)[0])

        networks = []
        for candidate in candidates:
            try:
                networks.append(ipaddress.ip_network(candidate, strict=False))
                break
            except ValueError:
                continue
        return networks

    def provider_type(self, matches):
        if matches.get("isTor"):
            return "tor"
        if matches.get("isVpn"):
            return "vpn"
        if matches.get("isProxy"):
            return "proxy"
        return "anonymizer"

    def ip_in_feed(self, ip, networks):
        for network in networks:
            if ip.version == network.version and ip in network:
                return True
        return False
