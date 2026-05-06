from .base import ModuleTestBase


class TestIpPrivacy(ModuleTestBase):
    module_name = "ip_privacy"
    targets = ["8.8.8.8", "1.1.1.1", "2.2.2.2"]
    config_overrides = {
        "modules": {
            "ip_privacy": {
                "tor_urls": "https://feeds.example.test/tor.txt",
                "proxy_urls": "https://feeds.example.test/proxy.netset",
                "vpn_urls": "https://feeds.example.test/vpn.txt",
            }
        }
    }

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://feeds.example.test/tor.txt",
            text="8.8.8.8\n",
        )
        module_test.httpx_mock.add_response(
            url="https://feeds.example.test/proxy.netset",
            text="1.1.1.0/24\nhttp://1.1.1.2:8080\n3.3.3.3:1080\n",
        )
        module_test.httpx_mock.add_response(
            url="https://feeds.example.test/vpn.txt",
            text="2.2.2.2\n",
        )

    def check(self, module_test, events):
        assert any(
            e.type == "GEOLOCATION" and e.data["ip"] == "8.8.8.8" and e.data["isTor"] is True
            for e in events
        ), "Failed to classify Tor IP from free feed"
        assert any(
            e.type == "GEOLOCATION"
            and e.data["ip"] == "8.8.8.8"
            and "isProxy" not in e.data
            and "isVpn" not in e.data
            for e in events
        ), "Tor-only match should not emit false proxy/VPN fields"
        assert any(
            e.type == "GEOLOCATION" and e.data["ip"] == "1.1.1.1" and e.data["isProxy"] is True
            for e in events
        ), "Failed to classify proxy IP from free feed"
        assert module_test.scan.modules["ip_privacy"].parse_feed_line("http://1.1.1.2:8080")[0].prefixlen == 32
        assert module_test.scan.modules["ip_privacy"].parse_feed_line("3.3.3.3:1080")[0].prefixlen == 32
        assert any(
            e.type == "GEOLOCATION" and e.data["ip"] == "2.2.2.2" and e.data["isVpn"] is True
            for e in events
        ), "Failed to classify VPN IP from free feed"
