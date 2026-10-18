from bbot.modules.robtex import robtex

from .base import ModuleTestBase


class TestRobtex(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://freeapi.robtex.com/pdns/forward/blacklanternsecurity.com",
            text="\n".join(
                [
                    '{"rrname":"blacklanternsecurity.com","rrtype":"A","rrdata":"198.51.100.8","time_first":1704067200,"time_last":1735689600}',
                    '{"rrname":"blacklanternsecurity.com","rrtype":"AAAA","rrdata":"2001:db8::8","time_first":1704067200}',
                    '{"rrname":"outside.example","rrtype":"A","rrdata":"192.0.2.3"}',
                    '{"rrname":"blacklanternsecurity.com","rrtype":"A","rrdata":"invalid"}',
                    '{"rrname":"blacklanternsecurity.com","rrtype":"MX","rrdata":"mail.example"}',
                ]
            ),
        )

    def check(self, module_test, events):
        histories = [e.data for e in events if e.type == "DOMAIN_DNS_HISTORY"]
        assert len(histories) == 1
        assert histories[0]["host"] == "blacklanternsecurity.com"
        assert histories[0]["records"] == [
            {
                "ip": "198.51.100.8",
                "record_type": "A",
                "source": "robtex",
                "first_seen": "2024-01-01T00:00:00+00:00",
                "last_seen": "2025-01-01T00:00:00+00:00",
            },
            {
                "ip": "2001:db8::8",
                "record_type": "AAAA",
                "source": "robtex",
                "first_seen": "2024-01-01T00:00:00+00:00",
            },
        ]
        assert (
            robtex.parse_records(
                '{"rrname":"blacklanternsecurity.com","rrtype":"AAAA","rrdata":"198.51.100.8"}',
                "blacklanternsecurity.com",
            )
            == []
        )
