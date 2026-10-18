from bbot.modules.mnemonic import mnemonic

from .base import ModuleTestBase


class TestMnemonic(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.mnemonic.no/pdns/v3/blacklanternsecurity.com?rrType=a&rrType=aaaa&limit=1000&offset=0",
            json={
                "count": 5,
                "data": [
                    {
                        "query": "blacklanternsecurity.com.",
                        "answer": "198.51.100.8",
                        "rrtype": "a",
                        "firstSeenTimestamp": 1704067200000,
                        "lastSeenTimestamp": 1735689600000,
                    },
                    {
                        "query": "blacklanternsecurity.com",
                        "answer": "2001:db8::8",
                        "rrtype": "aaaa",
                        "firstSeenTimestamp": 1704067200000,
                    },
                    {"query": "outside.example", "answer": "192.0.2.3", "rrtype": "a"},
                    {"query": "blacklanternsecurity.com", "answer": "invalid", "rrtype": "a"},
                    {"query": "blacklanternsecurity.com", "answer": "198.51.100.9", "rrtype": "aaaa"},
                ],
            },
        )

    def check(self, module_test, events):
        histories = [event.data for event in events if event.type == "DOMAIN_DNS_HISTORY"]
        assert histories == [
            {
                "host": "blacklanternsecurity.com",
                "records": [
                    {
                        "ip": "198.51.100.8",
                        "record_type": "A",
                        "source": "mnemonic",
                        "first_seen": "2024-01-01T00:00:00+00:00",
                        "last_seen": "2025-01-01T00:00:00+00:00",
                    },
                    {
                        "ip": "2001:db8::8",
                        "record_type": "AAAA",
                        "source": "mnemonic",
                        "first_seen": "2024-01-01T00:00:00+00:00",
                    },
                ],
            }
        ]
        assert (
            mnemonic.parse_records(
                [{"query": "blacklanternsecurity.com", "answer": "198.51.100.8", "rrtype": "aaaa"}],
                "blacklanternsecurity.com",
            )
            == []
        )


class TestMnemonicQuota(ModuleTestBase):
    module_name = "mnemonic"

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.mnemonic.no/pdns/v3/blacklanternsecurity.com?rrType=a&rrType=aaaa&limit=1000&offset=0",
            status_code=402,
            json={"messages": [{"message": "Resource limit exceeded"}]},
        )

    def check(self, module_test, events):
        assert module_test.module.quota_exhausted
        assert not any(event.type == "DOMAIN_DNS_HISTORY" for event in events)


class TestMnemonicMinuteLimit(ModuleTestBase):
    module_name = "mnemonic"

    async def setup_before_prep(self, module_test):
        url = "https://api.mnemonic.no/pdns/v3/blacklanternsecurity.com?rrType=a&rrType=aaaa&limit=1000&offset=0"
        module_test.httpx_mock.add_response(
            url=url,
            status_code=402,
            json={"metaData": {"millisUntilResourcesAvailable": 1}},
        )
        module_test.httpx_mock.add_response(
            url=url,
            json={"data": [{"query": "blacklanternsecurity.com", "answer": "198.51.100.8", "rrtype": "a"}]},
        )

    def check(self, module_test, events):
        assert not module_test.module.quota_exhausted
        assert any(event.type == "DOMAIN_DNS_HISTORY" for event in events)
