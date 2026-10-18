from .base import ModuleTestBase


class TestUrlScan(ModuleTestBase):
    config_overrides = {"modules": {"urlscan": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://urlscan.io/api/v1/search/?q=page.domain%3Ablacklanternsecurity.com&size=100",
            json={
                "results": [
                    {
                        "task": {
                            "visibility": "public",
                            "method": "api",
                            "domain": "asdf.blacklanternsecurity.com",
                            "apexDomain": "blacklanternsecurity.com",
                            "time": "2023-05-17T01:45:11.391Z",
                            "uuid": "c558b3b3-b274-4339-99ef-301eb043741f",
                            "url": "https://asdf.blacklanternsecurity.com/cna.html",
                        },
                        "stats": {
                            "uniqIPs": 6,
                            "uniqCountries": 3,
                            "dataLength": 926713,
                            "encodedDataLength": 332213,
                            "requests": 22,
                        },
                        "page": {
                            "country": "US",
                            "server": "GitHub.com",
                            "ip": "2606:50c0:8002::153",
                            "mimeType": "text/html",
                            "title": "Vulnerability Program | Black Lantern Security",
                            "url": "https://asdf.blacklanternsecurity.com/cna.html",
                            "tlsValidDays": 89,
                            "tlsAgeDays": 25,
                            "tlsValidFrom": "2023-04-21T19:16:58.000Z",
                            "domain": "asdf.blacklanternsecurity.com",
                            "apexDomain": "blacklanternsecurity.com",
                            "asnname": "FASTLY, US",
                            "asn": "AS54113",
                            "tlsIssuer": "R3",
                            "status": "200",
                        },
                        "_id": "c558b3b3-b274-4339-99ef-301eb043741f",
                        "_score": None,
                        "sort": [1684287911391, "c558b3b3-b274-4339-99ef-301eb043741f"],
                        "result": "https://urlscan.io/api/v1/result/c558b3b3-b274-4339-99ef-301eb043741f/",
                        "screenshot": "https://urlscan.io/screenshots/c558b3b3-b274-4339-99ef-301eb043741f.png",
                    },
                    {
                        "task": {
                            "domain": "blacklanternsecurity.com",
                            "url": "https://blacklanternsecurity.com/",
                            "time": "2023-05-18T01:45:11.391Z",
                        },
                        "page": {
                            "domain": "third-party.example",
                            "url": "https://third-party.example/",
                            "ip": "203.0.113.50",
                        },
                    },
                ]
            },
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.88"]},
                "asdf.blacklanternsecurity.com": {"AAAA": ["2606:50c0:8002::153"]},
            }
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "https://asdf.blacklanternsecurity.com/cna.html" for e in events), "Failed to detect URL"
        histories = [e.data for e in events if e.type == "DOMAIN_DNS_HISTORY"]
        assert histories == [
            {
                "host": "asdf.blacklanternsecurity.com",
                "records": [
                    {
                        "ip": "2606:50c0:8002::153",
                        "record_type": "AAAA",
                        "source": "urlscan",
                        "first_seen": "2023-05-17T01:45:11.391Z",
                        "last_seen": "2023-05-17T01:45:11.391Z",
                    }
                ],
            }
        ]


class TestUrlScanPagination(ModuleTestBase):
    module_name = "urlscan"
    config_overrides = {"modules": {"urlscan": {"urls": False, "page_size": 1, "max_pages": 2}}}

    async def setup_before_prep(self, module_test):
        base = "https://urlscan.io/api/v1/search/?q=page.domain%3Ablacklanternsecurity.com&size=1"
        module_test.httpx_mock.add_response(
            url=base,
            json={
                "results": [
                    {
                        "task": {"time": "2024-01-01T00:00:00Z"},
                        "page": {"domain": "blacklanternsecurity.com", "ip": "198.51.100.1"},
                        "sort": [1704067200000, "first"],
                    }
                ]
            },
        )
        module_test.httpx_mock.add_response(
            url=base + "&search_after=1704067200000%2Cfirst",
            json={
                "results": [
                    {
                        "task": {"time": "2020-01-01T00:00:00Z"},
                        "page": {"domain": "blacklanternsecurity.com", "ip": "2001:db8::1"},
                    }
                ]
            },
        )

    def check(self, module_test, events):
        histories = [e.data for e in events if e.type == "DOMAIN_DNS_HISTORY"]
        assert len(histories) == 1
        assert {record["ip"] for record in histories[0]["records"]} == {"198.51.100.1", "2001:db8::1"}
