from .base import ModuleTestBase


class TestDNSDumpster(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://dnsdumpster.com",
            content=b"""<form data-form-id="mainform" hx-post="/htmld/" hx-headers='{"Authorization": ""}'></form>""",
        )
        module_test.httpx_mock.add_response(
            url="https://dnsdumpster.com/htmld/",
            content=b"""<table id="a_rec_table"><thead><tr><th>Host</th><th>IP</th></tr></thead>
            <tbody><tr><td>asdf.blacklanternsecurity.com</td><td>198.51.100.10<br><span>reverse.example</span></td></tr>
            <tr><td>outside.example.com</td><td>198.51.100.20</td></tr></tbody></table>""",
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        histories = [e.data for e in events if e.type == "DOMAIN_DNS_HISTORY"]
        assert histories == [
            {
                "host": "asdf.blacklanternsecurity.com",
                "records": [{"ip": "198.51.100.10", "record_type": "A", "source": "dnsdumpster"}],
            }
        ]
