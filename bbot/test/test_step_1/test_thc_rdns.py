import pytest

from bbot.modules.thc_rdns import thc_rdns


class FakeResponse:
    status_code = 200

    def __init__(self, json_data=None, text=""):
        self._json_data = json_data
        self.text = text

    def json(self):
        if isinstance(self._json_data, Exception):
            raise self._json_data
        return self._json_data


@pytest.mark.asyncio
async def test_thc_rdns_falls_back_to_legacy_when_json_endpoint_is_empty(bbot_scanner):
    scan = bbot_scanner("8.8.8.8", modules=["thc_rdns"], config={"modules": {"thc_rdns": {"limit": 20}}})
    module = thc_rdns(scan)
    scan.modules["thc_rdns"] = module
    await module.setup()

    async def fake_request(url, *args, **kwargs):
        if url == module.api_url:
            return FakeResponse({"domains": []})
        return FakeResponse(
            text="""
;ASN    : 15169
;;Entries: 20/38305
dns.google
example.google
"""
        )

    module.helpers.request = fake_request

    assert await module.query("8.8.8.8") == {"dns.google", "example.google"}
