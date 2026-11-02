import gzip
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from botocore.exceptions import ClientError

from bbot.core.helpers import api_cache
from bbot.core.helpers.misc import safe_format
from bbot.modules.base import BaseModule
from bbot.modules.securitytrails import securitytrails
from bbot.modules.templates.osintverse import OSINTverseClient

BUCKET = "test-api-cache"
API_KEY = "st-secret-key-123"


class FakeS3:
    """In-memory S3 with LastModified timestamps; can be switched off to simulate an outage."""

    def __init__(self):
        self.objects = {}
        self.down = False
        self.calls = 0
        self.missing_code = "NoSuchKey"

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.calls += 1
        if self.down:
            raise ConnectionError("S3 unreachable")
        self.objects[(Bucket, Key)] = {"Body": Body, "LastModified": datetime.now(timezone.utc)}

    def get_object(self, Bucket, Key):
        self.calls += 1
        if self.down:
            raise ConnectionError("S3 unreachable")
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": self.missing_code, "Message": "missing"}}, "GetObject")
        obj = self.objects[(Bucket, Key)]
        return {"Body": SimpleNamespace(read=lambda: obj["Body"]), "LastModified": obj["LastModified"]}

    def age_all(self, seconds):
        for obj in self.objects.values():
            obj["LastModified"] -= timedelta(seconds=seconds)


@pytest.fixture
def s3(monkeypatch):
    monkeypatch.setenv(api_cache.BUCKET_ENV, BUCKET)
    monkeypatch.setenv(api_cache.PREFIX_ENV, "tenants/tenant-a")
    monkeypatch.delenv(api_cache.MAX_AGE_ENV, raising=False)
    monkeypatch.delenv(api_cache.REGION_ENV, raising=False)
    fake = FakeS3()
    cache = api_cache.get_api_cache()
    cache._client = fake
    yield fake
    api_cache._shared_cache_env = None


def make_module(cls=securitytrails, responses=None, api_key=API_KEY):
    """A real module instance wired to a fake scan whose HTTP layer returns the given responses in order."""
    module = object.__new__(cls)
    module._name = cls.__name__
    live = AsyncMock(side_effect=list(responses or []))
    module.scan = SimpleNamespace(
        id="scan-1",
        helpers=SimpleNamespace(request=live, safe_format=safe_format),
        config={"modules": {module.name: {"api_key": api_key}}},
    )
    module._api_keys = [api_key] if api_key else []
    module._api_request_failures = 0
    module._default_api_retries = 0
    for name in ("debug", "verbose", "trace", "warning", "set_error_state"):
        setattr(module, name, Mock())
    return module, live


def ok(payload):
    return httpx.Response(200, json=payload, request=httpx.Request("GET", "https://api.example.test"))


async def test_second_scan_reuses_cached_response_without_live_request(s3):
    url = f"https://api.securitytrails.com/v1/domain/example.com/subdomains?apikey={API_KEY}"
    first, first_live = make_module(responses=[ok({"subdomains": ["www", "api"]})])
    r1 = await first.api_request(url)
    assert r1.json() == {"subdomains": ["www", "api"]}
    assert first_live.await_count == 1

    second, second_live = make_module(responses=[])
    r2 = await second.api_request(url)
    assert second_live.await_count == 0
    assert r2.status_code == 200 and r2.is_success
    assert r2.json() == {"subdomains": ["www", "api"]}


async def test_cache_never_stores_credentials_urls_or_headers(s3):
    url = f"https://api.example.test/lookup?key={API_KEY}"
    module, _ = make_module(responses=[ok({"hosts": ["a.example.com"]})])
    await module.cached_api_request(url, headers={"Authorization": f"Bearer {API_KEY}", "X-Api-Key": API_KEY})
    assert len(s3.objects) == 1
    (bucket, key), obj = next(iter(s3.objects.items()))
    stored = gzip.decompress(obj["Body"]).decode()
    assert key.startswith("tenants/tenant-a/bbot-api-cache/securitytrails/")
    for secret in (API_KEY, "api.example.test", "Authorization", "Bearer"):
        assert secret not in key and secret not in stored


async def test_entry_older_than_16_hours_is_ignored_and_refreshed(s3):
    url = "https://api.example.test/subdomains/example.com"
    module, _ = make_module(responses=[ok({"n": 1})])
    await module.cached_api_request(url)

    s3.age_all(16 * 3600 - 60)
    fresh, fresh_live = make_module(responses=[])
    assert (await fresh.cached_api_request(url)).json() == {"n": 1}
    assert fresh_live.await_count == 0

    s3.age_all(120)  # now 16h + 1min old
    stale, stale_live = make_module(responses=[ok({"n": 2})])
    assert (await stale.cached_api_request(url)).json() == {"n": 2}
    assert stale_live.await_count == 1
    again, again_live = make_module(responses=[])
    assert (await again.cached_api_request(url)).json() == {"n": 2}
    assert again_live.await_count == 0


@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(429, json={"message": "Too many requests"}),
        httpx.Response(500, text="internal error"),
        httpx.Response(401, json={"message": "Invalid API key"}),
        httpx.Response(403, json={"message": "Forbidden"}),
        httpx.Response(404, json={"message": "not found"}),
        httpx.Response(200, json={"error": "Monthly quota exceeded"}),
        httpx.Response(200, json={"success": False, "message": "no credits"}),
        httpx.Response(200, json={"message": "You have exceeded your API usage limit"}),
        httpx.Response(200, json={"id": "abc", "status": "running"}),
        httpx.Response(200, text=""),
        None,
    ],
)
async def test_failures_and_incomplete_answers_are_never_cached(s3, failure):
    url = "https://api.example.test/search?q=example.com"
    module, live = make_module(responses=[failure])
    result = await module.cached_api_request(url)
    assert result is failure
    assert s3.objects == {}

    retry, retry_live = make_module(responses=[ok({"hosts": ["x"]})])
    assert (await retry.cached_api_request(url)).json() == {"hosts": ["x"]}
    assert retry_live.await_count == 1


async def test_success_with_false_error_flag_is_cached():
    # Leak-Lookup answers {"error": "false", "message": {...}} on success
    good = httpx.Response(200, json={"error": "false", "message": {"breach": ["a@example.com"]}})
    assert api_cache.response_is_cacheable(good)


async def test_no_bucket_configured_means_plain_live_requests(monkeypatch):
    monkeypatch.delenv(api_cache.BUCKET_ENV, raising=False)
    api_cache._shared_cache_env = None
    boto3_client = Mock(side_effect=AssertionError("S3 must not be used"))
    monkeypatch.setattr("boto3.client", boto3_client)
    module, live = make_module(responses=[ok({"a": 1}), ok({"a": 1})])
    url = "https://api.example.test/x"
    await module.api_request(url)
    await module.api_request(url)
    assert live.await_count == 2
    boto3_client.assert_not_called()


async def test_module_without_opt_in_never_touches_cache(s3):
    class free_api(BaseModule):
        _name = "free_api"

    module, live = make_module(cls=free_api, responses=[ok({"a": 1}), ok({"a": 1})])
    await module.api_request("https://free.example.test/x")
    await module.api_request("https://free.example.test/x")
    assert live.await_count == 2
    assert s3.calls == 0


async def test_s3_outage_falls_back_to_live_and_stops_retrying_s3(s3):
    s3.down = True
    url = "https://api.example.test/x"
    for i in range(5):
        module, live = make_module(responses=[ok({"i": i})])
        assert (await module.cached_api_request(url)).json() == {"i": i}
        assert live.await_count == 1
    # after a few failures the cache pauses instead of adding S3 timeouts to every request
    assert s3.calls == api_cache.FAILURES_BEFORE_PAUSE
    assert api_cache.get_api_cache().available is False


async def test_corrupt_cache_object_falls_back_to_live(s3):
    url = "https://api.example.test/x"
    module, _ = make_module(responses=[ok({"a": 1})])
    await module.cached_api_request(url)
    for obj in s3.objects.values():
        obj["Body"] = b"not gzip"
    again, live = make_module(responses=[ok({"a": 2})])
    assert (await again.cached_api_request(url)).json() == {"a": 2}
    assert live.await_count == 1


async def test_each_page_is_cached_separately(s3):
    url = "https://api.example.test/hosts?page={page}&size={page_size}"
    pages = [ok({"page": 1, "hosts": ["a"]}), ok({"page": 2, "hosts": ["b"]}), ok({"page": 3, "hosts": []})]

    async def collect(module):
        seen = []
        agen = module.api_page_iter(url, page_size=10)
        async for page in agen:
            if not page["hosts"]:
                break
            seen.append(page["page"])
        await agen.aclose()
        return seen

    first, first_live = make_module(responses=pages)
    assert await collect(first) == [1, 2]
    assert first_live.await_count == 3
    assert len(s3.objects) == 3

    second, second_live = make_module(responses=[])
    assert await collect(second) == [1, 2]
    assert second_live.await_count == 0


async def test_post_body_and_credential_are_part_of_the_key(s3):
    url = "https://api.example.test/search"
    module, _ = make_module(responses=[ok({"q": "a"})])
    await module.cached_api_request(url, method="POST", json={"query": "domain:a.com", "page": 1})

    other_body, live_body = make_module(responses=[ok({"q": "b"})])
    assert (
        await other_body.cached_api_request(url, method="POST", json={"query": "domain:b.com", "page": 1})
    ).json() == {"q": "b"}
    assert live_body.await_count == 1

    other_key, live_key = make_module(responses=[ok({"q": "a2"})], api_key="another-key")
    result = await other_key.cached_api_request(url, method="POST", json={"query": "domain:a.com", "page": 1})
    assert result.json() == {"q": "a2"}
    assert live_key.await_count == 1


async def test_tenant_prefixes_do_not_share_entries(s3, monkeypatch):
    url = "https://api.example.test/x"
    module, _ = make_module(responses=[ok({"tenant": "a"})])
    await module.cached_api_request(url)

    monkeypatch.setenv(api_cache.PREFIX_ENV, "tenants/tenant-b")
    api_cache.get_api_cache()._client = s3
    other, live = make_module(responses=[ok({"tenant": "b"})])
    assert (await other.cached_api_request(url)).json() == {"tenant": "b"}
    assert live.await_count == 1


async def test_osintverse_completed_search_is_reused_but_running_one_is_not(s3):
    completed = {"id": "s1", "status": "completed", "result": {"matches": [{"type": "breach_record"}]}}
    module, live = make_module(responses=[ok(completed)])
    client = OSINTverseClient(module, "ov-key")
    assert await client.search("leakradar", "domain", "example.com") == completed
    assert live.await_count == 1

    module2, live2 = make_module(responses=[])
    assert await OSINTverseClient(module2, "ov-key").search("leakradar", "domain", "example.com") == completed
    assert live2.await_count == 0

    failed = {"id": "s2", "status": "failed", "error": "provider down"}
    module3, live3 = make_module(responses=[ok(failed)])
    assert await OSINTverseClient(module3, "ov-key").search("snusbase", "domain", "example.com") is None
    stored = [json.loads(gzip.decompress(o["Body"])) for o in s3.objects.values()]
    assert all(e["result"]["status"] == "completed" for e in stored)


async def test_missing_object_hidden_as_access_denied_is_a_miss_not_an_outage(s3):
    # tenant roles have no s3:ListBucket, so S3 answers a missing key with 403 AccessDenied
    s3.missing_code = "AccessDenied"
    for i in range(api_cache.FAILURES_BEFORE_PAUSE + 2):
        module, live = make_module(responses=[ok({"i": i})])
        assert (await module.cached_api_request(f"https://api.example.test/{i}")).json() == {"i": i}
    assert api_cache.get_api_cache().available is True
    again, live = make_module(responses=[])
    assert (await again.cached_api_request("https://api.example.test/0")).json() == {"i": 0}
    assert live.await_count == 0
