"""
Optional S3 cache for responses of paid or quota-limited APIs.

Relaunching a scan should not pay for the same API queries again. When ``BBOT_API_CACHE_BUCKET`` is set, modules
that declare ``cache_api_responses = True`` read successful API responses from S3 if they are younger than 16 hours, and
store new successful responses there. Without the variable nothing changes.

Environment:
    BBOT_API_CACHE_BUCKET       S3 bucket (enables the cache)
    BBOT_API_CACHE_PREFIX       optional key prefix, e.g. one per tenant
    BBOT_API_CACHE_MAX_AGE      optional maximum age in seconds (capped at 16 hours)
    BBOT_API_CACHE_REGION       optional bucket region (defaults to the AWS SDK region)

The cache never stores URLs, request headers or credentials. Object keys are a SHA-256 of the module, method, URL,
body and a SHA-256 of the credential. Every S3 failure falls back to the live request; it is only logged at debug
level, and after a few consecutive failures the cache pauses itself for a while instead of slowing every request.
"""

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone

log = logging.getLogger("bbot.core.helpers.api_cache")

BUCKET_ENV = "BBOT_API_CACHE_BUCKET"
PREFIX_ENV = "BBOT_API_CACHE_PREFIX"
MAX_AGE_ENV = "BBOT_API_CACHE_MAX_AGE"
REGION_ENV = "BBOT_API_CACHE_REGION"

MAX_AGE_SECONDS = 16 * 60 * 60
# a few minutes of clock skew between S3 and this host is normal; more means the object can't be trusted
MAX_FUTURE_SKEW_SECONDS = 300
MAX_STORED_BYTES = 25 * 1024 * 1024
FAILURES_BEFORE_PAUSE = 3
PAUSE_SECONDS = 300
FORMAT_VERSION = 1

_UNCACHEABLE_KWARGS = {"files", "stream"}
_INCOMPLETE_STATUSES = {"running", "pending", "queued", "processing", "in_progress", "started", "error", "failed"}
_ERROR_HINTS = re.compile(
    r"quota|rate.?limit|too many requests|exceeded|insufficient|credits?|unauthori[sz]ed|forbidden|"
    r"invalid (api|key|token)|api key|expired|not allowed|subscription|payment|upgrade your plan",
    re.I,
)
_SECRET_OPTION = re.compile(r"(api_?keys?|token|secret|password|username|client_id|_key|_keys|api_id)$", re.I)


def _canonical(value):
    """Stable text for a request body or params, whatever type the caller passed."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return "bytes:" + hashlib.sha256(bytes(value)).hexdigest()
    if isinstance(value, str):
        return "str:" + value
    try:
        return "json:" + json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return "repr:" + repr(value)


def credential_fingerprint(*values):
    """SHA-256 of every credential value, so different keys never share entries and no key is ever stored."""
    flat = []
    for value in values:
        if isinstance(value, dict):
            flat.extend(f"{k}={_canonical(v)}" for k, v in sorted(value.items(), key=lambda kv: str(kv[0])))
        elif isinstance(value, (list, tuple, set)):
            flat.extend(sorted(_canonical(v) for v in value))
        else:
            flat.append(_canonical(value))
    return hashlib.sha256("\x1f".join(flat).encode("utf-8", "surrogatepass")).hexdigest()


def module_credentials(module):
    """The credential options of a module (api_key, *_api_key, token, client_secret...) plus its active key."""
    config = {}
    try:
        config = dict(module.config or {})
    except Exception:
        pass
    creds = {k: v for k, v in config.items() if _SECRET_OPTION.search(str(k)) and v not in (None, "", [], ())}
    with_keys = getattr(module, "_api_keys", None)
    if with_keys:
        creds["__api_keys__"] = list(with_keys)
    return creds


def request_key(module_name, method, url, body="", params=None, credential=""):
    material = json.dumps(
        [
            FORMAT_VERSION,
            str(module_name),
            str(method or "GET").upper(),
            str(url),
            _canonical(body),
            _canonical(params),
            credential,
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()


def request_kwargs_key_material(args, kwargs):
    """
    Split helpers.request() arguments into (method, url, body, params), or None if the request must not be cached.
    """
    if any(kwargs.get(k) for k in _UNCACHEABLE_KWARGS):
        return None
    url = args[0] if args else kwargs.get("url", "")
    if not url:
        return None
    method = str(kwargs.get("method", "GET") or "GET").upper()
    body = {k: kwargs[k] for k in ("json", "data", "content") if kwargs.get(k) is not None}
    params = kwargs.get("params")
    return method, str(url), body, params


def _json_payload(response):
    content_type = str(getattr(response, "headers", {}).get("content-type", "")).lower()
    content = response.content
    if "json" not in content_type and not content.lstrip()[:1] in (b"{", b"["):
        return None
    try:
        return json.loads(content)
    except Exception:
        return None


def _text_says_error(value):
    return isinstance(value, str) and bool(_ERROR_HINTS.search(value))


def _error_flag(value):
    # some APIs always send an "error" field and mark success with "false" (e.g. Leak-Lookup)
    if isinstance(value, str):
        return value.strip().lower() not in ("", "false", "0", "no", "none", "null", "ok", "success")
    return bool(value)


def json_is_complete(payload):
    """False when a 2xx JSON body is actually an error, a quota message, or an unfinished job."""
    if not isinstance(payload, dict):
        return True
    if payload.get("success") is False or payload.get("ok") is False:
        return False
    for key in ("error", "errors", "error_message", "errorMessage"):
        if _error_flag(payload.get(key)):
            return False
    status = payload.get("status")
    if isinstance(status, str) and status.strip().lower() in _INCOMPLETE_STATUSES:
        return False
    for key in ("message", "detail", "msg"):
        if _text_says_error(payload.get(key)) and len(payload) <= 3:
            return False
    return True


def response_is_cacheable(response):
    """
    Only a complete, successful answer may be cached: a 2xx with a fully read, non-empty body that is not an
    error, quota or "still running" message disguised as success. 404s, 429s, auth failures and empty bodies are
    never cached, so the next scan asks again.
    """
    try:
        if response is None or getattr(response, "headers", {}).get("x-bbot-api-cache") == "hit":
            return False
        status = int(getattr(response, "status_code", 0) or 0)
        if not 200 <= status < 300:
            return False
        content = response.content  # raises if the body was streamed and never read
        if not content or not content.strip():
            return False
        if len(content) > MAX_STORED_BYTES:
            return False
        payload = _json_payload(response)
        if payload is not None and not json_is_complete(payload):
            return False
        return True
    except Exception as e:
        log.debug(f"Not caching API response: {e}")
        return False


class APIResponseCache:
    def __init__(self, bucket, prefix="", max_age=MAX_AGE_SECONDS, region=None, client=None, clock=time.time):
        self.bucket = str(bucket).strip()
        self.prefix = "/".join(p for p in str(prefix or "").split("/") if p and p not in (".", ".."))
        self.max_age = max(0, min(float(max_age), MAX_AGE_SECONDS))
        self.region = region or None
        self._client = client
        self._clock = clock
        self._failures = 0
        self._paused_until = 0.0

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        bucket = str(environ.get(BUCKET_ENV, "") or "").strip()
        if not bucket:
            return None
        max_age = MAX_AGE_SECONDS
        raw_age = str(environ.get(MAX_AGE_ENV, "") or "").strip()
        if raw_age:
            try:
                max_age = float(raw_age)
            except ValueError:
                log.debug(f"Ignoring invalid {MAX_AGE_ENV}")
        return cls(bucket, environ.get(PREFIX_ENV, ""), max_age, environ.get(REGION_ENV, ""))

    def object_key(self, module_name, digest):
        module_name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(module_name)) or "module"
        parts = [self.prefix, "bbot-api-cache", module_name, digest[:2], f"{digest}.json.gz"]
        return "/".join(p for p in parts if p)

    @property
    def available(self):
        return self._clock() >= self._paused_until

    @property
    def client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config

            config = Config(connect_timeout=3, read_timeout=10, retries={"max_attempts": 2, "mode": "standard"})
            self._client = boto3.client("s3", region_name=self.region, config=config)
        return self._client

    def _failed(self, action, error):
        self._failures += 1
        log.debug(f"API cache {action} failed ({type(error).__name__}: {error}); using the live API")
        if self._failures >= FAILURES_BEFORE_PAUSE:
            self._paused_until = self._clock() + PAUSE_SECONDS
            self._failures = 0
            log.debug(f"API cache paused for {PAUSE_SECONDS}s after repeated S3 failures")

    def _get_sync(self, key):
        try:
            obj = self.client.get_object(Bucket=self.bucket, Key=key)
        except Exception as e:
            code = str(getattr(e, "response", {}).get("Error", {}).get("Code", ""))
            # without s3:ListBucket (tenant roles only see their own prefix) a missing object is a 403
            if code in ("NoSuchKey", "404", "NotFound", "AccessDenied", "403"):
                self._failures = 0
                return None
            raise
        modified = obj.get("LastModified")
        if not isinstance(modified, datetime):
            return None
        if modified.tzinfo is None:
            modified = modified.replace(tzinfo=timezone.utc)
        age = self._clock() - modified.timestamp()
        if age > self.max_age or age < -MAX_FUTURE_SKEW_SECONDS:
            log.debug(f"API cache entry {key} is {age:.0f}s old; ignoring it")
            return None
        entry = json.loads(gzip.decompress(obj["Body"].read()))
        if not isinstance(entry, dict) or entry.get("v") != FORMAT_VERSION:
            return None
        return entry

    def _put_sync(self, key, entry):
        body = gzip.compress(json.dumps(entry, separators=(",", ":")).encode())
        if len(body) > MAX_STORED_BYTES:
            return
        self.client.put_object(
            Bucket=self.bucket, Key=key, Body=body, ContentType="application/json", ContentEncoding="gzip"
        )

    async def get(self, key):
        """The stored entry if it exists and is fresh, else None. Never raises."""
        if not self.available:
            return None
        try:
            entry = await asyncio.to_thread(self._get_sync, key)
            self._failures = 0
            return entry
        except Exception as e:
            self._failed("read", e)
            return None

    async def put(self, key, entry):
        """Store an entry. Never raises."""
        if not self.available:
            return False
        try:
            await asyncio.to_thread(self._put_sync, key, dict(entry, v=FORMAT_VERSION))
            self._failures = 0
            return True
        except Exception as e:
            self._failed("write", e)
            return False

    @staticmethod
    def response_entry(response):
        return {
            "kind": "response",
            "status_code": int(response.status_code),
            "content_type": str(response.headers.get("content-type", "")),
            "body": base64.b64encode(response.content).decode(),
        }

    @staticmethod
    def build_response(entry, method, url):
        import httpx

        headers = {"x-bbot-api-cache": "hit"}
        if entry.get("content_type"):
            headers["content-type"] = entry["content_type"]
        return httpx.Response(
            int(entry["status_code"]),
            headers=headers,
            content=base64.b64decode(entry.get("body", "")),
            request=httpx.Request(method, url),
        )


_shared_cache = None
_shared_cache_env = None


def get_api_cache():
    """The process-wide cache configured from the environment, or None when it is not enabled."""
    global _shared_cache, _shared_cache_env
    env = tuple(os.environ.get(k, "") for k in (BUCKET_ENV, PREFIX_ENV, MAX_AGE_ENV, REGION_ENV))
    if env != _shared_cache_env:
        _shared_cache_env = env
        try:
            _shared_cache = APIResponseCache.from_env()
        except Exception as e:
            log.debug(f"API cache disabled: {e}")
            _shared_cache = None
    return _shared_cache
