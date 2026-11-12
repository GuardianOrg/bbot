import asyncio
import base64
import json
import re
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urljoin, urlsplit

import mmh3

from bbot.modules.base import BaseInterceptModule


ALIASES = {
    "wordpress": "WordPress",
    "jquery": "jQuery",
    "apache": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "nginx": "nginx",
    "php": "PHP",
    "asp.net": "ASP.NET",
    "microsoft-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
}
METADATA_PLUGINS = {
    "Country",
    "IP",
    "Title",
    "Email",
    "HTTPServer",
    "UncommonHeaders",
    "RedirectLocation",
    "Cookies",
    "HttpOnly",
    "PasswordField",
    "Meta-Author",
    "MetaGenerator",
    "X-Powered-By",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Access-Control-Allow-Methods",
}
# These signatures describe a page feature, response header, protocol, telemetry
# integration, or generic marker rather than customer-patchable software. Some
# WhatWeb plugins put metadata in their "version" field (for example, og:type=website).
NON_PRODUCT_SIGNATURES = {
    "allow",
    "basic",
    "content-language",
    "content-security-policy",
    "frame",
    "google cloud trace",
    "google tag manager",
    "google-analytics",
    "google-tag-manager",
    "hsts",
    "html5",
    "http/3",
    "metapoweredby",
    "meta-geo",
    "meta-refresh-redirect",
    "modern-security-headers",
    "open-graph-protocol",
    "poweredby",
    "script",
    "via-proxy",
    "x-ua-compatible",
}
WHATWEB_COVERAGE_FIELDS = (
    "responses",
    "html",
    "body_limit_reached",
    "challenged",
    "attempted",
    "analyzed",
    "failed",
    "limited",
    "technologies",
)


def normalized_technologies(httpx_tech, plugins):
    observations = {}

    def add(name, version, source):
        name = str(name).strip()[:100]
        if not name or name.casefold() in NON_PRODUCT_SIGNATURES:
            return
        name = ALIASES.get(name.lower(), name)
        version = str(version).strip()[:100] if version else ""
        key = (name.lower(), version)
        entry = observations.setdefault(key, {"name": name, **({"version": version} if version else {})})
        sources = set(entry.get("evidence", "").split("; ")) - {""}
        sources.add(source)
        entry["evidence"] = "; ".join(sorted(sources))[:100]

    for tech in httpx_tech or []:
        if isinstance(tech, str):
            name, _, version = tech.partition(":")
            add(name, version, "httpx technology signature")
    for name, match in plugins.items():
        if name in METADATA_PLUGINS or not isinstance(match, dict):
            continue
        versions = match.get("version", [])
        if not isinstance(versions, list):
            versions = [versions]
        for version in versions or [None]:
            add(name, version, "WhatWeb response signature")
    versioned = {name for name, version in observations if version}
    return [value for (name, version), value in observations.items() if version or name not in versioned]


def access_challenge(headers, status):
    """Positive, provider-documented signals for this response only."""
    values = {}
    for name, value in headers.items():
        value = value if isinstance(value, list) else [value]
        values.setdefault(name.lower(), []).extend(str(v).strip().lower() for v in value)
    if values.get("cf-mitigated") == ["challenge"]:
        return {"provider": "Cloudflare", "action": "challenge", "evidence": "cf-mitigated: challenge"}
    action = values.get("x-amzn-waf-action", [])
    if (action == ["challenge"] and status == 202) or (action == ["captcha"] and status == 405):
        return {
            "provider": "AWS WAF",
            "action": action[0],
            "evidence": f"x-amzn-waf-action: {action[0]}; HTTP {status}",
        }


class IconLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.base = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = attrs.get("href")
        if tag == "link" and "icon" in (attrs.get("rel") or "").lower().split() and attrs.get("href"):
            self.links.append(attrs["href"])


def icon_urls(url, body):
    parser = IconLinks()
    parser.feed(body)
    origin = urlsplit(url)
    try:
        base = urljoin(url, parser.base) if parser.base else url
    except ValueError:
        base = url
    result = []
    for href in [*parser.links, "/favicon.ico"]:
        try:
            candidate = urljoin(url if href == "/favicon.ico" else base, href)
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc) or parsed.username or parsed.password:
            continue
        candidate = parsed._replace(fragment="").geturl()
        if candidate not in result:
            result.append(candidate)
    return result[:2]


def favicon_fingerprint(url, content):
    # Reject login/challenge/SPA HTML and unknown formats instead of hashing them as an icon.
    is_image = content.startswith((b"\x00\x00\x01\x00", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"\xff\xd8\xff"))
    is_image |= content.startswith(b"RIFF") and content[8:12] == b"WEBP"
    is_image |= bool(re.match(rb"\s*(?:<\?xml[^>]*>\s*)?<svg[\s>]", content, re.I))
    if not is_image:
        return None
    return {"url": url, "sha256": sha256(content).hexdigest(), "mmh3": mmh3.hash(base64.encodebytes(content))}


class whatweb(BaseInterceptModule):
    """Enrich the existing response before any output consumer serializes it."""

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["TECHNOLOGY"]
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Offline WhatWeb technology detection, favicon fingerprints and explicit challenge markers",
        "created_date": "2026-10-20",
        "author": "@carlospolop",
    }
    options = {
        "version": "v0.6.4",
        "binary": "",
        "timeout": 20,
        "max_pages_per_origin": 20,
        "max_favicon_size": 262144,
    }
    options_desc = {
        "version": "Pinned WhatWeb release",
        "binary": "Optional WhatWeb executable path",
        "timeout": "Maximum seconds per offline analysis or favicon request",
        "max_pages_per_origin": "Maximum existing HTML responses to fingerprint per origin",
        "max_favicon_size": "Maximum complete favicon bytes to hash",
    }
    deps_apt = ["ruby", "ruby-addressable", "ruby-json"]
    deps_ansible = [
        {
            "name": "Install pinned WhatWeb",
            "git": {
                "repo": "https://github.com/urbanadventurer/WhatWeb.git",
                "dest": "#{BBOT_TOOLS}/whatweb",
                "version": "#{BBOT_MODULES_WHATWEB_VERSION}",
            },
        }
    ]
    in_scope_only = True
    _priority = 3
    fatal_on_error = True

    async def setup(self):
        self.binary = str(self.config.get("binary") or self.helpers.tools_dir / "whatweb" / "whatweb")
        self.timeout = max(1, int(self.config.get("timeout", 20)))
        self.max_pages = max(1, int(self.config.get("max_pages_per_origin", 20)))
        httpx_config = self.scan.config.get("modules", {}).get("httpx", {})
        self.httpx_body_cap = max(1, int(httpx_config.get("max_response_size", 5242880)))
        self.max_icon_size = max(1, int(self.config.get("max_favicon_size", 262144)))
        self.pages = {}
        self.fingerprint_cache = {}
        self.icons = {}
        self._coverage = {field: 0 for field in WHATWEB_COVERAGE_FIELDS}
        result = await self.run_process([self.binary, "--version"], idle_timeout=self.timeout)
        if result is None or result.returncode:
            return False, "WhatWeb or its Ruby dependencies are unavailable"
        return True

    async def handle_event(self, event, **kwargs):
        if not hasattr(self, "_coverage"):
            self._coverage = {field: 0 for field in WHATWEB_COVERAGE_FIELDS}
        self._coverage["responses"] += 1
        data = event.data
        headers = data.get("header-dict", {})
        challenge = access_challenge(headers, data.get("status_code"))
        if challenge:
            data["access_challenge"] = challenge
        url = data["url"]
        parsed = urlsplit(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        body = data.get("body", "")
        content_type = str(data.get("contentType") or data.get("content_type") or "").lower()
        is_html = "html" in content_type or bool(re.match(r"\s*(?:<!doctype html[^>]*>\s*)?<html[\s>]", body, re.I))
        if is_html:
            self._coverage["html"] += 1
            # httpx can return a body truncated exactly at its read cap (also
            # after decompression). Count limit hits without claiming that an
            # exactly sized response was necessarily truncated.
            if len(body.encode("utf-8")) >= getattr(self, "httpx_body_cap", 5242880):
                self._coverage["body_limit_reached"] += 1
        plugins = {}
        if is_html and not challenge:
            # WhatWeb analyzes a saved response packet, so identical packets on
            # different paths have identical results. Reuse them without using
            # another slot in the bounded per-origin subprocess budget.
            if not hasattr(self, "fingerprint_cache"):
                self.fingerprint_cache = {}
            cache = self.fingerprint_cache.setdefault(origin, {})
            packet = (data.get("status_code", 200), data.get("raw_header", ""), body)
            digest = sha256(repr(packet).encode("utf-8")).digest()
            if digest in cache:
                plugins = cache[digest]
                data["whatweb_checked"] = True
                self._coverage["attempted"] += 1
                self._coverage["analyzed"] += 1
            elif self.pages.get(origin, 0) < self.max_pages:
                self.pages[origin] = self.pages.get(origin, 0) + 1
                self._coverage["attempted"] += 1
                try:
                    plugins = await self.fingerprint(data)
                    cache[digest] = plugins
                    data["whatweb_checked"] = True
                    self._coverage["analyzed"] += 1
                except (TimeoutError, OSError, RuntimeError, ValueError) as error:
                    self._coverage["failed"] += 1
                    # A single slow or malformed response must not abort discovery.
                    # The required module's setup failure remains fatal.
                    self.warning(f"WhatWeb fingerprint skipped on {origin}: {type(error).__name__}")
                if origin not in self.icons:
                    try:
                        self.icons[origin] = await self.find_favicon(url, body)
                    except (TimeoutError, OSError, RuntimeError, ValueError) as error:
                        self.warning(f"Favicon fingerprint skipped on {origin}: {type(error).__name__}")
            else:
                self._coverage["limited"] += 1
        elif is_html and challenge:
            self._coverage["challenged"] += 1
        technologies = normalized_technologies(data.get("tech", []), plugins)
        self._coverage["technologies"] += len(technologies)
        if technologies:
            data["technologies"] = technologies
            for tech in technologies:
                await self.emit_event(
                    {
                        "host": str(event.host),
                        "url": url,
                        "technology": tech["name"],
                        **{key: value for key, value in tech.items() if key != "name"},
                    },
                    "TECHNOLOGY",
                    parent=event,
                    context="{module} identified {event.type}: {event.data[technology]}",
                )
        if self.icons.get(origin):
            data["favicon"] = self.icons[origin]
        return True

    async def report(self):
        coverage = getattr(self, "_coverage", {field: 0 for field in WHATWEB_COVERAGE_FIELDS})
        self.info(f"WhatWeb coverage: {json.dumps(coverage, sort_keys=True, separators=(',', ':'))}")

    async def fingerprint(self, data):
        with TemporaryDirectory(prefix="bbot-whatweb-") as directory:
            packet = Path(directory) / "response.http"
            output = Path(directory) / "result.json"
            raw = data.get("raw_header", "")
            # WhatWeb accepts a saved HTTP packet, preserving header signatures without another target request.
            raw = raw.strip().splitlines()
            if raw and raw[0].startswith("HTTP/"):
                raw.pop(0)
            # Saved-packet detection in WhatWeb requires an HTTP/1.x reason phrase.
            raw.insert(0, f"HTTP/1.1 {data.get('status_code', 200)} Response")
            packet.write_text("\r\n".join(raw) + "\r\n\r\n" + data.get("body", ""), encoding="utf-8")
            command = [
                self.binary,
                "--aggression=1",
                "--follow-redirect=never",
                "--color=never",
                "--quiet",
                f"--log-json={output}",
                str(packet),
            ]
            result = await asyncio.wait_for(self.run_process(command, idle_timeout=self.timeout), self.timeout + 1)
            if result is None or result.returncode or not output.is_file():
                raise RuntimeError("WhatWeb failed to produce its JSON result")
            records = json.loads(output.read_text())
            if len(records) != 1 or not isinstance(records[0].get("plugins"), dict):
                raise ValueError("Unexpected WhatWeb JSON output")
            return records[0]["plugins"]

    async def find_favicon(self, url, body):
        for icon_url in icon_urls(url, body):
            if not self.scan.in_scope(icon_url):
                continue
            with TemporaryDirectory(prefix="bbot-favicon-") as directory:
                filename = Path(directory) / "icon"
                downloaded = await self.helpers.download(
                    icon_url,
                    filename=filename,
                    max_size=self.max_icon_size + 8192,
                    follow_redirects=False,
                    timeout=self.timeout,
                    warn=False,
                    headers=dict(self.scan.custom_http_headers),
                )
                if not downloaded:
                    continue
                content = filename.read_bytes()
                if len(content) > self.max_icon_size:
                    continue
                fingerprint = favicon_fingerprint(icon_url, content)
                if fingerprint:
                    return fingerprint
