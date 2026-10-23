"""Bounded, origin-scoped URL inventory shared by web discovery consumers.

This module deliberately does not create one BBOT event per discovered URL.
The caller owns tool execution and passes observations through this reducer.
"""

from collections import defaultdict
from hashlib import sha256
import json
import re
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

MAX_URLS = 200
MAX_FOLDER = 10
MAX_DEPTH = 10
MAX_INPUT = 100_000
MAX_URL_LENGTH = 2_048
MAX_EVENT_BYTES = 8_000
STATIC_EXTENSIONS = {".css", ".gif", ".ico", ".jpeg", ".jpg", ".map", ".png", ".svg", ".woff", ".woff2"}
ID_SEGMENT = re.compile(r"^(?:\d{4,}|[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f-]{27,})$", re.I)


def canonical_origin(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return ""
        host = parsed.hostname.lower().rstrip(".")
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port and port != (443 if parsed.scheme.lower() == "https" else 80):
            host += f":{port}"
        return f"{parsed.scheme.lower()}://{host}"
    except (TypeError, ValueError):
        return ""


def normalize_url(url, origin):
    """Return a safe representative URL and a key; query values never enter events."""
    if (not isinstance(url, str) or len(url) > MAX_URL_LENGTH or any(ord(char) < 32 for char in url)
            or canonical_origin(url) != origin):
        return None
    parsed = urlsplit(url)
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if len([segment for segment in path.split("/") if segment]) > MAX_DEPTH:
        return None
    # Keep parameter names, since they distinguish endpoint shapes; drop values.
    keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key and len(key) <= 100})[:20]
    safe_query = "&".join(f"{quote(key, safe='')}=" for key in keys)
    safe_url = urlunsplit((urlsplit(origin).scheme, urlsplit(origin).netloc, path, safe_query, ""))
    family_segments = ["{id}" if ID_SEGMENT.fullmatch(unquote(part)) else part.lower() for part in path.split("/") if part]
    parent_segments = family_segments if path.endswith("/") else family_segments[:-1]
    family = "/" + "/".join(parent_segments[:2]) + "/" if parent_segments else "/"
    return safe_url, family


def observation(url, origin, source, *, status=None, length=None, content_type=None, body_hash=None, live=False):
    normalized = normalize_url(url, origin)
    if normalized is None:
        return None
    safe_url, folder = normalized
    record = {"url": safe_url, "folder": folder, "sources": [source], "live": bool(live)}
    if isinstance(status, int) and 100 <= status <= 599:
        record["status_code"] = status
    if isinstance(length, int) and 0 <= length <= 100_000_000:
        record["body_length"] = length
    if isinstance(content_type, str) and content_type:
        record["content_type"] = content_type.split(";", 1)[0][:80]
    if isinstance(body_hash, str) and re.fullmatch(r"[0-9a-f]{64}", body_hash):
        record["body_sha256"] = body_hash
    return record


def _shape_key(url):
    parts = urlsplit(url)
    path = "/".join("{id}" if ID_SEGMENT.fullmatch(unquote(part)) else part for part in parts.path.split("/"))
    return (path.rstrip("/") or "/", parts.query)


def merge_observations(records, origin):
    merged = {}
    counts = defaultdict(int)
    for index, record in enumerate(records):
        if index >= MAX_INPUT:
            counts["input_cap"] += 1
            break
        if not isinstance(record, dict) or not normalize_url(record.get("url"), origin):
            counts["invalid_or_out_of_scope"] += 1
            continue
        key = _shape_key(record["url"])
        previous = merged.get(key)
        if previous is None:
            merged[key] = {**record, "sources": sorted(set(record.get("sources", [])))}
            continue
        counts["duplicates"] += 1
        previous["sources"] = sorted(set(previous.get("sources", [])) | set(record.get("sources", [])))
        if record.get("live") and (not previous.get("live") or record.get("status_code")):
            previous.update({key: value for key, value in record.items() if key not in {"sources", "folder"}})
    return list(merged.values()), dict(counts)


def _rank(record):
    path = urlsplit(record["url"]).path.lower()
    interesting = any(part in path for part in ("/api", "/admin", "/login", "/auth", "/graphql", "/docs", "/swagger"))
    static = any(path.endswith(ext) for ext in STATIC_EXTENSIONS)
    return (int(record.get("live", False)), int(record.get("status_code", 0) in {200, 401, 403}),
            int(interesting), len(record.get("sources", [])), -int(static), -len(path), record["url"])


def select_urls(records, maximum=MAX_URLS, per_folder=MAX_FOLDER):
    """Round-robin across route families, reducing folder cap until <= maximum."""
    groups = defaultdict(list)
    for record in records:
        groups[record["folder"]].append(record)
    for entries in groups.values():
        entries.sort(key=_rank, reverse=True)
    for cap in range(1, per_folder + 1):
        if sum(min(len(entries), cap) for entries in groups.values()) >= maximum:
            break
    selected = []
    for level in range(cap):
        for folder in sorted(groups, key=lambda key: _rank(groups[key][0]), reverse=True):
            if len(groups[folder]) > level:
                selected.append(groups[folder][level])
                if len(selected) >= maximum:
                    return selected
    return selected


def choose_whatweb(records, maximum=20):
    """At most two distinct live HTML bodies per family, then one if over budget."""
    if maximum <= 0:
        return []
    groups = defaultdict(list)
    for record in records:
        if not record.get("live") or not record.get("body_sha256"):
            continue
        if "html" not in record.get("content_type", "").lower():
            continue
        groups[record["folder"]].append(record)
    for entries in groups.values():
        entries.sort(key=_rank, reverse=True)
    quota = 1 if sum(min(2, len(entries)) for entries in groups.values()) > maximum else 2
    chosen, bodies = [], set()
    for level in range(quota):
        for folder in sorted(groups, key=lambda key: _rank(groups[key][0]), reverse=True):
            if len(groups[folder]) <= level:
                continue
            record = groups[folder][level]
            if record["body_sha256"] in bodies:
                continue
            chosen.append(record)
            bodies.add(record["body_sha256"])
            if len(chosen) >= maximum:
                return chosen
    return chosen


def batches(origin, records, counts):
    """Emit compact events; a single 200-URL event would be compacted by Nexus."""
    shared = {"origin": origin, "host": urlsplit(origin).hostname, "counts": counts}
    pending = []
    for record in records:
        candidate = {**shared, "urls": pending + [record]}
        if pending and len(json.dumps(candidate, separators=(",", ":")).encode()) > MAX_EVENT_BYTES:
            yield {**shared, "urls": pending}
            pending = []
        pending.append(record)
    if pending or not records:
        yield {**shared, "urls": pending}


def body_digest(body):
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    return sha256(body).hexdigest()
