"""One bounded Katana/Waymore pass per observed website, with batched output."""

import asyncio
from collections import defaultdict
import gzip
import json
import os
from pathlib import Path
import re
import signal
from urllib.parse import urlsplit

from bbot.modules.base import BaseModule
from bbot.modules.whatweb import normalized_technologies
from bbot.web_recon import (batches, body_digest, canonical_origin, choose_whatweb,
                            merge_observations, normalize_url, observation, select_urls)


class web_recon(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["WEB_URL_BATCH"]
    flags = ["active", "safe", "web-basic"]
    meta = {"description": "Bounded website URL discovery with Katana and Waymore", "created_date": "2026-10-23", "author": "@carlospolop"}
    options = {"katana_version": "1.8.0", "waymore_version": "8.9", "crawl_seconds": 180,
               "archive_seconds": 180, "max_pages": 500, "max_websites_parallel": 2,
               "katana_binary": "katana", "waymore_binary": "waymore", "httpx_binary": "httpx", "whatweb_binary": ""}
    options_desc = {key: key.replace("_", " ") for key in options}
    deps_pip = ["waymore==8.9"]
    deps_ansible = [{"name": "Download Katana", "unarchive": {
        "src": "https://github.com/projectdiscovery/katana/releases/download/v#{BBOT_MODULES_WEB_RECON_KATANA_VERSION}/katana_#{BBOT_MODULES_WEB_RECON_KATANA_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
        "include": "katana", "dest": "#{BBOT_TOOLS}", "remote_src": True}},
        {"name": "Ensure Katana executable mode", "file": {"path": "#{BBOT_TOOLS}/katana", "mode": "0755"}}]
    _module_threads = 2
    in_scope_only = True

    async def setup(self):
        self.origins = {}
        self.live = defaultdict(dict)
        self.packet_paths = defaultdict(dict)
        self.existing_whatweb = defaultdict(set)
        self.completed = set()
        self.katana = self._binary("katana_binary", "katana")
        self.waymore = self._binary("waymore_binary", "waymore")
        self.httpx = self._binary("httpx_binary", "httpx")
        self.whatweb = str(self.config.get("whatweb_binary") or self.helpers.tools_dir / "whatweb" / "whatweb")
        for binary in (self.katana, self.waymore, self.httpx, self.whatweb):
            if not self.helpers.which(binary) and not Path(binary).is_file():
                return False, f"web_recon dependency unavailable: {Path(binary).name}"
        return True

    def _binary(self, option, default):
        value = str(self.config.get(option, default))
        bundled = self.helpers.tools_dir / value
        return str(bundled) if bundled.is_file() else value

    async def handle_event(self, event):
        data = event.data if isinstance(event.data, dict) else {}
        url = data.get("url")
        origin = canonical_origin(url)
        if not origin or not self.scan.in_scope(url):
            return
        self.origins.setdefault(origin, getattr(event, "parent", None) or event)
        normalized = normalize_url(url, origin)
        if normalized is None:
            return
        body = data.get("body")
        status = data.get("status_code")
        record = observation(url, origin, "bbot", status=status, length=len(body.encode()) if isinstance(body, str) else None,
                             content_type=data.get("contentType") or data.get("content_type"),
                             body_hash=body_digest(body) if isinstance(body, str) and len(body) <= 262_144 else None,
                             live=True)
        if record:
            technologies = data.get("technologies")
            if isinstance(technologies, list):
                record["technologies"] = [
                    {"name": item["name"][:100], **({"version": item["version"][:100]} if isinstance(item.get("version"), str) else {})}
                    for item in technologies[:20]
                    if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
                ]
        if record and len(self.live[origin]) < 500:
            self.live[origin][record["url"]] = record
            if data.get("whatweb_checked") is True:
                self.existing_whatweb[origin].add(record["url"])
            content_type = str(data.get("contentType") or data.get("content_type") or "").lower()
            if (isinstance(body, str) and len(body) <= 262_144 and "html" in content_type
                    and len(self.packet_paths[origin]) < 50):
                packet_dir = self.scan.home / "web_recon" / body_digest(origin)[:16] / "bbot_packets"
                packet_dir.mkdir(parents=True, exist_ok=True)
                packet_path = packet_dir / (body_digest(record["url"])[:16] + ".http")
                packet_path.write_text(self._packet_from_bbot(data), encoding="utf-8")
                self.packet_paths[origin][record["url"]] = packet_path

    async def finish(self):
        pending = [(origin, event) for origin, event in self.origins.items() if origin not in self.completed]
        self.completed.update(origin for origin, _ in pending)
        parallel = max(1, min(4, int(self.config.get("max_websites_parallel", 2))))
        semaphore = asyncio.Semaphore(parallel)

        async def bounded(origin, event):
            async with semaphore:
                await self._collect(origin, event)

        await asyncio.gather(*(bounded(origin, event) for origin, event in pending))

    async def _run(self, argv, seconds, cwd=None):
        process = await asyncio.create_subprocess_exec(*map(str, argv), cwd=cwd,
                                                       stdout=asyncio.subprocess.DEVNULL,
                                                       stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
        try:
            await asyncio.wait_for(process.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
            return "timeout"
        return "ok" if process.returncode == 0 else "error"

    async def _collect(self, origin, parent):
        folder = self.scan.home / "web_recon" / body_digest(origin)[:16]
        folder.mkdir(parents=True, exist_ok=True)
        katana_out, waymore_out = folder / "katana.jsonl", folder / "waymore.txt"
        response_dir = folder / "katana_responses"
        crawl_seconds = max(30, min(900, int(self.config.get("crawl_seconds", 180))))
        archive_seconds = max(30, min(900, int(self.config.get("archive_seconds", 180))))
        max_pages = max(10, min(2000, int(self.config.get("max_pages", 500))))
        scope = "^" + re.escape(origin) + r"(?:/|\?|$)"
        katana = [self.katana, "-u", origin + "/", "-fs", "fqdn", "-cs", scope, "-dr", "-d", "4",
                  "-jc", "-kf", "all", "-fsu", "-iqp", "-mdp", str(max_pages), "-mrs", "262144",
                  "-c", "10", "-p", "1", "-ct", f"{crawl_seconds}s", "-retry", "0",
                  "-jsonl", "-sr", "-srd", str(response_dir), "-o", str(katana_out), "-silent"]
        for key, value in self.scan.custom_http_headers.items():
            katana += ["-H", f"{key}: {value}"]
        # Historical URLs are leads, not current responses; fetching archive
        # bodies would add disk I/O without a reliable WhatWeb observation.
        waymore = [self.waymore, "-i", origin, "-n", "-mode", "U",
                   "-p", "4", "-r", "0", "-ow", "-oU", str(waymore_out)]
        states = await asyncio.gather(self._run(katana, crawl_seconds + 30), self._run(waymore, archive_seconds))
        records = list(self.live[origin].values())
        packets = dict(self.packet_paths[origin])
        records.extend(self._katana_records(katana_out, origin))
        records.extend(self._waymore_records(waymore_out, origin))
        merged, reductions = merge_observations(records, origin)
        selected = select_urls(merged)
        with gzip.open(folder / "candidates.jsonl.gz", "wt", encoding="utf-8") as stream:
            for record in merged:
                stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        # Probe only final candidates without a current response from BBOT or Katana.
        missing = [record for record in selected if not record.get("live")]
        if missing:
            await self._probe_missing(missing, folder, origin, packets)
        fingerprinted = await self._fingerprint(selected, packets, folder, origin, katana_out)
        counts = {"input": len(records), "unique": len(merged), "selected": len(selected),
                  "not_selected": max(0, len(merged) - len(selected)),
                  "whatweb": len(self.existing_whatweb[origin]) + fingerprinted,
                  "katana": states[0], "waymore": states[1], **reductions}
        (folder / "selected.json").write_text(json.dumps({"origin": origin, "counts": counts, "urls": selected}, ensure_ascii=False))
        for batch in batches(origin, selected, counts):
            await self.emit_event(batch, "WEB_URL_BATCH", parent=parent,
                                  context="{module} collected bounded URL observations for {event.data[origin]}")
        self.info(f"Web recon {origin}: {len(records)} candidates, {len(selected)} selected, {fingerprinted} offline fingerprints; Katana={states[0]} Waymore={states[1]}")

    def _katana_records(self, path, origin):
        records = []
        if not path.is_file():
            return records
        with path.open(errors="replace") as lines:
            for index, line in enumerate(lines):
                if index >= 100_000:
                    break
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                request = item.get("request") if isinstance(item.get("request"), dict) else {}
                response = item.get("response") if isinstance(item.get("response"), dict) else {}
                url = request.get("endpoint") or request.get("url") or item.get("url")
                body = response.get("body")
                status = response.get("status_code") or response.get("status")
                headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
                content_type = headers.get("content-type") or headers.get("Content-Type")
                live = isinstance(status, int) and 100 <= status <= 599
                length = response.get("content_length")
                record = observation(url, origin, "katana", status=status,
                                     length=length if isinstance(length, int) else len(body.encode()) if isinstance(body, str) else None,
                                     content_type=content_type, body_hash=body_digest(body) if isinstance(body, str) and body else None,
                                     live=live)
                if record:
                    records.append(record)
        return records

    def _katana_packets(self, path, origin, needed, packets):
        if not needed or not path.is_file():
            return
        with path.open(errors="replace") as lines:
            for index, line in enumerate(lines):
                if index >= 100_000 or not needed:
                    break
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                request = item.get("request") if isinstance(item, dict) else None
                response = item.get("response") if isinstance(item, dict) else None
                if not isinstance(request, dict) or not isinstance(response, dict):
                    continue
                normalized = normalize_url(request.get("endpoint") or request.get("url"), origin)
                if not normalized or normalized[0] not in needed:
                    continue
                body, status = response.get("body"), response.get("status_code")
                if not isinstance(body, str) or len(body) > 262_144 or not isinstance(status, int):
                    continue
                headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
                packets[normalized[0]] = self._packet(status, headers, body)
                needed.remove(normalized[0])

    def _waymore_records(self, path, origin):
        if not path.is_file():
            return []
        records = []
        with path.open(errors="replace") as lines:
            for index, url in enumerate(lines):
                if index >= 100_000:
                    break
                record = observation(url.strip(), origin, "waymore")
                if record:
                    records.append(record)
        return records

    async def _probe_missing(self, missing, folder, origin, packets):
        target_file, output_file = folder / "httpx_targets.txt", folder / "httpx.jsonl"
        target_file.write_text("\n".join(record["url"] for record in missing) + "\n")
        command = [self.httpx, "-l", str(target_file), "-json", "-include-response", "-silent",
                   "-threads", "15", "-retries", "0", "-timeout", "10",
                   "-rstr", "262144", "-rsts", "262144", "-o", str(output_file)]
        for key, value in self.scan.custom_http_headers.items():
            command += ["-H", f"{key}: {value}"]
        await self._run(command, 180)
        if not output_file.is_file():
            return
        by_url = {record["url"]: record for record in missing}
        with output_file.open(errors="replace") as lines:
            for line in lines:
                try:
                    result = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(result, dict):
                    continue
                url = result.get("url") or result.get("input")
                normalized = normalize_url(url, origin)
                if not normalized or normalized[0] not in by_url:
                    continue
                record = by_url[normalized[0]]
                status = result.get("status_code")
                if isinstance(status, int):
                    record["status_code"], record["live"] = status, True
                length = result.get("content_length")
                if isinstance(length, int):
                    record["body_length"] = length
                content_type = result.get("content_type")
                if isinstance(content_type, str):
                    record["content_type"] = content_type.split(";", 1)[0][:80]
                response = result.get("response")
                if isinstance(response, str) and response:
                    parts = re.split(r"\r?\n\r?\n", response, maxsplit=1)
                    if len(parts) != 2:
                        continue
                    body = parts[1][:262_144]
                    record["body_sha256"] = body_digest(body)
                    if "html" not in record.get("content_type", "").lower() or not isinstance(status, int):
                        continue
                    headers = {}
                    for header in parts[0].splitlines()[1:]:
                        key, separator, value = header.partition(":")
                        if separator and key:
                            headers[key] = value.strip()
                    packet_file = folder / (body_digest(record["url"])[:16] + ".http")
                    packet_file.write_text(self._packet(status, headers, body), encoding="utf-8")
                    packets[record["url"]] = packet_file

    async def _fingerprint(self, records, packets, folder, origin, katana_out):
        checked = 0
        remaining = max(0, 20 - len(self.existing_whatweb[origin]))
        candidates = [record for record in records if record["url"] not in self.existing_whatweb[origin]]
        choices = choose_whatweb(candidates, maximum=remaining)
        self._katana_packets(katana_out, origin, {record["url"] for record in choices if record["url"] not in packets}, packets)
        for record in choices:
            packet = packets.get(record["url"])
            if not packet:
                continue
            if isinstance(packet, Path):
                packet = packet.read_text(errors="replace")
            packet_file = folder / (body_digest(record["url"])[:16] + ".http")
            output_file = folder / (body_digest(record["url"])[:16] + ".whatweb.json")
            packet_file.write_text(packet[:524_288], encoding="utf-8")
            command = [self.whatweb, "--aggression=1", "--follow-redirect=never", "--color=never",
                       "--quiet", f"--log-json={output_file}", str(packet_file)]
            checked += 1
            if await self._run(command, 25) != "ok" or not output_file.is_file():
                continue
            try:
                entries = json.loads(output_file.read_text())
                plugins = entries[0].get("plugins", {}) if len(entries) == 1 else {}
                technologies = normalized_technologies([], plugins)
                if technologies:
                    record["technologies"] = technologies[:20]
            except (ValueError, TypeError, IndexError):
                continue
        return checked

    @staticmethod
    def _packet(status, headers, body):
        lines = [f"HTTP/1.1 {status} Response"]
        lines += [f"{key}: {value}" for key, value in headers.items() if isinstance(value, str)]
        return "\r\n".join(lines) + "\r\n\r\n" + body

    def _packet_from_bbot(self, data):
        body = data.get("body")
        if not isinstance(body, str) or len(body) > 262_144:
            return ""
        raw = data.get("raw_header", "")
        if isinstance(raw, str) and raw:
            lines = raw.strip().splitlines()
            if lines and lines[0].startswith("HTTP/"):
                lines.pop(0)
            return "\r\n".join([f"HTTP/1.1 {data.get('status_code', 200)} Response", *lines]) + "\r\n\r\n" + body
        return self._packet(data.get("status_code", 200), data.get("header-dict", {}), body)
