import ipaddress
import random
import re
import json
import asyncio
import time
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse, unquote
from urllib.parse import urljoin

from bbot.modules.base import BaseModule
from bbot.core.helpers import shared_infra
from bbot.core.helpers.malwareworld import lookup as malwareworld_lookup
from bbot.core.helpers.malwareworld import normalize_indicator
from bbot.core.helpers.malwareworld import json_resident_bytes


MAX_MALWAREWORLD_RESPONSE_BYTES = 160 * 1024 * 1024
MAX_MALWAREWORLD_CACHE_RESIDENT_BYTES = 256 * 1024 * 1024
MAX_MALWAREWORLD_CACHE_ENTRIES = 4
MAX_MALWAREWORLD_PARALLEL_DOWNLOADS = 2


class host_reputation(BaseModule):
    # paid or quota-limited API: reuse responses from the S3 API cache when it is configured
    cache_api_responses = True
    watched_events = [
        "DNS_NAME",
        "DNS_NAME_UNRESOLVED",
        "IP_ADDRESS",
        "IP_RANGE",
        "URL",
        "MOBILE_APP",
        "TLS_CERTIFICATE",
        "FILESYSTEM",
        "SOCIAL",
        "FINDING",
        "VULNERABILITY",
    ]
    produced_events = ["FINDING", "HOST_REPUTATION", "GEOLOCATION"]
    flags = ["passive", "safe", "ip-enum"]
    meta = {
        "description": "Check observed indicators against MalwareWorld threat intelligence",
        "created_date": "2026-04-27",
        "author": "@carlospolop",
    }
    options = {
        "abuseipdb_api_key": "",
        "virustotal_api_keys": "",
        "otx_api_key": "",
        "malwareworld_base": "https://malwareworld.com/data/",
    }
    options_desc = {
        "abuseipdb_api_key": "AbuseIPDB API key for IP reputation checks",
        "virustotal_api_keys": "Comma-separated VirusTotal API keys for domain and IP reputation checks",
        "otx_api_key": "AlienVault OTX API key for domain and IP reputation checks",
        "malwareworld_base": "MalwareWorld data base URL or local path",
    }
    scope_distance_modifier = 1

    async def setup(self):
        self.abuseipdb_api_key = self.config.get("abuseipdb_api_key", "")
        raw_vt_keys = self.config.get("virustotal_api_keys", "")
        if isinstance(raw_vt_keys, str):
            self.virustotal_api_keys = [k.strip() for k in raw_vt_keys.split(",") if k.strip()]
        else:
            self.virustotal_api_keys = [str(k).strip() for k in (raw_vt_keys or []) if str(k).strip()]
        self.virustotal_api_keys = list(dict.fromkeys(self.virustotal_api_keys))
        self.otx_api_key = self.config.get("otx_api_key", "")
        self.malwareworld_base = self._normalize_base(
            self.config.get("malwareworld_base", "https://malwareworld.com/data/")
        )
        return True

    async def filter_event(self, event):
        if isinstance(event.data, dict) and event.data.get("category") in ("host-reputation", "indicator-reputation"):
            return False, "do not process reputation output recursively"
        if event.scope_distance != 0:
            return False, "reputation requires an in-scope observation"
        host = self._event_host(event).strip("[]")
        tags = {str(tag).lower() for tag in getattr(event, "tags", ())}
        is_ip = self._is_ip(host)
        if is_ip or event.type == "IP_RANGE":
            marked_shared = (
                "shared-frontend" in tags
                or bool({"load-balancer", "fronted-proxy", "api-gateway", "proxy", "waf"} & tags)
                or ("cdn" in tags and not any("github" in tag for tag in tags))
                or any(
                    tag.startswith(("shared-", "cdn-", "waf-", "load-balancer-", "proxy-"))
                    and not tag.endswith("-github")
                    for tag in tags
                )
            )
            if marked_shared or (is_ip and shared_infra.known_frontend(self.scan, host)):
                return False, "shared frontend IP is not the scanned organization's reputation"
        if event.type == "IP_ADDRESS" and ipaddress.ip_address(str(event.data)).version != 4:
            return False, "MalwareWorld IP feeds cover IPv4 only"
        if event.type == "IP_RANGE" and ":" in str(event.data):
            return False, "MalwareWorld has no IPv6 range coverage"
        if event.type in ("DNS_NAME", "DNS_NAME_UNRESOLVED") and not self._is_ip(self._event_host(event)):
            try:
                normalize_indicator("domain", self._event_host(event))
            except ValueError:
                # Service labels such as _dmarc or _smtp._tls cannot be MalwareWorld domain indicators;
                # the registrable names above them are looked up as their own DNS_NAME events.
                return False, "name is not a valid MalwareWorld domain indicator"
        if (
            event.type == "URL"
            and event.host
            and self._is_ip(str(event.host))
            and ipaddress.ip_address(str(event.host)).version != 4
        ):
            return False, "MalwareWorld IP feeds cover IPv4 only"
        if (
            event.type == "MOBILE_APP"
            and isinstance(event.data, dict)
            and str(self.app_indicator(event.data)).isdigit()
        ):
            return False, "iOS numeric store ID is not an app package indicator"
        return True

    async def handle_event(self, event):
        if event.type not in ("DNS_NAME", "DNS_NAME_UNRESOLVED", "IP_ADDRESS", "URL"):
            await self.handle_indicator_event(event)
            return
        host = self._event_host(event)
        if not host:
            return

        is_ip = self._is_ip(host)

        report = await self.collect_host_reputation(host, is_ip)
        if report.get("shared"):
            shared_infra.remember_frontend(self.scan, host, "cdn", "AbuseIPDB")
            await self.emit_event({"host": host, "ip": host, "is_cdn": True, "isCdn": True,
                                   "usageType": "Content Delivery Network", "provider": "AbuseIPDB"},
                                  "GEOLOCATION", event, tags=["cdn", "shared-frontend"])
            return
        risk_score, malicious, sources = report["risk_score"], report["malicious"], report["sources"]
        verdict = "malicious" if malicious else "not malicious"
        # The host's reputation is asset information in its own right; the FINDING below is
        # only an observation that is grouped with the others of the scan.
        await self.emit_event(
            {
                "host": host,
                "kind": "ip" if is_ip else "domain",
                "risk_score": int(risk_score or 0),
                "malicious": bool(malicious),
                "sources": sources,
                "malwareworld": report["malwareworld"],
                "provider_coverage": report["provider_coverage"],
                "configured_providers": report["configured_providers"],
                "provider_errors": report["provider_errors"],
                "provider_verdicts": report["provider_verdicts"],
            },
            "HOST_REPUTATION",
            event,
            context=f"{{module}} checked reputation sources for {host} and emitted {{event.type}}",
        )
        # A completed clean lookup is a baseline observation, never a finding.
        # Incomplete negative observations fail before reaching this point.
        if not malicious and risk_score == 0 and not sources:
            return
        await self.emit_event(
            {
                "host": host,
                # Reputation is third-party context, not proof of compromise: never above MEDIUM.
                "severity": "MEDIUM" if malicious else "INFO",
                "title": f"Host reputation: {host} is {verdict}",
                "category": "host-reputation",
                "description": (
                    f"Reputation sources marked {host} as {verdict} with risk score {risk_score}. "
                    "A malicious reputation result can indicate malware hosting, abuse reports, suspicious infrastructure, or prior compromise, and should be validated before trusting traffic from or to this host. "
                    "Reputation data is not proof that the current system is compromised, because old incidents, shared hosting, recycled IP addresses, or third-party infrastructure can influence the result. "
                    "The host should still be reviewed carefully: confirm ownership, inspect recent DNS and hosting changes, check web and network logs for abuse, and decide whether traffic should be blocked, monitored, or escalated for incident response."
                ),
                "kind": "ip" if is_ip else "domain",
                "risk_score": risk_score,
                "malicious": malicious,
                "sources": sources,
                "malwareworld": report["malwareworld"],
                "provider_verdicts": report["provider_verdicts"],
                "dedupe_key": f"host-reputation:{host}",
            },
            "FINDING",
            event,
            context=f"{{module}} checked reputation sources for {host} and emitted {{event.type}}: {{event.data}}",
        )

    async def handle_indicator_event(self, event):
        data = event.data if isinstance(event.data, dict) else {}
        candidates = []
        fields = {
            "TLS_CERTIFICATE": (
                "certificate",
                (
                    "certFingerprintSha256",
                    "cert_fingerprint_sha256",
                    "fingerprint_sha256",
                    "fingerprintSha256",
                    "sha256",
                    "fingerprint",
                ),
            ),
            "FILESYSTEM": ("hash", ("sha256", "sha1")),
            "SOCIAL": ("phone", ("phone",)),
        }
        if event.type == "IP_RANGE":
            candidates.append(("range", str(event.data)))
        if event.type == "MOBILE_APP" and self.app_indicator(data):
            candidates.append(("app", self.app_indicator(data)))
        if event.type in fields:
            kind, names = fields[event.type]
            candidates.extend((kind, data[name]) for name in names if isinstance(data.get(name), str))
        if event.type in ("FINDING", "VULNERABILITY"):
            candidates.extend(
                ("vulnerability", cve.upper())
                for cve in re.findall(
                    r"\bCVE-\d{4}-\d{4,}\b",
                    " ".join(str(data.get(k, "")) for k in ("cve", "title", "description")),
                    re.I,
                )
            )
        for kind, value in sorted(set(candidates)):
            result = await self.check_malwareworld(value, kind)
            # MalwareWorld's explicit verdict is derived only from threat categories. Other
            # catalogue matches are context, not evidence that the scanned asset is malicious;
            # the original VULNERABILITY/FINDING event remains independently emitted and
            # ingested. Only an explicit positive verdict becomes a reputation finding.
            if not result["malicious"]:
                continue
            finding = {
                "kind": kind,
                "indicator": value,
                "category": "indicator-reputation",
                "severity": "MEDIUM",
                "title": f"MalwareWorld {kind} observation: {value}",
                "location": f"{kind}:{value}",
                "description": "Passive threat-intelligence match; review attribution and source categories before assigning company risk.",
                "poc": json.dumps(result["malwareworld"], sort_keys=True),
                "malicious": result["malicious"],
                "risk_score": result["risk_score"],
                "sources": result["sources"],
            }
            if event.host:
                finding["host"] = str(event.host)
            # Hostless indicators (app packages, file hashes) inherit the closest parent host;
            # an explicit empty host fails FINDING validation and would drop the match.
            await self.emit_event(finding, "FINDING", parent=event)

    @staticmethod
    def _event_host(event):
        return str(event.host or event.data).lower().rstrip(".")

    @staticmethod
    def app_indicator(data):
        return data.get("bundle_id") or data.get("bundleId") or data.get("id") or ""

    async def collect_host_reputation(self, host, is_ip):
        """Record the configured high-confidence providers; a failed provider is never a clean observation."""
        results, errors, configured = {}, {}, []
        checks = []
        if is_ip and getattr(self, "abuseipdb_api_key", ""):
            checks.append(("AbuseIPDB", self.check_abuseipdb))
        checks.append(("MalwareWorld", self.check_malwareworld))
        if getattr(self, "virustotal_api_keys", []):
            checks.append(("VirusTotal", self.check_vt_ip if is_ip else self.check_vt_domain))
        for name, check in checks:
            configured.append(name)
            try:
                result = await check(host)
                if result.get("error") or result.get("rate_limited") or type(result.get("malicious")) is not bool:
                    raise RuntimeError("Incomplete provider verdict")
                if result.get("shared"):
                    return result
                results[name] = result
            except Exception as error:
                errors[name] = type(error).__name__
        malicious = any(result["malicious"] for result in results.values())
        if not results or (errors and not malicious):
            raise RuntimeError("Reputation provider coverage incomplete: " + ", ".join(errors))
        verdicts = {name: {"malicious": result["malicious"], "risk_score": result.get("risk_score", 0),
                           "evidence": {key: value for key, value in result.get("details", {}).items()
                                        if key in {"abuseConfidenceScore", "totalReports", "lastReportedAt", "last_analysis_stats"}}}
                    for name, result in results.items()}
        return {"malicious": malicious, "risk_score": max(result.get("risk_score", 0) for result in results.values()),
                "sources": [source for result in results.values() for source in result.get("sources", [])],
                "malwareworld": results.get("MalwareWorld", {}).get("malwareworld"),
                "provider_coverage": sorted(results), "configured_providers": sorted(configured), "provider_errors": errors,
                "provider_verdicts": verdicts}

    async def check_abuseipdb(self, ip):
        if not self.abuseipdb_api_key:
            return {"error": "abuseipdb_api_key not set", "malicious": False}
        response = await self.request_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
        )
        data = response.get("data", {}) if isinstance(response, dict) else {}
        if str(data.get("usageType") or "").strip().lower() == "content delivery network":
            return {"shared": True, "malicious": False, "risk_score": 0}
        score, reports = data.get("abuseConfidenceScore"), data.get("totalReports", 0)
        if type(score) is not int or not 0 <= score <= 100 or type(reports) is not int or reports < 0:
            raise RuntimeError("AbuseIPDB: invalid confidence counters")
        malicious = score >= 90 and reports >= 3
        return {
            "malicious": malicious,
            "risk_score": score,
            "sources": [{"source": "IP in AbuseIPDB", "type": "abuse", "listed_date": data.get("lastReportedAt")}] if malicious else [],
            "type": "abuse",
            "listed_date": data.get("lastReportedAt"),
            "details": {
                "abuseConfidenceScore": score,
                "countryCode": data.get("countryCode"),
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
            },
        }

    async def check_vt_ip(self, ip):
        return await self.check_vt(f"https://www.virustotal.com/api/v3/ip_addresses/{self.helpers.quote(ip)}")

    async def check_vt_domain(self, domain):
        return await self.check_vt(f"https://www.virustotal.com/api/v3/domains/{self.helpers.quote(domain)}")

    async def check_vt(self, url):
        if not self.virustotal_api_keys:
            return {"error": "virustotal_api_keys not set", "malicious": False}

        keys = list(self.virustotal_api_keys)
        random.shuffle(keys)
        last_result = None
        for key in keys:
            response = await self.request_json(url, headers={"x-apikey": key})
            if response.get("status") == 429 or response.get("rate_limited"):
                last_result = response
                continue
            attributes = response.get("data", {}).get("attributes", {}) if isinstance(response, dict) else {}
            stats = attributes.get("last_analysis_stats", {}) or {}
            analysis_results = attributes.get("last_analysis_results", {}) or {}
            malicious_count, suspicious_count = stats.get("malicious"), stats.get("suspicious", 0)
            if type(malicious_count) is not int or malicious_count < 0 or type(suspicious_count) is not int or suspicious_count < 0:
                raise RuntimeError("VirusTotal: invalid analysis counters")
            reputation = self._to_int(attributes.get("reputation"))
            risk_score = min(100, malicious_count * 20 + suspicious_count * 10 + max(0, -reputation))
            sources = []
            for engine_name, engine_result in analysis_results.items():
                if not isinstance(engine_result, dict):
                    continue
                category = str(engine_result.get("category") or "").lower()
                if category not in ("malicious", "suspicious"):
                    continue
                result = engine_result.get("result") or category
                sources.append(
                    {
                        "source": f"VirusTotal:{engine_name}",
                        "type": str(result),
                        "listed_date": None,
                    }
                )
            return {
                "malicious": malicious_count >= 3,
                "risk_score": risk_score,
                "type": "malware-analysis",
                "listed_date": None,
                "sources": sources or ([{"source": "VirusTotal", "type": "malware-analysis", "listed_date": None}]
                                       if malicious_count >= 3 else []),
                "details": {
                    "last_analysis_stats": stats,
                    "last_analysis_results": analysis_results,
                    "reputation": reputation,
                },
            }
        return last_result or {"rate_limited": True, "status": 429, "malicious": False}

    async def check_otx(self, hostname):
        if not self.otx_api_key:
            return {"error": "otx_api_key not set", "malicious": False}
        response = await self.request_json(
            f"https://otx.alienvault.com/api/v1/indicators/hostname/{self.helpers.quote(hostname)}/general",
            headers={"X-OTX-API-KEY": self.otx_api_key},
        )
        pulse_info = response.get("pulse_info", {}) if isinstance(response, dict) else {}
        count = self._to_int(pulse_info.get("count"))
        pulses = pulse_info.get("pulses") or []
        sources = []
        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            pulse_name = pulse.get("name") or pulse.get("id") or "unknown-pulse"
            sources.append(
                {
                    "source": f"OTX:{pulse_name}",
                    "type": "pulse",
                    "listed_date": pulse.get("modified") or pulse.get("created"),
                }
            )
        return {
            "malicious": count > 0,
            "risk_score": min(100, count * 20),
            "type": "threat-intel-pulse",
            "listed_date": None,
            "sources": sources,
            "details": {
                "count": count,
                "pulses": pulses,
                "references": (pulse_info.get("references") or [])[:5],
            },
        }

    async def check_otx_ip(self, ip):
        if not self.otx_api_key:
            return {"error": "otx_api_key not set", "malicious": False}
        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            return {"error": "invalid IP address", "malicious": False}
        indicator_type = "IPv6" if version == 6 else "IPv4"
        response = await self.request_json(
            f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{self.helpers.quote(ip)}/reputation",
            headers={"X-OTX-API-KEY": self.otx_api_key},
        )
        pulse_info = response.get("pulse_info", {}) if isinstance(response, dict) else {}
        count = self._to_int(pulse_info.get("count"))
        reputation = max(
            self._to_int(response.get("reputation")) if isinstance(response, dict) else 0,
            self._to_int(response.get("threat_score")) if isinstance(response, dict) else 0,
            self._to_int(response.get("threatScore")) if isinstance(response, dict) else 0,
        )
        pulses = pulse_info.get("pulses") or []
        sources = []
        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            pulse_name = pulse.get("name") or pulse.get("id") or "unknown-pulse"
            sources.append(
                {
                    "source": f"OTX:{pulse_name}",
                    "type": "pulse",
                    "listed_date": pulse.get("modified") or pulse.get("created"),
                }
            )
        if reputation > 0 and not sources:
            sources.append(
                {
                    "source": "OTX:IP reputation",
                    "type": "reputation",
                    "listed_date": None,
                }
            )
        return {
            "malicious": count > 0 or reputation > 0,
            "risk_score": min(100, max(count * 20, reputation)),
            "type": "threat-intel-pulse" if count > 0 else "reputation",
            "listed_date": None,
            "sources": sources,
            "details": {
                "count": count,
                "reputation": reputation,
                "pulses": pulses,
                "references": (pulse_info.get("references") or [])[:5],
            },
        }

    async def check_malwareworld(self, host, kind=None):
        kind = kind or ("ip" if self._is_ip(host) else "domain")
        report = await malwareworld_lookup(kind, host, self.mw_load_json)
        sources = [
            {
                "source": "MalwareWorld",
                "type": category,
                "listed_date": None,
                "indicator": match["indicator"],
                "match": match["match"],
                "references": match["references"],
            }
            for match in report["matches"]
            for category in match["categories"]
        ]
        return {
            "found": bool(report["matches"]),
            "malicious": report["malicious"],
            "risk_score": report["riskScore"],
            "sources": sources,
            "malwareworld": report,
        }

    async def request_json(self, url, params=None, headers=None):
        try:
            response = await self.cached_api_request(url=url, params=params, headers=headers or {}, timeout=10)
            if response is None:
                return {"error": "no response"}
            if response.status_code == 429:
                return {"rate_limited": True, "status": 429}
            if response.status_code < 200 or response.status_code >= 300:
                return {"error": response.text[:200], "status": response.status_code}
            return response.json()
        except Exception as exc:
            return {"error": str(exc)}

    async def mw_load_json(self, asset):
        cache = getattr(self, "_mw_json_cache", None)
        if cache is None:
            self._mw_json_cache = cache = OrderedDict()
            self._mw_json_pending = {}
            self._mw_cache_resident_bytes = 0
            self._mw_download_slots = asyncio.Semaphore(MAX_MALWAREWORLD_PARALLEL_DOWNLOADS)
        cached = cache.get(asset)
        if cached and cached[0] > time.monotonic():
            cache.move_to_end(asset)
            return cached[1]
        if cached:
            self._mw_cache_resident_bytes -= cache.pop(asset)[2]
        pending = self._mw_json_pending.get(asset)
        if pending is None:
            pending = asyncio.create_task(self._mw_fetch_and_cache(asset))
            self._mw_json_pending[asset] = pending
        return await asyncio.shield(pending)

    async def _mw_fetch_and_cache(self, asset):
        try:
            async with self._mw_download_slots:
                value = await self.mw_fetch_json(asset)
            budget = getattr(self, "_mw_cache_max_resident_bytes", MAX_MALWAREWORLD_CACHE_RESIDENT_BYTES)
            resident_bytes = json_resident_bytes(value, budget)
            if resident_bytes <= budget:
                cache = self._mw_json_cache
                while cache and (
                    len(cache) >= MAX_MALWAREWORLD_CACHE_ENTRIES
                    or self._mw_cache_resident_bytes + resident_bytes > budget
                ):
                    self._mw_cache_resident_bytes -= cache.popitem(last=False)[1][2]
                cache[asset] = (time.monotonic() + 900, value, resident_bytes)
                self._mw_cache_resident_bytes += resident_bytes
            return value
        finally:
            self._mw_json_pending.pop(asset, None)

    async def mw_fetch_json(self, asset):
        if not self.malwareworld_base.startswith(("https://", "http://")):
            base = (
                unquote(urlparse(self.malwareworld_base).path)
                if self.malwareworld_base.startswith("file://")
                else self.malwareworld_base
            )
            path = Path(base) / asset
            if (await asyncio.to_thread(path.stat)).st_size > MAX_MALWAREWORLD_RESPONSE_BYTES:
                raise ValueError(f"MalwareWorld {asset}: response exceeds {MAX_MALWAREWORLD_RESPONSE_BYTES} bytes")
            body = await asyncio.to_thread(path.read_bytes)
            if len(body) > MAX_MALWAREWORLD_RESPONSE_BYTES:
                raise ValueError(f"MalwareWorld {asset}: response exceeds {MAX_MALWAREWORLD_RESPONSE_BYTES} bytes")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError(f"MalwareWorld {asset}: invalid JSON object")
            return data
        url = urljoin(self.malwareworld_base, asset)
        body = bytearray()
        async with self.helpers.AsyncClient().stream(
            "GET", url, headers={"User-Agent": "bbot-host-reputation"}, timeout=120
        ) as response:
            if response.status_code < 200 or response.status_code >= 300:
                raise RuntimeError(f"MalwareWorld {asset}: HTTP {response.status_code}")
            declared_size = response.headers.get("content-length")
            if declared_size and declared_size.isdigit() and int(declared_size) > MAX_MALWAREWORLD_RESPONSE_BYTES:
                raise ValueError(f"MalwareWorld {asset}: response exceeds {MAX_MALWAREWORLD_RESPONSE_BYTES} bytes")
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > MAX_MALWAREWORLD_RESPONSE_BYTES:
                    raise ValueError(f"MalwareWorld {asset}: response exceeds {MAX_MALWAREWORLD_RESPONSE_BYTES} bytes")
                body.extend(chunk)
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError(f"MalwareWorld {asset}: invalid JSON object")
        return data

    def _normalize_base(self, base):
        return base if str(base).endswith("/") else f"{base}/"

    def _is_ip(self, value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _event_tags(self, event):
        tags = getattr(event, "tags", []) or []
        return set(str(tag) for tag in tags)

    def _to_int(self, value):
        try:
            return int(value or 0)
        except Exception:
            return 0
