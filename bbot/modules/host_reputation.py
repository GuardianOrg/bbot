import ipaddress
import random
from urllib.parse import urljoin

from bbot.modules.base import BaseModule


class host_reputation(BaseModule):
    watched_events = ["DNS_NAME", "DNS_NAME_UNRESOLVED", "IP_ADDRESS"]
    produced_events = ["FINDING"]
    flags = ["passive", "safe", "ip-enum"]
    meta = {
        "description": "Check domains and IP addresses against AbuseIPDB, VirusTotal, OTX, and MalwareWorld",
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
        "otx_api_key": "AlienVault OTX API key for domain reputation checks",
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
        self.otx_api_key = self.config.get("otx_api_key", "")
        self.malwareworld_base = self._normalize_base(self.config.get("malwareworld_base", "https://malwareworld.com/data/"))
        return True

    async def filter_event(self, event):
        if event.scope_distance != 0:
            return False, "host_reputation only checks explicit seed targets"
        if "target" not in self._event_tags(event):
            return False, "host_reputation only checks explicit seed targets"
        return True

    async def handle_event(self, event):
        host = str(event.host or event.data).lower().rstrip(".")
        if not host:
            return

        is_ip = self._is_ip(host)
        results = {}

        mw_result = await self.check_malwareworld(host)
        results["MalwareWorld"] = mw_result

        if is_ip:
            results["IP in AbuseIPDB"] = await self.check_abuseipdb(host)
            results["IP in VirusTotal"] = await self.check_vt_ip(host)
        else:
            results["Hostname in VirusTotal"] = await self.check_vt_domain(host)
            results["Hostname in OTX"] = await self.check_otx(host)

        risk_score, malicious, sources = self.aggregate_results(results)
        verdict = "malicious" if malicious else "not malicious"
        await self.emit_event(
            {
                "host": host,
                "severity": "HIGH" if malicious else "INFO",
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
                "dedupe_key": f"host-reputation:{host}",
            },
            "FINDING",
            event,
            context=f"{{module}} checked reputation sources for {host} and emitted {{event.type}}: {{event.data}}",
        )

    async def check_abuseipdb(self, ip):
        if not self.abuseipdb_api_key:
            return {"error": "abuseipdb_api_key not set", "malicious": False}
        response = await self.request_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
        )
        data = response.get("data", {}) if isinstance(response, dict) else {}
        score = self._to_int(data.get("abuseConfidenceScore"))
        return {
            "malicious": score > 20,
            "risk_score": score,
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
            malicious_count = self._to_int(stats.get("malicious"))
            suspicious_count = self._to_int(stats.get("suspicious"))
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
                sources.append({
                    "source": f"VirusTotal:{engine_name}",
                    "type": str(result),
                    "listed_date": None,
                })
            return {
                "malicious": malicious_count > 1 or suspicious_count > 2,
                "risk_score": risk_score,
                "type": "malware-analysis",
                "listed_date": None,
                "sources": sources,
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
            sources.append({
                "source": f"OTX:{pulse_name}",
                "type": "pulse",
                "listed_date": pulse.get("modified") or pulse.get("created"),
            })
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

    async def check_malwareworld(self, host):
        try:
            data = await self.mw_lookup(host)
        except Exception as exc:
            return {"error": str(exc), "malicious": False}
        if not data:
            return {"found": False, "malicious": False, "risk_score": 0}

        types = data.get("type") or []
        is_whitelisted = "Whitelist" in types
        is_malicious = bool(types) and not is_whitelisted
        sources = []
        malicious_types = [str(entry) for entry in types if entry != "Whitelist"]
        for entry in malicious_types:
            sources.append({
                "source": f"MalwareWorld:{entry}",
                "type": entry,
                "listed_date": None,
            })

        source_urls = self._malwareworld_source_urls(data)
        for source_url in source_urls:
            for entry in malicious_types or ["malwareworld"]:
                sources.append({
                    "source": f"MalwareWorld:{source_url}",
                    "type": entry,
                    "listed_date": None,
                    "url": source_url,
                })
        return {
            "found": True,
            "malicious": is_malicious,
            "risk_score": 100 if is_malicious else 0,
            "type": ",".join(types) if types else "malwareworld",
            "listed_date": None,
            "sources": sources,
            "details": {
                "type": types,
                "urls": data.get("urls"),
                "references": data.get("references"),
                "title": data.get("title"),
            },
        }

    def aggregate_results(self, results):
        risk_score = 0
        sources = []
        for source, result in results.items():
            if not isinstance(result, dict):
                continue
            risk_score = max(risk_score, self._to_int(result.get("risk_score")))
            if result.get("malicious") is True:
                result_sources = result.get("sources")
                if isinstance(result_sources, list) and result_sources:
                    for result_source in result_sources:
                        if not isinstance(result_source, dict):
                            continue
                        source_name = result_source.get("source")
                        if not source_name:
                            continue
                        sources.append({
                            "source": str(source_name),
                            "type": str(result_source.get("type") or result.get("type") or "malicious"),
                            "listed_date": result_source.get("listed_date") or result.get("listed_date"),
                            **({"url": str(result_source.get("url"))} if result_source.get("url") else {}),
                        })
                else:
                    sources.append({
                        "source": source,
                        "type": str(result.get("type") or "malicious"),
                        "listed_date": result.get("listed_date"),
                    })
        return risk_score, bool(sources), sources

    async def request_json(self, url, params=None, headers=None):
        try:
            response = await self.helpers.request(url=url, params=params, headers=headers or {}, timeout=10)
            if response is None:
                return {"error": "no response"}
            if response.status_code == 429:
                return {"rate_limited": True, "status": 429}
            if response.status_code < 200 or response.status_code >= 300:
                return {"error": response.text[:200], "status": response.status_code}
            return response.json()
        except Exception as exc:
            return {"error": str(exc)}

    async def mw_lookup(self, host):
        manifest = await self.mw_load_json("manifest.json")
        normalized = host.lower().rstrip(".")
        if self._is_ip(normalized):
            asset = self.mw_ips_asset_for_host(normalized, manifest)
            return await self.mw_lookup_asset(normalized, asset)

        domain = normalized
        for _ in range(8):
            asset = f"domains_{self.mw_domain_shard(domain)}.json"
            obj = await self.mw_load_json(asset)
            if isinstance(obj, dict) and domain in obj:
                return obj[domain]
            parts = domain.split(".")
            if len(parts) <= 2:
                break
            domain = ".".join(parts[1:])
        return None

    async def mw_lookup_asset(self, key, asset):
        if not asset:
            return None
        obj = await self.mw_load_json(asset)
        return obj.get(key) if isinstance(obj, dict) else None

    async def mw_load_json(self, asset):
        url = urljoin(self.malwareworld_base, asset)
        response = await self.helpers.request(url=url, headers={"User-Agent": "bbot-host-reputation"}, timeout=10)
        if response is None or response.status_code == 404:
            return {}
        if response.status_code < 200 or response.status_code >= 300:
            return {}
        return response.json()

    def mw_ips_asset_for_host(self, host, manifest):
        try:
            octet = int(str(host).split(".")[0])
        except Exception:
            return None
        if octet < 0 or octet > 255:
            return None
        meta = (manifest or {}).get("ips", {})
        if meta.get("scheme") == "ipv4FirstOctet" and isinstance(meta.get("pattern"), str):
            return meta["pattern"].replace("{octet3}", f"{octet:03d}")
        group_size = int(meta.get("groupSize", 16)) if meta else 16
        start = (octet // group_size) * group_size
        end = min(255, start + group_size - 1)
        if isinstance(meta.get("pattern"), str):
            return meta["pattern"].replace("{from3}", f"{start:03d}").replace("{to3}", f"{end:03d}")
        return f"ips_{start:03d}-{end:03d}.json"

    def mw_domain_shard(self, domain):
        if not domain:
            return "_"
        char = domain[0]
        if "a" <= char <= "z" or "0" <= char <= "9" or char == "-":
            return char
        return "_"

    def _malwareworld_source_urls(self, data):
        urls = []
        for key in ("urls", "references"):
            value = data.get(key)
            if isinstance(value, str):
                candidates = [value]
            elif isinstance(value, list):
                candidates = value
            else:
                candidates = []
            for candidate in candidates:
                if not isinstance(candidate, str):
                    continue
                candidate = candidate.strip()
                if not candidate or candidate in urls:
                    continue
                urls.append(candidate)
        return urls

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
