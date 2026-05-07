import json
from contextlib import suppress
from urllib.parse import urlparse

from bbot.modules.base import BaseModule


class testssl(BaseModule):
    watched_events = ["URL", "URL_UNVERIFIED", "HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "slow", "web-thorough"]
    meta = {
        "description": "Run testssl.sh against HTTPS URLs and emit TLS/SSL issues",
        "created_date": "2026-05-07",
        "author": "@carlospolop + @codex",
    }
    options = {
        "version": "3.2.0",
        "timeout": 150,
        "connect_timeout": 10,
        "openssl_timeout": 10,
        "ip_mode": "one",
        "binary": "",
    }
    options_desc = {
        "version": "testssl.sh git tag/branch to install",
        "timeout": "Maximum seconds to wait for each testssl.sh scan",
        "connect_timeout": "testssl.sh TCP connect timeout",
        "openssl_timeout": "testssl.sh OpenSSL operation timeout",
        "ip_mode": "Value for testssl.sh --ip (default: one)",
        "binary": "Optional explicit path to testssl.sh",
    }
    deps_ansible = [
        {
            "name": "Clone testssl.sh repository",
            "git": {
                "repo": "https://github.com/testssl/testssl.sh.git",
                "dest": "#{BBOT_TOOLS}/testssl.sh",
                "version": "#{BBOT_MODULES_TESTSSL_VERSION}",
            },
        }
    ]
    in_scope_only = True
    per_hostport_only = True
    _batch_size = 50

    RECOMMENDATIONS = {
        "SSLv2": "Disable SSLv2.",
        "SSLv3": "Disable SSLv3.",
        "TLS1": "Disable TLS 1.0 unless a documented legacy requirement remains.",
        "TLS1_1": "Disable TLS 1.1 unless a documented legacy requirement remains.",
        "BEAST": "Prefer TLS 1.2+ and disable affected CBC cipher suites where possible.",
        "POODLE": "Disable SSLv3 and affected fallback behavior.",
        "SWEET32": "Disable 64-bit block ciphers such as 3DES.",
        "FREAK": "Disable export cipher suites.",
        "LOGJAM": "Use strong DH parameters, preferably 2048 bits or larger.",
        "DROWN": "Disable SSLv2 on all services sharing this certificate/key material.",
        "LUCKY13": "Prefer AEAD cipher suites such as GCM or ChaCha20-Poly1305.",
        "ROBOT": "Disable RSA key exchange cipher suites or update the TLS implementation.",
        "HEARTBLEED": "Update OpenSSL or the affected TLS implementation immediately.",
        "CCS": "Update OpenSSL to a version not affected by CCS injection.",
        "TICKETBLEED": "Update or reconfigure the affected TLS implementation.",
        "secure_renego": "Enable secure renegotiation.",
        "secure_client_renego": "Disable client-initiated renegotiation.",
        "BREACH": "Disable HTTP compression for sensitive responses or apply BREACH mitigations.",
        "CRIME": "Disable TLS compression.",
        "RC4": "Disable all RC4 cipher suites.",
        "cert_expired": "Renew the TLS certificate.",
        "cert_notYetValid": "Check server time and certificate validity period.",
        "cert_revocation": "Replace the revoked certificate.",
        "cert_chain": "Install the complete certificate chain.",
        "HSTS": "Enable HTTP Strict Transport Security if appropriate for this service.",
        "HSTS_time": "Increase HSTS max-age to at least six months when ready.",
        "OCSP_stapling": "Enable OCSP stapling.",
    }
    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "WARN": "INFO",
        "WARNING": "INFO",
        "INFO": "INFO",
    }
    SKIP_INFO_IDS = {"service", "cert_trust", "cert_chain_of_trust"}

    async def setup(self):
        self.timeout = max(1, int(self.config.get("timeout", 150)))
        self.connect_timeout = max(1, int(self.config.get("connect_timeout", 10)))
        self.openssl_timeout = max(1, int(self.config.get("openssl_timeout", 10)))
        self.ip_mode = str(self.config.get("ip_mode", "one") or "one").strip() or "one"
        configured_binary = str(self.config.get("binary", "") or "").strip()
        candidates = [configured_binary] if configured_binary else []
        candidates.extend([
            str(self.helpers.tools_dir / "testssl.sh" / "testssl.sh"),
            "/opt/testssl.sh/testssl.sh",
            "/usr/local/bin/testssl.sh",
            "testssl.sh",
        ])
        self.binary = next((candidate for candidate in candidates if candidate and self.helpers.which(candidate)), None)
        if not self.binary:
            return False, "testssl.sh was not found. Ensure dependencies are installed with --force-deps"
        return True

    async def filter_event(self, event):
        url = self.event_url(event)
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return False, "only accepts HTTPS URLs"
        if not parsed.hostname:
            return False, "URL has no hostname"
        return True

    async def handle_batch(self, *events):
        for event in events:
            url = self.event_url(event)
            if not url:
                continue
            async for result in self.execute_testssl(url):
                await self.emit_testssl_result(event, url, result)

    def event_url(self, event):
        if isinstance(event.data, dict):
            return str(event.data.get("url") or "")
        return str(event.data or "")

    def target_from_url(self, url):
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        return self.helpers.make_netloc(host, port)

    async def execute_testssl(self, url):
        output_file = self.helpers.tempfile("", pipe=False, extension="json")
        target = self.target_from_url(url)
        command = [
            self.binary,
            "--jsonfile-pretty",
            str(output_file),
            "--quiet",
            "--warnings",
            "off",
            "--ip",
            self.ip_mode,
            "--connect-timeout",
            str(self.connect_timeout),
            "--openssl-timeout",
            str(self.openssl_timeout),
            target,
        ]
        try:
            process = await self.run_process(command, _log_stderr=False, idle_timeout=self.timeout)
            results = self.load_results(output_file)
            if not results:
                results = self.parse_json_blob(getattr(process, "stdout", ""))
            if not results and getattr(process, "returncode", 0) not in (0, None):
                self.warning(f"testssl.sh exited with code {process.returncode} for {url}: {getattr(process, 'stderr', '')}")
                return
            for item in results:
                normalized = self.normalize_result(item)
                if normalized:
                    yield normalized
        except TimeoutError:
            self.warning(f"testssl.sh timed out after {self.timeout}s for {url}")
        finally:
            with suppress(Exception):
                output_file.unlink(missing_ok=True)

    def load_results(self, output_file):
        try:
            with open(output_file, "r", errors="ignore") as f:
                return self.normalize_results_container(json.load(f))
        except FileNotFoundError:
            return []
        except json.JSONDecodeError as e:
            self.debug(f"Failed to decode testssl.sh JSON output {output_file}: {e}")
            return []
        except Exception as e:
            self.warning(f"Unable to read testssl.sh JSON output {output_file}: {e}")
            return []

    def parse_json_blob(self, text):
        raw = str(text or "").strip()
        if not raw:
            return []
        try:
            return self.normalize_results_container(json.loads(raw))
        except json.JSONDecodeError:
            return []

    def normalize_results_container(self, payload):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("scanResult", "scan_results", "results", "findings"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
            return [payload]
        return []

    def normalize_result(self, item):
        if not isinstance(item, dict):
            return None
        item_id = str(item.get("id") or item.get("idName") or item.get("findingId") or "unknown").strip()
        raw_severity = str(item.get("severity") or "INFO").upper().strip()
        if raw_severity == "OK":
            return None
        severity = self.SEVERITY_MAP.get(raw_severity, raw_severity)
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"
        if severity == "INFO" and item_id in self.SKIP_INFO_IDS:
            return None
        finding = str(item.get("finding") or item.get("message") or item.get("value") or "").strip()
        if not finding:
            finding = item_id
        cwe = str(item.get("cwe") or "").strip()
        cve = str(item.get("cve") or "").strip()
        title = f"TLS: {item_id}"
        if cwe:
            title = f"{title} ({cwe})"
        return {
            "id": item_id,
            "title": title,
            "severity": severity,
            "description": finding,
            "evidence": f"testssl.sh finding: {item_id} = {finding}",
            "recommendation": self.RECOMMENDATIONS.get(item_id, f"Review TLS configuration for {item_id}."),
            "cwe": cwe or None,
            "cve": cve or None,
            "raw": item,
        }

    async def emit_testssl_result(self, event, url, result):
        payload = {
            "host": str(event.host),
            "url": url,
            "severity": result["severity"],
            "title": result["title"],
            "category": "TLS",
            "description": result["description"],
            "evidence": result["evidence"],
            "recommendation": result["recommendation"],
            "template": "testssl",
            "testssl_id": result["id"],
        }
        if result.get("cwe"):
            payload["cwe"] = result["cwe"]
        if result.get("cve"):
            payload["cve"] = result["cve"]
        event_type = "FINDING" if result["severity"] == "INFO" else "VULNERABILITY"
        await self.emit_event(
            payload,
            event_type,
            parent=event,
            tags=["testssl", "tls", f"testssl-{result['severity'].lower()}"],
            context=f"{{module}} scanned {url} and identified {{event.type}}: {result['title']}",
        )
