import re
import json
import asyncio
import subprocess
from bbot.modules.base import BaseModule
from bbot.core.helpers.recog import Recog

# Nerva protocol -> (Recog database, function giving the text that database expects).
# Recog's databases hold the banner without the protocol framing (no "220 ", "+OK ", "SSH-2.0-").


def _first_line(text):
    return (text or "").strip().splitlines()[0].strip() if (text or "").strip() else ""


def _strip(prefix_regex):
    return lambda result: re.sub(prefix_regex, "", _first_line(result["metadata"].get("banner")))


def _header(name):
    def get(result):
        headers = result["metadata"].get("response_headers") or {}
        values = next((v for k, v in headers.items() if k.lower() == name), None) or [""]
        return values[0] if isinstance(values, list) else str(values)

    return get


RECOG_SOURCES = {
    "ssh": ("ssh_banners", _strip(r"^SSH-[\d.]+-")),
    "ftp": ("ftp_banners", _strip(r"^\d{3}[- ]")),
    "ftps": ("ftp_banners", _strip(r"^\d{3}[- ]")),
    "smtp": ("smtp_banners", _strip(r"^\d{3}[- ]")),
    "smtps": ("smtp_banners", _strip(r"^\d{3}[- ]")),
    "pop3": ("pop_banners", _strip(r"^\+OK ")),
    "pop3s": ("pop_banners", _strip(r"^\+OK ")),
    "imap": ("imap_banners", _strip(r"^\* OK ")),
    "imaps": ("imap_banners", _strip(r"^\* OK ")),
    "telnet": ("telnet_banners", lambda result: (result["metadata"].get("banner") or "").strip()),
    "mysql": ("mysql_banners", lambda result: result.get("version") or ""),
    "http": ("http_servers", _header("server")),
    "https": ("http_servers", _header("server")),
    "rtsp": ("rtsp_servers", _header("server")),
}
WEB_PROTOCOLS = ("http", "https")
VERSION_REGEX = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)+[a-z0-9]*)", re.I)
SHODAN_PRODUCT_REGEX = re.compile(r'product:"([^"]+)"', re.I)


def cpe_parts(cpe):
    """(vendor, product, version) from a CPE 2.3 or 2.2 string; '*' and '-' mean unknown."""
    parts = cpe.split(":")[3:6] if cpe.startswith("cpe:2.3:") else cpe.replace("cpe:/", "", 1).split(":")[1:4]
    parts = [None if p in ("*", "-", "") else p for p in parts] + [None] * 3
    return parts[0], parts[1], parts[2]


def same_product(a, b):
    """Spellings of one product ("proftpd" / "ProFTPD", "openssh" / "OpenSSH")."""
    a, b = (re.sub(r"[^a-z0-9]", "", (x or "").lower()) for x in (a, b))
    return bool(a and b and (a in b or b in a))


def clean_version(version):
    if not version:
        return None
    version = str(version).strip()
    if re.match(r"^v\d", version):
        version = version[1:]
    return version if re.search(r"\d", version) else None


class Fingerprint:
    """What the cascade knows about one open port; complete once product and version are known."""

    def __init__(self, netloc, host, port, ip=None):
        self.netloc, self.host, self.port, self.ip = netloc, host, port, ip
        self.protocol = None
        self.transport = "tcp"
        self.tls = False
        self.banner = None
        self.product = None
        self.vendor = None
        self.version = None
        self.cpes = []
        self.source = None

    @property
    def complete(self):
        return bool(self.product and self.version)

    @property
    def is_web(self):
        return (self.protocol or "").lower() in WEB_PROTOCOLS

    def learn(self, source, product=None, version=None, vendor=None, cpes=()):
        """Fill what is still unknown; earlier stages keep precedence."""
        version = clean_version(version)
        if product and not self.product:
            self.product, self.source = product, source
        if version and not self.version and (not product or same_product(self.product, product)):
            self.version, self.source = version, source
        if vendor and not self.vendor:
            self.vendor = vendor
        for cpe in cpes:
            if cpe and cpe not in self.cpes:
                self.cpes.append(cpe)

    def protocol_data(self):
        data = {"host": self.host, "protocol": self.protocol or "UNKNOWN", "port": self.port}
        if self.ip and self.ip != self.host:
            data["ip"] = self.ip
        for key in ("transport", "product", "version", "banner"):
            value = getattr(self, key)
            if value:
                data[key] = value
        if self.cpes:
            data["cpes"] = self.cpes
        details = {"fingerprint_source": self.source} if self.source else {}
        if self.vendor:
            details["vendor"] = self.vendor
        if details:
            data["details"] = details
        return data


class service_fingerprint(BaseModule):
    watched_events = ["OPEN_TCP_PORT"]
    produced_events = ["PROTOCOL", "URL_UNVERIFIED"]
    flags = ["active", "safe", "service-enum", "slow"]
    meta = {
        "description": "Identify the service, product and version behind open ports: Nerva, then Recog on its banner, then Nuclei detection templates for what is still unknown",
        "created_date": "2026-11-07",
        "author": "@CarlosPolop",
    }
    _batch_size = 25
    _module_threads = 4
    _priority = 2

    options = {
        "version": "1.84.2",
        "recog_version": "3.3.2",
        "nuclei_version": "3.6.2",
        "skip_common_web": True,
        "timeout_ms": 2000,
        "workers": 50,
        "thorough_timeout": 60,
        "nuclei_fallback": True,
        "nuclei_timeout": 5,
    }
    options_desc = {
        "version": "Nerva version",
        "recog_version": "Recog fingerprint database version",
        "nuclei_version": "Nuclei version for the detection-template fallback",
        "skip_common_web": "Skip common web ports such as 80, 443, 8080, 8443, etc.",
        "timeout_ms": "Per-target Nerva timeout in milliseconds",
        "workers": "Concurrent Nerva workers per batch",
        "thorough_timeout": "Seconds Nerva's thorough mode may spend on each port its fast mode could not name (0 skips that pass)",
        "nuclei_fallback": "Run Nuclei network/javascript detection templates on ports Nerva and Recog left without a product and version",
        "nuclei_timeout": "Per-request Nuclei timeout in seconds",
    }

    deps_ansible = [
        {
            "name": "Download nerva",
            "unarchive": {
                "src": "https://github.com/praetorian-inc/nerva/releases/download/v#{BBOT_MODULES_SERVICE_FINGERPRINT_VERSION}/nerva_#{BBOT_MODULES_SERVICE_FINGERPRINT_VERSION}_#{BBOT_OS_PLATFORM}_#{BBOT_CPU_ARCH_GOLANG}.tar.gz",
                "include": "nerva",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
        {
            "name": "Create recog directory",
            "file": {"path": "#{BBOT_TOOLS}/recog", "state": "directory", "mode": "0755"},
        },
        {
            "name": "Download recog fingerprints",
            "unarchive": {
                "src": "https://github.com/rapid7/recog/releases/download/v#{BBOT_MODULES_SERVICE_FINGERPRINT_RECOG_VERSION}/recog-content-#{BBOT_MODULES_SERVICE_FINGERPRINT_RECOG_VERSION}.zip",
                "dest": "#{BBOT_TOOLS}/recog",
                "remote_src": True,
            },
        },
        {
            "name": "Download nuclei",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/nuclei/releases/download/v#{BBOT_MODULES_SERVICE_FINGERPRINT_NUCLEI_VERSION}/nuclei_#{BBOT_MODULES_SERVICE_FINGERPRINT_NUCLEI_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "nuclei",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
    ]

    common_web_ports = (80, 443, 8080, 8880, 2052, 2082, 2086, 2095, 2053, 2083, 2087, 2096, 8443)
    nuclei_template_dirs = ("network/detection", "javascript/detection")

    async def setup(self):
        if self.scan.custom_http_headers:
            # Nerva's HTTP plugins probe every open port with requests that cannot carry the headers.
            return None, "Nerva has no option to send the scan's custom HTTP headers"
        self.skip_common_web = self.config.get("skip_common_web", True)
        self.timeout_ms = int(self.config.get("timeout_ms", 2000))
        self.workers = int(self.config.get("workers", 50))
        self.thorough_timeout = int(self.config.get("thorough_timeout", 60))
        self.thorough_slots = asyncio.Semaphore(self.workers)
        self.nuclei_fallback = bool(self.config.get("nuclei_fallback", True))
        self.nuclei_timeout = int(self.config.get("nuclei_timeout", 5))
        recog_dir = self.helpers.tools_dir / "recog" / "xml"
        if not (recog_dir / "ssh_banners.xml").is_file():
            return False, f"Recog fingerprints are missing from {recog_dir}"
        self.recog = Recog(recog_dir)
        if self.nuclei_fallback:
            return await self.setup_nuclei_templates()
        return True

    async def setup_nuclei_templates(self):
        self.nuclei_templates_dir = self.helpers.tools_dir / "nuclei-templates"
        if not self.missing_nuclei_template_dirs():
            return True
        await self.run_process(
            ["nuclei", "-update-template-dir", self.nuclei_templates_dir, "-update-templates"]
        )
        missing = self.missing_nuclei_template_dirs()
        if missing:
            return False, f"Nuclei detection templates are missing: {', '.join(missing)}"
        return True

    def missing_nuclei_template_dirs(self):
        return [d for d in self.nuclei_template_dirs if not (self.nuclei_templates_dir / d).is_dir()]

    async def filter_event(self, event):
        if self.skip_common_web:
            port_str = str(event.port)
            if event.port in self.common_web_ports or any(port_str.endswith(x) for x in ("080", "443")):
                return False, "port is a common web port and skip_common_web=True"
        return True

    async def handle_batch(self, *events):
        parents = {e.data: e for e in events}
        fingerprints = {}
        # Fast mode only tries the plugins registered for each port number and names most ports in seconds.
        # Thorough mode tries every plugin one after another (minutes on a silent port), so it only gets
        # the ports fast mode could not name. Nerva prints nothing until every target of a run is done,
        # so each of those ports gets its own run and time limit, and a stuck port holds back no other.
        await self.fingerprint_with_nerva(parents, fingerprints, list(parents), "fast")
        missed = [netloc for netloc in parents if netloc not in fingerprints]
        if missed and self.thorough_timeout > 0:
            await asyncio.gather(*(self.fingerprint_thoroughly(parents, fingerprints, netloc) for netloc in missed))

        if self.nuclei_fallback:
            await self.handle_unidentified(parents, fingerprints)

    async def fingerprint_thoroughly(self, parents, fingerprints, netloc):
        async with self.thorough_slots:
            try:
                await self.fingerprint_with_nerva(parents, fingerprints, [netloc], "thorough", self.thorough_timeout)
            except asyncio.TimeoutError:
                self.verbose(f"Nerva thorough mode did not name {netloc} within {self.thorough_timeout}s")

    async def fingerprint_with_nerva(self, parents, fingerprints, targets, scan_depth, timeout=None):
        for result in await self.run_nerva(targets, scan_depth, timeout):
            fingerprint = self.fingerprint_from_nerva(result)
            if fingerprint is None or fingerprint.netloc not in parents or fingerprint.netloc in fingerprints:
                continue
            self.apply_recog(fingerprint, result)
            fingerprints[fingerprint.netloc] = fingerprint
            if fingerprint.complete or fingerprint.is_web or not self.nuclei_fallback:
                await self.emit_fingerprint(fingerprint, parents[fingerprint.netloc])

    async def handle_unidentified(self, parents, fingerprints):
        """One Nuclei pass over the ports Nerva and Recog left without a product and version.

        Web services are left to the URL-level modules (nuclei, httpx), which see their pages.
        """
        pending = {}
        for netloc, parent in parents.items():
            fingerprint = fingerprints.get(netloc) or self.blank_fingerprint(parent)
            if not (fingerprint.complete or fingerprint.is_web):
                pending[netloc] = fingerprint
        if not pending:
            return
        await self.apply_nuclei(pending)
        for netloc, fingerprint in pending.items():
            if fingerprint.protocol:
                await self.emit_fingerprint(fingerprint, parents[netloc])

    async def run_nerva(self, targets, scan_depth, timeout=None):
        command = ["nerva", "--json", "--scan-depth", scan_depth, "-w", str(self.timeout_ms), "-W", str(self.workers)]
        process = await self.run_process(command, input=targets, stderr=subprocess.DEVNULL, idle_timeout=timeout)
        results = []
        for line in (getattr(process, "stdout", None) or "").splitlines():
            try:
                results.append(json.loads(line))
            except Exception as e:
                self.debug(f'Error parsing nerva line "{line}" as JSON: {e}')
        return results

    def blank_fingerprint(self, event):
        return Fingerprint(event.data, str(event.host), int(event.port))

    def fingerprint_from_nerva(self, result):
        ip = result.get("ip", "")
        host = result.get("host") or ip
        port = result.get("port")
        protocol = result.get("protocol", "")
        if not (host and port and protocol):
            return None
        fingerprint = Fingerprint(self.helpers.make_netloc(host, port), host, int(port), ip=ip)
        fingerprint.protocol = protocol.upper()
        fingerprint.transport = result.get("transport") or "tcp"
        metadata = result.setdefault("metadata", {})
        fingerprint.banner = (metadata.get("banner") or "").strip() or None
        if fingerprint.is_web:
            self.learn_web_product(fingerprint, metadata)
        else:
            self.learn_service_product(fingerprint, result)
        return fingerprint

    def learn_service_product(self, fingerprint, result):
        """A protocol plugin's CPE names the product; a versioned CPE also gives the version."""
        cpes = result["metadata"].get("cpes") or []
        for cpe in sorted(cpes, key=lambda c: cpe_parts(c)[2] is None):
            vendor, product, version = cpe_parts(cpe)
            if product:
                fingerprint.learn("nerva", product.replace("_", " "), version, vendor, cpes=[cpe])
                break
        fingerprint.learn("nerva", cpes=cpes)

    def learn_web_product(self, fingerprint, metadata):
        """Nerva's web fingerprinters report a product per key; its technology entry carries the version."""
        technologies = [t.rsplit(":", 1) if ":" in t else [t, None] for t in metadata.get("technologies") or []]
        for key, details in (metadata.get("fingerprint_metadata") or {}).items():
            if key == "favicon":
                continue
            version = clean_version((details or {}).get("version")) or next(
                (clean_version(v) for name, v in technologies if name.lower() == key.lower() and clean_version(v)), None
            )
            named = next((name for name, v in technologies if version and clean_version(v) == version and name.lower() != key.lower()), None)
            product = (details or {}).get("product") or named or key
            matching = [c for c in metadata.get("cpes") or [] if version and cpe_parts(c)[2] == version]
            fingerprint.learn("nerva", product, version, (details or {}).get("vendor"), cpes=matching)
            if fingerprint.complete:
                return

    def apply_recog(self, fingerprint, result):
        if fingerprint.complete:
            return
        source = RECOG_SOURCES.get((result.get("protocol") or "").lower())
        if source is None:
            return
        database, text_of = source
        text = text_of(result)
        values = self.recog.match(database, text) if text else None
        if values:
            self.learn_recog(fingerprint, values)

    def learn_recog(self, fingerprint, values):
        product = values.get("service.product") or values.get("service.family")
        cpe = values.get("service.cpe23")
        fingerprint.learn(
            "recog", product, values.get("service.version"), values.get("service.vendor"), cpes=[cpe] if cpe else []
        )

    async def apply_nuclei(self, pending):
        command = ["nuclei", "-silent", "-nc", "-jsonl", "-duc", "-ni", "-retries", "0"]
        command += ["-timeout", str(self.nuclei_timeout)]
        for template_dir in self.nuclei_template_dirs:
            command += ["-t", str(self.nuclei_templates_dir / template_dir)]
        async for line in self.run_process_live(command, input=list(pending), stderr=subprocess.DEVNULL):
            try:
                result = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing nuclei line "{line}" as JSON: {e}')
                continue
            fingerprint = next((pending[n] for n in self.nuclei_netlocs(result) if n in pending), None)
            if fingerprint is not None and not fingerprint.complete:
                self.learn_nuclei(fingerprint, result)

    def nuclei_netlocs(self, result):
        host, port = result.get("host", ""), result.get("port", "")
        netlocs = [self.helpers.make_netloc(host, int(port))] if host and str(port).isdigit() else []
        return netlocs + [result.get("matched-at", ""), result.get("url", "")]

    def learn_nuclei(self, fingerprint, result):
        """A detection template names its product in metadata or its Shodan query; extracted text holds the version."""
        info = result.get("info") or {}
        metadata = info.get("metadata") or {}
        product = metadata.get("product")
        if not product:
            query = SHODAN_PRODUCT_REGEX.search(str(metadata.get("shodan-query") or ""))
            product = query.group(1) if query else None
        if not fingerprint.protocol:
            fingerprint.protocol = re.sub(r"-(server-)?detect(ion)?$", "", result.get("template-id", "")).upper() or None
        extracted = " ".join(result.get("extracted-results") or [])
        recog = self.recog_on_extracted(fingerprint, extracted)
        if recog:
            self.learn_recog(fingerprint, recog)
        version = VERSION_REGEX.search(extracted)
        fingerprint.learn("nuclei", product, version.group(1) if version else None, metadata.get("vendor"))

    def recog_on_extracted(self, fingerprint, extracted):
        source = RECOG_SOURCES.get((fingerprint.protocol or "").lower())
        if not source or not extracted:
            return None
        database, text_of = source
        return self.recog.match(database, text_of({"version": extracted, "metadata": {"banner": extracted}}))

    async def emit_fingerprint(self, fingerprint, parent_event):
        tags = {f"ip-{fingerprint.ip}"} if fingerprint.ip else set()
        port_data = fingerprint.netloc
        product = " ".join(x for x in (fingerprint.product, fingerprint.version) if x)
        await self.emit_event(
            fingerprint.protocol_data(),
            "PROTOCOL",
            parent=parent_event,
            tags=tags,
            context=f"{{module}} probed {port_data} and detected {{event.type}}: {fingerprint.protocol}"
            + (f" ({product})" if product else ""),
        )
        if fingerprint.is_web:
            protocol = fingerprint.protocol.lower()
            is_default_port = (protocol, fingerprint.port) in (("http", 80), ("https", 443))
            netloc = self.helpers.make_netloc(fingerprint.host, None if is_default_port else fingerprint.port)
            await self.emit_event(
                f"{protocol}://{netloc}",
                "URL_UNVERIFIED",
                parent=parent_event,
                tags=tags,
                context=f"{{module}} probed {port_data} and detected a {fingerprint.protocol} web service",
            )
