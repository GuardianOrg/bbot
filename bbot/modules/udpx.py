import base64
import ipaddress
import json
from contextlib import suppress
from pathlib import Path

from radixtarget import RadixTarget, host_size_key

from bbot.modules.base import BaseModule


class udpx(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_UDP_PORT", "PROTOCOL"]
    flags = ["active", "safe", "service-enum", "slow"]
    meta = {
        "description": "Fingerprint UDP services on discovered IP addresses with udpx",
        "created_date": "2026-05-09",
        "author": "GitHub Copilot",
    }
    options = {
        "binary": "udpx",
        "concurrency": 64,
        "timeout_ms": 750,
        "service": "",
        "capture_banner": True,
        "module_timeout": 259200,
    }
    options_desc = {
        "binary": "Path to the udpx executable",
        "concurrency": "Maximum concurrent UDP probes per udpx run",
        "timeout_ms": "Socket read timeout per probe in milliseconds",
        "service": "Optional udpx service filter (for example dns, ntp, snmp)",
        "capture_banner": "Store udpx response data as a banner string or hex when available",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }
    deps_apt = ["golang-go"]
    deps_ansible = [
        {
            "name": "Install udpx",
            "shell": "GOBIN=#{BBOT_TOOLS} go install github.com/carlospolop/udpx/cmd/udpx@94264b85770baa744eda7de7e06fc6a86220917f",
            "args": {"creates": "#{BBOT_TOOLS}/udpx"},
        },
        {
            "name": "Ensure udpx executable mode",
            "file": {"path": "#{BBOT_TOOLS}/udpx", "mode": "0755"},
        },
    ]

    batch_size = 1000000
    _shuffle_incoming_queue = False

    async def setup(self):
        self.binary = str(self.config.get("binary", "udpx")).strip() or "udpx"
        self.concurrency = max(1, int(self.config.get("concurrency", 64)))
        self.timeout_ms = max(100, int(self.config.get("timeout_ms", 750)))
        self.service = str(self.config.get("service", "")).strip().lower()
        self.capture_banner = bool(self.config.get("capture_banner", True))
        self.scanned = self.helpers.make_target(acl_mode=True)
        self.service_cache = {}
        return True

    async def handle_batch(self, *events):
        targets, correlator = await self.make_targets(events)
        if not targets:
            return

        targets_file = self.helpers.tempfile(sorted(targets), pipe=False)
        output_file = self.helpers.tempfile("", pipe=False, extension="jsonl")
        try:
            await self.run_process(self._build_command(targets_file, output_file), _log_stderr=False)
            results = self._load_results(output_file)

            emitted_ports = set()
            emitted_protocols = set()
            for ip, services in results.items():
                self.service_cache[hash(ip)] = tuple(services)
                parent_events = correlator.search(ip)
                if parent_events is None:
                    self.debug(f"udpx found UDP services on {ip} but could not correlate them to an input event")
                    continue
                for service in services:
                    for parent_event in parent_events:
                        await self.emit_service_events(ip, service, parent_event, emitted_ports, emitted_protocols)
        finally:
            targets_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)

    async def make_targets(self, events):
        correlator = RadixTarget()
        targets = set()

        for event in sorted(events, key=lambda event: host_size_key(event.host)):
            if not event.host:
                continue

            with suppress(Exception):
                ip = ipaddress.ip_network(str(event.host), strict=False)
                if ip.num_addresses != 1:
                    continue

                ip_address = ip.network_address
                cached_services = self.service_cache.get(hash(ip_address))
                if cached_services is not None:
                    for cached_service in cached_services:
                        await self.emit_service_events(ip_address, cached_service, event, set(), set())
                    continue

                events_set = correlator.search(ip)
                if events_set is None:
                    correlator.insert(ip, {event})
                else:
                    events_set.add(event)

                if not self.scanned.get(ip):
                    self.scanned.add(ip)
                    targets.add(str(ip_address))
                else:
                    self.debug(f"Skipping {ip} because udpx already scanned it")

        return targets, correlator

    def _build_command(self, targets_file, output_file):
        command = [
            self.binary,
            "-tf",
            str(targets_file),
            "-o",
            str(output_file),
            "-c",
            str(self.concurrency),
            "-w",
            str(self.timeout_ms),
        ]
        if self.service:
            command.extend(["-s", self.service])
        return command

    def _load_results(self, output_file):
        parsed_results = {}
        try:
            for line in Path(output_file).read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue

                try:
                    result = json.loads(line)
                except Exception as error:
                    self.debug(f"Failed to decode udpx JSON line: {error}")
                    continue

                address = str(result.get("address", "")).strip().strip("[]")
                service_name = str(result.get("service", "")).strip()
                port = result.get("port")
                if not address or not service_name or port is None:
                    continue

                try:
                    ip_address = ipaddress.ip_address(address)
                    port = int(port)
                except Exception:
                    continue

                service = {
                    "port": port,
                    "protocol": service_name.upper(),
                    "banner": self._decode_banner(result.get("response_data")),
                }
                parsed_results.setdefault(ip_address, []).append(service)
        except FileNotFoundError:
            return {}

        return parsed_results

    def _decode_banner(self, response_data):
        if not self.capture_banner or not response_data:
            return None
        try:
            raw = base64.b64decode(response_data, validate=False)
        except Exception:
            return None
        if not raw:
            return None

        text = raw.decode("utf-8", errors="ignore").strip()
        if text and all(character.isprintable() or character in "\r\n\t" for character in text):
            return text[:512]
        return raw.hex()[:1024]

    async def emit_service_events(self, ip_address, service, parent_event, emitted_ports, emitted_protocols):
        host = str(parent_event.host or ip_address)
        port = int(service["port"])
        port_key = (host, port, getattr(parent_event, "id", str(parent_event)))
        if port_key in emitted_ports:
            open_port_event = None
        else:
            open_port_event = await self.emit_open_port(host, port, parent_event)
            emitted_ports.add(port_key)

        protocol = service["protocol"]
        protocol_key = (host, port, protocol, getattr(parent_event, "id", str(parent_event)))
        if protocol_key in emitted_protocols:
            return

        protocol_data = {
            "host": host,
            "ip": str(ip_address),
            "port": port,
            "transport": "udp",
            "protocol": protocol,
        }
        banner = service.get("banner")
        if banner:
            protocol_data["banner"] = banner

        await self.emit_event(
            protocol_data,
            "PROTOCOL",
            parent=open_port_event or parent_event,
            tags=[f"ip-{ip_address}", "udp"],
            context=f"{{module}} fingerprinted UDP service {host}:{port} and detected {{event.type}}: {protocol}",
        )
        emitted_protocols.add(protocol_key)

    async def emit_open_port(self, host, port, parent_event):
        event_data = self.helpers.make_netloc(str(host), port)
        event = self.make_event(
            event_data,
            "OPEN_UDP_PORT",
            parent=parent_event,
            context=f"{{module}} probed UDP services on {parent_event.data} and found: {{event.type}}: {{event.data}}",
        )
        await self.emit_event(event)
        return event