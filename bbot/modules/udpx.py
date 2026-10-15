import base64
import asyncio
import ipaddress
import json
import re
from contextlib import suppress
from pathlib import Path

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from radixtarget import RadixTarget, host_size_key

from bbot.modules.base import BaseModule

QUIC_PROBE_DESTINATION_ID = bytes.fromhex("0102030405060708")
QUIC_PROBE_SOURCE_ID = bytes.fromhex("1112131415161718")


def parse_udp_response(service_name, response_data, capture_banner=True):
    """Extract protocol facts from the datagram, never from its port number."""
    if not response_data:
        return {}
    try:
        raw = base64.b64decode(response_data, validate=True)
    except (ValueError, TypeError):
        return {}
    if not raw:
        return {}

    details = {"response_bytes": len(raw)}
    result = {"details": details}
    service_name = service_name.lower()
    if service_name == "quic":
        # A Version Negotiation reply swaps the probe's connection IDs. Check
        # both IDs so an unrelated UDP/443 response cannot become QUIC.
        if len(raw) < 27 or not raw[0] & 0x80 or raw[1:5] != b"\x00" * 4:
            return None
        destination_length = raw[5]
        source_length_offset = 6 + destination_length
        if source_length_offset >= len(raw):
            return None
        source_length = raw[source_length_offset]
        versions_offset = source_length_offset + 1 + source_length
        if (raw[6:source_length_offset] != QUIC_PROBE_SOURCE_ID
                or raw[source_length_offset + 1:versions_offset] != QUIC_PROBE_DESTINATION_ID
                or versions_offset >= len(raw) or (len(raw) - versions_offset) % 4):
            return None
        versions = []
        for offset in range(versions_offset, len(raw), 4):
            number = int.from_bytes(raw[offset:offset + 4], "big")
            versions.append({1: "v1", 0x6B3343CF: "v2"}.get(number, f"0x{number:08x}"))
        details["supported_versions"] = versions
        if capture_banner:
            result["banner"] = f"QUIC Version Negotiation; supported: {', '.join(versions)}"
        return result
    if service_name == "dns":
        try:
            message = dns.message.from_wire(raw)
            if not message.flags & 0x8000:
                raise ValueError("not a DNS response")
            details["response_code"] = dns.rcode.to_text(message.rcode())
            details["authoritative"] = bool(message.flags & 0x0400)
            details["recursion_available"] = bool(message.flags & 0x0080)
            details["answer_count"] = sum(len(rrset) for rrset in message.answer)
            if message.question:
                details["query_name"] = str(message.question[0].name).rstrip(".")[:253]
                details["query_type"] = dns.rdatatype.to_text(message.question[0].rdtype)
            version_query = any(str(question.name).lower() == "version.bind."
                                and question.rdclass == dns.rdataclass.CH
                                for question in message.question)
            for rrset in (message.answer if version_query else ()):
                if rrset.rdtype != dns.rdatatype.TXT:
                    continue
                for record in rrset:
                    version_text = b"".join(record.strings).decode("utf-8", "replace").strip()
                    if version_text:
                        details["version_bind"] = version_text[:200]
                        match = re.fullmatch(r"BIND\s+([0-9][\w.\-]+)", version_text, flags=re.I)
                        if match:
                            result.update(product="BIND", version=match.group(1))
                        break
                if "version_bind" in details:
                    break
            if capture_banner:
                result["banner"] = (f"DNS {details.get('query_name', 'query')} response: {details['response_code']}"
                                    + (f"; VERSION.BIND: {details['version_bind']}" if "version_bind" in details else ""))
            return result
        except Exception:
            pass
    elif service_name == "ntp" and len(raw) >= 48:
        leap, version, mode = raw[0] >> 6, (raw[0] >> 3) & 7, raw[0] & 7
        if 1 <= version <= 4 and mode in (4, 5):
            details.update(protocol_version=version, stratum=raw[1], leap_indicator=leap,
                           mode="server" if mode == 4 else "broadcast")
            refid = raw[12:16]
            if all(32 <= byte < 127 for byte in refid):
                details["reference_id"] = refid.decode("ascii")
            if capture_banner:
                result["banner"] = f"NTPv{version} {details['mode']}; stratum {raw[1]}"
                if details.get("reference_id"):
                    result["banner"] += f"; reference {details['reference_id']}"
            return result
    elif service_name.startswith("snmp") and len(raw) >= 5 and raw[0] == 0x30:
        # The first INTEGER in an SNMP message is its protocol version.
        offset = 2 if raw[1] < 0x80 else 2 + (raw[1] & 0x7F)
        length = raw[1] if raw[1] < 0x80 else int.from_bytes(raw[2:offset], "big")
        if len(raw) >= offset + length and len(raw) > offset + 2 and raw[offset : offset + 2] == b"\x02\x01":
            protocol_version = {0: "1", 1: "2c", 3: "3"}.get(raw[offset + 2])
            if protocol_version:
                details["protocol_version"] = protocol_version
                if capture_banner:
                    result["banner"] = f"SNMPv{protocol_version} response"
                return result

    if capture_banner:
        text = raw.decode("utf-8", errors="replace").strip()
        if text and all(character.isprintable() or character in "\r\n\t" for character in text):
            result["banner"] = text[:2048]
            for key in ("server", "user-agent") if service_name in {"ssdp", "upnp", "sip"} else ():
                match = re.search(rf"(?im)^{re.escape(key)}:\s*(.+)$", text)
                if match:
                    details[key.replace("-", "_")] = match.group(1).strip()[:200]
        else:
            result["banner"] = raw.hex()[:2048]
    return result


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
        "target_concurrency": 1,
        "target_batch_size": 256,
        "timeout_ms": 750,
        "service": "",
        "capture_banner": True,
        "module_timeout": 259200,
    }
    options_desc = {
        "binary": "Path to the udpx executable",
        "concurrency": "Maximum concurrent UDP probes per udpx run",
        "target_concurrency": "Maximum udpx target batches to run in parallel",
        "target_batch_size": "Maximum target hosts per udpx process when target_concurrency is greater than 1",
        "timeout_ms": "Socket read timeout per probe in milliseconds",
        "service": "Optional udpx service filter (for example dns, ntp, snmp)",
        "capture_banner": "Store udpx response data as a banner string or hex when available",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }
    deps_apt = ["golang-go"]
    deps_ansible = [
        {
            "name": "Install udpx",
            "shell": "GOBIN=#{BBOT_TOOLS} go install github.com/carlospolop/udpx/cmd/udpx@a2c82a13a04d8e93cb2fd43c394fc292e2ff388f",
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
        self.target_concurrency = max(1, int(self.config.get("target_concurrency", 1)))
        self.target_batch_size = max(1, int(self.config.get("target_batch_size", 256)))
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

        emitted_ports = set()
        emitted_protocols = set()
        emitted_lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(self.target_concurrency)

        async def scan_batch(batch):
            async with semaphore:
                results = await self.scan_target_batch(batch)
                for ip, services in results.items():
                    self.service_cache[hash(ip)] = tuple(services)
                    parent_events = correlator.search(ip)
                    if parent_events is None:
                        self.debug(f"udpx found UDP services on {ip} but could not correlate them to an input event")
                        continue
                    for service in services:
                        for parent_event in parent_events:
                            async with emitted_lock:
                                await self.emit_service_events(ip, service, parent_event, emitted_ports, emitted_protocols)

        sorted_targets = sorted(targets)
        batches = [
            sorted_targets[offset : offset + self.target_batch_size]
            for offset in range(0, len(sorted_targets), self.target_batch_size)
        ]
        await asyncio.gather(*(scan_batch(batch) for batch in batches))

    async def scan_target_batch(self, targets):
        targets_file = self.helpers.tempfile(targets, pipe=False)
        output_file = self.helpers.tempfile("", pipe=False, extension="jsonl")
        try:
            await self.run_process(self._build_command(targets_file, output_file), _log_stderr=False)
            return self._load_results(output_file)
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

                interpreted = parse_udp_response(service_name, result.get("response_data"), self.capture_banner)
                if interpreted is None:
                    continue
                service = {
                    "port": port,
                    "protocol": service_name.upper(),
                    **interpreted,
                }
                parsed_results.setdefault(ip_address, []).append(service)
        except FileNotFoundError:
            return {}

        return parsed_results

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
        for field in ("product", "version", "details"):
            if service.get(field):
                protocol_data[field] = service[field]

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
