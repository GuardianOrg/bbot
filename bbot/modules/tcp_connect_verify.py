import asyncio
import ipaddress
from contextlib import suppress

from radixtarget import RadixTarget, host_size_key

from bbot.modules.base import BaseModule
from bbot.modules.naabu import NMAP_TOP_1000


class tcp_connect_verify(BaseModule):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {
        "description": "Direct TCP connect verifier for configured TCP ports.",
        "created_date": "2026-04-28",
        "author": "Guardian",
    }

    options = {
        "ports": "",
        "top_ports": "1000",
        "connect_concurrency": 5,
        "target_concurrency": 6,
        "global_connect_concurrency": 400,
        "timeout_ms": 1000,
        "retries": 2,
        "module_timeout": 259200,
    }
    options_desc = {
        "ports": "Ports to verify (BBOT port string); empty uses top_ports",
        "top_ports": "Top ports to verify when ports is empty. Currently supports 1000.",
        "connect_concurrency": "Maximum concurrent TCP connects per target host",
        "target_concurrency": "Maximum target hosts to verify in parallel",
        "global_connect_concurrency": "Maximum concurrent TCP connects across all target hosts",
        "timeout_ms": "Per-port TCP connect timeout in milliseconds",
        "retries": "TCP connect attempts per port",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }

    batch_size = 1000000
    _shuffle_incoming_queue = False

    async def setup(self):
        self.ports = self._normalize_port_string(self.config.get("ports", ""))
        self.top_ports = str(self.config.get("top_ports", "1000")).strip() or "1000"
        self.connect_concurrency = max(1, int(self.config.get("connect_concurrency", 5)))
        self.target_concurrency = max(1, int(self.config.get("target_concurrency", 6)))
        self.global_connect_concurrency = max(1, int(self.config.get("global_connect_concurrency", 400)))
        self.timeout_ms = int(self.config.get("timeout_ms", 1000))
        self.retries = max(1, int(self.config.get("retries", 1)))
        self.open_port_cache = {}
        self.scanned = self.helpers.make_target(acl_mode=True)

        try:
            self.configured_ports = self._configured_ports()
        except ValueError as e:
            return False, str(e)
        return True

    async def handle_batch(self, *events):
        targets, correlator = await self.make_targets(events)
        if not targets or not self.configured_ports:
            return

        emitted = set()
        emitted_lock = asyncio.Lock()
        connect_semaphore = asyncio.Semaphore(self.global_connect_concurrency)
        target_semaphore = asyncio.Semaphore(self.target_concurrency)

        async def verify_target(target):
            async with target_semaphore:
                await self.verify_target_ports(target, correlator, emitted, emitted_lock, connect_semaphore)

        await asyncio.gather(*(verify_target(target) for target in sorted(targets, key=str)))

    async def make_targets(self, events):
        correlator = RadixTarget()
        targets = set()
        for event in sorted(events, key=lambda e: host_size_key(e.host)):
            if not event.host:
                continue

            with suppress(Exception):
                ip = ipaddress.ip_network(event.host, strict=False)
                if ip.num_addresses == 1:
                    ip_hash = hash(ip.network_address)
                    cached_open_ports = self.open_port_cache.get(ip_hash)
                    if cached_open_ports is not None:
                        for port in cached_open_ports:
                            await self.emit_open_port(ip.network_address, port, event)
                        continue

                    events_set = correlator.search(ip)
                    if events_set is None:
                        correlator.insert(ip, {event})
                    else:
                        events_set.add(event)

                    if not self.scanned.get(ip):
                        self.scanned.add(ip)
                        targets.add(str(ip.network_address))
                    else:
                        self.debug(f"Skipping {ip} because it's already been verified")

        return targets, correlator

    async def verify_target_ports(self, target, correlator, emitted, emitted_lock, connect_semaphore):
        ip = ipaddress.ip_address(str(target))
        per_target_semaphore = asyncio.Semaphore(self.connect_concurrency)
        timeout = max(0.2, self.timeout_ms / 1000)

        async def verify(port):
            async with per_target_semaphore, connect_semaphore:
                for _ in range(self.retries):
                    writer = None
                    try:
                        _, writer = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout=timeout)
                        return port
                    except Exception:
                        continue
                    finally:
                        if writer is not None:
                            with suppress(Exception):
                                writer.close()
                                await writer.wait_closed()
            return None

        open_ports = []
        for offset in range(0, len(self.configured_ports), self.connect_concurrency * 4):
            chunk = self.configured_ports[offset : offset + self.connect_concurrency * 4]
            open_ports.extend(port for port in await asyncio.gather(*(verify(port) for port in chunk)) if port)

        normalized_open_ports = sorted(set(open_ports))
        self.open_port_cache[hash(ip)] = tuple(normalized_open_ports)

        if normalized_open_ports:
            self.info(f"tcp_connect_verify found {len(normalized_open_ports):,} open TCP ports on {ip}")

        parent_events = correlator.search(ip)
        if parent_events is None:
            self.warning(f"tcp_connect_verify found open ports on {ip} but could not correlate it to an input event")
            return

        for port in normalized_open_ports:
            for parent_event in parent_events:
                host = parent_event.host if parent_event.type == "DNS_NAME" else ip
                emit_key = (str(host), port, getattr(parent_event, "id", str(parent_event)))
                async with emitted_lock:
                    if emit_key in emitted:
                        continue
                    emitted.add(emit_key)
                await self.emit_open_port(host, port, parent_event)

    async def emit_open_port(self, host, port, parent_event):
        event_data = self.helpers.make_netloc(str(host), port)
        event = self.make_event(
            event_data,
            "OPEN_TCP_PORT",
            parent=parent_event,
            context=f"{{module}} verified a TCP connection against {parent_event.data} and found: {{event.type}}: {{event.data}}",
        )
        await self.emit_event(event)
        return event

    def _configured_ports(self):
        if self.ports:
            return sorted(self.helpers.parse_port_string(self.ports))
        if self.top_ports == "1000":
            return sorted(self.helpers.parse_port_string(NMAP_TOP_1000))
        with suppress(Exception):
            return sorted(self.helpers.top_tcp_ports(int(self.top_ports)))
        raise ValueError(f"Unsupported top_ports value for tcp_connect_verify: {self.top_ports}")

    def _normalize_port_string(self, value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            return ",".join(str(port).strip() for port in value if str(port).strip())
        return ",".join(part for part in str(value).replace(";", " ").split() if part)
