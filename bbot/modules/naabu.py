import json
import ipaddress
import math
import subprocess
import asyncio
from contextlib import suppress

from radixtarget import RadixTarget, host_size_key

from bbot.modules.base import BaseModule


NMAP_TOP_1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"


class naabu(BaseModule):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {
        "description": "Port scan with naabu (ProjectDiscovery). By default, scans top 100 ports.",
        "created_date": "2026-02-19",
        "author": "GitHub Copilot",
    }

    options = {
        "version": "2.5.0",
        "top_ports": "1000",
        "ports": "",
        "rate": 1200,
        "threads": 200,
        # 'c' (connect) works without root and is the production default; 's' (syn) generally requires root
        "scan_type": "c",
        "retries": 3,
        "timeout_ms": 3000,
        "process_timeout_multiplier": 4,
        "process_timeout_grace": 60,
        "exclude_cdn": False,
        "scan_all_ips": False,
        "verify": False,
        "expand_ip_ranges": False,
        "max_expanded_ip_range_hosts": 4096,
        "port_chunk_size": 0,
        "scan_passes": 1,
        "scan_individual_targets": True,
        "target_concurrency": 1,
        "module_timeout": 259200,  # 3 days
    }
    options_desc = {
        "version": "naabu version",
        "top_ports": "Top ports to scan (only used when 'ports' is empty)",
        "ports": "Ports to scan (naabu -p format, e.g. '80,443,100-200'; empty uses top_ports)",
        "rate": "Packets/connections to send per second (naabu -rate)",
        "threads": "General internal worker threads (naabu -c)",
        "scan_type": "Type of port scan: 'c' (connect) or 's' (syn)",
        "retries": "Number of retries for the port scan",
        "timeout_ms": "Per-port timeout in milliseconds; passed to naabu with an explicit ms suffix",
        "process_timeout_multiplier": "Safety multiplier for the calculated naabu process runtime limit",
        "process_timeout_grace": "Extra seconds added to the calculated naabu process runtime limit",
        "exclude_cdn": "Skip full port scans for CDN/WAF (only scan 80,443)",
        "scan_all_ips": "Scan all IPs associated with a hostname (naabu -sa)",
        "verify": "Ask naabu to validate discovered ports with TCP verification before emitting them",
        "expand_ip_ranges": "Deprecated compatibility option; IP_RANGE expansion is handled by BBOT's internal speculate module",
        "max_expanded_ip_range_hosts": "Maximum IP_RANGE host count to expand before falling back to CIDR input",
        "port_chunk_size": "Number of explicit ports to pass to each naabu run when expanding top_ports=1000",
        "scan_passes": "Number of naabu passes to run per target or port chunk; results are de-duplicated",
        "scan_individual_targets": "Scan one target per naabu process for better reliability on IP ranges",
        "target_concurrency": "Maximum number of individual target groups to scan concurrently",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }

    deps_ansible = [
        {
            "name": "Download naabu",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/naabu/releases/download/v#{BBOT_MODULES_NAABU_VERSION}/naabu_#{BBOT_MODULES_NAABU_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "naabu",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    batch_size = 1000000
    _shuffle_incoming_queue = False

    async def setup(self):
        self.top_ports = str(self.config.get("top_ports", "full")).strip() or "full"
        self.rate = int(self.config.get("rate", 1000))
        self.threads = int(self.config.get("threads", 25))
        self.scan_type = str(self.config.get("scan_type", "c")).lower().strip() or "c"
        self.retries = int(self.config.get("retries", 3))
        self.timeout_ms = int(self.config.get("timeout_ms", 1000))
        self.process_timeout_multiplier = float(self.config.get("process_timeout_multiplier", 4))
        self.process_timeout_grace = int(self.config.get("process_timeout_grace", 60))
        self.exclude_cdn = bool(self.config.get("exclude_cdn", False))
        self.scan_all_ips = bool(self.config.get("scan_all_ips", False))
        self.verify = bool(self.config.get("verify", True))
        self.expand_ip_ranges = bool(self.config.get("expand_ip_ranges", True))
        self.max_expanded_ip_range_hosts = int(self.config.get("max_expanded_ip_range_hosts", 4096))
        self.port_chunk_size = int(self.config.get("port_chunk_size", 0))
        self.scan_passes = max(1, int(self.config.get("scan_passes", 1)))
        self.scan_individual_targets = bool(self.config.get("scan_individual_targets", True))
        self.target_concurrency = max(1, int(self.config.get("target_concurrency", 1)))

        self.ports = self._normalize_port_string(self.config.get("ports", ""))
        if self.ports:
            try:
                self.helpers.parse_port_string(self.ports)
            except ValueError as e:
                return False, f"Error parsing ports '{self.ports}': {e}"

        if self.scan_type not in ("c", "s", "connect", "syn"):
            return False, f"Invalid scan_type '{self.scan_type}' (expected 'c' or 's')"

        # naabu runs CONNECT scans without root; SYN scans generally require root
        if self.scan_type in ("s", "syn"):
            self.helpers.depsinstaller.ensure_root(message="naabu SYN scans require root privileges")

        # keeps track of individual scanned IPs and their open ports (to avoid rescanning)
        self.open_port_cache = {}
        # keeps track of which IPs/subnets have already been scanned
        self.scanned = self.helpers.make_target(acl_mode=True)

        self.prep_blacklist()
        return True

    async def handle_batch(self, *events):
        targets, correlator = await self.make_targets(events, self.scanned)
        if not targets:
            return

        emitted = set()
        target_groups = [[target] for target in sorted(targets, key=str)] if self.scan_individual_targets else [targets]
        if self.target_concurrency <= 1:
            for target_group in target_groups:
                await self._scan_target_group(target_group, correlator, emitted)
            return

        emitted_lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(self.target_concurrency)

        async def scan_group(target_group):
            async with semaphore:
                await self._scan_target_group(target_group, correlator, emitted, emitted_lock)

        await asyncio.gather(*(scan_group(target_group) for target_group in target_groups))

    async def _scan_target_group(self, target_group, correlator, emitted, emitted_lock=None):
        target_file = self.helpers.tempfile(target_group, pipe=False)
        try:
            for command in self._build_naabu_commands(target_file, target_group):
                await self._run_naabu_command(command, target_group, correlator, emitted, emitted_lock)
        finally:
            target_file.unlink(missing_ok=True)

    async def _run_naabu_command(self, command, targets, correlator, emitted, emitted_lock=None):
        use_sudo = self.scan_type in ("s", "syn")
        try:
            async for line in self.run_process_live(command, sudo=use_sudo, stderr=subprocess.DEVNULL, check=True):
                for ip, port in self.parse_json_line(line):
                    if emitted_lock is None:
                        await self.emit_correlated_port(ip, port, correlator, emitted)
                    else:
                        async with emitted_lock:
                            await self.emit_correlated_port(ip, port, correlator, emitted)
        except subprocess.CalledProcessError as e:
            if e.returncode in (124, 137):
                self.warning(
                    f"naabu exceeded calculated process timeout while scanning {len(targets):,} targets; partial results were kept"
                )
            else:
                raise

    async def emit_correlated_port(self, ip, port, correlator, emitted):
        parent_events = correlator.search(ip) or correlator.search(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
        if not parent_events:
            self.debug(f"Failed to correlate {ip} to targets")
            return
        emitted_hosts = set()
        for parent_event in parent_events:
            if parent_event.type == "DNS_NAME":
                host = parent_event.host
            else:
                host = ip
            emit_key = (str(host), port, getattr(parent_event, "id", str(parent_event)))
            if host not in emitted_hosts and emit_key not in emitted:
                await self.emit_open_port(host, port, parent_event)
                emitted_hosts.add(host)
                emitted.add(emit_key)

    async def make_targets(self, events, scanned_tracker):
        """Convert events into a list of targets, skipping ones that have already been scanned."""
        correlator = RadixTarget()
        targets = set()
        for event in sorted(events, key=lambda e: host_size_key(e.host)):
            if not event.host:
                continue

            ips = set()
            try:
                ips.add(ipaddress.ip_network(event.host, strict=False))
            except Exception:
                for h in event.resolved_hosts:
                    with suppress(Exception):
                        ips.add(ipaddress.ip_network(h, strict=False))

            for ip in ips:
                # check if we already found open ports on this IP
                if event.type != "IP_RANGE":
                    ip_hash = hash(ip.network_address)
                    already_found_ports = self.open_port_cache.get(ip_hash, None)
                    if already_found_ports is not None:
                        for port in already_found_ports:
                            await self.emit_open_port(event.host, port, event)

                # build a correlation from the IP back to its original parent event
                events_set = correlator.search(ip)
                if events_set is None:
                    correlator.insert(ip, {event})
                else:
                    events_set.add(event)

                # has this IP already been scanned?
                if not scanned_tracker.get(ip):
                    scanned_tracker.add(ip)
                    for target in self._scan_targets_for_ip(event, ip):
                        targets.add(target)
                else:
                    self.debug(f"Skipping {ip} because it's already been scanned")

        return targets, correlator

    def _scan_targets_for_ip(self, event, ip):
        if event.type != "IP_RANGE" or not self.expand_ip_ranges:
            if ip.num_addresses == 1:
                return [str(ip.network_address)]
            return [str(ip)]

        host_count = ip.num_addresses
        if ip.version == 4 and ip.prefixlen < 31:
            host_count = max(0, host_count - 2)

        if host_count > self.max_expanded_ip_range_hosts:
            self.warning(
                f"IP range {ip} has {host_count} hosts; passing CIDR to naabu because it exceeds max_expanded_ip_range_hosts={self.max_expanded_ip_range_hosts}"
            )
            return [str(ip)]

        return [str(host) for host in ip.hosts()]

    async def emit_open_port(self, host, port, parent_event):
        event_data = self.helpers.make_netloc(str(host), port)
        event = self.make_event(
            event_data,
            "OPEN_TCP_PORT",
            parent=parent_event,
            context=f"{{module}} executed a naabu scan against {parent_event.data} and found: {{event.type}}: {{event.data}}",
        )
        await self.emit_event(event)
        return event

    def parse_json_line(self, line):
        try:
            j = json.loads(line)
        except Exception:
            return

        ip = j.get("ip", "")
        port = j.get("port", None)
        if not ip or port is None:
            return

        # ignore UDP results (BBOT event is OPEN_TCP_PORT)
        proto = str(j.get("protocol", "tcp")).lower()
        if proto and proto != "tcp":
            return

        try:
            port = int(port)
        except Exception:
            return

        ip = self.helpers.make_ip_type(ip)
        if not self.helpers.is_ip_type(ip, network=False):
            return

        ip_hash = hash(ip)
        try:
            self.open_port_cache[ip_hash].add(port)
        except KeyError:
            self.open_port_cache[ip_hash] = {port}

        yield ip, port

    def prep_blacklist(self):
        exclude = []
        for t in self.scan.blacklist:
            # blacklist events may be DNS_NAME, IP_ADDRESS, IP_RANGE, etc
            with suppress(Exception):
                exclude.append(str(t.data))
        if not exclude:
            self.exclude_file = None
            return
        self.exclude_file = self.helpers.tempfile(exclude, pipe=False)

    def _build_naabu_commands(self, target_file, targets):
        if not self.ports and str(self.top_ports).lower().strip() == "1000" and self.port_chunk_size > 0:
            ports = self._configured_ports()
            chunk_size = max(1, self.port_chunk_size)
            self.info(f"naabu scanning top 1,000 TCP ports in chunks of {chunk_size} to avoid dropped results from the native top-ports mode")
            for offset in range(0, len(ports), chunk_size):
                chunk = ports[offset : offset + chunk_size]
                for _ in range(self.scan_passes):
                    yield self._build_naabu_command(
                        target_file,
                        self._calculate_process_timeout(targets, port_count=len(chunk)),
                        ports=",".join(str(port) for port in chunk),
                    )
            return

        for _ in range(self.scan_passes):
            yield self._build_naabu_command(target_file, self._calculate_process_timeout(targets))

    def _build_naabu_command(self, target_file, process_timeout, ports=None, top_ports=None):
        scan_type = "c" if self.scan_type in ("c", "connect") else "s"
        command = [
            "timeout",
            str(process_timeout),
            "naabu",
            "-silent",
            "-json",
            "-scan-type",
            scan_type,
            "-list",
            str(target_file),
            "-rate",
            str(self.rate),
            "-c",
            str(self.threads),
            "-retries",
            str(self.retries),
            "-timeout",
            f"{self.timeout_ms}ms",
            "-Pn",
        ]

        if self.exclude_file is not None:
            command += ["-exclude-file", str(self.exclude_file)]

        ports = self.ports if ports is None else ports
        top_ports = self.top_ports if top_ports is None else top_ports

        # prefer explicit ports over top ports
        if ports:
            command += ["-p", str(ports)]
        elif str(top_ports).lower().strip() == "1000":
            command += ["-p", NMAP_TOP_1000]
        else:
            command += ["-top-ports", str(top_ports)]

        if self.exclude_cdn:
            command.append("-exclude-cdn")

        if self.scan_all_ips:
            command.append("-scan-all-ips")

        if self.verify:
            command.append("-verify")

        dns_resolvers = ",".join(self.helpers.system_resolvers)
        if dns_resolvers:
            command += ["-r", dns_resolvers]

        return command

    def _calculate_process_timeout(self, targets, port_count=None):
        target_count = sum(self._target_host_count(target) for target in targets)
        port_count = self._port_count() if port_count is None else port_count
        retry_count = max(1, self.retries)
        rate = max(1, self.rate)
        per_port_timeout = max(0.5, self.timeout_ms / 1000)

        # naabu connect scans are rate-limited and then wait for in-flight dial timeouts.
        # This is a hard safety ceiling, not a normal pacing mechanism.
        expected_seconds = ((target_count * port_count * retry_count) / rate) + (per_port_timeout * retry_count) + 2
        return max(1, math.ceil((expected_seconds * self.process_timeout_multiplier) + self.process_timeout_grace))

    def _target_host_count(self, target):
        with suppress(Exception):
            return max(1, ipaddress.ip_network(target, strict=False).num_addresses)
        return 1

    def _port_count(self):
        if self.ports:
            return len(self.helpers.parse_port_string(self.ports))
        top_ports = str(self.top_ports).lower().strip()
        if top_ports == "full":
            return 65535
        with suppress(Exception):
            return int(top_ports)
        return 100

    def _configured_ports(self):
        if self.ports:
            return sorted(self.helpers.parse_port_string(self.ports))
        if str(self.top_ports).lower().strip() == "1000":
            return sorted(self.helpers.parse_port_string(NMAP_TOP_1000))
        return []

    def _normalize_port_string(self, value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            return ",".join(str(port).strip() for port in value if str(port).strip())
        return ",".join(part for part in str(value).replace(";", " ").split() if part)

    async def cleanup(self):
        with suppress(Exception):
            if self.exclude_file is not None:
                self.exclude_file.unlink()
