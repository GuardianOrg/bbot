from bbot.modules.naabu import MAX_OPEN_PORTS_PER_IP, naabu


class naabu_fast(naabu):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {
        "description": "Best-effort naabu scan over TCP ports 1-10000.",
        "created_date": "2026-04-28",
        "author": "Guardian",
    }

    options = {
        "version": "2.5.0",
        "ports": "1-10000",
        "top_ports": "1000",
        "rate": 6000,
        "threads": 300,
        "scan_type": "c",
        "retries": 1,
        "timeout_ms": 800,
        "process_timeout_multiplier": 2,
        "process_timeout_grace": 30,
        "exclude_cdn": False,
        "scan_all_ips": False,
        "verify": False,
        "port_chunk_size": 0,
        "scan_passes": 1,
        "scan_individual_targets": True,
        "target_concurrency": 1,
        "max_open_ports_per_ip": 70,
        "module_timeout": 259200,
    }
    options_desc = {
        "ports": "Best-effort explicit TCP port range to scan",
        "rate": "Packets/connections to send per second (naabu -rate)",
        "threads": "General internal worker threads (naabu -c)",
        "scan_type": "Type of port scan: 'c' (connect) or 's' (syn)",
        "retries": "Number of retries for the port scan",
        "timeout_ms": "Per-port timeout in milliseconds",
        "process_timeout_multiplier": "Safety multiplier for the calculated naabu process runtime limit",
        "process_timeout_grace": "Extra seconds added to the calculated naabu process runtime limit",
        "target_concurrency": "Maximum number of individual target groups to scan concurrently",
        "max_open_ports_per_ip": "Discard this module's OPEN_TCP_PORT results for an IP when more than this many ports are found",
    }
