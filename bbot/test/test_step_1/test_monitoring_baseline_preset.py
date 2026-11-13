"""The maintenance preset must never expand into a normal active scan."""

from pathlib import Path

from bbot.scanner import Preset


def test_baseline_refresh_does_not_load_port_or_vulnerability_scanners():
    preset = Preset("example.com")
    preset.merge(Preset.from_yaml_file(Path(__file__).parents[3] / "my_bbot" / "monitoring-baselines.yml"))
    baked = preset.bake()
    # An allowlist also catches future scanner modules and implicit module dependencies.
    assert set(baked.scan_modules) <= {
        "offchain_scope_filter",
        "monitoring_dns",
        "domain_whois",
        "crt",
        "httpx",
        "sslcert",
        "domain_phishing",
        "host_reputation",
    }
    assert {"monitoring_dns", "sslcert", "httpx"} <= set(baked.scan_modules)
    assert baked.config.speculate is False
    assert baked.config.modules.httpx.in_scope_only is True
