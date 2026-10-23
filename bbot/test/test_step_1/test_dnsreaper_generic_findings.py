import asyncio
import json
from types import SimpleNamespace

from bbot.modules.dnsreaper import dnsreaper


def test_generic_dangling_cname_is_a_lead_while_confirmed_netlify_is_a_vulnerability(tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("vpn.example.com\ninquiry.example.com\nprovider.example.com\napi.apne1.d.predict.fun\n")
    results = [
        {
            "domain": "vpn.example.com",
            "signature": "_generic_cname_found_doesnt_resolve",
            "confidence": "POTENTIAL",
            "info": "CNAME target does not resolve; claimability was not established",
        },
        {
            "domain": "inquiry.example.com",
            "signature": "netlify",
            "confidence": "CONFIRMED",
            "info": "CNAME points to an unclaimed Netlify site",
        },
        {
            "domain": "provider.example.com",
            "signature": "specific-provider",
            "confidence": "POTENTIAL",
            "info": "Provider-specific fingerprint matched",
        },
        {
            "domain": "api.apne1.d.predict.fun",
            "signature": "_generic_cname_found_doesnt_resolve",
            "confidence": "POTENTIAL",
            "info": "CNAME target does not resolve; claimability was not established",
        },
    ]
    emitted = []
    class TestDnsreaper(dnsreaper):
        @property
        def helpers(self):
            return SimpleNamespace(tempfile=lambda *args, **kwargs: targets_file)

    module = object.__new__(TestDnsreaper)
    module.binary = "dnsreaper"
    module.parallelism = 2
    module.timeout = 5
    module.resolver = ""
    module.disable_probable = False
    module.enable_unlikely = False
    module.signatures = []
    module.exclude_signatures = []

    async def run_process(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps(results))

    async def emit_event(data, event_type, parent_event, **kwargs):
        emitted.append((data, event_type, parent_event))

    module.run_process = run_process
    module.emit_event = emit_event
    module.debug = lambda *args, **kwargs: None
    events = [
        SimpleNamespace(host="vpn.example.com", raw_dns_records={"CNAME": {"unclaimed.example.net."}}),
        SimpleNamespace(host="inquiry.example.com", raw_dns_records={"CNAME": {"site.netlify.app."}}),
        SimpleNamespace(host="provider.example.com", raw_dns_records={"CNAME": {"provider.example.net."}}),
        SimpleNamespace(
            host="api.apne1.d.predict.fun",
            raw_dns_records={
                "CNAME": {"a59ba760eda0f47f1ac5304f53faa6bf-3c9aad767abc6fd9.elb.ap-northeast-1.amazonaws.com."}
            },
        ),
    ]

    asyncio.run(module.handle_batch(*events))

    assert [(data["signature"], event_type) for data, event_type, _ in emitted] == [
        ("_generic_cname_found_doesnt_resolve", "FINDING"),
        ("netlify", "VULNERABILITY"),
        ("specific-provider", "VULNERABILITY"),
    ]
