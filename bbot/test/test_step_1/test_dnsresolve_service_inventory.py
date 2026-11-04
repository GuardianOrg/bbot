import asyncio
from types import SimpleNamespace

from bbot.modules.internal.dnsresolve import DNSResolve

from ..bbot_fixtures import *


def test_google_mail_dns_signal_enriches_technology_without_finding(bbot_scanner):
    scan = bbot_scanner("example.com")
    module = object.__new__(DNSResolve)
    module.policy_queries_done = set()
    module.policy_events_emitted = set()
    emitted = []

    async def emit_event(data, event_type, parent, **kwargs):
        emitted.append(scan.make_event(data, event_type, parent=scan.root_event, tags=kwargs.get("tags", [])))

    module.emit_event = emit_event
    record = lambda text: SimpleNamespace(to_text=lambda: text)
    parent = SimpleNamespace(raw_dns_records={
        "TXT": [record('"v=spf1 include:_spf.google.com ~all"')],
        "MX": [record("1 aspmx.l.google.com.")],
    })
    asyncio.run(module.emit_google_workspace_technology(parent, "example.com"))
    asyncio.run(module.emit_google_workspace_technology(parent, "example.com"))

    assert len(emitted) == 1
    assert emitted[0].type == "TECHNOLOGY"
    assert emitted[0].data["technology"] == "Google Workspace"
    assert emitted[0].data["host"] == "example.com"
    assert "spf-google" in emitted[0].data["evidence"]
    assert "mx-google" in emitted[0].data["evidence"]
