import asyncio
from types import SimpleNamespace

from bbot.core.helpers.workspace_providers import detect_workspace_providers
from bbot.modules.internal.dnsresolve import DNSResolve

from ..bbot_fixtures import *


def run_detection(bbot_scanner, records):
    scan = bbot_scanner("example.com")
    module = object.__new__(DNSResolve)
    module.policy_queries_done = set()
    module.policy_events_emitted = set()
    emitted = []

    async def emit_event(data, event_type, parent, **kwargs):
        emitted.append(scan.make_event(data, event_type, parent=scan.root_event, tags=kwargs.get("tags", [])))

    module.emit_event = emit_event
    record = lambda text: SimpleNamespace(to_text=lambda: text)
    parent = SimpleNamespace(raw_dns_records={rdtype: [record(text) for text in texts] for rdtype, texts in records.items()})
    asyncio.run(module.emit_workspace_providers(parent, "example.com"))
    asyncio.run(module.emit_workspace_providers(parent, "example.com"))
    return emitted


def test_google_mail_dns_signal_becomes_a_workspace_provider_without_finding(bbot_scanner):
    emitted = run_detection(bbot_scanner, {
        "TXT": ['"v=spf1 include:_spf.google.com ~all"'],
        "MX": ["1 aspmx.l.google.com."],
    })

    assert len(emitted) == 1
    assert emitted[0].type == "WORKSPACE_PROVIDER"
    assert emitted[0].data["provider"] == "google_workspace"
    assert emitted[0].data["name"] == "Google Workspace"
    assert emitted[0].data["host"] == "example.com"
    assert emitted[0].data["services"] == ["email"]
    assert emitted[0].data["signals"] == ["mx", "spf"]


def test_each_hosted_provider_is_reported_once(bbot_scanner):
    emitted = run_detection(bbot_scanner, {
        "TXT": ['"v=spf1 include:spf.protection.outlook.com -all"', '"MS=ms12345678"'],
        "MX": ["10 example-com.mail.protection.outlook.com.", "20 inbound-smtp.eu-west-1.amazonaws.com."],
    })

    providers = {event.data["provider"]: event.data["signals"] for event in emitted}
    assert providers == {
        "microsoft_365": ["mx", "spf", "verification-txt"],
        "amazon_workmail": ["mx"],
    }


def test_unrelated_records_do_not_name_a_provider():
    assert detect_workspace_providers(
        ["10 mail.example.com.", "20 mx.notzoho.example."],
        ["v=spf1 include:mailgun.org ~all", "google-site-verification=abc", "v=spf1 include:evilgoogle.com ~all"],
    ) == {}


def test_zoho_proton_and_fastmail_records_are_recognised():
    assert detect_workspace_providers(["10 mx.zoho.eu."], ["v=spf1 include:zoho.eu ~all"]) == {"zoho_mail": ["mx", "spf"]}
    assert detect_workspace_providers(["10 mail.protonmail.ch."], ["protonmail-verification=abc"]) == {
        "proton_mail": ["mx", "verification-txt"],
    }
    assert detect_workspace_providers(["10 in1-smtp.messagingengine.com."], []) == {"fastmail": ["mx"]}
