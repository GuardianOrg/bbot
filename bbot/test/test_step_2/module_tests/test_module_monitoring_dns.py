import asyncio
from types import SimpleNamespace


def test_initial_dns_preserves_absence_but_not_failed_or_conflicting_answers():
    from bbot.modules.monitoring_dns import monitoring_dns
    from bbot.core.event import make_event

    module = object.__new__(monitoring_dns)
    captured = []

    async def query(host, kind, provider):
        if kind == "SRV":
            return False, []
        if kind == "MX":
            return True, ["10 mx.one.example" if provider == "1.1.1.1" else "10 mx.two.example"]
        if kind == "TXT":
            return True, ["v=spf1 include:mail.example ~all"]
        if kind == "SOA":
            return True, [
                "ns.example hostmaster.example 10 60 60 86400 60"
                if provider == "1.1.1.1"
                else "ns.example hostmaster.example 11 60 60 86400 60"
            ]
        return True, []

    async def emit(payload, kind, **kwargs):
        event = make_event(payload, kind, dummy=True)
        captured.append(event)
        return event

    module.query_record = query
    module.emit_event = emit
    asyncio.run(module.handle_event(SimpleNamespace(host="example.com")))
    assert len(captured) == 1
    data = captured[0].data
    assert data["monitoring_records"]["A"] == []
    assert data["monitoring_records"]["TXT"] == ["v=spf1 include:mail.example ~all"]
    assert "SOA" in data["monitoring_records"]
    assert "MX" not in data["monitoring_records"]
    assert "SRV" not in data["monitoring_records"]
    assert data["monitoring_errors"] == {"MX": "resolvers-disagree", "SRV": "lookup-unavailable"}
