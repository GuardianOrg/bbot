import asyncio
from types import SimpleNamespace

from bbot.modules.host_reputation import host_reputation


def emitted_for_result(result):
    module = object.__new__(host_reputation)
    output = []

    async def check_malwareworld(*_):
        return result

    async def emit_event(data, event_type, *_args, **_kwargs):
        output.append((event_type, data))

    module.check_malwareworld = check_malwareworld
    module.emit_event = emit_event
    event = SimpleNamespace(type="DNS_NAME", host="example.com", data="example.com")
    asyncio.run(module.handle_event(event))
    return output


def test_no_match_does_not_become_a_finding():
    result = {"risk_score": 0, "malicious": False, "sources": [], "malwareworld": {"matches": []}}
    assert emitted_for_result(result) == []


def test_positive_reputation_still_becomes_a_finding():
    result = {"risk_score": 80, "malicious": True, "sources": [{"source": "MalwareWorld"}], "malwareworld": {"matches": [1]}}
    output = emitted_for_result(result)
    assert len(output) == 1
    assert output[0][0] == "FINDING"
    assert output[0][1]["severity"] == "HIGH"
