import asyncio
from types import SimpleNamespace

from bbot.modules.host_reputation import host_reputation

from ..bbot_fixtures import *


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


def test_positive_reputation_becomes_a_medium_finding_and_a_host_reputation_event():
    result = {"risk_score": 80, "malicious": True, "sources": [{"source": "MalwareWorld"}], "malwareworld": {"matches": [1]}}
    output = emitted_for_result(result)
    assert [event_type for event_type, _ in output] == ["HOST_REPUTATION", "FINDING"]
    reputation = output[0][1]
    assert reputation["host"] == "example.com"
    assert reputation["kind"] == "domain"
    assert reputation["risk_score"] == 80
    assert reputation["malicious"] is True
    assert reputation["sources"] == [{"source": "MalwareWorld"}]
    # reputation is never rated above MEDIUM
    assert output[1][1]["severity"] == "MEDIUM"


def test_non_malicious_signal_is_an_info_observation_with_reputation():
    result = {"risk_score": 10, "malicious": False, "sources": [{"source": "MalwareWorld"}], "malwareworld": {"matches": [1]}}
    output = emitted_for_result(result)
    assert [event_type for event_type, _ in output] == ["HOST_REPUTATION", "FINDING"]
    assert output[0][1]["malicious"] is False
    assert output[1][1]["severity"] == "INFO"


def test_host_reputation_event_validates(bbot_scanner):
    scan = bbot_scanner("example.com")
    event = scan.make_event(
        {"host": "example.com", "kind": "domain", "risk_score": 80, "malicious": True,
         "sources": [{"source": "MalwareWorld", "type": "phishing"}], "malwareworld": {"matches": []}},
        "HOST_REPUTATION",
        parent=scan.root_event,
    )
    assert event.type == "HOST_REPUTATION"
    assert event.host == "example.com"
