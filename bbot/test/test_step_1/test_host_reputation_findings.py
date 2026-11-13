import asyncio
from types import SimpleNamespace

from bbot.modules.host_reputation import host_reputation
from bbot.core.helpers import shared_infra

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
    output = emitted_for_result(result)
    assert [kind for kind, _ in output] == ["HOST_REPUTATION"]
    assert output[0][1]["malicious"] is False


def test_positive_reputation_becomes_a_medium_finding_and_a_host_reputation_event():
    result = {
        "risk_score": 80,
        "malicious": True,
        "sources": [{"source": "MalwareWorld"}],
        "malwareworld": {"matches": [1]},
    }
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
    result = {
        "risk_score": 10,
        "malicious": False,
        "sources": [{"source": "MalwareWorld"}],
        "malwareworld": {"matches": [1]},
    }
    output = emitted_for_result(result)
    assert [event_type for event_type, _ in output] == ["HOST_REPUTATION", "FINDING"]
    assert output[0][1]["malicious"] is False
    assert output[1][1]["severity"] == "INFO"


def test_host_reputation_event_validates(bbot_scanner):
    scan = bbot_scanner("example.com")
    event = scan.make_event(
        {
            "host": "example.com",
            "kind": "domain",
            "risk_score": 80,
            "malicious": True,
            "sources": [{"source": "MalwareWorld", "type": "phishing"}],
            "malwareworld": {"matches": []},
        },
        "HOST_REPUTATION",
        parent=scan.root_event,
    )
    assert event.type == "HOST_REPUTATION"
    assert event.host == "example.com"


async def test_shared_frontend_ip_is_rejected_before_reputation_lookup(bbot_scanner):
    scan = bbot_scanner("example.com")
    module = host_reputation(scan)
    module._name = "host_reputation"

    shared_ip = scan.make_event("104.16.1.1", "IP_ADDRESS", parent=scan.root_event)
    shared_ip.scope_distance = 0
    shared_ip.add_tag("shared-frontend")
    assert (await module.filter_event(shared_ip)) is not True

    # A later URL on the same edge can lose the event tag, but cloudcheck's
    # scan-wide classification still prevents another reputation lookup.
    shared_infra.remember_frontend(scan, "104.16.1.1", "cdn", "cloudflare")
    shared_url = scan.make_event("https://104.16.1.1/", "URL", parent=scan.root_event, tags=["status-200"])
    shared_url.scope_distance = 0
    assert "shared-frontend" not in shared_url.tags
    assert (await module.filter_event(shared_url)) is not True

    owned_ip = scan.make_event("8.8.8.8", "IP_ADDRESS", parent=scan.root_event)
    owned_ip.scope_distance = 0
    assert await module.filter_event(owned_ip) is True

    github_ip = scan.make_event("8.8.4.4", "IP_ADDRESS", parent=scan.root_event)
    github_ip.scope_distance = 0
    github_ip.add_tag("cdn-github")
    assert await module.filter_event(github_ip) is True

    shared_range = scan.make_event("104.16.0.0/16", "IP_RANGE", parent=scan.root_event)
    shared_range.scope_distance = 0
    shared_range.add_tag("shared-frontend")
    assert (await module.filter_event(shared_range)) is not True

    domain = scan.make_event("app.example.com", "DNS_NAME", parent=scan.root_event)
    domain.scope_distance = 0
    domain.add_tag("shared-frontend")
    assert await module.filter_event(domain) is True


def test_configured_provider_verdict_is_part_of_the_initial_reputation_observation():
    module = object.__new__(host_reputation)
    module.virustotal_api_keys = ['test']
    output = []
    async def feed(*_):
        return {'malicious': False, 'risk_score': 0, 'sources': [], 'malwareworld': {'matches': []}}
    async def vt(*_):
        return {'malicious': True, 'risk_score': 80, 'sources': [], 'provider': 'VirusTotal'}
    async def emit(data, kind, *_args, **_kwargs):
        output.append((kind, data))
    module.check_malwareworld, module.check_vt_domain, module.emit_event = feed, vt, emit
    asyncio.run(module.handle_event(SimpleNamespace(type='DNS_NAME', host='example.com', data='example.com')))
    assert output[0][1]['malicious'] is True
    assert output[0][1]['provider_coverage'] == ['MalwareWorld', 'VirusTotal']
    assert output[1][0] == 'FINDING' and output[1][1]['severity'] == 'MEDIUM'


def test_unavailable_configured_provider_cannot_become_a_clean_initial_reference():
    module = object.__new__(host_reputation)
    module.virustotal_api_keys = ['test']
    output = []
    async def feed(*_):
        return {'malicious': False, 'risk_score': 0, 'sources': [], 'malwareworld': {'matches': []}}
    async def vt(*_):
        return {'error': 'rate limited', 'malicious': False}
    async def emit(data, kind, *_args, **_kwargs):
        output.append((kind, data))
    module.check_malwareworld, module.check_vt_domain, module.emit_event = feed, vt, emit
    with pytest.raises(RuntimeError, match='incomplete'):
        asyncio.run(module.handle_event(SimpleNamespace(type='DNS_NAME', host='example.com', data='example.com')))
    assert output == []


async def test_provider_cdn_classification_is_persisted_before_other_reputation_sources(bbot_scanner):
    scan = bbot_scanner('example.com')
    module = host_reputation(scan)
    module._name = 'host_reputation'
    module.abuseipdb_api_key, module.virustotal_api_keys = 'test', ['test']
    output = []
    async def abuse(*_):
        return {'shared': True, 'malicious': False, 'risk_score': 0}
    async def forbidden(*_):
        raise AssertionError('A shared CDN must not be checked for reputation')
    async def emit(data, kind, *_args, **_kwargs):
        scan.make_event(data, kind, parent=scan.root_event)
        output.append((kind, data))
    module.check_abuseipdb, module.check_malwareworld, module.check_vt_ip, module.emit_event = abuse, forbidden, forbidden, emit
    event = scan.make_event('8.8.8.8', 'IP_ADDRESS', parent=scan.root_event)
    await module.handle_event(event)
    assert [kind for kind, _ in output] == ['GEOLOCATION']
    assert output[0][1]['is_cdn'] is True
    assert shared_infra.known_frontend(scan, '8.8.8.8') == ('cdn', 'AbuseIPDB')


@pytest.mark.parametrize(('score', 'reports', 'expected'), [(89, 10, False), (90, 2, False), (90, 3, True)])
def test_initial_abuse_evidence_uses_the_monitor_confidence_threshold(score, reports, expected):
    module = object.__new__(host_reputation)
    module.abuseipdb_api_key = 'test'
    async def request(*_args, **_kwargs):
        return {'data': {'abuseConfidenceScore': score, 'totalReports': reports}}
    module.request_json = request
    assert asyncio.run(module.check_abuseipdb('8.8.8.8'))['malicious'] is expected


@pytest.mark.parametrize(('malicious', 'suspicious', 'expected'), [(2, 9, False), (3, 0, True)])
def test_initial_virustotal_evidence_does_not_promote_suspicious_only_votes(malicious, suspicious, expected):
    module = object.__new__(host_reputation)
    module.virustotal_api_keys = ['test']
    async def request(*_args, **_kwargs):
        return {'data': {'attributes': {'last_analysis_stats': {'malicious': malicious, 'suspicious': suspicious}}}}
    module.request_json = request
    assert asyncio.run(module.check_vt('https://www.virustotal.com/api/v3/domains/example.com'))['malicious'] is expected
