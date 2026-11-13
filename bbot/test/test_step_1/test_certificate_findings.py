from datetime import datetime, timezone
from bbot.core.helpers.certificate_findings import initial_certificate_findings
from ..bbot_fixtures import *

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def snapshot(**patch):
    return {"host": "api.example.com", "url": "https://api.example.com/path?q=1",
            "certSubjectCn": "api.example.com", "certSanDomains": ["api.example.com"],
            "certNotAfter": "2027-01-01T00:00:00Z", "certChainTrusted": True, **patch}


def test_valid_certificate_has_no_finding():
    assert initial_certificate_findings(snapshot(), now=NOW) == []


def test_expired_certificate_is_one_stable_medium_issue_across_paths_and_rotations():
    a = initial_certificate_findings(snapshot(certNotAfter="2026-10-01T00:00:00Z", certChainTrusted=False,
                                            certValidationError="certificate has expired"), now=NOW)
    b = initial_certificate_findings(snapshot(url="https://api.example.com/other", certNotAfter="2026-09-01T00:00:00Z"), now=NOW)
    assert [f["title"] for f in a] == ["TLS certificate is expired for api.example.com"]
    assert a[0]["severity"] == "MEDIUM"
    assert a[0]["url"] == "https://api.example.com/"
    assert a[0]["dedupe_key"] == b[0]["dedupe_key"]


def test_sans_override_common_name_and_wildcard_covers_one_label_only():
    assert initial_certificate_findings(snapshot(certSanDomains=["*.example.com"]), now=NOW) == []
    findings = initial_certificate_findings(snapshot(certSanDomains=["*.other.com"]), now=NOW)
    assert [f["title"] for f in findings] == ["TLS certificate does not cover hostname api.example.com"]
    assert len(initial_certificate_findings(snapshot(host="deep.api.example.com", certSanDomains=["*.example.com"]), now=NOW)) == 1


def test_short_lived_certificates_use_renewal_window_instead_of_thirty_days():
    short = snapshot(certNotAfter="2026-12-01T00:00:00Z", certificate={"notBefore": "2026-09-02T00:00:00Z"})
    assert initial_certificate_findings(short, now=NOW) == []
    short["certNotAfter"] = "2026-11-20T00:00:00Z"
    assert initial_certificate_findings(short, now=NOW)[0]["severity"] == "LOW"


def test_tracking_host_mismatch_is_expected_but_untrusted_chain_is_still_actionable():
    tracking = snapshot(certSanDomains=["*.mailgun.org"], certSubjectCn="mailgun.org")
    assert initial_certificate_findings(tracking, now=NOW) == []
    findings = initial_certificate_findings({**tracking, "certChainTrusted": False, "certValidationError": "self signed certificate"}, now=NOW)
    assert [f["title"] for f in findings] == ["TLS certificate chain is not trusted for api.example.com"]


def test_discovered_ip_default_certificate_is_not_an_actionable_domain_issue():
    data = snapshot(host="8.8.8.8", url="https://8.8.8.8/", certChainTrusted=False)
    assert initial_certificate_findings(data, now=NOW) == []
    assert len(initial_certificate_findings(data, now=NOW, explicit_ip=True)) == 1


def test_unknown_legacy_certificate_identity_does_not_invent_a_mismatch():
    assert initial_certificate_findings(snapshot(certSubjectCn=None, certSanDomains=[]), now=NOW) == []
    observed = snapshot(certSubjectCn=None, certSanDomains=[], certificate={"subject": {}})
    assert len(initial_certificate_findings(observed, now=NOW)) == 1


async def test_sslcert_emits_validated_initial_findings_only_for_explicit_ip_seeds(bbot_scanner):
    from bbot.modules.sslcert import sslcert
    for seed, expected in [("8.8.8.8", 1), ("8.8.8.0/24", 0), ("https://8.8.8.8/", 1)]:
        scan = bbot_scanner(seed)
        module = sslcert(scan)
        module._name = "sslcert"
        output = []
        async def emit(data, kind, **_kwargs):
            output.append(scan.make_event(data, kind, parent=scan.root_event))
        module.emit_event = emit
        await module.emit_initial_findings(snapshot(host="8.8.8.8", url="https://8.8.8.8/", port=443, certChainTrusted=False), scan.root_event)
        assert len(output) == expected
        if output:
            assert output[0].type == "FINDING"
            assert output[0].data["dedupe_key"] == "tls-initial:chain:https://8.8.8.8/"
