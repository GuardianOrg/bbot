from bbot.modules.retirejs import RetireJSSeverity, library_findings


def advisory(severity, summary, cves=(), below="", info=()):
    return {"severity": severity, "below": below, "identifiers": {"summary": summary, "CVE": list(cves)}, "info": list(info)}


def results(*components):
    return {"data": [{"file": "library.js", "results": list(components)}]}


def test_advisories_of_one_library_version_are_one_finding():
    output = results(
        {
            "component": "axios",
            "version": "1.6.7",
            "vulnerabilities": [
                advisory("high", "SSRF via absolute URLs", ["CVE-2025-27152"], "1.8.2", ["https://a.example/1"]),
                advisory("critical", "NO_PROXY bypass", ["CVE-2025-62718"], "1.15.0", ["https://a.example/2"]),
                advisory("high", "Header injection", ["CVE-2025-27152"], "1.12.0", ["https://a.example/1"]),
                advisory("low", "Below the threshold", ["CVE-2000-0001"]),
            ],
        },
        {"component": "lodash", "version": "4.17.21", "vulnerabilities": [advisory("medium", "Template injection")]},
    )
    findings = library_findings(output, RetireJSSeverity.HIGH, "https://app.example.com/app.js", "https://app.example.com/")

    assert [finding["component"] for finding in findings] == ["axios"]
    axios = findings[0]
    assert axios["severity"] == "critical"
    assert axios["title"] == "Vulnerable JavaScript library axios v1.6.7"
    assert axios["cves"] == ["CVE-2025-62718", "CVE-2025-27152"]
    assert axios["advisory_urls"] == ["https://a.example/2", "https://a.example/1"]
    assert axios["url"] == "https://app.example.com/"
    assert "3 advisories: [CRITICAL] NO_PROXY bypass" in axios["description"]
    assert "[HIGH] Header injection CVE(s): CVE-2025-27152 Affected versions: [< 1.12.0]" in axios["description"]
    assert "Below the threshold" not in axios["description"]


def test_a_library_without_advisories_at_the_threshold_is_not_reported():
    output = results({"component": "jquery", "version": "3.4.1", "vulnerabilities": [advisory("medium", "XSS")]})
    assert library_findings(output, RetireJSSeverity.HIGH, "https://x.example/j.js", "https://x.example/") == []
    assert library_findings({"data": []}, RetireJSSeverity.LOW, "https://x.example/j.js", "https://x.example/") == []
