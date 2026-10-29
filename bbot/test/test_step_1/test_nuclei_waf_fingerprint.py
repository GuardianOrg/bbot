from bbot.modules.nuclei import nuclei


def test_vendor_waf_fingerprint_is_metadata():
    result = {
        "severity": "INFO",
        "template": "cloudflare",
        "tags": ["waf", "fuzz", "fuzzing", "vuln"],
        "description": "A web application firewall was detected.",
        "name": "cloudflare",
    }

    assert nuclei.is_waf_detection_result(result)
    assert nuclei.is_waf_detection_result({**result, "tags": "waf,fuzz,fuzzing,vuln"})
    assert nuclei.is_waf_detection_result({**result, "template": "waf-detect"})
    assert not nuclei.is_waf_detection_result({**result, "severity": "HIGH"})
    assert not nuclei.is_waf_detection_result({**result, "description": "A WAF bypass was confirmed."})
    assert not nuclei.is_waf_detection_result({**result, "tags": ["fuzz", "vuln"]})
