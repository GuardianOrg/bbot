from types import SimpleNamespace

from bbot.modules.subzy import subzy


def test_subzy_recognizes_claimed_gitbook_site_response():
    response = SimpleNamespace(
        status_code=200,
        headers={
            "X-GitBook-Route-Site": "lab.example.com/",
            "X-GitBook-Target": "site",
        },
    )

    assert subzy.is_claimed_provider_response(response) is True


def test_subzy_does_not_suppress_unclaimed_or_unrecognized_pages():
    unclaimed = SimpleNamespace(status_code=404, headers={"X-GitBook-Target": "site"})
    unrelated = SimpleNamespace(status_code=200, headers={"Server": "nginx"})

    assert subzy.is_claimed_provider_response(unclaimed) is False
    assert subzy.is_claimed_provider_response(unrelated) is False

def test_subzy_drops_body_match_when_cname_routes_to_another_provider():
    # demo.layerzero.network: Vercel serves Next.js's 404 text, which is also the Gemfury fingerprint.
    assert subzy.routes_to_other_provider(["bab5f6ed13b0a47e.vercel-dns-012.com"], ["furyns.com"]) is True

def test_subzy_keeps_matches_that_dns_does_not_contradict():
    assert subzy.routes_to_other_provider(["acme.furyns.com"], ["furyns.com"]) is False
    assert subzy.routes_to_other_provider(["edge.acme.net", "furyns.com"], ["furyns.com"]) is False
    # Apex A records to the provider, and fingerprints that declare no CNAME, cannot be contradicted.
    assert subzy.routes_to_other_provider([], ["furyns.com"]) is False
    assert subzy.routes_to_other_provider(["edge.acme.net"], []) is False
    assert subzy.routes_to_other_provider(["edge.acme.net"], None) is False
    # A suffix match needs a label boundary.
    assert subzy.routes_to_other_provider(["evilfuryns.com"], ["furyns.com"]) is True

def test_subzy_reads_service_cnames_from_fingerprints(tmp_path):
    fingerprints = tmp_path / "fingerprints.json"
    fingerprints.write_text(
        '[{"service": "Gemfury", "cname": ["FuryNS.com."]}, {"service": "Pantheon", "cname": []}, {"service": "X"}]'
    )

    assert subzy.load_service_cnames(fingerprints) == {"Gemfury": ["furyns.com"], "Pantheon": [], "X": []}
    assert subzy.load_service_cnames(tmp_path / "missing.json") == {}
