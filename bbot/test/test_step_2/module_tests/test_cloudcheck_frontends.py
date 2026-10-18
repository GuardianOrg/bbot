from bbot.modules.internal.cloudcheck import cloud_ip_metadata, frontend_cname_evidence


def test_managed_frontend_cname_evidence():
    assert frontend_cname_evidence(["dualstack.app-123.elb.eu-west-1.amazonaws.com"]) == ("load_balancer", "aws")
    assert frontend_cname_evidence(["dualstack.app-123.eu-west-1.elb.amazonaws.com"]) == ("load_balancer", "aws")
    assert frontend_cname_evidence(["edge.example.akamaiedge.net."]) == ("cdn", "akamai")
    assert frontend_cname_evidence(["site.azurefd.net"]) == ("cdn", "azure")
    assert frontend_cname_evidence(["wp.wpenginepowered.com"]) == ("proxy", "wpengine")
    assert frontend_cname_evidence(["tenant.hosting.gitbook.io"]) == ("proxy", "gitbook")
    assert frontend_cname_evidence(["evil-elb.eu-west-1.amazonaws.com.attacker.example"]) is None
    assert frontend_cname_evidence(["instance.eu-west-1.compute.amazonaws.com"]) is None


def test_provider_tags_are_interpreted_as_positive_evidence_only():
    assert cloud_ip_metadata("104.16.1.1", "cloudflare", ["waf"])["isCdn"] is True
    assert cloud_ip_metadata("185.199.108.153", "github", ["cdn"]).get("isCdn") is None
    assert cloud_ip_metadata("185.199.108.153", "github", ["cdn"], ("proxy", "github"))["isFrontedProxy"] is True
    assert cloud_ip_metadata("54.1.2.3", "amazon", ["cloud"]).get("isFrontedProxy") is None
