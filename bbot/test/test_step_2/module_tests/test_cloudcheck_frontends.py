from bbot.modules.internal.cloudcheck import frontend_cname_evidence


def test_managed_frontend_cname_evidence():
    assert frontend_cname_evidence(["dualstack.app-123.elb.eu-west-1.amazonaws.com"]) == ("load_balancer", "aws")
    assert frontend_cname_evidence(["edge.example.akamaiedge.net."]) == ("cdn", "akamai")
    assert frontend_cname_evidence(["site.azurefd.net"]) == ("cdn", "azure")
    assert frontend_cname_evidence(["evil-elb.eu-west-1.amazonaws.com.attacker.example"]) is None
    assert frontend_cname_evidence(["instance.eu-west-1.compute.amazonaws.com"]) is None
