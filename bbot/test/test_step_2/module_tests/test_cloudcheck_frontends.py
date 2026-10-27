from bbot.modules.internal.cloudcheck import cloud_ip_metadata, frontend_cname_evidence


def test_managed_frontend_cname_evidence():
    assert frontend_cname_evidence(["dualstack.app-123.elb.eu-west-1.amazonaws.com"])[:2] == ("load_balancer", "aws")
    assert frontend_cname_evidence(["dualstack.app-123.eu-west-1.elb.amazonaws.com"])[:2] == ("load_balancer", "aws")
    assert frontend_cname_evidence(["edge.example.akamaiedge.net."])[:2] == ("cdn", "akamai")
    assert frontend_cname_evidence(["site.azurefd.net"])[:2] == ("cdn", "azure")
    assert frontend_cname_evidence(["wp.wpenginepowered.com"])[:2] == ("proxy", "wpengine")
    assert frontend_cname_evidence(["tenant.hosting.gitbook.io"])[:2] == ("proxy", "gitbook")
    assert frontend_cname_evidence(["evil-elb.eu-west-1.amazonaws.com.attacker.example"]) is None
    assert frontend_cname_evidence(["instance.eu-west-1.compute.amazonaws.com"]) is None


def test_provider_tags_preserve_frontend_classification():
    assert cloud_ip_metadata("104.16.1.1", "cloudflare", ["waf"])["isCdn"] is True
    assert cloud_ip_metadata("185.199.108.153", "github", ["cdn"])["isCdn"] is False
    assert cloud_ip_metadata("185.199.108.153", "github", ["cdn"], ("proxy", "github"))["isFrontedProxy"] is True
    assert cloud_ip_metadata("54.1.2.3", "amazon", ["cloud"])["isFrontedProxy"] is False
    assert cloud_ip_metadata("54.1.2.3", "amazon", ["cloud"])["isLoadBalancer"] is False
    assert cloud_ip_metadata("54.1.2.3", "amazon", ["cloud"])["isCdn"] is False
    assert cloud_ip_metadata("54.1.2.3", "amazon", ["cloud"], ("api_gateway", "aws", "HTTP answer header x-amzn-errortype"))[
        "isApiGateway"] is True


def test_shared_platform_provider_ranges_are_fronted_proxies():
    data = cloud_ip_metadata("13.110.1.1", "salesforce", ["cloud"])
    assert data["isFrontedProxy"] is True and data["providerType"] == "proxy"
    gateway = cloud_ip_metadata("54.1.2.3", "amazon", ["cloud"], ("api_gateway", "aws", "HTTP answer header x-amzn-errortype"))
    assert gateway["providerType"] == "api_gateway" and gateway["isFrontedProxy"] is True
    assert gateway["frontendEvidence"] == "HTTP answer header x-amzn-errortype: api_gateway (aws)"
