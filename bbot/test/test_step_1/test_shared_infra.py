import io
import json
from types import SimpleNamespace

import pytest

from bbot.core.helpers import shared_infra
from bbot.core.helpers.shared_infra import classify_hostname, classify_ip, classify_response, load_service_ranges
from bbot.modules.internal.cloudcheck import CloudCheck


@pytest.mark.parametrize(
    "host, expected",
    [
        ("dualstack.app-1.eu-west-1.elb.amazonaws.com", ("load_balancer", "aws")),
        ("app-1.elb.cn-north-1.amazonaws.com.cn", ("load_balancer", "aws")),
        ("abc123.execute-api.us-east-1.amazonaws.com.", ("api_gateway", "aws")),
        ("abc.lambda-url.eu-west-1.on.aws", ("api_gateway", "aws")),
        ("bucket.s3.eu-west-1.amazonaws.com", ("proxy", "aws")),
        ("a1.awsglobalaccelerator.com", ("load_balancer", "aws")),
        ("d111.cloudfront.net", ("cdn", "cloudfront")),
        ("www.example.com.edgekey.net", ("cdn", "akamai")),
        ("site.azurefd.net", ("cdn", "azure")),
        ("api.azure-api.net", ("api_gateway", "azure")),
        ("app.azurewebsites.net", ("proxy", "azure")),
        ("cname.vercel-dns.com", ("proxy", "vercel")),
        ("go.pardot.com", ("proxy", "salesforce")),
        ("svc-abc.a.run.app", ("proxy", "google")),
    ],
)
def test_shared_frontend_aliases(host, expected):
    assert classify_hostname(host) == expected


@pytest.mark.parametrize(
    "host",
    [
        "ec2-54-1-2-3.eu-west-1.compute.amazonaws.com",
        "vm.westeurope.cloudapp.azure.com",
        "3.2.1.54.bc.googleusercontent.com",
        "evil-elb.eu-west-1.amazonaws.com.attacker.example",
        "env.eu-west-1.elasticbeanstalk.com",
        "app.example.com",
    ],
)
def test_dedicated_machines_are_not_shared_frontends(host):
    assert classify_hostname(host) is None


def test_published_edge_ranges():
    assert classify_ip("76.76.21.21")[:2] == ("proxy", "vercel")
    assert classify_ip("104.16.1.1")[:2] == ("cdn", "cloudflare")
    assert classify_ip("2606:4700::6810:1")[:2] == ("cdn", "cloudflare")
    assert classify_ip("185.199.108.153")[:2] == ("proxy", "github")
    assert classify_ip("54.1.2.3") is None
    assert classify_ip("not-an-ip") is None


def test_service_ranges_keep_cloud_customer_blocks_out():
    feeds = {
        shared_infra.AWS_RANGES_URL: {
            "prefixes": [{"ip_prefix": "3.5.0.0/16", "service": "S3"}, {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
                         {"ip_prefix": "54.0.0.0/8", "service": "EC2"}, {"ip_prefix": "52.0.0.0/8", "service": "AMAZON"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"}],
        },
        shared_infra.GOOGLE_RANGES_URL: {"prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv4Prefix": "34.0.0.0/8"}]},
        shared_infra.GOOGLE_CLOUD_RANGES_URL: {"prefixes": [{"ipv4Prefix": "34.64.0.0/10"}]},
    }
    ranges = load_service_ranges(opener=lambda url, timeout: io.StringIO(json.dumps(feeds[url])))
    assert classify_ip("13.32.1.1", ranges)[:2] == ("cdn", "cloudfront")
    assert classify_ip("2600:9000::1", ranges)[:2] == ("cdn", "cloudfront")
    assert classify_ip("3.5.1.1", ranges)[:2] == ("proxy", "aws")
    assert classify_ip("8.8.8.8", ranges)[:2] == ("proxy", "google")
    # EC2, the AMAZON superset and Google Cloud customer blocks hold customer machines.
    assert classify_ip("54.1.2.3", ranges) is None
    assert classify_ip("52.1.2.3", ranges) is None
    assert classify_ip("34.70.1.1", ranges) is None


def test_failed_range_download_degrades_to_static_ranges():
    def offline(url, timeout):
        raise OSError("offline")

    assert len(load_service_ranges(opener=offline)) == 0


@pytest.mark.parametrize(
    "response, expected",
    [
        ({"webserver": "awselb/2.0", "status_code": 503}, ("load_balancer", "aws")),
        ({"header": {"set_cookie": "AWSALB=abc; Path=/"}}, ("load_balancer", "aws")),
        ({"header": {"x_amzn_errortype": "ForbiddenException", "x_amzn_requestid": "1"},
          "body": '{"message":"Forbidden"}'}, ("api_gateway", "aws")),
        ({"body": '{"message":"Missing Authentication Token"}'}, ("api_gateway", "aws")),
        ({"tls": {"subject_cn": "*.execute-api.eu-west-1.amazonaws.com"}}, ("api_gateway", "aws")),
        ({"raw_header": "HTTP/1.1 403 Forbidden\r\nServer: CloudFront\r\nX-Amz-Cf-Id: abc\r\n"}, ("cdn", "cloudfront")),
        ({"webserver": "cloudflare", "body": "error code: 1003"}, ("cdn", "cloudflare")),
        ({"webserver": "AkamaiGHost", "body": "Reference&#32;&#35;18.1"}, ("cdn", "akamai")),
        ({"header": {"x_served_by": "cache-mad2200-MAD"}, "body": "Fastly error: unknown domain"}, ("cdn", "fastly")),
        ({"webserver": "Microsoft-Azure-Application-Gateway/v2"}, ("load_balancer", "azure")),
        ({"header": {"via": "1.1 google"}}, ("load_balancer", "google")),
        ({"webserver": "Vercel", "header": {"x_vercel_id": "fra1::x"}}, ("proxy", "vercel")),
        ({"webserver": "Netlify", "header": {"x_nf_request_id": "01H"}}, ("proxy", "netlify")),
        ({"header": {"via": "1.1 vegur"}}, ("proxy", "heroku")),
        ({"header": {"x_iinfo": "1-2-3"}}, ("waf", "imperva")),
    ],
)
def test_shared_frontend_answers(response, expected):
    assert classify_response(response)[:2] == expected


@pytest.mark.parametrize(
    "response",
    [
        {"webserver": "nginx/1.24.0", "header": {"x_request_id": "abc"}, "body": "<html>Welcome</html>"},
        {"webserver": "Express", "body": '{"message":"Not Found"}'},
        {"webserver": "Apache/2.4.58 (Ubuntu)", "tls": {"issuer_org": ["Amazon"], "subject_cn": "app.example.com"}},
        {"webserver": "Microsoft-IIS/10.0"},
        "not a response",
    ],
)
def test_dedicated_server_answers_are_not_shared_frontends(response):
    assert classify_response(response) is None


@pytest.mark.asyncio
async def test_discovered_answers_flag_their_addresses_without_full_cloud_tagging():
    class Module(CloudCheck):
        helpers = None

    module = Module.__new__(Module)
    module.scope_input_only = True
    module.service_ranges = None
    module.probe_cloud_frontends = False
    emitted = []

    async def lookup(host):
        return [{"name": "Amazon", "tags": ["cloud"]}]

    async def emit_event(data, event_type, **kwargs):
        emitted.append((event_type, data))

    module.helpers = SimpleNamespace(is_ip=lambda host: host[0].isdigit(), cloudcheck=SimpleNamespace(lookup=lookup))
    module.emit_event = emit_event
    tags = set()
    event = SimpleNamespace(
        type="HTTP_RESPONSE", tags=tags, host_original="api.example.com", resolved_hosts={"54.1.2.3"},
        dns_children={}, data={"url": "https://api.example.com/", "header": {"x_amzn_errortype": "ForbiddenException"}},
        add_tag=tags.add, get_parents=lambda: [],
    )
    await module.handle_event(event)
    assert "shared-frontend" in tags
    assert emitted[0][0] == "GEOLOCATION"
    assert emitted[0][1]["ip"] == "54.1.2.3"
    assert emitted[0][1]["isApiGateway"] is True and emitted[0][1]["isFrontedProxy"] is True

    emitted.clear()
    tags.clear()
    event.data = {"url": "https://api.example.com/", "webserver": "nginx"}
    await module.handle_event(event)
    assert emitted == [] and tags == set()


def probe_module(answers, probe=True, provider_tags=("cloud",)):
    """CloudCheck in Naxus/Sentry mode whose web requests return ``answers[url]`` (an httpx.Response or None)."""
    import httpx

    class Module(CloudCheck):
        helpers = None

    module = Module.__new__(Module)
    module.scope_input_only = True
    module.service_ranges = None
    module.probe_cloud_frontends = probe
    module.probe_timeout = 1
    module._probe_verdicts, module._probe_tasks = {}, {}
    module.requests, module.emitted = [], []

    async def lookup(host):
        return [{"name": "Amazon", "tags": list(provider_tags)}]

    async def request(url, **kwargs):
        module.requests.append(url)
        answer = answers.get(url)
        return httpx.Response(answer[0], headers=answer[1], content=answer[2]) if answer else None

    async def emit_event(data, event_type, **kwargs):
        module.emitted.append((event_type, data))

    module.helpers = SimpleNamespace(is_ip=lambda host: host[0].isdigit(), request=request,
                                     cloudcheck=SimpleNamespace(lookup=lookup))
    module.emit_event = emit_event
    return module


def ip_event(ip, ptr=()):
    tags = set()
    return SimpleNamespace(type="IP_ADDRESS", tags=tags, host_original=ip, resolved_hosts=set(),
                           dns_children={"PTR": set(ptr)} if ptr else {}, data=ip, add_tag=tags.add,
                           get_parents=lambda: [])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answers, kind",
    [
        ({"https://3.81.181.36/": (503, [("server", "awselb/2.0")], b"<html>503</html>")}, "isLoadBalancer"),
        ({"http://3.81.181.36/": (301, [("Server", "awselb/2.0")], b"")}, "isLoadBalancer"),
        ({"https://3.81.181.36/": (403, [("x-amzn-ErrorType", "ForbiddenException"), ("x-amz-apigw-id", "F5y=")],
                                   b'{"message":"Forbidden"}')}, "isApiGateway"),
    ],
)
async def test_bare_cloud_address_probe_flags_frontends_before_port_scans(answers, kind):
    module = probe_module(answers)
    event = ip_event("3.81.181.36")
    await module.handle_event(event)
    assert "shared-frontend" in event.tags
    assert module.emitted[0][0] == "GEOLOCATION" and module.emitted[0][1][kind] is True
    assert module.emitted[0][1]["frontendEvidence"].startswith("HTTP probe of http")
    assert sorted(module.requests) == ["http://3.81.181.36/", "https://3.81.181.36/"]

    # The verdict is cached: the same address on another event is not requested again.
    await module.handle_event(ip_event("3.81.181.36"))
    assert len(module.requests) == 2


@pytest.mark.asyncio
async def test_dedicated_cloud_server_answering_as_itself_is_not_flagged():
    module = probe_module({"https://3.140.158.16/": (200, [("server", "nginx/1.24.0")], b"<html>app</html>")})
    event = ip_event("3.140.158.16")
    await module.handle_event(event)
    assert module.emitted == [] and event.tags == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("probe, provider_tags", [(False, ("cloud",)), (True, ())])
async def test_probe_is_opt_in_and_limited_to_general_cloud_ranges(probe, provider_tags):
    module = probe_module({"https://3.81.181.36/": (503, [("server", "awselb/2.0")], b"")}, probe, provider_tags)
    await module.handle_event(ip_event("3.81.181.36"))
    assert module.requests == [] and module.emitted == []


@pytest.mark.asyncio
async def test_edge_ptr_names_flag_without_requests_but_instance_ptrs_do_not():
    module = probe_module({})
    event = ip_event("13.32.1.1", ptr=["server-13-32-1-1.mad50.r.cloudfront.net"])
    await module.handle_event(event)
    assert module.emitted[0][1]["isCdn"] is True and module.requests == []
    assert module.emitted[0][1]["frontendEvidence"].startswith("PTR server-13-32-1-1")

    module = probe_module({}, probe=False)
    event = ip_event("54.1.2.3", ptr=["ec2-54-1-2-3.compute-1.amazonaws.com"])
    await module.handle_event(event)
    assert module.emitted == [] and event.tags == set()


def test_cloudcheck_cdn_tags_inside_aws_need_a_published_cloudfront_block():
    import ipaddress

    module = probe_module({})
    module.service_ranges = shared_infra.NetworkIndex(
        {ipaddress.ip_network("3.167.0.0/16"): ("cdn", "cloudfront")}, sources={"aws"})
    found = [("amazon", ["cloud"]), ("cloudfront", ["cdn"]), ("quiccloud", ["cdn"]), ("github", ["cdn"])]
    # A dedicated EC2 address that cloudcheck's CDN lists also claim keeps only its cloud provider, so it is probed.
    assert module.trusted_providers("3.140.158.16", found) == [("amazon", ["cloud"])]
    assert module.trusted_providers("3.167.226.150", found) == [("amazon", ["cloud"]), ("cloudfront", ["cdn"])]
    # Outside AWS, or without AWS's published list, cloudcheck's tags stand.
    assert module.trusted_providers("151.101.1.1", [("fastly", ["cdn"])]) == [("fastly", ["cdn"])]
    module.service_ranges = shared_infra.NetworkIndex({})
    assert module.trusted_providers("3.140.158.16", found) == found
