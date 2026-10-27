"""Recognise CDNs, WAFs, load balancers, API gateways and shared hosting platforms.

An address that one of these services answers on is not a server of the scanned organisation: port scans
reach the provider's edge and every customer behind it. A dedicated cloud instance (EC2, a VM, a droplet) is.

Three independent kinds of evidence are checked, because none of them is enough alone:

* DNS aliases: a CNAME to ``*.cloudfront.net`` or ``*.execute-api.<region>.amazonaws.com`` names the service.
* Published address blocks: providers that publish dedicated edge ranges (Cloudflare, Vercel, AWS CloudFront
  and API Gateway, Google front ends...). General cloud ranges never count, since customer instances share them.
* HTTP answers: AWS load balancers and regional API gateways use ordinary EC2 addresses, so only their own
  answer (``Server: awselb/2.0``, ``x-amzn-ErrorType``...) or their default TLS certificate tells them apart.
  cloudcheck can request a bare cloud address before port scanning (``probe_cloud_frontends``): with no
  matching Host or SNI, these services answer with their own default response. Reverse DNS does not help
  here, because their PTR is the same ``ec2-*.compute.amazonaws.com`` name as a dedicated instance's; it only
  names edge providers such as CloudFront or Akamai, and is checked as an alias.

BBOT is the only place that decides this. Consumers (naxus, Sentry) trust the flags BBOT emits on GEOLOCATION.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.request

# Ranking used when several pieces of evidence disagree: the most specific frontend kind wins.
KIND_PRIORITY = {"cdn": 5, "waf": 4, "api_gateway": 3, "load_balancer": 2, "proxy": 1}

# DNS alias suffix: (kind, provider). "proxy" is a shared hosting, PaaS or SaaS platform.
CNAME_SUFFIXES = {
    # CDNs
    "cloudfront.net": ("cdn", "cloudfront"),
    "cdn.cloudflare.net": ("cdn", "cloudflare"),
    "akamaiedge.net": ("cdn", "akamai"),
    "akamaiedge-staging.net": ("cdn", "akamai"),
    "edgekey.net": ("cdn", "akamai"),
    "edgekey-staging.net": ("cdn", "akamai"),
    "edgesuite.net": ("cdn", "akamai"),
    "edgesuite-staging.net": ("cdn", "akamai"),
    "akamaized.net": ("cdn", "akamai"),
    "akamaihd.net": ("cdn", "akamai"),
    "akamai.net": ("cdn", "akamai"),
    "akamaitechnologies.com": ("cdn", "akamai"),
    "akadns.net": ("cdn", "akamai"),
    "fastly.net": ("cdn", "fastly"),
    "fastlylb.net": ("cdn", "fastly"),
    "azureedge.net": ("cdn", "azure"),
    "azurefd.net": ("cdn", "azure"),
    "edgecastcdn.net": ("cdn", "edgio"),
    "edgio.net": ("cdn", "edgio"),
    "llnwd.net": ("cdn", "edgio"),
    "llnw.net": ("cdn", "edgio"),
    "systemcdn.net": ("cdn", "edgio"),
    "stackpathdns.com": ("cdn", "stackpath"),
    "stackpathcdn.com": ("cdn", "stackpath"),
    "hwcdn.net": ("cdn", "stackpath"),
    "b-cdn.net": ("cdn", "bunnycdn"),
    "cdn77.org": ("cdn", "cdn77"),
    "cdn77.net": ("cdn", "cdn77"),
    "kxcdn.com": ("cdn", "keycdn"),
    "gcdn.co": ("cdn", "gcore"),
    "cachefly.net": ("cdn", "cachefly"),
    "cdnetworks.net": ("cdn", "cdnetworks"),
    "panthercdn.com": ("cdn", "cdnetworks"),
    "alikunlun.com": ("cdn", "alibaba"),
    "alikunlun.net": ("cdn", "alibaba"),
    "kunlunca.com": ("cdn", "alibaba"),
    "w.kunlungr.com": ("cdn", "alibaba"),
    "cdn.dnsv1.com": ("cdn", "tencent"),
    "dsa.dnsv1.com": ("cdn", "tencent"),
    "cdnhwc1.com": ("cdn", "huawei"),
    "cdnhwc2.com": ("cdn", "huawei"),
    "bdydns.com": ("cdn", "baidu"),
    # WAFs and DDoS protection
    "impervadns.net": ("waf", "imperva"),
    "incapdns.net": ("waf", "imperva"),
    "sucuri.net": ("waf", "sucuri"),
    "sucuridns.com": ("waf", "sucuri"),
    "ddos-guard.net": ("waf", "ddos-guard"),
    "qrator.net": ("waf", "qrator"),
    "stormwall.network": ("waf", "stormwall"),
    # Load balancers and traffic managers of the clouds
    "awsglobalaccelerator.com": ("load_balancer", "aws"),
    "cloudapp.azure.com": None,  # an Azure VM's own public address: never shared
    "trafficmanager.net": ("load_balancer", "azure"),
    "oraclecloud.com": None,
    # API gateways and function endpoints
    "azure-api.net": ("api_gateway", "azure"),
    "apigee.net": ("api_gateway", "google"),
    "cloudfunctions.net": ("api_gateway", "google"),
    "a.run.app": ("proxy", "google"),
    "run.app": ("proxy", "google"),
    "appspot.com": ("proxy", "google"),
    "web.app": ("proxy", "firebase"),
    "firebaseapp.com": ("proxy", "firebase"),
    "ghs.googlehosted.com": ("proxy", "google"),
    "googlehosted.com": ("proxy", "google"),
    "awsapprunner.com": ("proxy", "aws"),
    "amplifyapp.com": ("cdn", "cloudfront"),
    # Platforms hosting many customers behind one edge
    "azurewebsites.net": ("proxy", "azure"),
    "azurestaticapps.net": ("proxy", "azure"),
    "azurecontainerapps.io": ("proxy", "azure"),
    "blob.core.windows.net": ("proxy", "azure"),
    "web.core.windows.net": ("proxy", "azure"),
    "vercel-dns.com": ("proxy", "vercel"),
    "vercel-dns-016.com": ("proxy", "vercel"),
    "vercel.app": ("proxy", "vercel"),
    "now.sh": ("proxy", "vercel"),
    "netlify.app": ("proxy", "netlify"),
    "netlify.com": ("proxy", "netlify"),
    "netlifyglobalcdn.com": ("proxy", "netlify"),
    "herokuapp.com": ("proxy", "heroku"),
    "herokudns.com": ("proxy", "heroku"),
    "herokussl.com": ("proxy", "heroku"),
    "onrender.com": ("proxy", "render"),
    "fly.dev": ("proxy", "fly"),
    "edgeapp.net": ("proxy", "fly"),
    "up.railway.app": ("proxy", "railway"),
    "ondigitalocean.app": ("proxy", "digitalocean"),
    "pages.dev": ("proxy", "cloudflare"),
    "workers.dev": ("proxy", "cloudflare"),
    "github.io": ("proxy", "github"),
    "gitlab.io": ("proxy", "gitlab"),
    "wpenginepowered.com": ("proxy", "wpengine"),
    "wpengine.com": ("proxy", "wpengine"),
    "kinsta.cloud": ("proxy", "kinsta"),
    "pantheonsite.io": ("proxy", "pantheon"),
    "pantheon.io": ("proxy", "pantheon"),
    "hosting.gitbook.io": ("proxy", "gitbook"),
    "gitbook.io": ("proxy", "gitbook"),
    "readthedocs.io": ("proxy", "readthedocs"),
    "readme.io": ("proxy", "readme"),
    "webflow.io": ("proxy", "webflow"),
    "proxy-ssl.webflow.com": ("proxy", "webflow"),
    "webflow.com": ("proxy", "webflow"),
    "squarespace.com": ("proxy", "squarespace"),
    "wixdns.net": ("proxy", "wix"),
    "myshopify.com": ("proxy", "shopify"),
    "shopify.com": ("proxy", "shopify"),
    "bigcommerce.com": ("proxy", "bigcommerce"),
    "ghost.io": ("proxy", "ghost"),
    "hubspot.net": ("proxy", "hubspot"),
    "hs-sites.com": ("proxy", "hubspot"),
    "hubspotpagebuilder.com": ("proxy", "hubspot"),
    "pardot.com": ("proxy", "salesforce"),
    "force.com": ("proxy", "salesforce"),
    "salesforce-sites.com": ("proxy", "salesforce"),
    "my.salesforce.com": ("proxy", "salesforce"),
    "mktoweb.com": ("proxy", "marketo"),
    "mktossl.com": ("proxy", "marketo"),
    "unbounce.com": ("proxy", "unbounce"),
    "unbouncepages.com": ("proxy", "unbounce"),
    "instapage.com": ("proxy", "instapage"),
    "zendesk.com": ("proxy", "zendesk"),
    "freshdesk.com": ("proxy", "freshworks"),
    "helpscoutdocs.com": ("proxy", "helpscout"),
    "intercom.help": ("proxy", "intercom"),
    "custom.intercom.help": ("proxy", "intercom"),
    "atlassian.net": ("proxy", "atlassian"),
    "statuspage.io": ("proxy", "atlassian"),
    "betteruptime.com": ("proxy", "betteruptime"),
    "status.io": ("proxy", "statusio"),
    "teamtailor.com": ("proxy", "teamtailor"),
    "greenhouse.io": ("proxy", "greenhouse"),
    "lever.co": ("proxy", "lever"),
    "workable.com": ("proxy", "workable"),
    "ashbyhq.com": ("proxy", "ashby"),
    "mailchimpsites.com": ("proxy", "mailchimp"),
    "sendgrid.net": ("proxy", "sendgrid"),
    "mailgun.org": ("proxy", "mailgun"),
    "outlook.com": ("proxy", "microsoft"),
    "office.com": ("proxy", "microsoft"),
    "microsoftonline.com": ("proxy", "microsoft"),
    "sharepoint.com": ("proxy", "microsoft"),
    "microsoft.com": ("proxy", "microsoft"),
    "windows.net": ("proxy", "microsoft"),
    "google.com": ("proxy", "google"),
    "ghs.google.com": ("proxy", "google"),
    "googlemail.com": ("proxy", "google"),
    "fusionauth.io": ("proxy", "fusionauth"),
    "auth0.com": ("proxy", "auth0"),
    "okta.com": ("proxy", "okta"),
    "oktapreview.com": ("proxy", "okta"),
    "onelogin.com": ("proxy", "onelogin"),
    "frontegg.com": ("proxy", "frontegg"),
    "clerk.services": ("proxy", "clerk"),
    "zohohost.com": ("proxy", "zoho"),
    "manageengine.com": ("proxy", "zoho"),
    "sopro.io": ("proxy", "sopro"),
    "carrd.co": ("proxy", "carrd"),
    "framer.app": ("proxy", "framer"),
    "framer.website": ("proxy", "framer"),
    "notion.site": ("proxy", "notion"),
    "super.site": ("proxy", "super"),
    "strikinglydns.com": ("proxy", "strikingly"),
    "weebly.com": ("proxy", "weebly"),
    "wordpress.com": ("proxy", "wordpress.com"),
    "wpcomstaging.com": ("proxy", "wordpress.com"),
    "tumblr.com": ("proxy", "tumblr"),
    "medium.com": ("proxy", "medium"),
    "substack.com": ("proxy", "substack"),
    "cargo.site": ("proxy", "cargo"),
    "surge.sh": ("proxy", "surge"),
    "smartling.com": ("proxy", "smartling"),
    "weglot.com": ("proxy", "weglot"),
}
# Cloud hostnames whose provider part is not a fixed suffix.
AWS_HOSTNAMES = (
    (re.compile(r"(?:^|\.)(?:[a-z0-9-]+\.elb|elb\.[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$"), ("load_balancer", "aws")),
    (re.compile(r"(?:^|\.)execute-api\.[a-z0-9-]+\.amazonaws\.com$"), ("api_gateway", "aws")),
    (re.compile(r"(?:^|\.)lambda-url\.[a-z0-9-]+\.on\.aws$"), ("api_gateway", "aws")),
    (re.compile(r"(?:^|\.)appsync-api\.[a-z0-9-]+\.amazonaws\.com$"), ("api_gateway", "aws")),
    (re.compile(r"(?:^|\.)s3[.-](?:website[.-])?(?:[a-z0-9-]+\.)?amazonaws\.com$"), ("proxy", "aws")),
    (re.compile(r"(?:^|\.)auth\.[a-z0-9-]+\.amazoncognito\.com$"), ("proxy", "aws")),
    (re.compile(r"(?:^|\.)[a-z0-9-]+\.[a-z0-9-]+\.elasticbeanstalk\.com$"), None),  # ELB or a dedicated EIP
)

# Published address blocks of shared edges, for providers that cloudcheck does not cover or tags as general cloud.
NETWORKS = {
    # https://www.cloudflare.com/ips/
    **{network: ("cdn", "cloudflare") for network in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32")},
    # Vercel's edge (apex A records and cname.vercel-dns.com).
    **{network: ("proxy", "vercel") for network in (
        "76.76.21.0/24", "66.33.60.0/24", "216.150.1.0/24", "216.150.16.0/24", "216.198.79.0/24",
        "64.29.17.0/24")},
    # GitHub Pages; the rest of GitHub's ranges serve its own API and Git endpoints.
    "185.199.108.0/22": ("proxy", "github"),
    "2606:50c0:8000::/46": ("proxy", "github"),
    # Apex addresses that site builders and PaaS ask customers to point at.
    "75.2.60.5/32": ("proxy", "netlify"),
    "75.2.70.75/32": ("proxy", "webflow"),
    "99.83.190.102/32": ("proxy", "webflow"),
    "198.202.211.1/32": ("proxy", "webflow"),
    "216.24.57.0/24": ("proxy", "render"),
    "23.227.38.0/24": ("proxy", "shopify"),
    "198.185.159.0/24": ("proxy", "squarespace"),
    "198.49.23.0/24": ("proxy", "squarespace"),
    "185.230.63.0/24": ("proxy", "wix"),
    "23.236.62.147/32": ("proxy", "wix"),
    "199.36.158.100/32": ("proxy", "firebase"),
    "35.185.44.232/32": ("proxy", "gitlab"),
    "23.185.0.0/24": ("proxy", "pantheon"),
    "66.241.124.0/24": ("proxy", "fly"),
    "66.241.125.0/24": ("proxy", "fly"),
}
NETWORKS = {ipaddress.ip_network(network): label for network, label in NETWORKS.items() if label}

# AWS services in ip-ranges.json whose addresses are a provider edge, never a customer's instance.
AWS_SHARED_SERVICES = {
    "CLOUDFRONT": ("cdn", "cloudfront"), "API_GATEWAY": ("api_gateway", "aws"),
    "GLOBALACCELERATOR": ("load_balancer", "aws"), "S3": ("proxy", "aws"), "DYNAMODB": ("proxy", "aws"),
    "ROUTE53": ("proxy", "aws"), "ROUTE53_HEALTHCHECKS": ("proxy", "aws"),
    "ROUTE53_HEALTHCHECKS_PUBLISHING": ("proxy", "aws"), "ROUTE53_RESOLVER": ("proxy", "aws"),
    "WORKSPACES_GATEWAYS": ("proxy", "aws"), "AMAZON_CONNECT": ("proxy", "aws"),
    "CHIME_VOICECONNECTOR": ("proxy", "aws"), "CHIME_MEETINGS": ("proxy", "aws"),
    "KINESIS_VIDEO_STREAMS": ("proxy", "aws"), "IVS_REALTIME": ("proxy", "aws"), "IVS_LOW_LATENCY": ("proxy", "aws"),
    "MEDIA_PACKAGE_V2": ("proxy", "aws"), "AMAZON_APPFLOW": ("proxy", "aws"), "EC2_INSTANCE_CONNECT": ("proxy", "aws"),
    "CLOUD9": ("proxy", "aws"), "CODEBUILD": ("proxy", "aws"), "EBS": ("proxy", "aws"), "EFS": ("proxy", "aws"),
    "AURORA_DSQL": ("proxy", "aws"),
}
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
# Google's own services minus the addresses it leases to Cloud customers are Google front ends.
GOOGLE_RANGES_URL = "https://www.gstatic.com/ipranges/goog.json"
GOOGLE_CLOUD_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"

# Response evidence. Header names are compared lowercase with "_" turned into "-" (httpx's JSON form).
SERVER_PREFIXES = (
    ("awselb", ("load_balancer", "aws")),
    ("amazons3", ("proxy", "aws")),
    ("cloudfront", ("cdn", "cloudfront")),
    ("cloudflare", ("cdn", "cloudflare")),
    ("akamaighost", ("cdn", "akamai")),
    ("akamainetstorage", ("cdn", "akamai")),
    ("akamai", ("cdn", "akamai")),
    ("ecacc", ("cdn", "edgio")),
    ("ecs (", ("cdn", "edgio")),
    ("ecd (", ("cdn", "edgio")),
    ("bunnycdn", ("cdn", "bunnycdn")),
    ("cdn77", ("cdn", "cdn77")),
    ("keycdn", ("cdn", "keycdn")),
    ("cachefly", ("cdn", "cachefly")),
    ("ddos-guard", ("waf", "ddos-guard")),
    ("qrator", ("waf", "qrator")),
    ("sucuri", ("waf", "sucuri")),
    ("microsoft-azure-application-gateway", ("load_balancer", "azure")),
    ("windows-azure-blob", ("proxy", "azure")),
    ("windows-azure-web", ("proxy", "azure")),
    ("google frontend", ("proxy", "google")),
    ("gws", ("proxy", "google")),
    ("gse", ("proxy", "google")),
    ("esf", ("proxy", "google")),
    ("sffe", ("proxy", "google")),
    ("uploadserver", ("proxy", "google")),
    ("vercel", ("proxy", "vercel")),
    ("netlify", ("proxy", "netlify")),
    ("github.com", ("proxy", "github")),
    ("gitlab pages", ("proxy", "gitlab")),
    ("fly/", ("proxy", "fly")),
    ("railway-edge", ("proxy", "railway")),
    ("heroku", ("proxy", "heroku")),
    ("squarespace", ("proxy", "squarespace")),
    ("pepyaka", ("proxy", "wix")),
    ("sfdcedge", ("proxy", "salesforce")),
    ("tencent-cos", ("proxy", "tencent")),
    ("aliyunoss", ("proxy", "alibaba")),
)
# Header name: evidence. The header proves the provider answered, whatever its value.
HEADERS = (
    ("x-amzn-errortype", ("api_gateway", "aws")),
    ("x-amz-apigw-id", ("api_gateway", "aws")),
    ("x-amzn-requestid", ("api_gateway", "aws")),
    ("x-amz-cf-id", ("cdn", "cloudfront")),
    ("x-amz-cf-pop", ("cdn", "cloudfront")),
    ("cf-ray", ("cdn", "cloudflare")),
    ("cf-mitigated", ("cdn", "cloudflare")),
    ("x-akamai-transformed", ("cdn", "akamai")),
    ("x-akamai-request-id", ("cdn", "akamai")),
    ("akamai-grn", ("cdn", "akamai")),
    ("x-fastly-request-id", ("cdn", "fastly")),
    ("fastly-debug-digest", ("cdn", "fastly")),
    ("x-azure-ref", ("cdn", "azure")),
    ("x-fd-healthprobe", ("cdn", "azure")),
    ("x-msedge-ref", ("cdn", "azure")),
    ("x-ec-custom-error", ("cdn", "edgio")),
    ("x-hw", ("cdn", "stackpath")),
    ("cdn-pullzone", ("cdn", "bunnycdn")),
    ("cdn-requestid", ("cdn", "bunnycdn")),
    ("x-77-nzt", ("cdn", "cdn77")),
    ("x-cdn77-pop", ("cdn", "cdn77")),
    ("x-nws-log-uuid", ("cdn", "tencent")),
    ("eagleid", ("cdn", "alibaba")),
    ("ali-swift-global-savetime", ("cdn", "alibaba")),
    ("x-iinfo", ("waf", "imperva")),
    ("x-sucuri-id", ("waf", "sucuri")),
    ("x-sucuri-cache", ("waf", "sucuri")),
    ("x-qrator", ("waf", "qrator")),
    ("x-ms-request-id", ("proxy", "azure")),
    ("x-ms-routing-name", ("proxy", "azure")),
    ("x-goog-generation", ("proxy", "google")),
    ("x-guploader-uploadid", ("proxy", "google")),
    ("x-cloud-trace-context", ("proxy", "google")),
    ("opc-request-id", ("proxy", "oracle")),
    ("x-vercel-id", ("proxy", "vercel")),
    ("x-vercel-cache", ("proxy", "vercel")),
    ("x-nf-request-id", ("proxy", "netlify")),
    ("x-github-request-id", ("proxy", "github")),
    ("fly-request-id", ("proxy", "fly")),
    ("x-railway-edge", ("proxy", "railway")),
    ("x-railway-request-id", ("proxy", "railway")),
    ("rndr-id", ("proxy", "render")),
    ("x-render-origin-server", ("proxy", "render")),
    ("x-pantheon-styx-hostname", ("proxy", "pantheon")),
    ("x-kinsta-cache", ("proxy", "kinsta")),
    ("wpe-backend", ("proxy", "wpengine")),
    ("x-shopid", ("proxy", "shopify")),
    ("x-shopify-stage", ("proxy", "shopify")),
    ("x-wix-request-id", ("proxy", "wix")),
    ("x-hs-hub-id", ("proxy", "hubspot")),
    ("x-hs-cf-cache-status", ("proxy", "hubspot")),
    ("x-zendesk-origin-server", ("proxy", "zendesk")),
    ("x-sfdc-request-id", ("proxy", "salesforce")),
    ("x-sfdc-edge-cache", ("proxy", "salesforce")),
    ("x-served-by-gitbook", ("proxy", "gitbook")),
)
# Header name: (value pattern, evidence).
HEADER_VALUES = (
    ("via", re.compile(r"cloudfront"), ("cdn", "cloudfront")),
    ("via", re.compile(r"\bvegur\b|heroku-router"), ("proxy", "heroku")),
    ("via", re.compile(r"^1\.1 google$|, ?1\.1 google$"), ("load_balancer", "google")),
    ("x-served-by", re.compile(r"\bcache-[a-z0-9-]+"), ("cdn", "fastly")),
    ("x-cache", re.compile(r"cloudfront"), ("cdn", "cloudfront")),
    ("x-cdn", re.compile(r"imperva|incapsula"), ("waf", "imperva")),
    ("x-powered-by", re.compile(r"wp engine"), ("proxy", "wpengine")),
    ("x-powered-by", re.compile(r"shopify"), ("proxy", "shopify")),
    ("x-azure-fdid", re.compile(r"."), ("cdn", "azure")),
    ("set-cookie", re.compile(r"\barraffinity(?:samesite)?="), ("proxy", "azure")),
    ("set-cookie", re.compile(r"\bincap_ses_|\bvisid_incap_"), ("waf", "imperva")),
    ("set-cookie", re.compile(r"\b__cf_bm=|\bcf_clearance="), ("cdn", "cloudflare")),
    ("set-cookie", re.compile(r"\bawsalb(?:cors|tg|tgcors)?="), ("load_balancer", "aws")),
    ("set-cookie", re.compile(r"\bawselb="), ("load_balancer", "aws")),
    ("set-cookie", re.compile(r"\bgclb="), ("load_balancer", "google")),
    ("set-cookie", re.compile(r"\bak_bmsc=|\bbm_sz=|\b_abck="), ("cdn", "akamai")),
)
# Default pages that an edge returns for a host it does not serve, as when it is reached by bare IP.
BODY_MARKERS = (
    (re.compile(r"error code: 100[0-9]|direct ip access not allowed|cloudflare ray id"), ("cdn", "cloudflare")),
    (re.compile(r"the request could not be satisfied.{0,400}cloudfront", re.S), ("cdn", "cloudfront")),
    (re.compile(r"\"message\"\s*:\s*\"missing authentication token\""), ("api_gateway", "aws")),
    (re.compile(r"<code>nosuchbucket</code>|<code>allaccessdisabled</code>"), ("proxy", "aws")),
    (re.compile(r"reference&#32;&#35;\d+\.|errors\.edgesuite\.net"), ("cdn", "akamai")),
    (re.compile(r"fastly error: unknown domain"), ("cdn", "fastly")),
    (re.compile(r"deployment_not_found|the deployment could not be found on vercel"), ("proxy", "vercel")),
    (re.compile(r"not found - request id: [0-9a-z-]{10,}"), ("proxy", "netlify")),
    (re.compile(r"there isn't a github pages site here"), ("proxy", "github")),
    (re.compile(r"herokucdn\.com/error-pages"), ("proxy", "heroku")),
    (re.compile(r"404 web site not found|the web app you have attempted to reach is not available|"
                r"error 404 - web app not found"), ("proxy", "azure")),
    (re.compile(r"our services aren't available right now"), ("cdn", "azure")),
    (re.compile(r"the requested url .{0,80} was not found on this server\. that(?:’|&#8217;|')s all we know", re.S),
     ("proxy", "google")),
    (re.compile(r"sorry, this shop is currently unavailable"), ("proxy", "shopify")),
    (re.compile(r"squarespace - (?:no such account|domain not claimed)"), ("proxy", "squarespace")),
    (re.compile(r"the gods are wise, but do not know of the site which you seek"), ("proxy", "pantheon")),
    (re.compile(r"incapsula incident id"), ("waf", "imperva")),
    (re.compile(r"sucuri website firewall"), ("waf", "sucuri")),
)


def _pick(matches):
    matches = [match for match in matches if match]
    return max(matches, key=lambda match: KIND_PRIORITY[match[0][0]]) if matches else None


def classify_hostname(host):
    """(kind, provider) for a DNS name that belongs to a shared frontend, else None."""
    host = str(host or "").lower().strip().rstrip(".")
    if not host:
        return None
    for pattern, label in AWS_HOSTNAMES:
        if pattern.search(host):
            return label
    # The longest matching suffix decides, so cloudapp.azure.com is not shadowed by a shorter rule.
    best = None
    for suffix, label in CNAME_SUFFIXES.items():
        if (host == suffix or host.endswith(f".{suffix}")) and (best is None or len(suffix) > len(best[0])):
            best = (suffix, label)
    return best[1] if best else None


def classify_hostnames(hosts):
    """Strongest (kind, provider, evidence) among DNS aliases, else None."""
    matches = [(label, f"DNS alias {str(host).lower().rstrip('.')}")
               for host in hosts for label in [classify_hostname(host)] if label]
    return _as_triple(_pick(matches))


def _as_triple(match):
    return (match[0][0], match[0][1], match[1]) if match else None


def load_service_ranges(timeout=15, opener=urllib.request.urlopen):
    """Index of the shared-edge blocks that AWS and Google publish. A failed download leaves its blocks out."""
    networks = {}
    loaded = set()
    try:
        with opener(AWS_RANGES_URL, timeout=timeout) as response:
            data = json.load(response)
        for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
            for prefix in data.get(key) or []:
                label = AWS_SHARED_SERVICES.get(prefix.get("service"))
                if label and prefix.get(field):
                    networks[ipaddress.ip_network(prefix[field])] = label
        loaded.add("aws")
    except Exception:
        pass
    try:
        blocks = []
        for url in (GOOGLE_RANGES_URL, GOOGLE_CLOUD_RANGES_URL):
            with opener(url, timeout=timeout) as response:
                data = json.load(response)
            blocks.append([ipaddress.ip_network(prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix"))
                           for prefix in data.get("prefixes") or [] if prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")])
        google, cloud = blocks
        for network in google:
            # Skip any block that contains or overlaps a Cloud customer block.
            if not any(network.version == leased.version and network.overlaps(leased) for leased in cloud):
                networks[network] = ("proxy", "google")
        loaded.add("google")
    except Exception:
        pass
    return NetworkIndex(networks, loaded)


class NetworkIndex:
    """Longest-prefix lookup over many blocks, by masking the address once per distinct prefix length."""

    def __init__(self, networks, sources=()):
        # Providers whose published list made it into the index, so a miss there is authoritative.
        self.sources = frozenset(sources)
        self.tables = {}
        for network, label in networks.items():
            table = self.tables.setdefault((network.version, network.prefixlen), {})
            table.setdefault(int(network.network_address), (network, label))
        self.lengths = {version: sorted({length for v, length in self.tables if v == version}, reverse=True)
                        for version in (4, 6)}

    def __len__(self):
        return sum(len(table) for table in self.tables.values())

    def lookup(self, address):
        bits = 32 if address.version == 4 else 128
        value = int(address)
        for length in self.lengths[address.version]:
            mask = ((1 << length) - 1) << (bits - length) if length else 0
            found = self.tables[(address.version, length)].get(value & mask)
            if found:
                return found
        return None


STATIC_INDEX = NetworkIndex(NETWORKS)


def classify_ip(ip, service_ranges=None):
    """(kind, provider, evidence) for an address inside a published shared-edge block, else None.

    ``service_ranges`` is a NetworkIndex (or a dict of blocks) from ``load_service_ranges``.
    """
    try:
        address = ipaddress.ip_address(str(ip).strip("[]"))
    except ValueError:
        return None
    if service_ranges is not None and not isinstance(service_ranges, NetworkIndex):
        service_ranges = NetworkIndex(service_ranges)
    for index, source in ((STATIC_INDEX, "published range"), (service_ranges, "provider service range")):
        found = index.lookup(address) if index else None
        if found:
            network, label = found
            return (label[0], label[1], f"{source} {network}")
    return None


def _headers(response):
    headers = {}
    for name, value in (response.get("header") or response.get("headers") or {}).items():
        values = value if isinstance(value, list) else [value]
        headers[str(name).lower().replace("_", "-")] = " ".join(str(item) for item in values).lower()
    raw = str(response.get("raw_header") or "")
    for line in raw.splitlines()[1:]:
        name, _, value = line.partition(":")
        if name and value:
            key = name.strip().lower()
            headers[key] = f"{headers[key]} {value.strip().lower()}" if key in headers else value.strip().lower()
    return headers


def classify_response(response):
    """(kind, provider, evidence) when an HTTP answer came from a shared frontend, else None.

    ``response`` is an httpx JSON record (``header``/``raw_header``, ``webserver``, ``body``, ``tls``).
    """
    if not isinstance(response, dict):
        return None
    headers = _headers(response)
    matches = []
    server = (headers.get("server") or str(response.get("webserver") or "")).lower().strip()
    for prefix, label in SERVER_PREFIXES:
        if label and server.startswith(prefix):
            matches.append((label, f"Server: {server[:60]}"))
            break
    for name, label in HEADERS:
        if name in headers:
            matches.append((label, f"header {name}"))
    for name, pattern, label in HEADER_VALUES:
        if pattern.search(headers.get(name, "")):
            matches.append((label, f"header {name}: {headers[name][:60]}"))
    body = str(response.get("body") or "")[:20000].lower()
    for pattern, label in BODY_MARKERS:
        if pattern.search(body):
            matches.append((label, "default page of the provider"))
    tls = response.get("tls") or {}
    if isinstance(tls, dict):
        # A bare-IP handshake returns the endpoint's default certificate, such as *.execute-api.<region>.amazonaws.com.
        # The issuer proves nothing: exportable ACM and Google Trust Services certificates work on any server.
        names = [tls.get("subject_cn"), *(tls.get("subject_an") or [])]
        for name in names:
            label = classify_hostname(str(name or "").lstrip("*."))
            if label:
                matches.append((label, f"TLS certificate for {name}"))
                break
    return _as_triple(_pick(matches))


def classify(hostnames=(), ip=None, response=None, service_ranges=None):
    """Strongest evidence from aliases, the address and an HTTP answer."""
    found = [classify_hostnames(hostnames), classify_ip(ip, service_ranges) if ip else None,
             classify_response(response) if response else None]
    found = [match for match in found if match]
    return max(found, key=lambda match: KIND_PRIORITY[match[0]]) if found else None
