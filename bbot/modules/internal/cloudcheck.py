import asyncio
import regex as re
from contextlib import suppress
from urllib.parse import urlparse

from bbot.modules.base import BaseInterceptModule


# DNS names are evidence for managed frontends whose IPs can share a provider's
# general cloud range. Never infer an origin from the absence of these suffixes.
FRONTEND_CNAME_SUFFIXES = {
    "cloudfront.net": ("cdn", "cloudfront"),
    "akamaiedge.net": ("cdn", "akamai"),
    "edgekey.net": ("cdn", "akamai"),
    "edgesuite.net": ("cdn", "akamai"),
    "fastly.net": ("cdn", "fastly"),
    "fastlylb.net": ("cdn", "fastly"),
    "azureedge.net": ("cdn", "azure"),
    "azurefd.net": ("cdn", "azure"),
    "impervadns.net": ("waf", "imperva"),
    "incapdns.net": ("waf", "imperva"),
    "ghs.googlehosted.com": ("proxy", "google"),
    "github.io": ("proxy", "github"),
    "wpenginepowered.com": ("proxy", "wpengine"),
    "hosting.gitbook.io": ("proxy", "gitbook"),
    "vercel-dns.com": ("proxy", "vercel"),
    "netlify.app": ("proxy", "netlify"),
}
# Application, network and classic load balancers use names like
# app.example-123.eu-west-1.elb.amazonaws.com. Older aliases may place elb
# before the region instead.
ELB_HOSTNAME = re.compile(r"(?:^|\.)(?:[a-z0-9-]+\.elb\.amazonaws\.com|elb\.[a-z0-9-]+\.amazonaws\.com)$")


def frontend_cname_evidence(hosts):
    matches = []
    for raw_host in hosts:
        host = str(raw_host).lower().rstrip(".")
        if ELB_HOSTNAME.search(host):
            matches.append(("load_balancer", "aws"))
        for suffix, classification in FRONTEND_CNAME_SUFFIXES.items():
            if host == suffix or host.endswith(f".{suffix}"):
                matches.append(classification)
    priority = {"cdn": 3, "waf": 2, "load_balancer": 1, "proxy": 0}
    return max(matches, key=lambda match: priority[match[0]]) if matches else None


def cloud_ip_metadata(host, provider_name, tags, cname_frontend=None):
    provider_slug = str(provider_name or "").lower() or None
    tag_set = {str(tag).lower() for tag in tags}
    frontend_kind, frontend_provider = cname_frontend or (None, None)
    # Cloudflare's published edge ranges are tagged "waf" by cloudcheck.
    # Conversely, cloudcheck tags *all* GitHub ranges "cdn", including API
    # and Git endpoints; that tag alone cannot prove a CDN edge.
    is_cdn = (
        ("cdn" in tag_set and provider_slug != "github") or provider_slug == "cloudflare" or frontend_kind == "cdn"
    )
    is_waf = "waf" in tag_set or frontend_kind == "waf"
    is_load_balancer = frontend_kind == "load_balancer"
    data = {"ip": str(host), "isCdn": bool(is_cdn),
            "isLoadBalancer": bool(is_load_balancer),
            "isFrontedProxy": bool(is_cdn or is_waf or is_load_balancer or frontend_kind == "proxy")}
    if provider_slug or frontend_provider:
        data["cloudProvider"] = provider_slug or frontend_provider
    if is_cdn:
        data["providerType"] = "cdn"
        data["isCdn"] = True
        data["cdnName"] = frontend_provider if frontend_kind == "cdn" else provider_slug
    elif is_load_balancer:
        data["providerType"] = "load_balancer"
        data["isLoadBalancer"] = True
    elif is_waf:
        data["providerType"] = "waf"
    elif frontend_kind == "proxy":
        data["providerType"] = "proxy"
    else:
        data["providerType"] = "cloud" if provider_slug else "unknown"
    if cname_frontend:
        data["frontendEvidence"] = f"DNS CNAME: {frontend_kind} ({frontend_provider})"
    elif is_cdn or is_waf:
        data["frontendEvidence"] = f"cloudcheck provider range: {provider_slug}"
    return data


class CloudCheck(BaseInterceptModule):
    watched_events = ["*"]
    produced_events = ["GEOLOCATION", "STORAGE_BUCKET"]
    meta = {
        "description": "Tag events by cloud provider, identify cloud resources like storage buckets",
        "created_date": "2024-07-07",
        "author": "@TheTechromancer",
    }
    # tag events up to and including distance-2
    scope_distance_modifier = 2
    _priority = 3

    async def setup(self):
        self._cloud_hostname_regexes = None
        self._cloud_hostname_regexes_lock = asyncio.Lock()
        self.scope_input_only = bool(self.config.get("scope_input_only", False))
        # Perform a test lookup during setup to force a signature update.
        # Signature-fetch failures should degrade cloud tagging, not abort
        # an otherwise valid scan.
        from cloudcheck import CloudCheckError

        try:
            await self.helpers.cloudcheck.lookup("8.8.8.8")
        except CloudCheckError as e:
            self.warning(f"Failed to load cloud provider signatures ({e}); continuing with cloud detection degraded")
        return True

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        if self.scope_input_only and "target" not in event.tags:
            return False, "cloudcheck is limited to explicit scan input events"
        return True

    async def handle_event(self, event, **kwargs):
        # cloud tagging by hosts
        hosts_to_check = set(event.resolved_hosts)
        with suppress(KeyError):
            hosts_to_check.remove(event.host_original)
        hosts_to_check = [str(event.host_original)] + list(hosts_to_check)

        cname_hosts = set(event.dns_children.get("CNAME", ()))
        cname_hosts.update(
            host for host in hosts_to_check if not self.helpers.is_ip(host) and host != str(event.host_original)
        )
        if event.type == "IP_ADDRESS":
            for parent in event.get_parents():
                if parent.type == "DNS_NAME":
                    cname_hosts.update(parent.dns_children.get("CNAME", ()))
                    break
        cname_frontend = frontend_cname_evidence(cname_hosts)
        ip_providers = {}

        for i, host in enumerate(hosts_to_check):
            host_is_ip = self.helpers.is_ip(host)
            try:
                cloudcheck_results = await self.helpers.cloudcheck.lookup(host)
            except Exception as e:
                self.warning(f"Error running cloudcheck against {event} (host: {host}): {e}")
                continue
            for provider in cloudcheck_results:
                provider_name = provider["name"].lower()
                tags = provider.get("tags", [])
                if host_is_ip:
                    ip_providers.setdefault(host, []).append((provider_name, tags))
                for tag in tags:
                    event.add_tag(tag)
                    event.add_tag(f"{tag}-{provider_name}")
                    if host_is_ip:
                        event.add_tag(f"{provider_name}-ip")
                    else:
                        # if the original hostname is a cloud domain, tag it as such
                        if i == 0:
                            event.add_tag(f"{provider_name}-domain")
                        # any children are tagged as CNAMEs
                        else:
                            event.add_tag(f"{provider_name}-cname")

        for host in hosts_to_check:
            if self.helpers.is_ip(host):
                await self.emit_cloud_ip_metadata(event, host, ip_providers.get(host, []), cname_frontend)

        # we only generate storage buckets off of in-scope or distance-1 events
        if event.scope_distance >= self.max_scope_distance:
            return

        # see if any of our hosts are storage buckets, etc.
        regexes = await self.cloud_hostname_regexes()
        regexes = regexes.get("STORAGE_BUCKET_HOSTNAME", [])
        for regex_name, regex in regexes.items():
            for host in hosts_to_check:
                if match := regex.match(host):
                    provider_attr = regex_name.split("-STORAGE_BUCKET_HOSTNAME-", 1)[0]
                    bucket_name = match.groupdict().get("name")
                    if not bucket_name:
                        with suppress(IndexError):
                            bucket_name = match.groups()[0]
                    if not bucket_name:
                        self.error(f"Bucket regex {regex_name} ({regex}) did not expose a bucket name capture group")
                        continue
                    bucket_url = f"https://{host}"
                    provider_slug = self._provider_slug(provider_attr)
                    region = self.get_bucket_region(bucket_url)
                    event_data = {
                        "name": bucket_name,
                        "url": bucket_url,
                        "provider": provider_slug,
                        "resource_type": "storage_bucket",
                        "is_public": False,
                        "context": f"{{module}} analyzed {event.type} and found {{event.type}}: {bucket_url}",
                    }
                    if region:
                        event_data["region"] = region
                    await self.emit_event(
                        event_data,
                        "STORAGE_BUCKET",
                        parent=event,
                        tags={f"cloud-{provider_attr.lower()}", f"{provider_attr.lower()}-domain"},
                    )

    async def cloud_hostname_regexes(self):
        async with self._cloud_hostname_regexes_lock:
            if not self._cloud_hostname_regexes:
                storage_bucket_regexes = {}
                self._cloud_hostname_regexes = {"STORAGE_BUCKET_HOSTNAME": storage_bucket_regexes}
                from cloudcheck import providers

                for attr in dir(providers):
                    if attr.startswith("_"):
                        continue
                    provider = getattr(providers, attr)
                    provider_regexes = getattr(provider, "regexes", {})
                    for regex_name, regexes in provider_regexes.items():
                        for i, regex in enumerate(regexes):
                            if not regex_name in ("STORAGE_BUCKET_HOSTNAME"):
                                continue
                            try:
                                storage_bucket_regexes[f"{attr}-{regex_name}-{i}"] = re.compile(regex)
                            except Exception as e:
                                self.error(f"Error compiling regex for {attr}-{regex_name}: {e}")
                                continue
            return self._cloud_hostname_regexes

    def _provider_slug(self, provider_attr_name):
        provider_name = str(provider_attr_name or "").strip().lower()
        return {
            "amazon": "aws",
            "google": "gcp",
            "microsoft": "azure",
        }.get(provider_name, provider_name)

    def get_bucket_region(self, url):
        parsed = urlparse(str(url or ""))
        host = (parsed.hostname or "").lower().rstrip(".")
        for pattern in (
            r"\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$",
            r"\.([a-z0-9-]+)\.digitaloceanspaces\.com$",
        ):
            match = re.search(pattern, host)
            if match:
                return match.group(1)
        return None

    async def emit_cloud_ip_metadata(self, event, host, providers, cname_frontend=None):
        ranked = sorted(
            providers,
            key=lambda item: ("cdn" in item[1], "waf" in item[1], "cloud" in item[1]),
            reverse=True,
        )
        provider_name, tags = ranked[0] if ranked else (None, [])
        if not provider_name and not cname_frontend and event.type != "IP_ADDRESS":
            return
        provider_slug = self._provider_slug(provider_name) if provider_name else None
        data = cloud_ip_metadata(host, provider_slug, tags, cname_frontend)
        await self.emit_event(
            data,
            "GEOLOCATION",
            parent=event,
            context=f"{{module}} classified {host} as {{event.type}} cloud metadata",
        )
