import asyncio
import regex as re
from contextlib import suppress
from urllib.parse import urlparse

from bbot.core.helpers import shared_infra
from bbot.modules.base import BaseInterceptModule


# Providers whose whole published range is a shared SaaS or platform edge, though cloudcheck tags it "cloud".
# Akamai's "cloud" range also holds Linode instances, so it is not listed.
SHARED_CLOUD_PROVIDERS = {"heroku", "salesforce", "microsoft365", "zscaler"}
# Event types checked for shared frontends even when full cloud tagging is limited to the scan input.
FRONTEND_EVENT_TYPES = {"IP_ADDRESS", "DNS_NAME", "HTTP_RESPONSE"}


def frontend_cname_evidence(hosts):
    """(kind, provider, evidence) when a DNS alias names a CDN, WAF, load balancer, API gateway or shared platform."""
    return shared_infra.classify_hostnames(hosts)


def cloud_ip_metadata(host, provider_name, tags, cname_frontend=None):
    """GEOLOCATION data for an address. ``cname_frontend`` is (kind, provider[, evidence]) from any frontend check."""
    provider_slug = str(provider_name or "").lower() or None
    tag_set = {str(tag).lower() for tag in tags}
    frontend_kind, frontend_provider = (cname_frontend or (None, None))[:2]
    frontend_detail = cname_frontend[2] if cname_frontend and len(cname_frontend) > 2 else None
    if not frontend_kind and provider_slug in SHARED_CLOUD_PROVIDERS:
        frontend_kind, frontend_provider = "proxy", provider_slug
        frontend_detail = f"cloudcheck provider range: {provider_slug}"
    # Cloudflare's published edge ranges are tagged "waf" by cloudcheck.
    # Conversely, cloudcheck tags *all* GitHub ranges "cdn", including API
    # and Git endpoints; that tag alone cannot prove a CDN edge.
    is_cdn = (
        ("cdn" in tag_set and provider_slug != "github") or provider_slug == "cloudflare" or frontend_kind == "cdn"
    )
    is_waf = "waf" in tag_set or frontend_kind == "waf"
    is_load_balancer = frontend_kind == "load_balancer"
    is_api_gateway = frontend_kind == "api_gateway"
    data = {"ip": str(host), "isCdn": bool(is_cdn),
            "isLoadBalancer": bool(is_load_balancer),
            "isApiGateway": bool(is_api_gateway),
            "isFrontedProxy": bool(is_cdn or is_waf or is_load_balancer or is_api_gateway or frontend_kind == "proxy")}
    if provider_slug or frontend_provider:
        data["cloudProvider"] = provider_slug or frontend_provider
    if frontend_provider:
        data["frontendProvider"] = frontend_provider
    if is_cdn:
        data["providerType"] = "cdn"
        data["cdnName"] = frontend_provider if frontend_kind == "cdn" else provider_slug
    elif is_waf:
        data["providerType"] = "waf"
    elif is_api_gateway:
        data["providerType"] = "api_gateway"
    elif is_load_balancer:
        data["providerType"] = "load_balancer"
    elif frontend_kind == "proxy":
        data["providerType"] = "proxy"
    else:
        data["providerType"] = "cloud" if provider_slug else "unknown"
    if frontend_kind:
        detail = frontend_detail or "DNS CNAME"
        data["frontendEvidence"] = f"{detail}: {frontend_kind} ({frontend_provider})"[:250]
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
    # Frontend probes wait on the network; several workers keep one slow address from holding up the scan.
    _module_threads = 10

    async def setup(self):
        self._cloud_hostname_regexes = None
        self._cloud_hostname_regexes_lock = asyncio.Lock()
        self.scope_input_only = bool(self.config.get("scope_input_only", False))
        # One request to a bare cloud address before port scanning, to recognise load balancers and API gateways.
        self.probe_cloud_frontends = bool(self.config.get("probe_cloud_frontends", False))
        self.probe_timeout = float(self.config.get("probe_timeout", 5))
        self._probe_verdicts = {}
        self._probe_tasks = {}
        # AWS and Google publish which of their blocks are CloudFront, API Gateway, S3, Google front ends...
        try:
            self.service_ranges = await self.helpers.run_in_executor(shared_infra.load_service_ranges)
        except Exception as e:
            self.warning(f"Failed to load provider service ranges ({e}); shared frontend detection degraded")
            self.service_ranges = None
        # Perform a test lookup during setup to force a signature update.
        # Signature-fetch failures should degrade cloud tagging, not abort
        # an otherwise valid scan.
        from cloudcheck import CloudCheckError

        try:
            await self.helpers.cloudcheck.lookup("8.8.8.8")
        except CloudCheckError as e:
            self.warning(f"Failed to load cloud provider signatures ({e}); continuing with cloud detection degraded")
        return True

    def trusted_providers(self, host, providers):
        """cloudcheck's CDN lists also cover customer EC2 blocks (dedicated instances come back as Cloudfront,
        Quiccloud or GitHub). Inside AWS, AWS's own ip-ranges.json decides: a CDN or WAF provider is kept only
        where AWS publishes the block as CloudFront. Anything dropped is still probed as a general cloud address."""
        if "aws" not in getattr(self.service_ranges, "sources", ()) or not any(name == "amazon" for name, _ in providers):
            return providers
        published = shared_infra.classify_ip(host, self.service_ranges)
        is_cloudfront = bool(published and published[:2] == ("cdn", "cloudfront"))
        return [(name, tags) for name, tags in providers
                if not {"cdn", "waf"} & {str(tag).lower() for tag in tags} or (name == "cloudfront" and is_cloudfront)]

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        if self.scope_input_only and "target" not in event.tags and event.type not in FRONTEND_EVENT_TYPES:
            return False, "cloudcheck is limited to explicit scan input events"
        return True

    def alias_evidence(self, event):
        """Frontend named by the event's DNS aliases (CNAME) or, for an address, its provider-owned PTR name."""
        cname_hosts = set(event.dns_children.get("CNAME", ()))
        if event.type == "IP_ADDRESS":
            for parent in event.get_parents():
                if parent.type == "DNS_NAME":
                    cname_hosts.update(parent.dns_children.get("CNAME", ()))
                    break
        found = [frontend_cname_evidence(cname_hosts)]
        # Edge PTRs such as *.r.cloudfront.net or *.akamaitechnologies.com name their provider. Cloud instances
        # (ec2-*.compute.amazonaws.com, *.bc.googleusercontent.com) and customer-chosen names never match a suffix.
        ptr = shared_infra.classify_hostnames(event.dns_children.get("PTR", ()))
        found.append((ptr[0], ptr[1], ptr[2].replace("DNS alias", "PTR", 1)) if ptr else None)
        found = [match for match in found if match]
        return max(found, key=lambda match: shared_infra.KIND_PRIORITY[match[0]]) if found else None

    async def probe_frontend(self, ip):
        """Ask the bare address what it is. Without a matching Host or SNI, a load balancer or API gateway answers
        with its own default response (``Server: awselb/2.0``, ``x-amzn-ErrorType``), while a dedicated server
        answers as itself. Both schemes are requested at once; the verdict is cached per address."""
        if ip in self._probe_verdicts:
            return self._probe_verdicts[ip]
        task = self._probe_tasks.get(ip)
        if task is None:
            task = self._probe_tasks[ip] = asyncio.create_task(self._probe_frontend(ip))
        try:
            verdict = await asyncio.shield(task)
        finally:
            self._probe_tasks.pop(ip, None)
        self._probe_verdicts[ip] = verdict
        return verdict

    async def _probe_frontend(self, ip):
        host = f"[{ip}]" if ":" in ip else ip
        urls = [f"https://{host}/", f"http://{host}/"]
        responses = await asyncio.gather(*(self.helpers.request(url, timeout=self.probe_timeout,
                                                                follow_redirects=False) for url in urls),
                                         return_exceptions=True)
        found = []
        for url, response in zip(urls, responses):
            if response is None or isinstance(response, BaseException) or not hasattr(response, "headers"):
                continue
            headers = {}
            for name, value in response.headers.multi_items():
                headers.setdefault(name, []).append(value)
            answer = shared_infra.classify_response(
                {"status_code": response.status_code, "header": headers,
                 "body": response.content[:20000].decode("utf-8", "ignore")})
            if answer:
                found.append((answer[0], answer[1], f"HTTP probe of {url}: {answer[2]}"))
        return max(found, key=lambda match: shared_infra.KIND_PRIORITY[match[0]]) if found else None

    async def probed_evidence(self, event, ip, frontend, providers):
        """Probe an IP_ADDRESS (what port scanners consume) in a general cloud range that nothing else classified."""
        if frontend or not self.probe_cloud_frontends or event.type != "IP_ADDRESS":
            return frontend
        if not any("cloud" in {str(tag).lower() for tag in tags} for _, tags in providers):
            return None
        return await self.probe_frontend(ip)

    def frontend_evidence(self, event, ip, cname_frontend):
        """Strongest shared-frontend evidence for one address of an event: alias, published range or HTTP answer."""
        response = event.data if event.type == "HTTP_RESPONSE" and isinstance(event.data, dict) else None
        found = [cname_frontend, shared_infra.classify_ip(ip, self.service_ranges)]
        if response:
            answer = shared_infra.classify_response(response)
            found.append((answer[0], answer[1], f"HTTP answer {answer[2]}") if answer else None)
        found = [match for match in found if match]
        return max(found, key=lambda match: shared_infra.KIND_PRIORITY[match[0]]) if found else None

    async def handle_frontends_only(self, event):
        """Flag shared frontends on discovered events without the full cloud tagging of scan input."""
        hosts = [str(event.host_original)] + [str(host) for host in event.resolved_hosts]
        cname_frontend = self.alias_evidence(event)
        for host in dict.fromkeys(hosts):
            if not self.helpers.is_ip(host):
                continue
            frontend = self.frontend_evidence(event, host, cname_frontend)
            # cloudcheck's own CDN/WAF ranges (Fastly, Imperva, Sucuri...) and shared SaaS ranges, without tagging.
            providers = []
            try:
                providers = [(provider["name"].lower(), provider.get("tags", []))
                             for provider in await self.helpers.cloudcheck.lookup(host)]
            except Exception as e:
                self.debug(f"Error running cloudcheck against {host}: {e}")
            providers = self.trusted_providers(host, providers)
            shared = [(name, tags) for name, tags in providers
                      if {"cdn", "waf"} & {str(tag).lower() for tag in tags} or name in SHARED_CLOUD_PROVIDERS]
            if not shared:
                frontend = await self.probed_evidence(event, host, frontend, providers)
            if frontend or shared:
                data = cloud_ip_metadata(host, self._provider_slug(shared[0][0]) if shared else None,
                                         shared[0][1] if shared else (), frontend)
                if not data["isFrontedProxy"] and not data["isCdn"]:
                    continue
                self.tag_frontend(event, (data["providerType"], data.get("cloudProvider") or "unknown"))
                await self.emit_event(data, "GEOLOCATION", parent=event,
                                      context=f"{{module}} classified {host} as a shared frontend")

    def tag_frontend(self, event, frontend):
        event.add_tag("shared-frontend")
        event.add_tag(f"shared-{frontend[0].replace('_', '-')}-{frontend[1]}")

    async def handle_event(self, event, **kwargs):
        if self.scope_input_only and "target" not in event.tags:
            await self.handle_frontends_only(event)
            return
        # cloud tagging by hosts
        hosts_to_check = set(event.resolved_hosts)
        with suppress(KeyError):
            hosts_to_check.remove(event.host_original)
        hosts_to_check = [str(event.host_original)] + list(hosts_to_check)

        cname_hosts = {host for host in hosts_to_check if not self.helpers.is_ip(host) and host != str(event.host_original)}
        found = [self.alias_evidence(event), frontend_cname_evidence(cname_hosts)]
        found = [match for match in found if match]
        cname_frontend = max(found, key=lambda match: shared_infra.KIND_PRIORITY[match[0]]) if found else None
        ip_providers = {}

        for i, host in enumerate(hosts_to_check):
            host_is_ip = self.helpers.is_ip(host)
            try:
                cloudcheck_results = await self.helpers.cloudcheck.lookup(host)
            except Exception as e:
                self.warning(f"Error running cloudcheck against {event} (host: {host}): {e}")
                continue
            found = [(provider["name"].lower(), provider.get("tags", [])) for provider in cloudcheck_results]
            if host_is_ip:
                found = self.trusted_providers(host, found)
            for provider_name, tags in found:
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
                frontend = self.frontend_evidence(event, host, cname_frontend)
                providers = ip_providers.get(host, [])
                if not any({"cdn", "waf"} & {str(tag).lower() for tag in tags} or name in SHARED_CLOUD_PROVIDERS
                           for name, tags in providers):
                    frontend = await self.probed_evidence(event, host, frontend, providers)
                if frontend:
                    self.tag_frontend(event, frontend)
                await self.emit_cloud_ip_metadata(event, host, ip_providers.get(host, []), frontend)

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
