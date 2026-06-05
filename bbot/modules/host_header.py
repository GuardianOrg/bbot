from bbot.errors import InteractshError
from bbot.modules.base import BaseModule


class host_header(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {
        "description": "Try common HTTP Host header spoofing techniques",
        "created_date": "2022-07-27",
        "author": "@liquidsec",
    }

    in_scope_only = True
    per_hostport_only = True

    deps_apt = ["curl"]

    async def setup(self):
        self.subdomain_tags = {}
        if self.scan.config.get("interactsh_disable", False) is False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")
                return False
        else:
            self.warning("Interactsh is disabled globally. Interaction based detections will be disabled.")
            self.domain = f"{self.rand_string(12, digits=False)}.com"
        return True

    def rand_string(self, *args, **kwargs):
        return self.helpers.rand_string(*args, **kwargs)

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                match = self.subdomain_tags.get(full_id.split(".")[0])
                if match is None:
                    return
                matched_event = match[0]
                matched_technique = match[1]

                protocol = r.get("protocol").upper()
                await self.emit_event(
                    {
                        "host": str(matched_event.host),
                        "url": matched_event.data["url"],
                        "description": (
                            f"Spoofed Host header using the {matched_technique} technique triggered an out-of-band {protocol} interaction. "
                            "The application or an upstream proxy appears to trust attacker-controlled host information when building requests, links, redirects, or backend calls. "
                            "This can enable password-reset poisoning, cache poisoning, phishing links on a trusted domain, or server-side requests to attacker-controlled infrastructure. "
                            "The Host header is the part of an HTTP request that tells a server which hostname the client wanted. If an application trusts that value without validation, an attacker can make the application generate links, callbacks, or internal requests using an attacker-chosen domain. "
                            "The application should use a fixed allow-list of expected hostnames, ignore override headers from untrusted clients, and configure proxies so only one trusted layer decides the canonical host."
                        ),
                    },
                    "FINDING",
                    matched_event,
                    context=f"{{module}} spoofed host header and induced {{event.type}}: {protocol} interaction",
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping results because subdomain tag was missing")

    async def finish(self):
        if self.scan.config.get("interactsh_disable", False) is False:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")

    async def cleanup(self):
        if self.scan.config.get("interactsh_disable", False) is False:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def handle_event(self, event):
        # get any set-cookie responses from the response and add them to the request
        url = event.data["url"]

        added_cookies = {}

        for header_values in event.data["header-dict"].values():
            for header_value in header_values:
                if header_value.lower() == "set-cookie":
                    header_split = header_value.split("=")
                    try:
                        added_cookies = {header_split[0]: header_split[1]}
                    except IndexError:
                        self.debug(f"failed to parse cookie from string {header_value}")

        domain_reflections = []

        # host header replacement
        technique_description = "standard"
        self.debug(f"Performing {technique_description} case")
        subdomain_tag = self.rand_string(4, digits=False)
        self.subdomain_tags[subdomain_tag] = (event, technique_description)
        output = await self.helpers.curl(
            url=url,
            headers={"Host": f"{subdomain_tag}.{self.domain}"},
            ignore_bbot_global_settings=True,
            cookies=added_cookies,
        )
        if self.domain in output:
            domain_reflections.append(technique_description)

        # absolute URL / Host header transposition
        technique_description = "absolute URL transposition"
        self.debug(f"Performing {technique_description} case")
        subdomain_tag = self.rand_string(4, digits=False)
        self.subdomain_tags[subdomain_tag] = (event, technique_description)
        output = await self.helpers.curl(
            url=url,
            path_override=url,
            cookies=added_cookies,
        )

        if self.domain in output:
            domain_reflections.append(technique_description)

        # duplicate host header tolerance
        technique_description = "duplicate host header tolerance"
        output = await self.helpers.curl(
            url=url,
            # Sending a blank HOST first as a hack to trick curl. This makes it no longer an "internal header", thereby allowing for duplicates
            # The fact that it's accepting two host headers is rare enough to note on its own, and not too noisy. Having the 3rd header be an interactsh would result in false negatives for the slightly less interesting cases.
            headers={"Host": ["", str(event.host), str(event.host)]},
            cookies=added_cookies,
            head_mode=True,
        )

        split_output = output.split("\n")
        if " 4" in split_output:
            description = (
                "The application tolerated duplicate Host headers. "
                "Accepting multiple Host values can create inconsistent routing between proxies, caches, and the application, and may become exploitable when one layer trusts a different Host value than another. "
                "For a non-specialist, this means the front door and the application may disagree about which website a request is for. Attackers can use that disagreement to poison caches, influence redirects, or bypass host-based routing and security checks. "
                "Requests with duplicate Host headers should be rejected at the edge, and the application should only trust a single normalized hostname supplied by a trusted proxy or server configuration."
            )
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "description": description,
                },
                "FINDING",
                event,
                context=f"{{module}} scanned {event.data['url']} and identified {{event.type}}: {description}",
            )

        # host header overrides
        technique_description = "host override headers"
        self.verbose(f"Performing {technique_description} case")
        subdomain_tag = self.rand_string(4, digits=False)
        self.subdomain_tags[subdomain_tag] = (event, technique_description)

        override_headers_list = [
            "X-Host",
            "X-Forwarded-Server",
            "X-Forwarded-Host",
            "X-Original-Host",
            "X-Forwarded-For",
            "X-Host",
            "X-HTTP-Host-Override",
            "Forwarded",
        ]
        override_headers = {}
        for oh in override_headers_list:
            override_headers[oh] = f"{subdomain_tag}.{self.domain}"

        output = await self.helpers.curl(
            url=url,
            headers=override_headers,
            cookies=added_cookies,
        )
        if self.domain in output:
            domain_reflections.append(technique_description)

        # emit all the domain reflections we found
        for dr in domain_reflections:
            description = (
                f"Possible Host header injection using the {dr} technique. "
                "The response reflected or used attacker-controlled host input, which may let an attacker generate trusted-looking links, poison caches, influence redirects, or abuse password-reset flows. "
                "This happens when an application builds absolute URLs, emails, redirects, or backend requests from the incoming Host value instead of a configured public hostname. "
                "The finding should be validated by checking whether the injected host appears in security-sensitive places such as password reset links, Location headers, canonical links, or cached pages. "
                "Use an allow-list of expected domains and avoid trusting host override headers from the public internet."
            )
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "description": description,
                },
                "FINDING",
                event,
                context=f"{{module}} scanned {url} and identified {{event.type}}: {description}",
            )
