from .base import BaseLightfuzz


class ssrf(BaseLightfuzz):
    """
    Detects Server-Side Request Forgery (SSRF) vulnerabilities.

    Techniques:

    * OOB (Out-of-Band) Detection:
       - Injects URLs pointing to an Interactsh server as parameter values
       - Tries HTTP, HTTPS, and bare-domain values
       - Detects SSRF through DNS/HTTP interaction callbacks via Interactsh
    """

    friendly_name = "Server-Side Request Forgery"
    uses_interactsh = True

    async def fuzz(self):
        if not self.lightfuzz.interactsh_instance:
            return

        cookies = self.event.data.get("assigned_cookies", {})
        for prefix in ("http://", "https://", ""):
            subdomain_tag = self.lightfuzz.helpers.rand_string(4, digits=False)
            interactsh_url = f"{prefix}{subdomain_tag}.{self.lightfuzz.interactsh_domain}"
            probe_label = prefix if prefix else "no scheme"
            self.lightfuzz.interactsh_subdomain_tags[subdomain_tag] = {
                "event": self.event,
                "event_type": "VULNERABILITY",
                "dns_event_type": "FINDING",
                "severity": "HIGH",
                "description": (
                    f"Server-side request forgery was detected through an out-of-band interaction. "
                    f"Parameter: [{self.event.data['name']}] Type: [{self.event.data['type']}] Probe: [{probe_label}]. "
                    "The application made an outbound request using attacker-controlled input. An attacker may be able to reach internal services, cloud metadata endpoints, or other systems that are not directly exposed to the internet. "
                    "The affected input should use a strict destination allow-list, reject private and link-local addresses after DNS resolution, and prevent redirects to blocked destinations."
                ),
            }

            await self.standard_probe(
                self.event.data["type"],
                cookies,
                interactsh_url,
                timeout=15,
            )
