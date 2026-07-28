from bbot.errors import HttpCompareError
from .base import BaseLightfuzz

import urllib.parse


class cmdi(BaseLightfuzz):
    """
    Detects command injection vulnerabilities.

    Techniques:

    * Echo Canary Detection:
       - Injects command delimiters (;, &&, ||, &, |) along with an echo command
       - Checks if the echoed canary appears in the response without the "echo" itself
       - Uses a false positive probe to validate findings

    * Blind Command Injection:
       - Injects nslookup commands with unique subdomain tags
       - Detects command execution through DNS resolution via Interactsh
    """

    friendly_name = "Command Injection"
    uses_interactsh = True

    async def fuzz(self):
        cookies = self.event.data.get(
            "assigned_cookies", {}
        )  # Retrieve assigned cookies from WEB_PARAMETER event data, if present
        probe_value = self.incoming_probe_value()

        canary = self.lightfuzz.helpers.rand_string(10, numeric_only=True)
        http_compare = self.compare_baseline(
            self.event.data["type"], probe_value, cookies
        )  # Initialize the http_compare object and establish a baseline HTTP response

        cmdi_probe_strings = [
            "AAAA",  # False positive probe
            ";",
            "&&",
            "||",
            "&",
            "|",
        ]

        positive_detections = []
        for p in cmdi_probe_strings:
            try:
                # add "echo" to the cmdi probe value to construct the command to be executed
                echo_probe = f"{probe_value}{p} echo {canary} {p}"
                # we have to handle our own URL-encoding here, because our payloads include the & character
                if self.event.data["type"] == "GETPARAM":
                    echo_probe = urllib.parse.quote(echo_probe.encode(), safe="")

                # send cmdi probe and compare with baseline response
                cmdi_probe = await self.compare_probe(
                    http_compare, self.event.data["type"], echo_probe, cookies, skip_urlencoding=True
                )

                # ensure we received an HTTP response
                if cmdi_probe[3]:
                    # check if the canary is in the response and the word "echo" is NOT in the response text, ruling out mere reflection of the entire probe value without execution
                    if canary in cmdi_probe[3].text and "echo" not in cmdi_probe[3].text:
                        self.debug(f"canary [{canary}] found in response when sending probe [{p}]")
                        if p == "AAAA":  # Handle detection false positive probe
                            self.warning(
                                f"False Postive Probe appears to have been triggered for {self.event.data['url']}, aborting remaining detection"
                            )
                            return
                        positive_detections.append(p)  # Add detected probes to positive detections
            except HttpCompareError as e:
                self.debug(e)
                continue
        if len(positive_detections) > 0:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": (
                        f"Possible OS command injection. {self.metadata()} Detection Method: [echo canary] Command delimiters that changed behavior: [{' '.join(positive_detections)}]. "
                        "The parameter may be reaching an operating-system command context. If confirmed, an attacker could execute commands on the server and compromise the application host. "
                        "Command injection happens when application input is combined with a shell command without safe separation between data and instructions. "
                        "Even limited command execution can expose files, environment variables, service credentials, or network access from the server. "
                        "The code path should use safe library calls instead of shell commands, pass arguments as structured values, and enforce a strict allow-list for any user-controlled option."
                    ),
                }
            )

        # Blind OS Command Injection
        if self.lightfuzz.interactsh_instance:
            self.lightfuzz.event_dict[self.event.data["url"]] = self.event  # Store the event associated with the URL
            for p in cmdi_probe_strings:
                # generate a random subdomain tag and associate it with the event, type, name, and probe
                subdomain_tag = self.lightfuzz.helpers.rand_string(4, digits=False)
                self.lightfuzz.interactsh_subdomain_tags[subdomain_tag] = {
                    "event": self.event,
                    "event_type": "VULNERABILITY",
                    "severity": "CRITICAL",
                    "description": (
                        f"OS Command Injection (OOB Interaction) Type: [{self.event.data['type']}] Parameter Name: [{self.event.data['name']}] Probe: [{p}]. "
                        "OS command injection was confirmed through an out-of-band interaction. "
                        "The application appears to pass user-controlled input into an operating-system command. An attacker may be able to execute commands on the server, read sensitive files, modify data, or pivot deeper into the hosting environment. "
                        "For a non-specialist, this means input from a request may be reaching a shell or command-line tool on the server. If the attacker can add command separators or arguments, the server may run commands chosen by the attacker rather than only the intended application action. "
                        "The affected parameter should be removed from command construction, replaced with safe APIs, strictly allow-listed, and reviewed for evidence of command execution attempts."
                    ),
                }
                # payload is an nslookup command that includes the interactsh domain prepended the previously generated subdomain tag
                interactsh_probe = f"{p} nslookup {subdomain_tag}.{self.lightfuzz.interactsh_domain} {p}"
                # we have to handle our own URL-encoding here, because our payloads include the & character
                if self.event.data["type"] == "GETPARAM":
                    interactsh_probe = urllib.parse.quote(interactsh_probe.encode(), safe="")
                # we send the probe here, and any positive detections are processed in the interactsh_callback defined in lightfuzz.py
                await self.standard_probe(
                    self.event.data["type"],
                    cookies,
                    f"{probe_value}{interactsh_probe}",
                    timeout=15,
                    skip_urlencoding=True,
                )
