from .base import BaseLightfuzz


class esi(BaseLightfuzz):
    """
    Detects Edge Side Includes (ESI) processing vulnerabilities.

    Tests if the server processes ESI tags by sending a payload containing ESI tags
    and checking if the tags are processed (removed) in the response.
    """

    # Technique lifted from https://github.com/PortSwigger/active-scan-plus-plus

    friendly_name = "Edge Side Includes"

    async def check_probe(self, cookies, probe, match):
        """
        Sends the probe and checks if the expected match string is found in the response.
        """
        probe_result = await self.standard_probe(self.event.data["type"], cookies, probe)
        if probe_result and match in probe_result.text:
            self.results.append(
                {
                    "type": "FINDING",
                    "description": (
                        f"Edge Side Include processing was detected for parameter [{self.event.data['name']}] of type [{self.event.data['type']}]{self.conversion_note()}. "
                        "If attacker-controlled ESI markup is processed by an edge cache or reverse proxy, an attacker may be able to inject content, include internal resources, or manipulate cached responses served to other users. "
                        "ESI is a feature that lets proxies assemble pages from smaller fragments before returning them to the browser. It is safe only when the markup is fully controlled by trusted templates. "
                        "When user input is interpreted as ESI, the proxy may perform server-side includes or alter shared cached content. "
                        "Disable ESI where it is not required, escape user-controlled values before they reach the edge layer, and avoid caching personalized responses that contain untrusted markup."
                    ),
                }
            )
            return True
        return False

    async def fuzz(self):
        """
        Main fuzzing method that sends the ESI test payload and checks for processing.
        """
        cookies = self.event.data.get("assigned_cookies", {})

        # ESI test payload: if ESI is processed, <!--esi--> will be removed
        # leaving AABB<!--esx-->CC in the response
        payload = "AA<!--esi-->BB<!--esx-->CC"
        detection_string = "AABB<!--esx-->CC"

        await self.check_probe(cookies, payload, detection_string)
