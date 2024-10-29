from bbot.modules.base import BaseModule


class reflected_parameters(BaseModule):
    watched_events = ["WEB_PARAMETER"]
    produced_events = ["FINDING"]
    flags = ["active", "safe", "web-thorough"]
    meta = {
        "description": "Highlight parameters that reflect their contents in response body",
        "author": "@liquidsec",
        "created_date": "2024-10-29",
    }

    async def handle_event(self, event):
        url = event.data.get("url")
        from_paramminer = str(event.module) == "paramminer_getparams"
        reflection_detected = (
            "http-reflection" in event.tags if from_paramminer else await self.detect_reflection(event, url)
        )

        if reflection_detected:
            description = (
                f"GET Parameter value reflected in response body. Name: [{event.data['name']}] "
                f"Source Module: [{str(event.module)}]"
            )
            if event.data.get("original_value"):
                description += (
                    f" Original Value: [{self.helpers.truncate_string(str(event.data['original_value']), 200)}]"
                )
            data = {"host": str(event.host), "description": description, "url": url}
            await self.emit_event(data, "FINDING", event)

    async def detect_reflection(self, event, url):
        """Detects reflection by sending a probe with a random value."""
        probe_parameter_name = event.data["name"]
        probe_parameter_value = self.helpers.rand_string()
        probe_url = self.helpers.add_get_params(url, {probe_parameter_name: probe_parameter_value}).geturl()
        self.debug(f"reflected_parameters Probe URL: {probe_url}")
        probe_response = await self.helpers.request(probe_url, method="GET")
        return probe_response and probe_parameter_value in probe_response.text
