from .base import ModuleTestBase

class TestService_Fingerprint(ModuleTestBase):
    targets = ["127.0.0.1:8888"]

    async def setup_before_prep(self, module_test):
        # The test config sends a custom header, which Nerva cannot carry, so the module would stand down.
        module_test.scan.custom_http_headers = {}

    def check(self, module_test, events):
        assert any(
            event.type == "PROTOCOL"
            and event.host == module_test.scan.helpers.make_ip_type("127.0.0.1")
            and event.port == 8888
            and event.data["protocol"] == "HTTP"
            for event in events
        ), "HTTP protocol not detected"
