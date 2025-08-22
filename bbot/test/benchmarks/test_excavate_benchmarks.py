import pytest
import random
from ..bbot_fixtures import *
from ..test_step_2.module_tests.base import ModuleTestBase


class ExcavateBenchmarkBase(ModuleTestBase):
    """Base class for excavate benchmarks with shared setup"""

    targets = ["http://127.0.0.1:8888/"]

    def setup_method(self):
        """Setup test data"""
        random.seed(42)  # Deterministic for reproducible tests

        # Generate test HTML documents with extractable content
        self.test_response_data = []
        for i in range(10):  # Start with fewer for debugging
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Test Page {i}</title></head>
            <body>
                <h1>Test Document {i}</h1>
                
                <!-- URLs that excavate should extract -->
                <a href="https://api{i}.example.com/v1/users">API Link {i}</a>
                <a href="http://subdomain{i}.test.com/path">Subdomain Link {i}</a>
                <a href="/relative{i}.html">Relative Link {i}</a>
                <link href="/css/style{i}.css" rel="stylesheet">
                <img src="/images/photo{i}.jpg" alt="Photo {i}">
                
                <!-- Forms with parameters -->
                <form action="/submit{i}" method="post">
                    <input type="text" name="username{i}" value="user{i}">
                    <input type="password" name="password{i}" value="pass{i}">
                </form>
                
                <!-- JavaScript with URLs -->
                <script>
                    var apiUrl = "https://api{i}.example.com/endpoint";
                    var imageUrl = "/images/icon{i}.png";
                </script>
                
                <!-- Email links -->
                <a href="mailto:admin{i}@example.com">Contact {i}</a>
                
                <!-- Database connection strings -->
                <div>DB: postgresql://user:pass@localhost:5432/db{i}</div>
            </body>
            </html>
            """
            self.test_response_data.append(html_content)

    async def setup_before_prep(self, module_test):
        """Setup HTTP responses like the existing tests do"""
        # Set up all the HTTP responses that will contain extractable content
        response_data = "\n".join(self.test_response_data)
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": response_data}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        """Required by ModuleTestBase - validate the scan worked"""
        # Just ensure we got some events from excavate
        assert len(events) > 0, "Expected excavate to emit some events"


class TestExcavateBasicBenchmarks(ExcavateBenchmarkBase):
    """Benchmark for excavate module's basic content processing (no parameter extraction)"""

    modules_overrides = ["excavate", "httpx"]  # No hunt = no parameter extraction

    @pytest.mark.benchmark(group="excavate_basic")
    def test_excavate_basic_processing(self, module_test, benchmark):
        """Benchmark excavate module's basic processing (no parameter extraction)"""

        def run_full_scan():
            # The ModuleTestBase framework runs the full scan and returns all events
            return module_test.events

        # Run the benchmark on the full scan
        events = benchmark(run_full_scan)

        # Count what excavate found during the full scan
        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        web_param_events = [e for e in events if e.type == "WEB_PARAMETER"]
        total_events = len(events)

        # Validate that excavate actually processed the content and found things
        assert total_events > 0, (
            f"Expected excavate to emit some events, but emitted {total_events}. Check if excavate is working."
        )

        print(f"✅ Basic excavate benchmark processed scan")
        print(f"📊 Full scan emitted {total_events} total events:")
        print(f"   - URL_UNVERIFIED: {len(url_events)}")
        print(f"   - WEB_PARAMETER: {len(web_param_events)} (should be 0 without hunt)")


class TestExcavateFullBenchmarks(ExcavateBenchmarkBase):
    """Benchmark for excavate module's full content processing (with parameter extraction)"""

    modules_overrides = ["excavate", "httpx", "hunt"]  # hunt enables parameter extraction

    @pytest.mark.benchmark(group="excavate_full")
    def test_excavate_full_processing(self, module_test, benchmark):
        """Benchmark excavate module's full processing (with parameter extraction)"""

        def run_full_scan():
            # The ModuleTestBase framework runs the full scan and returns all events
            return module_test.events

        # Run the benchmark on the full scan
        events = benchmark(run_full_scan)

        # Count what excavate found during the full scan
        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        web_param_events = [e for e in events if e.type == "WEB_PARAMETER"]
        total_events = len(events)

        # Validate that excavate actually processed the content and found things
        assert total_events > 0, (
            f"Expected excavate to emit some events, but emitted {total_events}. Check if excavate is working."
        )

        print(f"✅ Full excavate benchmark processed scan")
        print(f"📊 Full scan emitted {total_events} total events:")
        print(f"   - URL_UNVERIFIED: {len(url_events)}")
        print(f"   - WEB_PARAMETER: {len(web_param_events)} (should be >0 with hunt)")
