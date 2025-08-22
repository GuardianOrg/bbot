import pytest
import random
import asyncio
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from bbot.scanner import Scanner


class MockHTTPHandler(BaseHTTPRequestHandler):
    """Mock HTTP server that returns our test HTML content"""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Get the test content from the server instance
        test_content = self.server.test_content
        self.wfile.write(test_content.encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress logging
        pass


class TestExcavateBenchmarks:
    """
    Benchmark tests for Excavate module operations.

    These tests measure the performance of content extraction and processing
    which are critical for web scanning efficiency in BBOT.
    """

    # Number of test pages to generate for consistent benchmarking
    TEST_PAGES_COUNT = 8

    def setup_method(self):
        random.seed(42)
        self.test_response_data = []

        # Generate intensive HTML content that excavate can actually extract from
        for i in range(self.TEST_PAGES_COUNT):
            html_content = f"""
            <html>
            <head>
                <title>Test Page {i}</title>
            </head>
            <body>
                <h1>Welcome to Test Site {i}</h1>
                
                <!-- In-scope subdomains of foo.com target -->
                <a href="https://api{i}.foo.com/v1/users">API Link {i}</a>
                <a href="https://www{i}.foo.com/page{i}">WWW Link {i}</a>
                <a href="https://cdn{i}.foo.com/assets/">CDN Link {i}</a>
                
                <!-- Form with parameters -->
                <form action="/search/{i}" method="GET">
                    <input type="text" name="q{i}" value="search{i}">
                    <button type="submit">Search</button>
                </form>
                
                <!-- Real-time services -->
                <p>WebSocket: wss://realtime{i}.foo.com/socket</p>
                <p>SSH: ssh://server{i}.foo.com:22/</p>
                <p>FTP: ftp://ftp{i}.foo.com:21/</p>
            </body>
            </html>
            """
            self.test_response_data.append(html_content)

        # Start mock HTTP server
        self.start_mock_server()

    def teardown_method(self):
        # Stop mock HTTP server
        self.stop_mock_server()

    def start_mock_server(self):
        """Start a mock HTTP server on port 8888"""
        self.mock_server = HTTPServer(("127.0.0.1", 8888), MockHTTPHandler)
        self.mock_server.test_content = "\n".join(self.test_response_data)

        # Start server in a separate thread
        self.server_thread = threading.Thread(target=self.mock_server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        # Wait a moment for server to start
        time.sleep(0.1)

    def stop_mock_server(self):
        """Stop the mock HTTP server"""
        if hasattr(self, "mock_server"):
            self.mock_server.shutdown()
            self.mock_server.server_close()
            if hasattr(self, "server_thread"):
                self.server_thread.join(timeout=1)

    @pytest.mark.benchmark(group="excavate_basic")
    def test_excavate_basic_processing(self, benchmark):
        """Benchmark excavate module's basic processing (no parameter extraction)"""

        def run_excavate_scan():
            # Create a scanner with excavate enabled
            scan = Scanner("http://127.0.0.1:8888/", "foo.com", modules=["httpx"], config={"excavate": True})

            # Run the scan to measure execution time
            events = []

            async def run_scan():
                async for event in scan.async_start():
                    events.append(event)

            asyncio.run(run_scan())

            # Return both events and event counts for analysis
            total_events = len(events)
            excavate_events = [e for e in events if e.module == "excavate"]
            url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
            dns_events = [e for e in events if e.type in ["DNS_NAME_UNRESOLVED", "DNS_NAME"]]
            protocol_events = [e for e in events if e.type == "PROTOCOL"]

            return {
                "events": events,
                "total_events": total_events,
                "excavate_events": len(excavate_events),
                "url_events": len(url_events),
                "dns_events": len(dns_events),
                "protocol_events": len(protocol_events),
            }

        # Run the benchmark on the scan execution
        result = benchmark(run_excavate_scan)

        # Extract event counts from the result
        total_events = result["total_events"]
        excavate_events = result["excavate_events"]
        url_events = result["url_events"]
        dns_events = result["dns_events"]
        protocol_events = result["protocol_events"]

        # Validate that excavate actually processed content and emitted events
        assert total_events > 0, "Expected to find some events from the scan"

        # Print detailed event counts
        print(f"\n✅ Basic excavate benchmark completed")
        print(f"📊 Total events: {total_events}")
        print(f"📊 Excavate events (module=excavate): {excavate_events}")
        print(f"📊 URL events: {url_events}")
        print(f"📊 DNS events: {dns_events}")
        print(f"📊 Protocol events: {protocol_events}")

        # Validate that excavate actually found and processed content
        # Look for events that excavate typically emits, not just module=excavate
        assert url_events > 0 or dns_events > 0 or protocol_events > 0, (
            "Expected excavate to find URLs, DNS names, or protocols"
        )


class TestExcavateFullBenchmarks:
    """
    Benchmark tests for Excavate module with parameter extraction enabled.

    These tests measure the performance of excavate operations with hunt module
    enabled, which triggers parameter extraction functionality.
    """

    # Number of test pages to generate for consistent benchmarking
    TEST_PAGES_COUNT = 8

    def setup_method(self):
        random.seed(42)
        self.test_response_data = []

        # Generate intensive HTML content that excavate can actually extract from
        for i in range(self.TEST_PAGES_COUNT):
            html_content = f"""
            <html>
            <head>
                <title>Test Page {i}</title>
            </head>
            <body>
                <h1>Welcome to Test Site {i}</h1>
                
                <!-- In-scope subdomains of foo.com target -->
                <a href="https://api{i}.foo.com/v1/users">API Link {i}</a>
                <a href="https://www{i}.foo.com/page{i}">WWW Link {i}</a>
                <a href="https://cdn{i}.foo.com/assets/">CDN Link {i}</a>
                
                <!-- Form with parameters -->
                <form action="/search/{i}" method="GET">
                    <input type="text" name="q{i}" value="search{i}">
                    <button type="submit">Search</button>
                </form>
                
                <!-- Real-time services -->
                <p>WebSocket: wss://realtime{i}.foo.com/socket</p>
                <p>SSH: ssh://server{i}.foo.com:22/</p>
                <p>FTP: ftp://ftp{i}.foo.com:21/</p>
            </body>
            </html>
            """
            self.test_response_data.append(html_content)

        # Start mock HTTP server
        self.start_mock_server()

    def teardown_method(self):
        # Stop mock HTTP server
        self.stop_mock_server()

    def start_mock_server(self):
        """Start a mock HTTP server on port 8888"""
        self.mock_server = HTTPServer(("127.0.0.1", 8888), MockHTTPHandler)
        self.mock_server.test_content = "\n".join(self.test_response_data)

        # Start server in a separate thread
        self.server_thread = threading.Thread(target=self.mock_server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        # Wait a moment for server to start
        time.sleep(0.1)

    def stop_mock_server(self):
        """Stop the mock HTTP server"""
        if hasattr(self, "mock_server"):
            self.mock_server.shutdown()
            self.mock_server.server_close()
            if hasattr(self, "server_thread"):
                self.server_thread.join(timeout=1)

    @pytest.mark.benchmark(group="excavate_full")
    def test_excavate_full_processing(self, benchmark):
        """Benchmark excavate module's full processing (with parameter extraction)"""

        def run_excavate_scan():
            # Create a scanner with excavate and hunt enabled
            scan = Scanner("http://127.0.0.1:8888/", "foo.com", modules=["httpx", "hunt"], config={"excavate": True})

            # Run the scan to measure execution time
            events = []

            async def run_scan():
                async for event in scan.async_start():
                    events.append(event)

            asyncio.run(run_scan())

            # Return both events and event counts for analysis
            total_events = len(events)
            excavate_events = [e for e in events if e.module == "excavate"]
            url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
            dns_events = [e for e in events if e.type in ["DNS_NAME_UNRESOLVED", "DNS_NAME"]]
            protocol_events = [e for e in events if e.type == "PROTOCOL"]
            web_params = [e for e in events if e.type == "WEB_PARAMETER"]

            return {
                "events": events,
                "total_events": total_events,
                "excavate_events": len(excavate_events),
                "url_events": len(url_events),
                "dns_events": len(dns_events),
                "protocol_events": len(protocol_events),
                "web_params": len(web_params),
            }

        # Run the benchmark on the scan execution
        result = benchmark(run_excavate_scan)

        # Extract event counts from the result
        total_events = result["total_events"]
        excavate_events = result["excavate_events"]
        url_events = result["url_events"]
        dns_events = result["dns_events"]
        protocol_events = result["protocol_events"]
        web_params = result["web_params"]

        # Validate that excavate actually processed content and emitted events
        assert total_events > 0, "Expected to find some events from the scan"

        # Print detailed event counts
        print(f"\n✅ Full excavate benchmark completed")
        print(f"📊 Total events: {total_events}")
        print(f"📊 Excavate events (module=excavate): {excavate_events}")
        print(f"📊 URL events: {url_events}")
        print(f"📊 DNS events: {dns_events}")
        print(f"📊 Protocol events: {protocol_events}")
        print(f"📊 Web parameters: {web_params}")

        # Validate that excavate actually found and processed content
        # Look for events that excavate typically emits, not just module=excavate
        assert url_events > 0 or dns_events > 0 or protocol_events > 0, (
            "Expected excavate to find URLs, DNS names, or protocols"
        )
