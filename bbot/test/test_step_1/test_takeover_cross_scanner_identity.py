import asyncio
import json
from types import SimpleNamespace

from bbot.modules.dnsreaper import dnsreaper
from bbot.modules.subzy import subzy


def test_netlify_takeover_has_one_title_across_subzy_and_dnsreaper(tmp_path):
    host = "inquiry.cumberland.io"
    target_file = tmp_path / "targets.txt"
    output_file = tmp_path / "subzy.json"
    emitted = []
    files = iter((target_file, output_file))

    class TestSubzy(subzy):
        @property
        def helpers(self):
            return SimpleNamespace(tempfile=lambda *args, **kwargs: next(files))

        async def is_claimed_provider_host(self, *args, **kwargs):
            return False

    subzy_module = object.__new__(TestSubzy)
    subzy_module.binary = "subzy"
    subzy_module.concurrency = 1
    subzy_module.timeout = 5
    subzy_module.https = False
    subzy_module.verify_ssl = False
    subzy_module.resolver = ""

    async def subzy_process(*args, **kwargs):
        output_file.write_text(json.dumps([{"status": "vulnerable", "subdomain": host, "engine": "Netlify"}]))

    async def emit(data, event_type, parent_event, **kwargs):
        emitted.append((data, event_type))

    subzy_module.run_process = subzy_process
    subzy_module.emit_event = emit
    asyncio.run(subzy_module.handle_batch(SimpleNamespace(host=host)))

    class TestDnsreaper(dnsreaper):
        @property
        def helpers(self):
            return SimpleNamespace(tempfile=lambda *args, **kwargs: target_file)

    dnsreaper_module = object.__new__(TestDnsreaper)
    dnsreaper_module.binary = "dnsreaper"
    dnsreaper_module.parallelism = 1
    dnsreaper_module.timeout = 5
    dnsreaper_module.resolver = ""
    dnsreaper_module.disable_probable = False
    dnsreaper_module.enable_unlikely = False
    dnsreaper_module.signatures = []
    dnsreaper_module.exclude_signatures = []

    async def dnsreaper_process(*args, **kwargs):
        return SimpleNamespace(stdout=json.dumps([{"domain": host, "signature": "netlify", "confidence": "CONFIRMED"}]))

    dnsreaper_module.run_process = dnsreaper_process
    dnsreaper_module.emit_event = emit
    asyncio.run(dnsreaper_module.handle_batch(SimpleNamespace(host=host)))

    assert [(data["category"], event_type) for data, event_type in emitted] == [
        ("subdomain-takeover", "VULNERABILITY"),
        ("subdomain-takeover", "VULNERABILITY"),
    ]
    assert emitted[0][0]["title"] == emitted[1][0]["title"]
