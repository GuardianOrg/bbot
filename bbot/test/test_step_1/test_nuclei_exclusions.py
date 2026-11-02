import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from bbot.modules.nuclei import nuclei

from ..bbot_fixtures import *


def make_setup_module(tmp_path, **options):
    binary = tmp_path / "nuclei"
    binary.touch()
    module = object.__new__(nuclei)
    module._name = "nuclei"
    module.scan = SimpleNamespace(
        config={"modules": {"nuclei": {"mode": "manual", **options}}},
        helpers=SimpleNamespace(
            tools_dir=tmp_path,
            mkdir=lambda path: path.mkdir(parents=True, exist_ok=True),
            which=lambda name: str(binary) if name == "nuclei" else None,
        ),
        temp_dir=tmp_path,
        web_config={},
    )
    for level in ("info", "warning", "success", "verbose", "debug"):
        setattr(module, level, lambda *args, **kwargs: None)

    async def no_extra_template_sources(*args, **kwargs):
        return []

    module.resolve_template_sources = no_extra_template_sources
    templates = tmp_path / "nuclei-templates"
    (templates / "http" / "osint").mkdir(parents=True)
    (templates / "http" / "osint" / "lookup.yaml").write_text("id: lookup\n")
    return module, templates


def test_setup_anchors_relative_exclusions_to_templates_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("BBOT_NUCLEI_UPDATE_TEMPLATES", raising=False)
    module, templates = make_setup_module(
        tmp_path,
        exclude_templates=" http/osint/, http/not-installed/ ,/abs/other.yaml,http/osint/",
        exclude_ids=" robots-txt, ,security-txt,robots-txt\n,  dmarc-detect",
    )
    assert asyncio.run(module.setup()) is True
    # an existing relative path becomes absolute; unknown or absolute entries are kept as given; duplicates collapse
    assert module.exclude_templates.split(",") == [
        str(templates / "http/osint/"),
        "http/not-installed/",
        "/abs/other.yaml",
    ]
    assert module.exclude_ids == "robots-txt,security-txt,dmarc-detect"
    assert module.bundled_template_dirs == []


def test_setup_adds_bundled_templates_only_when_enabled(tmp_path, monkeypatch):
    monkeypatch.delenv("BBOT_NUCLEI_UPDATE_TEMPLATES", raising=False)
    module, _ = make_setup_module(tmp_path, bundled_templates=True)
    assert asyncio.run(module.setup()) is True
    assert module.bundled_template_dirs == [nuclei.bundled_templates_dir.resolve()]
    assert (nuclei.bundled_templates_dir / "http" / "naxus-missing-security-headers.yaml").is_file()
    # bundled templates are not a user template source
    assert module.template_source_dirs == []


def make_command_module(scan, tmp_path):
    module = object.__new__(nuclei)
    module._name = "nuclei"
    module.scan = scan
    module.nuclei_templates_dir = tmp_path / "nuclei-templates"
    module.ratelimit = 1
    module.concurrency = 1
    module.retries = 0
    module.timeout = 1
    module.bulk_size = 1
    module.severity = ""
    module.iserver = None
    module.itoken = None
    module.tags = ""
    module.etags = ""
    module.exclude_types = ""
    module.exclude_templates = ""
    module.exclude_ids = ""
    module.mobile_template_source_dirs = []
    module.template_source_dirs = []
    module.bundled_template_dirs = []
    module.templates = ""
    module.mode = "manual"
    module.verbose_templates = False
    module.proxy = ""
    module.silent = True
    module._nuclei_env = lambda: {}
    commands = []

    async def capture(command, *args, **kwargs):
        commands.append([str(part) for part in command])
        return
        yield

    module.run_process_live = capture
    return module, commands


def option(command, flag):
    return command[command.index(flag) + 1] if flag in command else None


@pytest.mark.asyncio
async def test_command_passes_exclude_ids_and_bundled_templates(bbot_scanner, tmp_path, monkeypatch):
    scan = bbot_scanner("127.0.0.1")
    monkeypatch.setattr(scan.helpers, "tempfile_tail", lambda callback: tmp_path / "stats.log")
    module, commands = make_command_module(scan, tmp_path)
    bundled = tmp_path / "bundled"
    mobile = tmp_path / "mobile"

    [_ async for _ in module.execute_nuclei(["http://127.0.0.1/"])]
    assert option(commands[-1], "-eid") is None
    assert option(commands[-1], "-t") is None

    module.exclude_ids = "robots-txt,security-txt"
    module.exclude_templates = "/t/http/osint"
    module.bundled_template_dirs = [bundled]
    [_ async for _ in module.execute_nuclei(["http://127.0.0.1/"])]
    assert option(commands[-1], "-eid") == "robots-txt,security-txt"
    assert option(commands[-1], "-et") == "/t/http/osint"
    # the whole default tree still runs, plus the bundled directory
    assert option(commands[-1], "-t") == f"{module.nuclei_templates_dir},{bundled}"

    # explicit templates keep priority and still get the bundled directory
    module.templates = "/custom/one.yaml"
    [_ async for _ in module.execute_nuclei(["http://127.0.0.1/"])]
    assert option(commands[-1], "-t") == f"/custom/one.yaml,{bundled}"

    # a mobile-only batch must not pick up web templates through the bundled directory
    module.templates = ""
    module.mobile_template_source_dirs = [mobile]
    [_ async for _ in module.execute_nuclei(["/tmp/app.apk.txt"], include_mobile_templates=True)]
    assert option(commands[-1], "-t") == str(mobile)


@pytest.mark.asyncio
async def test_every_emitted_payload_names_its_template():
    url = "https://app.example.com/"
    parent_event = Mock(type="URL", data=url, host="app.example.com", resolved_hosts=set())
    emitted = []
    results = [
        {"severity": "INFO", "template": "waf-detect", "tags": ["waf", "tech"], "name": "cloudfront"},
        {"severity": "INFO", "template": "tech-detect", "tags": ["tech"], "name": "Nginx"},
        {
            "severity": "INFO",
            "template": "naxus-missing-security-headers",
            "tags": ["headers"],
            "name": "x-frame-options",
        },
        {"severity": "UNKNOWN", "template": "odd-template", "tags": [], "name": "Odd"},
        {"severity": "HIGH", "template": "generic-env", "tags": ["exposure"], "name": "Env file"},
    ]

    async def execute_nuclei(inputs, **_kwargs):
        for result in results:
            yield {**result, "host": url, "url": url, "matched_at": url}

    async def emit_event(data, event_type, _parent, **_kwargs):
        emitted.append((event_type, data))

    target = SimpleNamespace(add=lambda *_args: None, get=lambda *_args: None)
    subject = SimpleNamespace(
        _is_mobile_artifact=lambda _event: False,
        mobile_app_discovered=False,
        helpers=SimpleNamespace(make_target=lambda: target, is_ip=lambda _host: False, is_url=lambda _url: True),
        execute_nuclei=execute_nuclei,
        is_waf_detection_result=nuclei.is_waf_detection_result,
        is_takeover_result=lambda _result: False,
        emit_event=emit_event,
    )
    await nuclei.handle_batch(subject, parent_event)

    assert [(event_type, data["template"]) for event_type, data in emitted] == [
        ("WAF", "waf-detect"),
        ("TECHNOLOGY", "tech-detect"),
        ("FINDING", "naxus-missing-security-headers"),
        ("FINDING", "odd-template"),
        ("VULNERABILITY", "generic-env"),
    ]


def test_event_schemas_keep_the_template_id(bbot_scanner):
    scan = bbot_scanner("example.com")
    root = scan.root_event
    payloads = {
        "TECHNOLOGY": {"technology": "nginx", "host": "example.com", "template": "tech-detect"},
        "WAF": {"waf": "cloudflare", "url": "https://example.com/", "host": "example.com", "template": "waf-detect"},
        "FINDING": {"host": "example.com", "description": "x", "template": "robots-txt"},
        "VULNERABILITY": {"host": "example.com", "severity": "LOW", "description": "x", "template": "t"},
    }
    for event_type, data in payloads.items():
        event = scan.make_event(dict(data), event_type, parent=root)
        assert event.data["template"] == data["template"], event_type
    # the technology identity must not depend on which template found it
    a = scan.make_event({"technology": "nginx", "host": "example.com", "template": "a"}, "TECHNOLOGY", parent=root)
    b = scan.make_event({"technology": "nginx", "host": "example.com", "template": "b"}, "TECHNOLOGY", parent=root)
    assert a.id == b.id
