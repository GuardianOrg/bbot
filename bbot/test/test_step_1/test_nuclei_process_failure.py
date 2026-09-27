from contextlib import nullcontext
from subprocess import CalledProcessError

import pytest

from bbot.modules.nuclei import nuclei

from ..bbot_fixtures import *


@pytest.mark.asyncio
@pytest.mark.parametrize("binary,should_fail", [("/usr/bin/false", True), ("/usr/bin/true", False)])
async def test_nuclei_process_exit_is_not_reported_as_empty_results(
    bbot_scanner, tmp_path, monkeypatch, binary, should_fail
):
    scan = bbot_scanner("127.0.0.1")
    module = object.__new__(nuclei)
    module._name = "nuclei"
    module.scan = scan
    module.nuclei_templates_dir = tmp_path
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
    module.mobile_template_source_dirs = []
    module.template_source_dirs = []
    module.templates = str(tmp_path / "nuclei-test.yaml")
    module.mode = "manual"
    module.verbose_templates = False
    module.proxy = ""
    module.silent = True
    module._nuclei_env = lambda: {}
    monkeypatch.setattr(scan.helpers, "tempfile_tail", lambda callback: tmp_path / "stats.log")

    async def failed_nuclei_process(command, *args, **kwargs):
        async for line in scan.helpers.run_live([binary], check=kwargs.get("check", False)):
            yield line

    module.run_process_live = failed_nuclei_process

    expected = pytest.raises(CalledProcessError) if should_fail else nullcontext()
    with expected:
        assert [result async for result in module.execute_nuclei(["http://127.0.0.1:8888/"])] == []
