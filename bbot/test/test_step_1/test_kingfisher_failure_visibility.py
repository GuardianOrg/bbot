import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bbot.modules.kingfisher import kingfisher


def scanner(result):
    module = object.__new__(kingfisher)
    module.jobs = 1
    module.run_process = AsyncMock(return_value=result)
    module.error = lambda *args, **kwargs: None
    return module


@pytest.mark.parametrize('result', [
    SimpleNamespace(returncode=1, stdout='', stderr='scan failed'),
    SimpleNamespace(returncode=0, stdout='{not json}', stderr=''),
    SimpleNamespace(returncode=0, stdout='{"error":"unknown output"}', stderr=''),
    SimpleNamespace(returncode=200, stdout='', stderr=''),
    SimpleNamespace(returncode=200, stdout='{"findings":[{"finding":null}]}', stderr=''),
])
def test_single_file_scan_failure_is_not_an_empty_success(result):
    module = scanner(result)

    async def run():
        return [finding async for finding in module.iter_findings('/tmp/fixture', SimpleNamespace())]

    with pytest.raises(RuntimeError, match='Kingfisher'):
        asyncio.run(run())
    assert module.fatal_on_error is True


def test_quiet_clean_scan_stays_a_success():
    module = scanner(SimpleNamespace(returncode=0, stdout='', stderr=''))
    assert asyncio.run(module.run_kingfisher(['/tmp/fixture'])) == []


def test_individual_fallback_finishes_other_inputs_and_then_fails():
    module = scanner(SimpleNamespace())
    seen = []
    module._name = 'kingfisher'

    async def handle_event(event):
        seen.append(event)
        if event == 'bad':
            raise RuntimeError('unreadable input')

    module.handle_event = handle_event
    files = {'bad': ('bad', None), 'good': ('good', None)}
    with pytest.raises(RuntimeError, match='failed'):
        asyncio.run(module.rescan_individually(files, 'the batched scan failed'))
    assert seen == ['bad', 'good']


def test_partial_single_file_report_keeps_valid_findings_before_failure():
    module = scanner(SimpleNamespace(returncode=200, stdout='{"findings":[{"finding":{"path":"fixture"}},7]}', stderr=''))
    module.format_record = AsyncMock(return_value={'title': 'valid fixture finding'})
    findings = []

    async def collect():
        with pytest.raises(RuntimeError, match='Kingfisher'):
            async for finding in module.iter_findings('/tmp/fixture', SimpleNamespace()):
                findings.append(finding)

    asyncio.run(collect())
    assert findings == [{'title': 'valid fixture finding'}]


def test_partial_batch_report_keeps_individual_fallback_available():
    module = scanner(SimpleNamespace(returncode=200, stdout='{"findings":[{"finding":{"path":"fixture"}},7]}', stderr=''))
    assert asyncio.run(module.scan_file_batch(['/tmp/fixture'])) is None
