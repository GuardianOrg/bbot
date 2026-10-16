import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bbot.modules.gitleaks import gitleaks
from bbot.modules.trufflehog import trufflehog


@pytest.mark.parametrize('returncode,report', [(1, '[]'), (0, '{bad json}'), (0, '{}'), (0, '[7]')])
def test_gitleaks_failure_is_not_clean(tmp_path, returncode, report):
    output = tmp_path / 'report.json'
    output.write_text(report)
    module = object.__new__(gitleaks)
    module.scan = SimpleNamespace(helpers=SimpleNamespace(temp_filename=lambda **kwargs: output))
    module.redact = False
    module.config_file = ''
    module.disabled_rules = set()
    module.run_process = AsyncMock(return_value=SimpleNamespace(returncode=returncode))

    async def collect():
        return [finding async for finding in module.iter_findings(tmp_path, SimpleNamespace(type='FILESYSTEM'))]

    with pytest.raises(RuntimeError, match='Gitleaks'):
        asyncio.run(collect())
    assert module.fatal_on_error
    assert not output.exists()


@pytest.mark.parametrize('report', ['[]', 'null'])
def test_gitleaks_valid_empty_report_is_clean(tmp_path, report):
    output = tmp_path / 'report.json'
    output.write_text(report)
    module = object.__new__(gitleaks)
    module.scan = SimpleNamespace(helpers=SimpleNamespace(temp_filename=lambda **kwargs: output))
    module.redact = False
    module.config_file = ''
    module.disabled_rules = set()
    module.run_process = AsyncMock(return_value=SimpleNamespace(returncode=0))

    async def collect():
        return [finding async for finding in module.iter_findings(tmp_path, SimpleNamespace(type='FILESYSTEM'))]

    assert asyncio.run(collect()) == []


def test_gitleaks_missing_report_preserves_killed_process_diagnostic(tmp_path):
    output = tmp_path / 'missing-report.json'
    module = object.__new__(gitleaks)
    module.scan = SimpleNamespace(helpers=SimpleNamespace(temp_filename=lambda **kwargs: output))
    module.redact = False
    module.config_file = ''
    module.disabled_rules = set()
    module.run_process = AsyncMock(return_value=SimpleNamespace(returncode=-9, stderr='killed'))

    async def collect():
        return [finding async for finding in module.iter_findings(tmp_path, SimpleNamespace(type='FILESYSTEM'))]

    with pytest.raises(RuntimeError, match=r'Gitleaks report could not be read \(exit -9; FileNotFoundError\)'):
        asyncio.run(collect())
    assert module.run_process.await_count == 1


def truffle_module(returncode, stdout):
    module = object.__new__(trufflehog)
    module.scan = SimpleNamespace(home=Path('/tmp/fixture'), helpers=SimpleNamespace(tools_dir=Path('/tmp/tools')))
    module.verified = False
    module.config_file = ''
    module.concurrency = 1
    module.debug = lambda *args: None
    module.run_process = AsyncMock(return_value=SimpleNamespace(returncode=returncode, stdout=stdout, stderr=''))
    return module


@pytest.mark.parametrize('returncode,stdout', [(1, ''), (0, '{bad json}'), (0, '[]')])
def test_trufflehog_failure_is_not_clean(returncode, stdout):
    module = truffle_module(returncode, stdout)

    async def collect():
        return [finding async for finding in module.execute_trufflehog('filesystem', '/tmp/fixture')]

    with pytest.raises(RuntimeError, match='TruffleHog'):
        asyncio.run(collect())
    assert module.fatal_on_error


def test_trufflehog_valid_empty_output_is_clean():
    module = truffle_module(0, '')

    async def collect():
        return [finding async for finding in module.execute_trufflehog('filesystem', '/tmp/fixture')]

    assert asyncio.run(collect()) == []


def test_trufflehog_partial_report_retains_valid_observations():
    module = truffle_module(1, '{bad json}\n{"DetectorName":"fixture","Raw":"fixture-secret","Verified":false}')
    findings = []

    async def collect():
        with pytest.raises(RuntimeError, match='TruffleHog'):
            async for finding in module.execute_trufflehog('filesystem', '/tmp/fixture'):
                findings.append(finding)

    asyncio.run(collect())
    assert len(findings) == 1
    assert findings[0][1] == 'fixture'


@pytest.mark.parametrize('verified', [False, True])
def test_trufflehog_success_preserves_verification_evidence(verified):
    import json
    module = truffle_module(0, json.dumps({'DetectorName': 'fixture', 'Raw': 'fixture-secret', 'Verified': verified}))

    async def collect():
        return [finding async for finding in module.execute_trufflehog('filesystem', '/tmp/fixture')]

    findings = asyncio.run(collect())
    assert len(findings) == 1
    assert findings[0][4] is verified


def test_gitleaks_partial_report_retains_valid_observations(tmp_path):
    output = tmp_path / 'report.json'
    output.write_text('[7,{"RuleID":"fixture","Secret":"fixture-secret"}]')
    module = object.__new__(gitleaks)
    module.scan = SimpleNamespace(helpers=SimpleNamespace(temp_filename=lambda **kwargs: output))
    module.redact = False
    module.config_file = ''
    module.disabled_rules = set()
    module.run_process = AsyncMock(return_value=SimpleNamespace(returncode=1))
    module.format_github_leak = AsyncMock(return_value={'title': 'fixture finding'})
    findings = []

    async def collect():
        with pytest.raises(RuntimeError, match='Gitleaks'):
            async for finding in module.iter_findings(tmp_path, SimpleNamespace(type='FILESYSTEM')):
                findings.append(finding)

    asyncio.run(collect())
    assert findings == [{'title': 'fixture finding'}]
