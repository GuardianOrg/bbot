from unittest.mock import AsyncMock

import pytest

from bbot import cli
from bbot.errors import ScanError
from bbot.scanner import Scanner


@pytest.mark.asyncio
async def test_cli_dry_run_succeeds_after_preparation_without_a_finish_event(monkeypatch, tmp_path):
    monkeypatch.setattr('sys.argv', [
        'bbot', '-t', '127.0.0.1', '-m', 'robots', '-om', 'python',
        '-c', f'home={tmp_path}', 'deps.behavior=disable', '--dry-run', '-y',
    ])
    prep = AsyncMock(return_value=None)
    run = AsyncMock()
    monkeypatch.setattr(Scanner, '_prep', prep)
    monkeypatch.setattr(Scanner, 'async_start_without_generator', run)
    assert await cli._main() is True
    prep.assert_awaited_once()
    run.assert_not_awaited()


@pytest.mark.asyncio
async def test_cli_dry_run_keeps_preparation_failures_unsuccessful(monkeypatch, tmp_path):
    monkeypatch.setattr('sys.argv', [
        'bbot', '-t', '127.0.0.1', '-m', 'robots', '-om', 'python',
        '-c', f'home={tmp_path}', 'deps.behavior=disable', '--dry-run', '-y',
    ])
    monkeypatch.setattr(Scanner, '_prep', AsyncMock(side_effect=ScanError('required module failed')))
    assert not await cli._main()


def test_cli_preparation_failure_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.setattr('sys.argv', [
        'bbot', '-t', '127.0.0.1', '-m', 'robots', '-om', 'python',
        '-c', f'home={tmp_path}', 'deps.behavior=disable', '--dry-run', '-y',
    ])
    monkeypatch.setattr(Scanner, '_prep', AsyncMock(side_effect=ScanError('required module failed')))
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 1


def test_cli_invalid_arguments_exit_nonzero(monkeypatch):
    from bbot.errors import BBOTArgumentError
    from bbot.scanner.preset import Preset

    monkeypatch.setattr(Preset, 'parse_args', lambda *_args: (_ for _ in ()).throw(BBOTArgumentError('invalid arguments')))
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 1


def test_cli_cancelled_scan_exits_nonzero(monkeypatch):
    import asyncio

    async def cancelled():
        raise asyncio.CancelledError

    monkeypatch.setattr(cli, '_main', cancelled)
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 1
