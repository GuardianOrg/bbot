import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bbot.scanner import Scanner


@pytest.mark.parametrize('write_fails', [False, True])
def test_terminal_output_failure_is_reflected_in_final_scan_status(write_fails):
    scan = Scanner('127.0.0.1', output_modules=['python'], config={'deps': {'behavior': 'disable'}})
    scan._success = True
    scan.start_time = datetime.now()

    async def queue_terminal(event):
        if write_fails:
            scan.record_fatal_module_error('sqlite', 'terminal event write failed')

    output = SimpleNamespace(_type='output', name='sqlite', finished=True, queue_event=AsyncMock(side_effect=queue_terminal))
    scan.modules = {'sqlite': output}
    result = asyncio.run(scan._mark_finished())
    expected = 'FAILED' if write_fails else 'FINISHED'
    assert result.data['status'] == expected
    assert scan.status == expected
    assert scan._success is not write_fails
    assert scan._scan_finish_status_message.endswith('status ' + expected)
    output.queue_event.assert_awaited_once()
