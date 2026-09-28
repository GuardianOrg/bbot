from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from bbot.modules.filedownload import filedownload


@pytest.mark.asyncio
async def test_redirect_outside_scan_scope_does_not_emit_downloaded_artifact(tmp_path):
    destination = tmp_path / "download.md"
    destination.write_text("public third-party content")
    source = SimpleNamespace(type="URL_UNVERIFIED", data="https://docs.example.com/video.md")
    helpers = SimpleNamespace(download=AsyncMock(return_value=(destination, "https://www.youtube.com/playlist")))
    module = SimpleNamespace(
        make_filename=lambda url, content_type=None: ("video.md", destination, "https://docs.example.com"),
        helpers=helpers,
        scan=SimpleNamespace(in_scope=lambda url: url.startswith("https://docs.example.com/")),
        info=Mock(),
        make_event=Mock(),
        emit_event=AsyncMock(),
        files_downloaded=0,
        urls_downloaded=set(),
        max_filesize="10MB",
    )

    await filedownload.download_file(module, source.data, source_event=source)

    module.make_event.assert_not_called()
    module.emit_event.assert_not_awaited()
    assert not destination.exists()
    assert module.files_downloaded == 0


@pytest.mark.asyncio
async def test_same_scope_redirect_keeps_downloaded_artifact(tmp_path):
    destination = tmp_path / "download.md"
    destination.write_text("first-party content")
    source = SimpleNamespace(type="URL_UNVERIFIED", data="https://docs.example.com/old.md")
    file_event = object()
    module = SimpleNamespace(
        make_filename=lambda url, content_type=None: ("old.md", destination, "https://docs.example.com"),
        helpers=SimpleNamespace(download=AsyncMock(return_value=(destination, "https://docs.example.com/new.md"))),
        scan=SimpleNamespace(in_scope=lambda url: url.startswith("https://docs.example.com/")),
        info=Mock(),
        make_event=Mock(return_value=file_event),
        emit_event=AsyncMock(),
        files_downloaded=0,
        urls_downloaded=set(),
        max_filesize="10MB",
    )

    await filedownload.download_file(module, source.data, source_event=source)

    module.emit_event.assert_awaited_once_with(file_event)
    assert destination.exists()
    assert module.files_downloaded == 1
