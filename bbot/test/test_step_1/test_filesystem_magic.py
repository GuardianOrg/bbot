from bbot.core.helpers.libmagic import get_magic_info
from bbot.scanner import Scanner

UNIDENTIFIED_MAGIC = {
    "magic_extension": "",
    "magic_mime_type": "",
    "magic_description": "",
    "magic_confidence": 0,
}

def test_magic_info_treats_an_empty_file_as_unidentified(tmp_path):
    empty = tmp_path / "empty.apk"
    empty.write_bytes(b"")

    assert get_magic_info(empty) == ("", "", "", 0)

def test_filesystem_file_event_always_carries_magic_fields(tmp_path):
    # A zero-byte download used to leave the event without magic fields, crashing jadx.filter_event.
    empty = tmp_path / "empty.apk"
    empty.write_bytes(b"")
    unreadable = tmp_path / "unreadable.apk"
    unreadable.write_bytes(b"PK\x03\x04")
    unreadable.chmod(0)

    scan = Scanner()
    try:
        for path in (empty, unreadable):
            event = scan.make_event({"path": path}, "FILESYSTEM", parent=scan.root_event)
            assert event.data == {"path": str(path), **UNIDENTIFIED_MAGIC}
            assert event.tags == {"file"}
    finally:
        unreadable.chmod(0o600)
