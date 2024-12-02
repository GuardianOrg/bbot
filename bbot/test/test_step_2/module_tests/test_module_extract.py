import zipfile
import bz2
import lzma
import tarfile

import py7zr
from librar import archive
import lz4.frame

from pathlib import Path
from .base import ModuleTestBase


class TestExtract(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["filedownload", "httpx", "excavate", "speculate", "extract"]
    temp_path = Path("/tmp/.bbot_test")

    # Create a text file to compress
    text_file = temp_path / "test.txt"
    with open(text_file, "w") as f:
        f.write("This is a test file")

    # ZIP
    zip_file = temp_path / "test.zip"
    with zipfile.ZipFile(zip_file, "w") as z:
        z.write(text_file, "test.txt")

    # BZ2
    bz2_file = temp_path / "test.bz2"
    with bz2.BZ2File(bz2_file, "wb") as b:
        with open(text_file, "rb") as f:
            b.write(f.read())

    # XZ
    xz_file = temp_path / "test.xz"
    with lzma.open(xz_file, "wb") as x:
        with open(text_file, "rb") as f:
            x.write(f.read())

    # 7Z
    seven_z_file = temp_path / "test.7z"
    with py7zr.SevenZipFile(seven_z_file, "w") as z:
        z.write(text_file, "test.txt")

    # RAR
    rar_file = temp_path / "test.rar"
    with archive.Archive(rar_file, base) as r:
        r.write(text_file, "test.txt")

    # LZMA
    lzma_file = temp_path / "test.lzma"
    with lzma.open(lzma_file, "wb") as l:
        with open(text_file, "rb") as f:
            l.write(f.read())

    # TAR
    tar_file = temp_path / "test.tar"
    with tarfile.open(tar_file, "w") as t:
        t.add(text_file, arcname="test.txt")

    # LZ4
    lz4_file = temp_path / "test.lz4"
    with open(text_file, "rb") as f:
        content = f.read()
        with lz4.frame.open(lz4_file, "wb") as l:
            l.write(content)

    # TAR.GZ
    tgz_file = temp_path / "test.tgz"
    with tarfile.open(tgz_file, "w:gz") as t:
        t.add(text_file, arcname="test.txt")

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            dict(uri="/"),
            dict(
                response_data="""<a href="/test.zip"/>
                <a href="/test.bz2"/>
                <a href="/test.xz"/>
                <a href="/test.7z"/>
                <a href="/test.rar"/>
                <a href="/test.lzma"/>
                <a href="/test.tar"/>
                <a href="/test.lz4"/>
                <a href="/test.tgz"/>"""
            ),
        )
        module_test.set_expect_requests(
            dict(uri="/test.zip"),
            dict(
                response_data=self.zip_file.read_bytes(),
                headers={"Content-Type": "application/zip"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.bz2"),
            dict(
                response_data=self.bz2_file.read_bytes(),
                headers={"Content-Type": "application/x-bzip2"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.xz"),
            dict(
                response_data=self.xz_file.read_bytes(),
                headers={"Content-Type": "application/x-xz"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.7z"),
            dict(
                response_data=self.seven_z_file.read_bytes(),
                headers={"Content-Type": "application/x-7z-compressed"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.rar"),
            dict(
                response_data=self.rar_file.read_bytes(),
                headers={"Content-Type": "application/vnd.rar"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.lzma"),
            dict(
                response_data=self.lzma_file.read_bytes(),
                headers={"Content-Type": "application/x-lzma"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.lz4"),
            dict(
                response_data=self.lz4_file.read_bytes(),
                headers={"Content-Type": "application/x-lz4"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.tar"),
            dict(
                response_data=self.tar_file.read_bytes(),
                headers={"Content-Type": "application/x-tar"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.tgz"),
            dict(
                response_data=self.tgz_file.read_bytes(),
                headers={"Content-Type": "application/x-tgz"},
            ),
        ),

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]

        # ZIP
        zip_file_event = [e for e in filesystem_events if "test.zip" in e.data["path"]]
        assert 1 == len(zip_file_event), "No zip file found"
        file = Path(zip_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_zip" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract zip"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # BZ2
        bz2_file_event = [e for e in filesystem_events if "test.bz2" in e.data["path"]]
        assert 1 == len(bz2_file_event), "No bz2 file found"
        file = Path(bz2_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_bz2" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract bz2"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # XZ
        xz_file_event = [e for e in filesystem_events if "test.xz" in e.data["path"]]
        assert 1 == len(xz_file_event), "No xz file found"
        file = Path(xz_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_xz" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract xz"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # 7Z
        seven_z_file_event = [e for e in filesystem_events if "test.7z" in e.data["path"]]
        assert 1 == len(seven_z_file_event), "No 7z file found"
        file = Path(seven_z_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_7z" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract 7z"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # RAR
        rar_file_event = [e for e in filesystem_events if "test.rar" in e.data["path"]]
        assert 1 == len(rar_file_event), "No rar file found"
        file = Path(rar_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_rar" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract rar"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # LZMA
        lzma_file_event = [e for e in filesystem_events if "test.lzma" in e.data["path"]]
        assert 1 == len(lzma_file_event), "No lzma file found"
        file = Path(lzma_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_lzma" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract lzma"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # LZ4
        lz4_file_event = [e for e in filesystem_events if "test.lz4" in e.data["path"]]
        assert 1 == len(lz4_file_event), "No lz4 file found"
        file = Path(lz4_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_lz4" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract lz4"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # TAR
        tar_file_event = [e for e in filesystem_events if "test.tar" in e.data["path"]]
        assert 1 == len(tar_file_event), "No tar file found"
        file = Path(tar_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_tar" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract tar"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"

        # TAR.GZ
        tgz_file_event = [e for e in filesystem_events if "test.tgz" in e.data["path"]]
        assert 1 == len(tgz_file_event), "No tgz file found"
        file = Path(tgz_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_tgz" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract tgz"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"
