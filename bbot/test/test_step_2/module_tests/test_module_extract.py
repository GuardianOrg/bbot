import subprocess

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
    zip_file = temp_path / "test.zip"
    zip_zip_file = temp_path / "test_zip.zip"
    bz2_file = temp_path / "test.bz2"
    xz_file = temp_path / "test.xz"
    zip7_file = temp_path / "test.7z"
    rar_file = temp_path / "test.rar"
    lzma_file = temp_path / "test.lzma"
    tar_file = temp_path / "test.tar"
    tgz_file = temp_path / "test.tgz"
    commands = [
        ("7z", "a", '-p""', "-aoa", f"{zip_file}", f"{text_file}"),
        ("7z", "a", '-p""', "-aoa", f"{zip_zip_file}", f"{zip_file}"),
        ("tar", "-C", f"{temp_path}", "-cvjf", f"{bz2_file}", f"{text_file.name}"),
        ("tar", "-C", f"{temp_path}", "-cvJf", f"{xz_file}", f"{text_file.name}"),
        ("7z", "a", '-p""', "-aoa", f"{zip7_file}", f"{text_file}"),
        ("rar", "a", f"{rar_file}", f"{text_file}"),
        ("tar", "-C", f"{temp_path}", "--lzma", "-cvf", f"{lzma_file}", f"{text_file.name}"),
        ("tar", "-C", f"{temp_path}", "-cvf", f"{tar_file}", f"{text_file.name}"),
        ("tar", "-C", f"{temp_path}", "-cvzf", f"{tgz_file}", f"{text_file.name}"),
    ]

    for command in commands:
        subprocess.run(command, check=True)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            dict(uri="/"),
            dict(
                response_data="""<a href="/test.zip">
                <a href="/test-zip.zip">
                <a href="/test.bz2">
                <a href="/test.xz">
                <a href="/test.7z">
                <a href="/test.rar">
                <a href="/test.lzma">
                <a href="/test.tar">
                <a href="/test.tgz">""",
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
            dict(uri="/test-zip.zip"),
            dict(
                response_data=self.zip_zip_file.read_bytes(),
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
                response_data=self.zip7_file.read_bytes(),
                headers={"Content-Type": "application/x-7z-compressed"},
            ),
        ),
        module_test.set_expect_requests(
            dict(uri="/test.rar"),
            dict(
                response_data=self.zip7_file.read_bytes(),
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
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # Recursive ZIP
        zip_zip_file_event = [e for e in filesystem_events if "test-zip.zip" in e.data["path"]]
        assert 1 == len(zip_zip_file_event), "No recursive file found"
        file = Path(zip_zip_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test-zip_zip" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract zip"
        extract_path = Path(extract_event[0].data["path"]) / "test" / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # BZ2
        bz2_file_event = [e for e in filesystem_events if "test.bz2" in e.data["path"]]
        assert 1 == len(bz2_file_event), "No bz2 file found"
        file = Path(bz2_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_bz2" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract bz2"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # XZ
        xz_file_event = [e for e in filesystem_events if "test.xz" in e.data["path"]]
        assert 1 == len(xz_file_event), "No xz file found"
        file = Path(xz_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_xz" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract xz"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # 7z
        zip7_file_event = [e for e in filesystem_events if "test.7z" in e.data["path"]]
        assert 1 == len(zip7_file_event), "No 7z file found"
        file = Path(zip7_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_7z" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract 7z"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # RAR
        rar_file_event = [e for e in filesystem_events if "test.rar" in e.data["path"]]
        assert 1 == len(rar_file_event), "No rar file found"
        file = Path(rar_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_rar" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract rar"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # LZMA
        lzma_file_event = [e for e in filesystem_events if "test.lzma" in e.data["path"]]
        assert 1 == len(lzma_file_event), "No lzma file found"
        file = Path(lzma_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_lzma" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract lzma"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # TAR
        tar_file_event = [e for e in filesystem_events if "test.tar" in e.data["path"]]
        assert 1 == len(tar_file_event), "No tar file found"
        file = Path(tar_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_tar" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract tar"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"

        # TGZ
        tgz_file_event = [e for e in filesystem_events if "test.tgz" in e.data["path"]]
        assert 1 == len(tgz_file_event), "No tgz file found"
        file = Path(tgz_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_tgz" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract tgz"
        extract_path = Path(extract_event[0].data["path"]) / "test.txt"
        assert extract_path.is_file(), "Failed to extract the test file"
