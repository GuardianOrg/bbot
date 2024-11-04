import zipfile

from pathlib import Path
from .base import ModuleTestBase, tempapkfile


class TestExtractZip(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["filedownload", "httpx", "excavate", "speculate", "extract"]

    temp_path = Path("/tmp/.bbot_test")
    zip_file = temp_path / "test.zip"
    with zipfile.ZipFile(zip_file, "w") as z:
        z.writestr("test.txt", "This is a test file")

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            dict(uri="/"),
            dict(
                response_data='<a href="/test.zip"/>',
            ),
        )
        module_test.set_expect_requests(
            dict(uri="/test.zip"),
            dict(
                response_data=self.zip_file.read_bytes(),
                headers={"Content-Type": "application/zip"},
            ),
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]

        zip_file_event = [e for e in filesystem_events if "test.zip" in e.data["path"]]
        assert 1 == len(zip_file_event), "No zip file found"
        file = Path(zip_file_event[0].data["path"])
        assert file.is_file(), f"File not found at {file}"
        extract_event = [e for e in filesystem_events if "test_zip" in e.data["path"] and "folder" in e.tags]
        assert 1 == len(extract_event), "Failed to extract zip"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination folder doesn't exist"


class TestExtractApk(ModuleTestBase):
    modules_overrides = ["apkpure", "google_playstore", "speculate", "extract"]
    apk_file = tempapkfile()

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.99"]}})
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/search?q=blacklanternsecurity&c=apps",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>"blacklanternsecurity" - Android Apps on Google Play</title>
            </head>
            <body>
            <a href="/store/apps/details?id=com.bbot.test&pcampaignid=dontmatchme&pli=1"/>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.bbot.test",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>BBOT</title>
            </head>
            <body>
            <meta name="appstore:developer_url" content="https://www.blacklanternsecurity.com">
            </div>
            </div>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://d.apkpure.com/b/XAPK/com.bbot.test?version=latest",
            content=self.apk_file,
        )

    def check(self, module_test, events):
        extract_event = [
            e
            for e in events
            if e.type == "FILESYSTEM" and "com_bbot_test_xapk" in e.data["path"] and "folder" in e.tags
        ]
        assert 1 == len(extract_event), "Failed to extract apk"
        extract_path = Path(extract_event[0].data["path"])
        assert extract_path.is_dir(), "Destination apk doesn't exist"
