from pathlib import Path
from subprocess import CompletedProcess

from .base import ModuleTestBase, tempapkfile
from bbot.test.bbot_fixtures import bbot_test_dir


class TestApkeep(ModuleTestBase):
    modules_overrides = ["apkeep", "google_playstore", "speculate"]
    config_overrides = {
        "modules": {
            "apkeep": {
                "output_folder": str(bbot_test_dir / "test_apkeep_files"),
                "google_email": "test@example.com",
                "google_aas_token": "test-aas-token",
            }
        }
    }
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

        async def fake_run_process(command, *args, **kwargs):
            output_dir = Path(command[-1])
            output_dir.mkdir(parents=True, exist_ok=True)
            with open(output_dir / "com.bbot.test.apk", "wb") as f:
                f.write(self.apk_file)
            return CompletedProcess(command, 0, stdout="com.bbot.test downloaded successfully!", stderr="")

        module_test.monkeypatch.setattr(module_test.scan.modules["apkeep"], "run_process", fake_run_process)

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "MOBILE_APP"
                and "android" in e.tags
                and e.data["id"] == "com.bbot.test"
                and e.data["url"] == "https://play.google.com/store/apps/details?id=com.bbot.test"
            ]
        ), "Failed to find bbot android app"
        filesystem_event = [e for e in events if e.type == "FILESYSTEM" and "com.bbot.test.apk" in e.data["path"]]
        assert 1 == len(filesystem_event), "Failed to download apk"
        file = Path(filesystem_event[0].data["path"])
        assert file.is_file(), "Destination apk doesn't exist"
        assert "apk" in filesystem_event[0].tags
        assert "file" in filesystem_event[0].tags


class TestApkeepDirectPlayStoreUrl(ModuleTestBase):
    targets = ["MOBILE_APP:https://play.google.com/store/apps/details?id=com.bbot.test"]
    modules_overrides = ["apkeep"]
    config_overrides = {
        "modules": {
            "apkeep": {
                "output_folder": str(bbot_test_dir / "test_apkeep_direct_files"),
                "google_email": "test@example.com",
                "google_aas_token": "test-aas-token",
            }
        }
    }
    apk_file = tempapkfile()

    async def setup_after_prep(self, module_test):
        seen_commands = []

        async def fake_run_process(command, *args, **kwargs):
            seen_commands.append(command)
            output_dir = Path(command[-1])
            output_dir.mkdir(parents=True, exist_ok=True)
            with open(output_dir / "com.bbot.test.apk", "wb") as f:
                f.write(self.apk_file)
            return CompletedProcess(command, 0, stdout="com.bbot.test downloaded successfully!", stderr="")

        module_test.seen_commands = seen_commands
        module_test.monkeypatch.setattr(module_test.scan.modules["apkeep"], "run_process", fake_run_process)

    def check(self, module_test, events):
        assert module_test.seen_commands, "apkeep was not invoked"
        command = module_test.seen_commands[0]
        assert command[:3] == ["apkeep", "-a", "com.bbot.test"]
        assert command[command.index("-d") + 1] == "google-play"
        assert command[command.index("--email") + 1] == "test@example.com"
        assert command[command.index("--aas-token") + 1] == "test-aas-token"
        assert "https://play.google.com" not in command
        filesystem_event = [e for e in events if e.type == "FILESYSTEM" and "com.bbot.test.apk" in e.data["path"]]
        assert 1 == len(filesystem_event), "Failed to download apk from direct Play Store URL seed"
        assert Path(filesystem_event[0].data["path"]).is_file(), "Destination apk doesn't exist"


class TestApkeepDirectPlayStoreUrlFailureFinding(ModuleTestBase):
    targets = ["MOBILE_APP:https://play.google.com/store/apps/details?id=com.bbot.test"]
    modules_overrides = ["apkeep"]

    def check(self, module_test, events):
        findings = [
            e
            for e in events
            if e.type == "FINDING"
            and e.data.get("category") == "mobile-apk-analysis-failed"
            and e.data.get("host") == "com.bbot.test"
        ]
        assert 1 == len(findings), "Failed APK downloads must emit a visible scan-coverage finding"
        assert findings[0].data.get("severity") == "medium"
