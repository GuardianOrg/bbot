import re
from pathlib import Path
from subprocess import CalledProcessError
from urllib.parse import parse_qs, urlparse

from bbot.modules.base import BaseModule


class apkeep(BaseModule):
    watched_events = ["MOBILE_APP"]
    produced_events = ["FILESYSTEM", "FINDING"]
    flags = ["passive", "safe", "code-enum", "download"]
    meta = {
        "description": "Download Android applications with apkeep",
        "created_date": "2026-05-28",
        "author": "@guardian",
    }
    options = {
        "binary": "apkeep",
        "download_source": "google-play",
        "output_folder": "",
        "options": "",
        "google_email": "",
        "google_aas_token": "",
        "google_auth_token": "",
        "google_oauth_token": "",
        "google_accept_tos": False,
        "sleep_duration": 0,
        "parallel": 1,
        "timeout": 900,
    }
    options_desc = {
        "binary": "apkeep binary path",
        "download_source": "apkeep source: google-play, apk-pure, f-droid, or huawei-app-gallery",
        "output_folder": "Folder to download APKs to. If not specified, downloaded APKs will be deleted when the scan completes.",
        "options": "Comma-separated additional options passed to apkeep with -o",
        "google_email": "Google account email address for the google-play source",
        "google_aas_token": "Google AAS token for the google-play source",
        "google_auth_token": "Google auth token for the google-play source, e.g. from Aurora dispenser",
        "google_oauth_token": "Google OAuth token used by apkeep to retrieve a long-lived AAS token",
        "google_accept_tos": "Pass --accept-tos to apkeep for the google-play source",
        "sleep_duration": "Sleep duration in milliseconds before apkeep download requests",
        "parallel": "Number of parallel APK fetches used by apkeep",
        "timeout": "Idle timeout in seconds for apkeep downloads",
    }
    mobile_app_seed_scope_only = True

    async def setup(self):
        self.apkeep_bin = str(self.config.get("binary", "apkeep")).strip() or "apkeep"
        output_folder = self.config.get("output_folder", "")
        if output_folder:
            self.output_dir = Path(output_folder) / "apk_files"
        else:
            self.output_dir = self.scan.temp_dir / "apk_files"
        self.helpers.mkdir(self.output_dir)
        return await super().setup()

    async def filter_event(self, event):
        if event.type == "MOBILE_APP":
            if "android" not in event.tags and not self._is_android_app_event(event):
                return False, "event is not an android app"
        return True

    async def handle_event(self, event):
        app_id = self._app_id_from_event(event)
        if not app_id:
            self.warning(f"Unable to determine Android package id from mobile app event: {event.data}")
            return

        path = await self.download_apk(app_id)
        if path:
            tags = ["apk", "file"]
            suffix_tag = path.suffix.lower().lstrip(".")
            if suffix_tag and suffix_tag not in tags:
                tags.append(suffix_tag)
            await self.emit_event(
                {"path": str(path)},
                "FILESYSTEM",
                tags=tags,
                parent=event,
                context=f'{{module}} downloaded the mobile app "{app_id}" to: {path}',
            )
        else:
            await self.emit_download_failure(event, app_id)

    async def download_apk(self, app_id):
        app_dir = self.output_dir / app_id
        self.helpers.rm_rf(app_dir, ignore_errors=True)
        self.helpers.mkdir(app_dir)

        command = [
            self.apkeep_bin,
            "-a",
            app_id,
            "-d",
            str(self.config.get("download_source", "google-play") or "google-play"),
            "-r",
            str(int(self.config.get("parallel", 1) or 1)),
        ]
        google_play_args = self.google_play_args(command[command.index("-d") + 1])
        if google_play_args is None:
            return None
        command.extend(google_play_args)

        sleep_duration = int(self.config.get("sleep_duration", 0) or 0)
        if sleep_duration > 0:
            command.extend(["-s", str(sleep_duration)])

        extra_options = str(self.config.get("options", "") or "").strip()
        if extra_options:
            command.extend(["-o", extra_options])

        command.append(str(app_dir))

        try:
            result = await self.run_process(
                command,
                check=True,
                idle_timeout=int(self.config.get("timeout", 900) or 900),
                _log_stderr=False,
            )
        except FileNotFoundError:
            self.warning("apkeep binary was not found; cannot download mobile app APK")
            return None
        except CalledProcessError as e:
            self.warning(f'apkeep failed to download "{app_id}". STDOUT: {e.stdout} STDERR: {repr(e.stderr)}')
            return None

        candidates = sorted(
            (p for p in app_dir.iterdir() if p.is_file() and p.suffix.lower() in {".apk", ".xapk", ".apks"}),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            self.warning(
                f'apkeep completed without producing an APK/XAPK/APKS for "{app_id}". '
                f"STDOUT: {getattr(result, 'stdout', '')} STDERR: {repr(getattr(result, 'stderr', ''))}"
            )
            return None

        self.info(f'Downloaded "{app_id}" with apkeep to {candidates[0]}')
        return candidates[0]

    def _is_android_app_event(self, event):
        data = event.data if isinstance(event.data, dict) else {}
        app_id = self._app_id_from_event(event)
        app_url = str(data.get("url") or "").lower() if isinstance(event.data, dict) else str(event.data or "").lower()
        return "play.google.com/store/apps/details" in app_url or bool(self._is_package_id(app_id))

    def _app_id_from_event(self, event):
        data = event.data
        if isinstance(data, dict):
            app_id = str(data.get("id") or "").strip()
            if self._is_package_id(app_id):
                return app_id
            app_url = str(data.get("url") or "").strip()
        else:
            app_url = str(data or "").strip()
            app_id = app_url
            if self._is_package_id(app_id):
                return app_id

        parsed = urlparse(app_url)
        query_id = parse_qs(parsed.query).get("id", [""])[0].strip()
        if self._is_package_id(query_id):
            return query_id
        return ""

    def _is_package_id(self, app_id):
        return bool(re.match(r"^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_-]+)+$", str(app_id or "")))

    def google_play_args(self, source):
        if source != "google-play":
            return []

        email = str(self.config.get("google_email", "") or "").strip()
        aas_token = str(self.config.get("google_aas_token", "") or "").strip()
        auth_token = str(self.config.get("google_auth_token", "") or "").strip()
        oauth_token = str(self.config.get("google_oauth_token", "") or "").strip()
        if not email or not (aas_token or auth_token or oauth_token):
            self.warning(
                "apkeep google-play downloads require google_email and one of google_aas_token, "
                "google_auth_token, or google_oauth_token"
            )
            return None

        args = ["--email", email]
        if aas_token:
            args.extend(["--aas-token", aas_token])
        elif auth_token:
            args.extend(["--auth-token", auth_token])
        else:
            args.extend(["--oauth-token", oauth_token])

        if self.config.get("google_accept_tos", False):
            args.append("--accept-tos")
        return args

    async def emit_download_failure(self, event, app_id):
        severity = "medium" if "target" in event.tags else "info"
        await self.emit_event(
            {
                "host": app_id,
                "severity": severity,
                "category": "mobile-apk-analysis-failed",
                "title": f"Mobile APK analysis did not run for {app_id}",
                "description": (
                    f'An APK, XAPK, or APKS package could not be downloaded for "{app_id}", so downstream mobile file analysis modules could not inspect the application package. '
                    "This is not a vulnerability in the application by itself, but it creates an analysis gap: static mobile checks cannot review the manifest, permissions, embedded URLs, hardcoded secrets, exported components, certificates, or third-party libraries. "
                    "The package may require store authentication, may be unavailable in the selected region, may have a different package identifier, or may need to be supplied manually. "
                    "Confirm the package source and rerun analysis with a known-good artifact so mobile risks are not missed."
                ),
                "recommendation": (
                    "Confirm the package id and download source, provide any required store credentials, or run the "
                    "mobile APK analysis with a known-good APK artifact."
                ),
            },
            "FINDING",
            parent=event,
            context=f'{{module}} could not download the mobile app "{app_id}" for APK analysis',
        )
