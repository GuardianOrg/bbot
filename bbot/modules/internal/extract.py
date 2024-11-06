import zipfile

from pathlib import Path
from subprocess import CalledProcessError
from bbot.modules.internal.base import BaseInternalModule


class extract(BaseInternalModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive"]
    meta = {
        "description": "Extract different types of files into folders on the filesystem",
        "created_date": "2024-11-04",
        "author": "@domwhewell-sage",
    }
    options = {
        "threads": 4,
    }
    options_desc = {
        "threads": "Maximum jadx threads for extracting apk's, default: 4",
    }
    deps_ansible = [
        {
            "name": "Install latest JRE (Debian)",
            "package": {"name": ["default-jre"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian'",
        },
        {
            "name": "Install latest JRE (Arch)",
            "package": {"name": ["jre-openjdk"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Archlinux'",
        },
        {
            "name": "Install latest JRE (Fedora)",
            "package": {"name": ["java-openjdk-headless"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'RedHat'",
        },
        {
            "name": "Install latest JRE (Alpine)",
            "package": {"name": ["openjdk11"], "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Alpine'",
        },
        {
            "name": "Download jadx",
            "unarchive": {
                "src": "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
                "include": "bin/jadx",
                "dest": "#{BBOT_TOOLS}",
                "extra_opts": "-j",
                "remote_src": True,
            },
        },
    ]

    zipcompressed = ["doc", "dot", "docm", "docx", "ppt", "pptm", "pptx", "xls", "xlt", "xlsm", "xlsx", "zip"]
    jadx = ["xapk", "apk"]
    allowed_extensions = zipcompressed + jadx

    async def setup(self):
        self.threads = self.config.get("threads", 4)
        return True

    async def filter_event(self, event):
        if "file" in event.tags:
            if not any(event.data["path"].endswith(f".{ext}") for ext in self.allowed_extensions):
                return False, "Extract unable to handle file type"
        else:
            return False, "Event is not a file"
        return True

    async def handle_event(self, event):
        path = Path(event.data["path"])
        extension = path.suffix.strip(".").lower()
        output_dir = path.parent / path.name.replace(".", "_")
        self.helpers.mkdir(output_dir)

        # Use the appropriate extraction method based on the file type
        self.info(f"Extracting {path} to {output_dir}")
        if extension in self.zipcompressed:
            success = self.extract_zip_file(path, output_dir)
        elif extension in self.jadx:
            success = await self.decompile_apk(path, output_dir)

        # If the extraction was successful, emit the event
        if success:
            await self.emit_event(
                {"path": str(output_dir)},
                "FILESYSTEM",
                tags="folder",
                parent=event,
                context=f'extracted "{path}" to: {output_dir}',
            )
        else:
            output_dir.rmdir()

    def extract_zip_file(self, path, output_dir):
        try:
            with zipfile.ZipFile(path, "r") as zip_ref:
                zip_ref.extractall(output_dir)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    async def decompile_apk(self, path, output_dir):
        command = ["jadx", "--threads-count", self.threads, "--output-dir", str(output_dir), str(path)]
        try:
            output = await self.run_process(command, check=True)
        except CalledProcessError as e:
            self.warning(f"Error decompiling {path}. STDERR: {repr(e.stderr)}")
            return False
        if not Path(output_dir / "resources").exists() and not Path(output_dir / "sources").exists():
            self.warning(f"JADX was unable to decompile {path}.")
            self.warning(output)
            return False
        return True
