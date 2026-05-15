import json
import shlex

from bbot.modules.base import BaseModule
from bbot.modules.templates.code_repository_scope import code_repository_scope
from bbot.modules.templates.github_leak_formatter import github_leak_formatter


class trufflehog(code_repository_scope, github_leak_formatter, BaseModule):
    watched_events = ["CODE_REPOSITORY", "FILESYSTEM"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["passive", "safe", "code-enum"]
    meta = {
        "description": "TruffleHog is a tool for finding credentials",
        "created_date": "2024-03-12",
        "author": "@domwhewell-sage",
    }

    options = {
        "version": "3.90.8",
        "config": "",
        "only_verified": True,
        "concurrency": 8,
        "deleted_forks": False,
    }
    options_desc = {
        "version": "trufflehog version",
        "config": "File path or URL to YAML trufflehog config",
        "only_verified": "Only report credentials that have been verified",
        "concurrency": "Number of concurrent workers",
        "deleted_forks": "Scan for deleted github forks. WARNING: This is SLOW. For a smaller repository, this process can take 20 minutes. For a larger repository, it could take hours.",
    }
    deps_apt = ["git"]
    deps_ansible = [
        {
            "name": "Download trufflehog",
            "shell": {
                "cmd": "set -e\nif [ -x \"#{BBOT_TOOLS}/trufflehog\" ]; then exit 0; fi\ntmpdir=\"$(mktemp -d)\"\ntrap 'rm -rf \"$tmpdir\"' EXIT\ncurl -fsSL --retry 3 --connect-timeout 20 --max-time 180 -o \"$tmpdir/trufflehog.tar.gz\" \"https://github.com/trufflesecurity/trufflehog/releases/download/v#{BBOT_MODULES_TRUFFLEHOG_VERSION}/trufflehog_#{BBOT_MODULES_TRUFFLEHOG_VERSION}_#{BBOT_OS_PLATFORM}_#{BBOT_CPU_ARCH_GOLANG}.tar.gz\"\ntar -xzf \"$tmpdir/trufflehog.tar.gz\" -C \"$tmpdir\" trufflehog\ninstall -m 0755 \"$tmpdir/trufflehog\" \"#{BBOT_TOOLS}/trufflehog\""
            },
        }
    ]

    scope_distance_modifier = 2

    async def setup_deps(self):
        self.config_file = self.config.get("config", "")
        if self.config_file:
            self.config_file = await self.helpers.wordlist(self.config_file)
        return True

    async def setup(self):
        self.setup_repository_scope()
        self.verified = self.config.get("only_verified", True)
        self.concurrency = int(self.config.get("concurrency", 8))

        self.deleted_forks = self.config.get("deleted_forks", False)
        self.github_token = ""
        if self.deleted_forks:
            self.warning(
                "Deleted forks is enabled. Scanning for deleted forks is slooooooowwwww. For a smaller repository, this process can take 20 minutes. For a larger repository, it could take hours."
            )
            for module_name in ("github", "github_codesearch", "github_org", "git_clone"):
                module_config = self.scan.config.get("modules", {}).get(module_name, {})
                api_key = module_config.get("api_key", "")
                if api_key:
                    self.github_token = api_key
                    break

            # soft-fail if we don't have a github token as well
            if not self.github_token:
                self.deleted_forks = False
                return None, "A github api_key must be provided to the github modules for deleted forks to be scanned"
        return True

    async def filter_event(self, event):
        if event.type == "CODE_REPOSITORY":
            if not self.is_code_repository_in_scope(event):
                return False, "CODE_REPOSITORY is outside configured repository owner/repo scope"
            if self.deleted_forks:
                if "git" not in event.tags:
                    return False, "Module only accepts git CODE_REPOSITORY events"
                if "github" not in event.data["url"]:
                    return False, "Module only accepts github CODE_REPOSITORY events"
            else:
                if "git" not in event.tags:
                    return False, "Module only accepts git CODE_REPOSITORY events"
        else:
            if "unarchived-folder" in event.tags:
                return False, "Not accepting unarchived-folder events"
        return True

    async def handle_event(self, event):
        description = ""
        if isinstance(event.data, dict):
            description = event.data.get("description", "")

        if event.type == "CODE_REPOSITORY":
            cleanup_path = None
            if self.deleted_forks:
                path = event.data["url"]
                module = "github-experimental"
            else:
                # Let TruffleHog scan the remote Git URL directly. Its Git scanner
                # walks reachable history and reports repository/file metadata,
                # while our old shallow local clone could silently miss test keys.
                path = event.data["url"]
                module = "git"
        elif event.type == "FILESYSTEM":
            cleanup_path = None
            path = event.data["path"]
            if "git" in event.tags:
                module = "git"
            elif "docker" in event.tags:
                module = "docker"
            elif "postman" in event.tags:
                module = "postman"
            else:
                module = "filesystem"
        elif event.type in ("HTTP_RESPONSE", "RAW_TEXT"):
            module = "filesystem"
            file_data = event.raw_response if event.type == "HTTP_RESPONSE" else event.data
            # write the response to a tempfile
            # this is necessary because trufflehog doesn't yet support reading from stdin
            # https://github.com/trufflesecurity/trufflehog/issues/162
            path = self.helpers.tempfile(file_data, pipe=False)
            cleanup_path = None

        if event.type == "CODE_REPOSITORY":
            host = event.host
        else:
            host = str(event.parent.host)
        async for (
            decoder_name,
            detector_name,
            raw_result,
            rawv2_result,
            verified,
            source_metadata,
        ) in self.execute_trufflehog(module, path):
            metadata_items = source_metadata if isinstance(source_metadata, list) else [source_metadata]
            git_meta = {}
            for metadata_item in metadata_items:
                if not isinstance(metadata_item, dict):
                    continue
                data_item = metadata_item.get("Data") if isinstance(metadata_item.get("Data"), dict) else metadata_item
                if isinstance(data_item, dict) and isinstance(data_item.get("Git"), dict):
                    git_meta = data_item["Git"]
                    break
            data = None
            if host == "github.com" and git_meta:
                data = await self.format_github_leak(
                    event,
                    path,
                    raw_result,
                    detector=detector_name,
                    file_path=git_meta.get("file") or "",
                    line=git_meta.get("line") or "",
                    commit=git_meta.get("commit") or "",
                    verified=verified,
                    severity="High" if verified else "Medium",
                    finding_details=source_metadata,
                    extra_fields={
                        "decoder": decoder_name,
                    },
                )
            if data is None:
                verified_str = "Verified" if verified else "Possible"
                data = {
                    "description": f"{verified_str} Secret Found. Detector Type: [{detector_name}] Decoder Type: [{decoder_name}] Details: [{source_metadata}]",
                }
                if host:
                    data["host"] = host
                if verified:
                    data["severity"] = "High"
                if description:
                    data["description"] += f" Description: [{description}]"
                if raw_result:
                    data["description"] += f" Raw result: [{raw_result}]"
                    data["secretValue"] = raw_result
                    data["secret_value"] = raw_result
                if rawv2_result:
                    data["description"] += f" RawV2 result: [{rawv2_result}]"
            await self.emit_event(
                data,
                "FINDING" if data.get("force_finding") else ("VULNERABILITY" if verified else "FINDING"),
                event,
                context=f'{{module}} searched {event.type} using "{module}" method and found secret ({{event.type}})',
            )

        # clean up the tempfile when we're done with it
        if event.type in ("HTTP_RESPONSE", "RAW_TEXT"):
            path.unlink(missing_ok=True)
        elif cleanup_path is not None and cleanup_path.exists():
            self.helpers.rm_rf(cleanup_path, ignore_errors=True)

    async def execute_trufflehog(self, module, path=None, string=None):
        command = [
            str(self.helpers.tools_dir / "trufflehog"),
            "--json",
            "--no-update",
        ]
        if self.verified:
            command.append("--only-verified")
        if self.config_file:
            command.append("--config=" + str(self.config_file))
        command.append("--concurrency=" + str(self.concurrency))
        if module == "git":
            command.append("git")
            path = str(path)
            if path.startswith(("http://", "https://", "ssh://", "git@")):
                command.append(path)
            else:
                command.append("file://" + path)
        elif module == "docker":
            command.append("docker")
            command.append("--image=file://" + path)
        elif module == "postman":
            command.append("postman")
            command.append("--workspace-paths=" + path)
        elif module == "filesystem":
            command.append("filesystem")
            command.append(path)
        elif module == "github-experimental":
            command.append("github-experimental")
            command.append("--repo=" + path)
            command.append("--object-discovery")
            command.append("--delete-cached-data")
            command.append("--token=" + self.github_token)

        result = await self.run_process(
            ["bash", "-lc", " ".join(shlex.quote(str(part)) for part in command)],
            env={"HOME": str(self.scan.home), "PATH": f"{self.helpers.tools_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            _log_stderr=False,
        )
        self.debug(
            f"TruffleHog command completed rc={getattr(result, 'returncode', '?')} "
            f"stdout_bytes={len(str(getattr(result, 'stdout', '') or ''))} "
            f"stderr_bytes={len(str(getattr(result, 'stderr', '') or ''))}"
        )
        for line in str(getattr(result, "stdout", "") or "").splitlines():
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue

            decoder_name = j.get("DecoderName", "")
            detector_name = j.get("DetectorName", "")
            raw_result = j.get("Raw", "")
            rawv2_result = j.get("RawV2", "")
            verified = j.get("Verified", False)
            source_metadata = j.get("SourceMetadata", {})
            yield (decoder_name, detector_name, raw_result, rawv2_result, verified, source_metadata)

        stderr = str(getattr(result, "stderr", "") or "")
        for line in stderr.splitlines():
            self.log_trufflehog_status(path, line)

    def log_trufflehog_status(self, path, line):
        try:
            line = json.loads(line)
        except Exception:
            self.info(str(line))
            return
        message = line.get("msg", "")
        ts = line.get("ts", "")
        status = f"Message: {message} | Timestamp: {ts}"
        self.verbose(f"Current scan target: {path}")
        self.verbose(status)
