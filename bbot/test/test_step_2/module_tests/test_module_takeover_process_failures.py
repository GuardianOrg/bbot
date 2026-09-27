import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from bbot.modules.dnsreaper import dnsreaper
from bbot.modules.domain_config_dns_audit import domain_config_dns_audit
from bbot.modules.nuclei_takeover import nuclei_takeover
from bbot.modules.subzy import subzy
from bbot.modules.subfinder import subfinder

from .base import ModuleTestBase


class _TakeoverFailureBase(ModuleTestBase):
    config_overrides = {"deps": {"behavior": "disable"}}

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def fake_install_core_deps(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, "install_core_deps", fake_install_core_deps)

    async def setup_after_prep(self, module_test):
        async def failed_run_process(cmd, *args, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="takeover scanner failed")

        module_test.monkeypatch.setattr(module_test.module, "run_process", failed_run_process)

    def check(self, module_test, events):
        assert module_test.scan.finish_event().data["status"] == "FAILED"
        assert not any(event.type == "VULNERABILITY" for event in events)


class TestDnsreaperFailedProcess(_TakeoverFailureBase):
    module_name = "dnsreaper"
    config_overrides = {
        **_TakeoverFailureBase.config_overrides,
        "modules": {"dnsreaper": {"binary": "/bin/echo"}},
    }


class TestSubzyFailedProcess(_TakeoverFailureBase):
    module_name = "subzy"
    config_overrides = {
        **_TakeoverFailureBase.config_overrides,
        "modules": {"subzy": {"binary": "/bin/echo"}},
    }


class TestDnsreaperTimeout(TestDnsreaperFailedProcess):
    async def setup_after_prep(self, module_test):
        async def timed_out_run_process(cmd, *args, **kwargs):
            raise asyncio.TimeoutError

        module_test.monkeypatch.setattr(module_test.module, "run_process", timed_out_run_process)


class TestDnsreaperMalformedOutput(TestDnsreaperFailedProcess):
    async def setup_after_prep(self, module_test):
        async def malformed_run_process(cmd, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="{not json}", stderr="")

        module_test.monkeypatch.setattr(module_test.module, "run_process", malformed_run_process)


class TestSubzyMalformedOutput(TestSubzyFailedProcess):
    async def setup_after_prep(self, module_test):
        async def malformed_run_process(cmd, *args, **kwargs):
            Path(cmd[cmd.index("--output") + 1]).write_text("{not json}")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        module_test.monkeypatch.setattr(module_test.module, "run_process", malformed_run_process)


class TestSubfinderFailedProcess(_TakeoverFailureBase):
    module_name = "subfinder"
    config_overrides = {
        **_TakeoverFailureBase.config_overrides,
        "modules": {"subfinder": {"binary": "/bin/echo"}},
    }


class TestNucleiTakeoverTimeout(_TakeoverFailureBase):
    module_name = "nuclei_takeover"

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        import os

        from bbot.modules.base import BaseModule

        real_isfile = os.path.isfile
        module_test.monkeypatch.setattr(
            os.path, "isfile", lambda path: str(path).endswith("/nuclei") or real_isfile(path)
        )

        async def fake_update_templates(module, *args, **kwargs):
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        module_test.monkeypatch.setattr(BaseModule, "run_process", fake_update_templates)

    async def setup_after_prep(self, module_test):
        async def timed_out_process(cmd, *args, **kwargs):
            assert kwargs["check"] is True
            raise TimeoutError("nuclei timeout")
            yield  # pragma: no cover

        module_test.monkeypatch.setattr(module_test.module, "run_process_live", timed_out_process)


@pytest.mark.parametrize(
    ("module_type", "config"),
    [
        (dnsreaper, {"binary": "/nonexistent/dnsreaper"}),
        (subzy, {"binary": "/nonexistent/subzy"}),
        (subfinder, {"binary": "/nonexistent/subfinder"}),
        (nuclei_takeover, {}),
        (domain_config_dns_audit, {"wildcard_nameservers": ["1.1.1.1", "8.8.8.8"]}),
    ],
)
def test_takeover_and_dns_audit_setup_errors_are_hard_failures(module_type, config):
    module = object.__new__(module_type)
    module._name = module_type.__name__
    module.scan = SimpleNamespace(
        config={"modules": {module.name: config}},
        helpers=SimpleNamespace(chain_lists=lambda value: value, tools_dir=Path("/nonexistent/bbot-tools")),
    )

    status, _reason = asyncio.run(module.setup())
    assert status is False
