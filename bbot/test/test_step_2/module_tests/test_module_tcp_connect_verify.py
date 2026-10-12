import asyncio

from .base import ModuleTestBase


class TestTcpConnectVerify(ModuleTestBase):
    module_name = 'tcp_connect_verify'
    targets = ['127.0.0.1']
    config_overrides = {
        'deps': {'behavior': 'disable'},
        'modules': {'tcp_connect_verify': {'ports': '443,8443', 'retries': 1}},
    }

    async def setup_before_prep(self, module_test):
        from bbot.core.helpers.depsinstaller.installer import DepsInstaller

        async def installed(self):
            return None

        module_test.monkeypatch.setattr(DepsInstaller, 'install_core_deps', installed)

    async def setup_after_prep(self, module_test):
        class Writer:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def connect(host, port):
            assert host == '127.0.0.1'
            if port == 8443:
                raise ConnectionRefusedError
            return object(), Writer()

        module_test.monkeypatch.setattr(asyncio, 'open_connection', connect)

    def check(self, module_test, events):
        ports = [str(event.data) for event in events if event.type == 'OPEN_TCP_PORT']
        assert ports == ['127.0.0.1:443']
        assert module_test.scan.finish_event().data['status'] == 'FINISHED'
