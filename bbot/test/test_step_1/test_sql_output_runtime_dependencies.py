import asyncio
import importlib
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest


SQL_OUTPUT_MODULES = ('sqlite', 'postgres', 'mysql')


def test_sql_output_discovery_does_not_import_optional_database_dependencies():
    # BBOT imports every module during discovery, before enabled-module dependencies install.
    result = subprocess.run([
        sys.executable, '-c', '''
import importlib
import importlib.abc
import sys
class BlockSqlImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'sqlmodel', 'sqlalchemy', 'greenlet'}:
            raise ImportError('SQL runtime unavailable during discovery')
sys.meta_path.insert(0, BlockSqlImports())
for name in ('sqlite', 'postgres', 'mysql'):
    importlib.import_module('bbot.modules.output.' + name)
'''], capture_output=True, text=True, env={**os.environ, 'BBOT_TESTING': 'True'})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('module_name', SQL_OUTPUT_MODULES)
def test_sql_outputs_request_sqlalchemy_asyncio_extra(module_name):
    module = importlib.import_module(f'bbot.modules.output.{module_name}')
    cls = getattr(module, {'sqlite': 'SQLite', 'postgres': 'Postgres', 'mysql': 'MySQL'}[module_name])
    assert 'sqlalchemy[asyncio]' in cls.deps_pip


def test_missing_sql_runtime_still_fails_enabled_output_setup(monkeypatch):
    from bbot.modules.output.sqlite import SQLite
    import builtins
    original_import = builtins.__import__

    def block_sql(name, *args, **kwargs):
        if name.split('.')[0] in {'sqlmodel', 'sqlalchemy'}:
            raise ImportError('SQL runtime unavailable during setup')
        return original_import(name, *args, **kwargs)

    output = object.__new__(SQLite)
    output.scan = SimpleNamespace(config={'output_modules': {'sqlite': {}}})
    output.create_database = lambda: None
    monkeypatch.setattr(builtins, '__import__', block_sql)
    with pytest.raises(ImportError, match='SQL runtime unavailable during setup'):
        asyncio.run(output.init_database())
