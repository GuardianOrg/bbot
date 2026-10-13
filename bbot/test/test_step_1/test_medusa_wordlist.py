from pathlib import Path
from types import SimpleNamespace

import pytest

from bbot.modules.medusa import medusa
from bbot.scanner.preset.preset import Preset


@pytest.mark.asyncio
async def test_medusa_default_wordlist_is_packaged_and_complete():
    async def wordlist(path):
        return Path(path)

    module = SimpleNamespace(config={"snmp_wordlist": medusa.options["snmp_wordlist"]},
                             helpers=SimpleNamespace(wordlist=wordlist))
    await medusa.setup_deps(module)
    wordlist = module.snmp_wordlist_path
    assert wordlist.is_file()
    lines = wordlist.read_text().splitlines()
    assert len(lines) >= 100
    assert "public" in lines
    assert "private" in lines


def test_medusa_can_be_preloaded_without_executing_module_options():
    config = Preset().module_loader.preloaded()["medusa"]["config"]
    assert config["snmp_wordlist"] == "bundled"
