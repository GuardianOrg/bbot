import asyncio
from types import SimpleNamespace

import pytest

from bbot.modules.nuclei import nuclei


def make_module(tmp_path, templates=""):
    module = object.__new__(nuclei)
    module._name = "nuclei"
    module.scan = SimpleNamespace(
        config={"modules": {"nuclei": {"mode": "technology", "templates": templates}}},
        helpers=SimpleNamespace(tools_dir=tmp_path, mkdir=lambda path: path.mkdir(parents=True, exist_ok=True)),
        temp_dir=tmp_path,
        web_config={},
    )
    module.info = lambda *args, **kwargs: None
    module.warning = lambda *args, **kwargs: None
    module.success = lambda *args, **kwargs: None

    async def no_extra_template_sources(*args, **kwargs):
        return []

    module.resolve_template_sources = no_extra_template_sources
    return module


def test_nuclei_setup_rejects_missing_default_templates(tmp_path, monkeypatch):
    monkeypatch.delenv("BBOT_NUCLEI_UPDATE_TEMPLATES", raising=False)
    module = make_module(tmp_path)

    result = asyncio.run(module.setup())
    assert isinstance(result, tuple) and result[0] is False
    assert "templates" in result[1]


@pytest.mark.parametrize("custom", [False, True])
def test_nuclei_setup_accepts_available_templates(tmp_path, monkeypatch, custom):
    monkeypatch.delenv("BBOT_NUCLEI_UPDATE_TEMPLATES", raising=False)
    if custom:
        template = tmp_path / "custom.yaml"
        template.write_text("id: example\n")
        module = make_module(tmp_path, templates=str(template))
    else:
        (tmp_path / "nuclei-templates").mkdir()
        module = make_module(tmp_path)

    assert asyncio.run(module.setup()) is True
