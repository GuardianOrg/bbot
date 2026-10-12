from types import SimpleNamespace

import pytest

from bbot.modules.leaklookup import leaklookup


@pytest.mark.parametrize('payload', [
    {}, {'error': False}, {'message': {}},
    {'error': 'unknown', 'message': {}},
    {'error': ['false'], 'message': {}}, {'error': 0, 'message': {}},
])
def test_leaklookup_rejects_ambiguous_provider_responses(payload):
    module = object.__new__(leaklookup)
    response = SimpleNamespace(status_code=200, json=lambda: payload)
    with pytest.raises(RuntimeError, match='malformed'):
        module._safe_json(response)


@pytest.mark.parametrize('flag', [False, True, 'false', 'true', ' FALSE ', ' TRUE '])
def test_leaklookup_preserves_and_normalizes_explicit_error_flags(flag):
    module = object.__new__(leaklookup)
    response = SimpleNamespace(status_code=200, json=lambda: {'error': flag, 'message': []})
    parsed = module._safe_json(response)
    assert parsed['error'] is (str(flag).strip().lower() == 'true')
    assert parsed['message'] == []
