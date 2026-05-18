from my_bbot.modules.offchain_scope_filter import offchain_scope_filter as _GuardianOffchainScopeFilter


class offchain_scope_filter(_GuardianOffchainScopeFilter):
    watched_events = ["*"]
    flags = ["passive", "safe"]
    options = {"scope_targets": []}
    options_desc = {
        "scope_targets": "GuardianSentry effective offchain scope targets, encoded as type:value strings",
    }
    meta = {
        "description": "Drop offchain events outside the seeded GuardianSentry scope",
        "created_date": "2026-05-18",
        "author": "GitHub Copilot",
    }

