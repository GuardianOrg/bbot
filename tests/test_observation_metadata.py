"""Offline contract tests; run with python -m unittest discover -s tests."""

import importlib.util
import json
from pathlib import Path
import unittest
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mw = load_module("mw_contract", "bbot/core/helpers/malwareworld.py")
dates = load_module("observation_dates", "bbot/core/helpers/observation_dates.py")
formatter_module = load_module("leak_formatter", "bbot/modules/templates/github_leak_formatter.py")


class MetadataTests(unittest.IsolatedAsyncioTestCase):
    async def test_git_dates_survive_secret_deduplication(self):
        formatter = formatter_module.github_leak_formatter()
        formatter.get_repository_url = AsyncMock(return_value="https://github.com/example/repo")
        formatter.run_process = AsyncMock(
            side_effect=[
                SimpleNamespace(stdout="2024-01-01T00:00:00Z"),
                SimpleNamespace(stdout="2024-06-01T00:00:00Z"),
            ]
        )
        first = await formatter.format_github_leak(None, "/fixture", "dummy-secret", commit="a" * 40)
        latest = await formatter.format_github_leak(None, "/fixture", "dummy-secret", commit="b" * 40)
        self.assertEqual(first["secretFingerprint"], latest["secretFingerprint"])
        self.assertNotEqual(first["dedupe_key"], latest["dedupe_key"])
        self.assertEqual(latest["secret_latest_commit_at"], "2024-06-01T00:00:00Z")

    async def test_unknown_git_dates_are_not_replaced_with_scan_head_date(self):
        formatter = formatter_module.github_leak_formatter()
        formatter.get_repository_url = AsyncMock(return_value="https://github.com/example/repo")
        formatter.get_repository_commit = AsyncMock(return_value="a" * 40)
        formatter.run_process = AsyncMock()
        result = await formatter.format_github_leak(None, "/fixture", "dummy-secret")
        self.assertNotIn("secret_latest_commit_at", result)
        formatter.run_process.assert_not_called()
        self.assertIsNone(await formatter.get_exposure_commit_date("/fixture", "--evil-option"))
        formatter.run_process.assert_not_called()

    async def test_contract(self):
        fixtures = json.loads((ROOT / "tests/fixtures/malwareworld-contract.json").read_text())

        async def load(file):
            return fixtures["files"].get(file, {})

        for sample in fixtures["cases"]:
            with self.subTest(sample=sample):
                report = await mw.lookup(sample["kind"], sample["value"], load)
                self.assertEqual(report["malicious"], sample["malicious"])
                self.assertEqual(report["riskScore"], 80 if sample["malicious"] else 0)
                self.assertEqual(len(report["matches"]), sample["count"])
                if "evil" in sample["value"]:
                    self.assertEqual(len(report["sourceStatus"]), 1)

    async def test_source_failure(self):
        async def load(file):
            raise RuntimeError("HTTP 503")

        with self.assertRaisesRegex(RuntimeError, "503"):
            await mw.lookup("domain", "evil.test", load)

    def test_indexed_dates(self):
        self.assertEqual(dates.indexed_date({"date": ["2024-01-01", "2024-03-01"]}), "2024-03-01T00:00:00Z")
        self.assertIsNone(dates.indexed_date({"dob": "2024-01-01", "date": "invalid"}))
        self.assertEqual(dates.indexed_date_tags({"indexed_at": "2024-01-01"}), ["leak-indexed-at-1704067200"])

    def test_invalid_indicators(self):
        for kind, value in [
            ("phone", "34600000000"),
            ("range", "192.0.2.1/33"),
            ("ip", "::1"),
            ("certificate", "abc"),
        ]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                mw.normalize_indicator(kind, value)
