"""Tests for scan scanner-selection normalization."""

import asyncio
from types import SimpleNamespace

from app.config import DEFAULT_DATABASE_URL
from app.api.scans import collect_scan_provenance, normalise_scanner_config


def test_normalise_scanner_config_maps_dependency_aliases():
    config = normalise_scanner_config({"dependencies": False, "codeql": False})

    assert config["dep_audit"] is False
    assert config["codeql"] is False
    assert config["semgrep"] is True


def test_normalise_scanner_config_defaults_enable_known_scanners():
    config = normalise_scanner_config(None)

    assert config == {
        "semgrep": True,
        "bandit": True,
        "eslint": True,
        "codeql": True,
        "secrets": True,
        "dep_audit": True,
    }


def test_default_database_url_uses_sqlite():
    assert DEFAULT_DATABASE_URL.startswith("sqlite+aiosqlite:///")


def test_collect_scan_provenance_snapshots_enabled_scanner_versions(monkeypatch):
    class _FakeScanner:
        def __init__(self, version):
            self._version = version

        async def get_version(self):
            return self._version

    monkeypatch.setattr(
        "app.api.scans.create_scanner_set",
        lambda: {
            "semgrep": _FakeScanner("semgrep 1.2.3"),
            "bandit": _FakeScanner("bandit 2.0.0"),
            "eslint": _FakeScanner("eslint 9.0.0"),
            "codeql": _FakeScanner("2.25.0"),
            "secrets": _FakeScanner("secrets 2.0.0"),
            "dep_audit": _FakeScanner("2026.04.10"),
        },
    )

    provenance = asyncio.run(
        collect_scan_provenance(
            {
                "semgrep": True,
                "bandit": False,
                "eslint": True,
                "codeql": True,
                "secrets": True,
                "dep_audit": True,
            },
            llm_profile=SimpleNamespace(model_name="gpt-test"),
        )
    )

    assert provenance == {
        "semgrep_version": "semgrep 1.2.3",
        "bandit_version": None,
        "eslint_version": "eslint 9.0.0",
        "codeql_version": "2.25.0",
        "secrets_version": "secrets 2.0.0",
        "advisory_db_ver": "2026.04.10",
        "llm_model": "gpt-test",
    }
