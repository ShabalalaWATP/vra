"""Tests for dependency advisory matching."""

import json
from pathlib import Path

import pytest

from app.scanners.dep_audit import DepAuditAdapter, version_in_range


def test_version_in_range_basic():
    assert version_in_range("1.2.3", ">=1.0.0,<2.0.0")
    assert not version_in_range("2.0.0", ">=1.0.0,<2.0.0")
    assert not version_in_range("0.9.0", ">=1.0.0,<2.0.0")


def test_version_in_range_less_than():
    assert version_in_range("1.5.0", "<2.0.0")
    assert not version_in_range("2.0.0", "<2.0.0")


def test_version_in_range_exact():
    assert version_in_range("1.0.0", "=1.0.0")
    assert not version_in_range("1.0.1", "=1.0.0")


def test_version_in_range_empty():
    assert not version_in_range("", ">=1.0.0")
    assert not version_in_range("1.0.0", "")


@pytest.mark.asyncio
async def test_dep_audit_finds_vulnerabilities(tmp_path):
    # Create a package.json with a known-vulnerable package
    pkg = {
        "name": "test-app",
        "dependencies": {
            "express": "4.17.0",
            "lodash": "4.17.15",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))

    # Create advisory DB
    advisories_dir = tmp_path / "advisories" / "npm"
    advisories_dir.mkdir(parents=True)
    advisories = [
        {
            "id": "TEST-001",
            "package": "lodash",
            "severity": "high",
            "summary": "Prototype Pollution",
            "affected_range": ">=0.0.1,<4.17.20",
            "fixed_version": "4.17.20",
        }
    ]
    (advisories_dir / "advisories.json").write_text(json.dumps(advisories))
    (tmp_path / "advisories" / "VERSION").write_text("test")

    # Run adapter
    from unittest.mock import patch
    with patch("app.config.settings") as mock_settings:
        mock_settings.advisory_db_path = tmp_path / "advisories"
        adapter = DepAuditAdapter()
        adapter._loaded = False
        adapter._advisories = {}
        adapter._load_advisories()

        result = await adapter.run(tmp_path)

    assert result.success
    # Should find lodash vulnerability
    lodash_hits = [h for h in result.hits if h.metadata.get("package") == "lodash"]
    assert len(lodash_hits) >= 1
