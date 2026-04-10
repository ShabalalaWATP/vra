"""Tests for dependency advisory matching."""

import json
from pathlib import Path

import pytest

from app.scanners.dep_audit import DepAuditAdapter, version_in_range, version_matches_advisory


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


def test_version_in_range_supports_or_ranges():
    assert version_in_range("1.3.5", ">=1.0.0,<1.2.0 || >=1.3.0,<1.4.0")
    assert not version_in_range("1.2.5", ">=1.0.0,<1.2.0 || >=1.3.0,<1.4.0")


def test_version_in_range_empty():
    assert not version_in_range("", ">=1.0.0")
    assert not version_in_range("1.0.0", "")


def test_version_in_range_supports_pep440_prereleases():
    assert version_in_range("5.2.9", ">=0,<5.3.0rc1", "pypi")
    assert not version_in_range("5.3.0", ">=0,<5.3.0rc1", "pypi")


def test_version_matches_advisory_checks_explicit_versions():
    advisory = {
        "affected_versions": ["2.0.0", "2.1.0"],
        "affected_range": "",
    }

    assert version_matches_advisory("2.1.0", advisory)
    assert not version_matches_advisory("2.2.0", advisory)


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
    with patch("app.scanners.dep_audit.settings") as mock_settings:
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


@pytest.mark.asyncio
async def test_dep_audit_finds_pub_vulnerabilities_from_pubspec_lock(tmp_path):
    (tmp_path / "pubspec.lock").write_text(
        "packages:\n"
        "  async:\n"
        "    dependency: transitive\n"
        "    description:\n"
        "      name: async\n"
        "      url: https://pub.dev\n"
        "    source: hosted\n"
        "    version: \"2.11.0\"\n"
        "  lints:\n"
        "    dependency: direct dev\n"
        "    description:\n"
        "      name: lints\n"
        "      url: https://pub.dev\n"
        "    source: hosted\n"
        "    version: \"3.0.0\"\n"
        "  local_pkg:\n"
        "    dependency: direct main\n"
        "    description:\n"
        "      path: ../local_pkg\n"
        "      relative: true\n"
        "    source: path\n"
        "    version: \"1.0.0\"\n",
        encoding="utf-8",
    )

    advisories_dir = tmp_path / "advisories" / "pub"
    advisories_dir.mkdir(parents=True)
    (advisories_dir / "advisories.json").write_text(
        json.dumps(
            [
                {
                    "id": "PUB-001",
                    "package": "async",
                    "severity": "medium",
                    "summary": "Example async vulnerability",
                    "affected_range": ">=2.0.0,<2.12.0",
                    "fixed_version": "2.12.0",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "advisories" / "VERSION").write_text("test", encoding="utf-8")

    from unittest.mock import patch

    with patch("app.scanners.dep_audit.settings") as mock_settings:
        mock_settings.advisory_db_path = tmp_path / "advisories"
        mock_settings.data_dir = tmp_path / "data"
        mock_settings.upload_dir = tmp_path / "uploads"
        mock_settings.export_dir = tmp_path / "exports"

        adapter = DepAuditAdapter()
        result = await adapter.run(tmp_path)

    assert result.success
    async_hits = [h for h in result.hits if h.metadata.get("package") == "async"]
    assert len(async_hits) == 1
    assert async_hits[0].metadata["ecosystem"] == "pub"


@pytest.mark.asyncio
async def test_dep_audit_finds_hex_vulnerabilities_from_mix_lock(tmp_path):
    (tmp_path / "mix.lock").write_text(
        "%{\n"
        '  "jason" => {:hex, :jason, "1.4.1", "checksum", [:mix], [], "hexpm", "hash"},\n'
        '  "phoenix" => {:hex, :phoenix, "1.7.10", "checksum", [:mix], [], "hexpm", "hash"},\n'
        '  "git_dep" => {:git, "https://github.com/example/repo.git", "abc123", []}\n'
        "}\n",
        encoding="utf-8",
    )

    advisories_dir = tmp_path / "advisories" / "hex"
    advisories_dir.mkdir(parents=True)
    (advisories_dir / "advisories.json").write_text(
        json.dumps(
            [
                {
                    "id": "HEX-001",
                    "package": "jason",
                    "severity": "high",
                    "summary": "Example jason vulnerability",
                    "affected_range": ">=1.0.0,<1.4.2",
                    "fixed_version": "1.4.2",
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "advisories" / "VERSION").write_text("test", encoding="utf-8")

    from unittest.mock import patch

    with patch("app.scanners.dep_audit.settings") as mock_settings:
        mock_settings.advisory_db_path = tmp_path / "advisories"
        mock_settings.data_dir = tmp_path / "data"
        mock_settings.upload_dir = tmp_path / "uploads"
        mock_settings.export_dir = tmp_path / "exports"

        adapter = DepAuditAdapter()
        result = await adapter.run(tmp_path)

    assert result.success
    jason_hits = [h for h in result.hits if h.metadata.get("package") == "jason"]
    assert len(jason_hits) == 1
    assert jason_hits[0].metadata["ecosystem"] == "hex"


def test_dep_audit_respects_vragentignore_when_discovering_packages(tmp_path):
    (tmp_path / ".vragentignore").write_text("generated/\n", encoding="utf-8")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "package.json").write_text(
        json.dumps({"dependencies": {"ignored-lib": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"kept-lib": "2.0.0"}}),
        encoding="utf-8",
    )

    adapter = DepAuditAdapter()
    packages = adapter._discover_packages(tmp_path)

    assert {pkg["name"] for pkg in packages} == {"kept-lib"}


def test_dep_audit_merges_enriched_vulnerable_functions(tmp_path):
    advisories_dir = tmp_path / "advisories" / "npm"
    advisories_dir.mkdir(parents=True)
    (advisories_dir / "advisories.json").write_text(
        json.dumps(
            [
                {
                    "id": "NPM-001",
                    "package": "lodash",
                    "severity": "high",
                    "summary": "Prototype pollution",
                    "affected_range": ">=0.0.1,<4.17.20",
                    "fixed_version": "4.17.20",
                    "vulnerable_functions": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    (advisories_dir / "enrichment.json").write_text(
        json.dumps(
            {
                "advisories": {
                    "NPM-001": {
                        "vulnerable_functions": ["_.merge", "defaultsDeep"],
                        "sources": ["details_inline_code"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    from unittest.mock import patch

    with patch("app.scanners.dep_audit.settings") as mock_settings:
        mock_settings.advisory_db_path = tmp_path / "advisories"
        adapter = DepAuditAdapter()
        matches = adapter.lookup_package("npm", "lodash", "4.17.15")

    assert len(matches) == 1
    assert matches[0]["vulnerable_functions"] == ["_.merge", "defaultsDeep"]


def test_dep_audit_lookup_matches_normalised_pypi_names(tmp_path):
    advisories_dir = tmp_path / "advisories" / "pypi"
    advisories_dir.mkdir(parents=True)
    (advisories_dir / "advisories.json").write_text(
        json.dumps(
            [
                {
                    "id": "PYPI-001",
                    "package": "my-package",
                    "severity": "medium",
                    "summary": "Normalised package name match",
                    "affected_range": ">=1.0,<2.0",
                    "fixed_version": "2.0.0",
                }
            ]
        ),
        encoding="utf-8",
    )

    from unittest.mock import patch

    with patch("app.scanners.dep_audit.settings") as mock_settings:
        mock_settings.advisory_db_path = tmp_path / "advisories"
        adapter = DepAuditAdapter()
        matches = adapter.lookup_package("pypi", "my_package", "1.5.0")

    assert len(matches) == 1
    assert matches[0]["match_type"] == "canonical_package_match"
    assert matches[0]["advisory_package"] == "my-package"


def test_dep_audit_lookup_matches_maven_artifact_alias(tmp_path):
    advisories_dir = tmp_path / "advisories" / "maven"
    advisories_dir.mkdir(parents=True)
    (advisories_dir / "advisories.json").write_text(
        json.dumps(
            [
                {
                    "id": "MAVEN-001",
                    "package": "org.apache.logging.log4j:log4j-core",
                    "severity": "critical",
                    "summary": "Artifact alias match",
                    "affected_range": ">=2.0.0,<2.15.0",
                    "fixed_version": "2.15.0",
                }
            ]
        ),
        encoding="utf-8",
    )

    from unittest.mock import patch

    with patch("app.scanners.dep_audit.settings") as mock_settings:
        mock_settings.advisory_db_path = tmp_path / "advisories"
        adapter = DepAuditAdapter()
        matches = adapter.lookup_package("maven", "log4j-core", "2.14.0")

    assert len(matches) == 1
    assert matches[0]["match_type"] == "artifact_alias_match"
    assert matches[0]["advisory_package"] == "org.apache.logging.log4j:log4j-core"
