"""Tests for CVE correlation helpers."""

import json

from app.analysis import cve_correlator
from app.analysis.import_resolver import ImportResolution


def test_parse_pubspec_lock_extracts_hosted_packages():
    content = (
        "packages:\n"
        "  async:\n"
        "    dependency: transitive\n"
        "    description:\n"
        "      name: async\n"
        "      url: https://pub.dev\n"
        "    source: hosted\n"
        '    version: "2.11.0"\n'
        "  local_pkg:\n"
        "    dependency: direct main\n"
        "    description:\n"
        "      path: ../local_pkg\n"
        "      relative: true\n"
        "    source: path\n"
        '    version: "1.0.0"\n'
    )

    assert cve_correlator._parse_pubspec_lock(content) == [("async", "2.11.0")]


def test_parse_mix_lock_extracts_hex_packages():
    content = (
        "%{\n"
        '  "jason" => {:hex, :jason, "1.4.1", "checksum", [:mix], [], "hexpm", "hash"},\n'
        '  "phoenix" => {:hex, :phoenix, "1.7.10", "checksum", [:mix], [], "hexpm", "hash"},\n'
        '  "git_dep" => {:git, "https://github.com/example/repo.git", "abc123", []}\n'
        "}\n"
    )

    assert cve_correlator._parse_mix_lock(content) == [
        ("jason", "1.4.1"),
        ("phoenix", "1.7.10"),
    ]


def test_correlate_by_cwe_maps_dart_and_elixir_languages(monkeypatch):
    monkeypatch.setattr(
        cve_correlator,
        "_cwe_index",
        {
            "CWE-79": [
                {"cve_id": "CVE-PUB-1", "ecosystem": "pub", "summary": "pub issue"},
                {"cve_id": "CVE-HEX-1", "ecosystem": "hex", "summary": "hex issue"},
                {"cve_id": "CVE-NPM-1", "ecosystem": "npm", "summary": "npm issue"},
            ]
        },
    )
    monkeypatch.setattr(cve_correlator, "_func_index", {})

    dart_results = cve_correlator.correlate_by_cwe(["CWE-79"], languages=["dart"])
    elixir_results = cve_correlator.correlate_by_cwe(["CWE-79"], languages=["elixir"])

    assert [result["cve_id"] for result in dart_results] == ["CVE-PUB-1"]
    assert [result["cve_id"] for result in elixir_results] == ["CVE-HEX-1"]


def test_correlate_by_cwe_keeps_advisory_only_entries(monkeypatch):
    monkeypatch.setattr(
        cve_correlator,
        "_cwe_index",
        {
            "CWE-502": [
                {
                    "display_id": "GHSA-pub-1234",
                    "advisory_id": "GHSA-pub-1234",
                    "cve_id": None,
                    "ecosystem": "pub",
                    "package": "archive",
                    "summary": "Deserializer issue",
                }
            ]
        },
    )
    monkeypatch.setattr(cve_correlator, "_func_index", {})

    results = cve_correlator.correlate_by_cwe(["CWE-502"], languages=["dart"])

    assert len(results) == 1
    assert results[0]["display_id"] == "GHSA-pub-1234"
    assert results[0]["advisory_id"] == "GHSA-pub-1234"
    assert results[0]["cve_id"] is None


def test_find_vulnerable_function_calls_keeps_advisory_only_function_matches(monkeypatch):
    monkeypatch.setattr(cve_correlator, "_cwe_index", {})
    monkeypatch.setattr(
        cve_correlator,
        "_func_index",
        {
            "load": [
                {
                    "display_id": "GHSA-hex-9999",
                    "advisory_id": "GHSA-hex-9999",
                    "cve_id": None,
                    "package": "phoenix_html",
                    "severity": "high",
                    "summary": "Unsafe load helper",
                }
            ]
        },
    )

    results = cve_correlator.find_vulnerable_function_calls(
        "lib/example.ex",
        "load(user_input)\n",
        languages=["elixir"],
    )

    assert len(results) == 1
    assert results[0]["display_id"] == "GHSA-hex-9999"
    assert results[0]["advisory_id"] == "GHSA-hex-9999"
    assert results[0]["cve_id"] is None
    assert results[0]["function"] == "load"
    assert results[0]["evidence_strength"] == "weak"
    assert results[0]["package_evidence_source"] == "function_name_only"
    assert results[0]["match_type"] == "function_name_overlap"


def test_find_vulnerable_function_calls_marks_import_confirmed_package_matches(monkeypatch):
    monkeypatch.setattr(cve_correlator, "_cwe_index", {})
    monkeypatch.setattr(
        cve_correlator,
        "_func_index",
        {
            "load": [
                {
                    "display_id": "GHSA-pypi-1111",
                    "advisory_id": "GHSA-pypi-1111",
                    "cve_id": None,
                    "package": "pyyaml",
                    "ecosystem": "pypi",
                    "severity": "high",
                    "summary": "Unsafe yaml loader",
                }
            ]
        },
    )

    results = cve_correlator.find_vulnerable_function_calls(
        "app.py",
        "load(payload)\n",
        languages=["python"],
        import_resolutions=[
            ImportResolution(
                import_module="yaml",
                imported_names=["load"],
                is_external=True,
                source_file="app.py",
                line=1,
            )
        ],
    )

    assert len(results) == 1
    assert results[0]["evidence_strength"] == "medium"
    assert results[0]["package_evidence_source"] == "import_graph"
    assert results[0]["match_type"] == "import_confirmed_function_match"
    assert results[0]["import_module"] == "yaml"


def test_find_vulnerable_function_calls_marks_dep_confirmed_matches_as_strong(monkeypatch):
    monkeypatch.setattr(cve_correlator, "_cwe_index", {})
    monkeypatch.setattr(
        cve_correlator,
        "_func_index",
        {
            "load": [
                {
                    "display_id": "GHSA-pypi-2222",
                    "advisory_id": "GHSA-pypi-2222",
                    "cve_id": None,
                    "package": "pyyaml",
                    "ecosystem": "pypi",
                    "severity": "high",
                    "summary": "Unsafe yaml loader",
                }
            ]
        },
    )

    results = cve_correlator.find_vulnerable_function_calls(
        "app.py",
        "load(payload)\n",
        languages=["python"],
        import_resolutions=[
            ImportResolution(
                import_module="yaml",
                imported_names=["load"],
                is_external=True,
                source_file="app.py",
                line=1,
            )
        ],
        vulnerable_dependencies=[
            {
                "package": "pyyaml",
                "ecosystem": "pypi",
                "advisory_id": "GHSA-pypi-2222",
                "import_match_source": "import_graph",
                "import_match_confidence": 1.0,
                "import_module": "yaml",
            }
        ],
    )

    assert len(results) == 1
    assert results[0]["evidence_strength"] == "strong"
    assert results[0]["package_evidence_source"] == "import_graph"
    assert results[0]["match_type"] == "confirmed_vulnerable_dependency_function_match"


def test_find_vulnerable_function_calls_filters_other_ecosystems(monkeypatch):
    monkeypatch.setattr(cve_correlator, "_cwe_index", {})
    monkeypatch.setattr(
        cve_correlator,
        "_func_index",
        {
            "load": [
                {
                    "display_id": "GHSA-pypi-3333",
                    "advisory_id": "GHSA-pypi-3333",
                    "cve_id": None,
                    "package": "pyyaml",
                    "ecosystem": "pypi",
                    "severity": "high",
                    "summary": "Unsafe yaml loader",
                },
                {
                    "display_id": "GHSA-hex-3333",
                    "advisory_id": "GHSA-hex-3333",
                    "cve_id": None,
                    "package": "phoenix_html",
                    "ecosystem": "hex",
                    "severity": "high",
                    "summary": "Unsafe html loader",
                },
            ]
        },
    )

    results = cve_correlator.find_vulnerable_function_calls(
        "app.py",
        "load(payload)\n",
        languages=["python"],
    )

    assert [result["display_id"] for result in results] == ["GHSA-pypi-3333"]


def test_find_vulnerable_function_calls_loads_enriched_functions_from_disk(tmp_path, monkeypatch):
    advisories_dir = tmp_path / "advisories" / "go"
    advisories_dir.mkdir(parents=True)
    (advisories_dir / "advisories.json").write_text(
        json.dumps(
            [
                {
                    "id": "GO-001",
                    "package": "example.com/lib",
                    "severity": "high",
                    "summary": "Example advisory",
                    "affected_range": ">=0,<1.2.0",
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
                    "GO-001": {
                        "vulnerable_functions": ["Repository::revparse_single"],
                        "sources": ["details_inline_code"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(cve_correlator.settings, "advisory_db_dir", tmp_path / "advisories")
    monkeypatch.setattr(cve_correlator, "_cwe_index", None)
    monkeypatch.setattr(cve_correlator, "_func_index", None)

    results = cve_correlator.find_vulnerable_function_calls(
        "main.go",
        'repo.revparse_single("HEAD")\n',
        languages=["go"],
    )

    assert len(results) == 1
    assert results[0]["display_id"] == "GO-001"
    assert results[0]["package"] == "example.com/lib"
    assert results[0]["evidence_strength"] == "weak"
