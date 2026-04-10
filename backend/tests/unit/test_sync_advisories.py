"""Tests for advisory sync enrichment heuristics."""

from scripts.sync_advisories import (
    build_enrichment_artifact,
    convert_osv,
    extract_vulnerable_functions,
)


def test_extract_vulnerable_functions_finds_qualified_symbols():
    advisory = {
        "summary": "Issue in `Repository::revparse_single` and `Index::add` methods",
        "details": (
            "The `git_index_add` function may corrupt memory. "
            "Applications using `clean_text` should update."
        ),
    }

    functions, sources = extract_vulnerable_functions(advisory)

    assert "Repository::revparse_single" in functions
    assert "Index::add" in functions
    assert "git_index_add" in functions
    assert "clean_text" in functions
    assert "summary_inline_code" in sources
    assert "details_inline_code" in sources


def test_build_enrichment_artifact_only_writes_new_functions():
    enrichment = build_enrichment_artifact(
        [
            {
                "id": "ADV-001",
                "summary": "Issue in `EventCache::find_event_with_relations`",
                "details": "The `EventCache::find_event_with_relations` method is vulnerable.",
                "vulnerable_functions": ["existing_fn"],
            }
        ]
    )

    assert enrichment["stats"]["enriched_advisories"] == 1
    assert enrichment["advisories"]["ADV-001"]["vulnerable_functions"] == [
        "EventCache::find_event_with_relations"
    ]


def test_convert_osv_preserves_multiple_packages_and_ranges():
    osv = {
        "id": "GHSA-test-1234",
        "aliases": ["CVE-2026-0001"],
        "summary": "Example vulnerability",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "alpha"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.3.0"}, {"fixed": "1.4.0"}],
                    },
                ],
            },
            {
                "package": {"ecosystem": "npm", "name": "beta"},
                "versions": ["2.0.0", "2.1.0"],
            },
        ],
        "references": [{"url": "https://example.com/advisory"}],
    }

    converted = convert_osv(osv)

    assert len(converted) == 2
    alpha = next(record for record in converted if record["package"] == "alpha")
    beta = next(record for record in converted if record["package"] == "beta")
    assert alpha["affected_ranges"] == [">=0,<1.2.0", ">=1.3.0,<1.4.0"]
    assert alpha["affected_range"] == ">=0,<1.2.0 || >=1.3.0,<1.4.0"
    assert alpha["fixed_version"] == "1.2.0"
    assert alpha["cvss_score"] == 9.8
    assert alpha["severity"] == "critical"
    assert beta["affected_versions"] == ["2.0.0", "2.1.0"]
