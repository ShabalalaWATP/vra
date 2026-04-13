"""Tests for advisory sync enrichment heuristics."""

import gzip
import json

from scripts.sync_advisories import (
    build_enrichment_artifact,
    convert_osv,
    extract_vulnerable_functions,
    write_json_artifacts,
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
    assert enrichment["advisories"]["ADV-001"]["vulnerable_symbols"] == [
        {
            "symbol": "EventCache::find_event_with_relations",
            "sources": ["details_inline_code", "summary_inline_code"],
            "confidence": 0.45,
        }
    ]


def test_extract_vulnerable_functions_filters_obvious_noise_tokens():
    advisory = {
        "summary": "Issue in `safe_eval` but not `SECURITY.md` or `NODE_ENV`.",
        "details": "Headers like `Set-Cookie` and versions like `v3.0.0-beta.18.3` are not function symbols.",
    }

    functions, _ = extract_vulnerable_functions(advisory)

    assert functions == ["safe_eval"]


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


def test_convert_osv_extracts_structured_symbols_from_imports():
    osv = {
        "id": "GO-TEST-0001",
        "summary": "Go import-level vulnerability metadata",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "github.com/example/mod"},
                "ecosystem_specific": {
                    "imports": [
                        {
                            "path": "github.com/example/mod/http",
                            "symbols": ["Serve", "Handle"],
                        },
                        {
                            "modules": ["example.jwt", "example.jwt.api"],
                            "name": "decode",
                        },
                    ]
                },
            }
        ],
    }

    converted = convert_osv(osv)

    assert len(converted) == 1
    record = converted[0]
    assert record["vulnerable_functions"] == ["Handle", "Serve", "decode"]
    assert record["vulnerable_import_paths"] == [
        "github.com/example/mod/http",
        "example.jwt",
        "example.jwt.api",
    ]
    assert record["vulnerable_symbols"] == [
        {
            "symbol": "Handle",
            "sources": ["ecosystem_specific.imports"],
            "confidence": 1.0,
            "import_path": "github.com/example/mod/http",
        },
        {
            "symbol": "Serve",
            "sources": ["ecosystem_specific.imports"],
            "confidence": 1.0,
            "import_path": "github.com/example/mod/http",
        },
        {
            "symbol": "decode",
            "sources": ["ecosystem_specific.imports"],
            "confidence": 1.0,
            "import_path": "example.jwt",
        },
        {
            "symbol": "decode",
            "sources": ["ecosystem_specific.imports"],
            "confidence": 1.0,
            "import_path": "example.jwt.api",
        },
    ]


def test_build_enrichment_artifact_enriches_pypi_symbols_from_patch_refs():
    advisory = {
        "id": "PYSEC-TEST-1",
        "package": "demo",
        "summary": "Websocket issue",
        "details": "",
        "references": [
            "https://github.com/example/demo/commit/0123456789abcdef0123456789abcdef01234567"
        ],
    }
    patch_text = (
        "diff --git a/src/demo/websocket.py b/src/demo/websocket.py\n"
        "--- a/src/demo/websocket.py\n"
        "+++ b/src/demo/websocket.py\n"
        "@@ -10,6 +10,6 @@ class NovaProxyRequestHandlerBase:\n"
        "-    def new_websocket_client(self, target):\n"
        "+    def new_websocket_client(self, target):\n"
        "         return target\n"
    )

    def patch_fetcher(url: str) -> str | None:
        assert url.endswith(".patch")
        return patch_text

    enrichment = build_enrichment_artifact(
        [advisory],
        ecosystem="pypi",
        patch_fetcher=patch_fetcher,
    )

    assert enrichment["stats"]["patch_enriched_advisories"] == 1
    assert enrichment["stats"]["patch_extracted_vulnerable_symbols"] == 1
    assert enrichment["stats"]["patch_fetch_attempts"] == 1
    assert enrichment["stats"]["patch_fetch_hits"] == 1
    assert enrichment["advisories"]["PYSEC-TEST-1"]["vulnerable_functions"] == [
        "NovaProxyRequestHandlerBase.new_websocket_client"
    ]
    assert enrichment["advisories"]["PYSEC-TEST-1"]["vulnerable_symbols"] == [
        {
            "symbol": "NovaProxyRequestHandlerBase.new_websocket_client",
            "sources": ["patch_fix_ref"],
            "confidence": 0.86,
            "import_path": "demo.websocket",
        }
    ]


def test_build_enrichment_artifact_enriches_npm_symbols_from_patch_refs():
    advisory = {
        "id": "GHSA-NPM-TEST-1",
        "package": "express",
        "summary": "Router issue",
        "details": "",
        "references": [
            "https://github.com/example/express/commit/0123456789abcdef0123456789abcdef01234567"
        ],
    }
    patch_text = (
        "diff --git a/lib/router/layer.js b/lib/router/layer.js\n"
        "--- a/lib/router/layer.js\n"
        "+++ b/lib/router/layer.js\n"
        "@@ -10,6 +10,6 @@\n"
        "-function sanitizeInput(value) {\n"
        "+function sanitizeInput(value) {\n"
        "   return value\n"
        " }\n"
        "diff --git a/lib/router/index.js b/lib/router/index.js\n"
        "--- a/lib/router/index.js\n"
        "+++ b/lib/router/index.js\n"
        "@@ -20,6 +20,6 @@ class Layer {\n"
        "-  handle_request(req, res) {\n"
        "+  handle_request(req, res) {\n"
        "     return this\n"
        "   }\n"
    )

    enrichment = build_enrichment_artifact(
        [advisory],
        ecosystem="npm",
        patch_fetcher=lambda url: patch_text,
    )

    assert enrichment["stats"]["patch_enriched_advisories"] == 1
    assert enrichment["stats"]["patch_extracted_vulnerable_symbols"] == 4
    assert enrichment["advisories"]["GHSA-NPM-TEST-1"]["vulnerable_functions"] == [
        "sanitizeInput",
        "Layer.handle_request",
    ]
    assert enrichment["advisories"]["GHSA-NPM-TEST-1"]["vulnerable_symbols"] == [
        {
            "symbol": "sanitizeInput",
            "sources": ["patch_fix_ref"],
            "confidence": 0.84,
            "import_path": "express/lib/router/layer",
        },
        {
            "symbol": "sanitizeInput",
            "sources": ["patch_fix_ref"],
            "confidence": 0.84,
            "import_path": "express/router/layer",
        },
        {
            "symbol": "Layer.handle_request",
            "sources": ["patch_fix_ref"],
            "confidence": 0.84,
            "import_path": "express/lib/router",
        },
        {
            "symbol": "Layer.handle_request",
            "sources": ["patch_fix_ref"],
            "confidence": 0.84,
            "import_path": "express/router",
        },
    ]


def test_build_enrichment_artifact_skips_npm_test_and_spec_patch_files():
    advisory = {
        "id": "GHSA-NPM-TEST-2",
        "package": "demo",
        "summary": "Only test files changed",
        "details": "",
        "references": [
            "https://github.com/example/demo/commit/0123456789abcdef0123456789abcdef01234567"
        ],
    }
    patch_text = (
        "diff --git a/spec/vulnerabilities.spec.js b/spec/vulnerabilities.spec.js\n"
        "--- a/spec/vulnerabilities.spec.js\n"
        "+++ b/spec/vulnerabilities.spec.js\n"
        "@@ -1,4 +1,4 @@\n"
        "-function loginWithRecovery() {\n"
        "+function loginWithRecovery() {\n"
        "   return true\n"
        " }\n"
    )

    enrichment = build_enrichment_artifact(
        [advisory],
        ecosystem="npm",
        patch_fetcher=lambda url: patch_text,
    )

    assert enrichment["stats"]["patch_enriched_advisories"] == 0
    assert enrichment["stats"]["patch_extracted_vulnerable_symbols"] == 0
    assert enrichment["stats"]["patch_fetch_attempts"] == 1
    assert enrichment["stats"]["patch_fetch_hits"] == 1
    assert enrichment["advisories"] == {}


def test_build_enrichment_artifact_skips_npm_named_test_files_and_test_dirs():
    advisory = {
        "id": "GHSA-NPM-TEST-3",
        "package": "demo",
        "summary": "Only integration test files changed",
        "details": "",
        "references": [
            "https://github.com/example/demo/commit/0123456789abcdef0123456789abcdef01234567"
        ],
    }
    patch_text = (
        "diff --git a/dev-packages/node-integration-tests/suites/http/test.js b/dev-packages/node-integration-tests/suites/http/test.js\n"
        "--- a/dev-packages/node-integration-tests/suites/http/test.js\n"
        "+++ b/dev-packages/node-integration-tests/suites/http/test.js\n"
        "@@ -1,4 +1,4 @@\n"
        "-function getCommonHttpRequestHeaders() {\n"
        "+function getCommonHttpRequestHeaders() {\n"
        "   return {}\n"
        " }\n"
    )

    enrichment = build_enrichment_artifact(
        [advisory],
        ecosystem="npm",
        patch_fetcher=lambda url: patch_text,
    )

    assert enrichment["stats"]["patch_enriched_advisories"] == 0
    assert enrichment["advisories"] == {}


def test_write_json_artifacts_emits_plain_and_gzip_variants(tmp_path):
    out_file = tmp_path / "advisories.json"
    payload = [{"id": "ADV-001", "package": "demo"}]

    write_json_artifacts(out_file, payload)

    assert json.loads(out_file.read_text(encoding="utf-8")) == payload
    with gzip.open(tmp_path / "advisories.json.gz", "rt", encoding="utf-8") as handle:
        assert json.load(handle) == payload
