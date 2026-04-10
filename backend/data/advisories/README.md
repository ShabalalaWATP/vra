# Offline Vulnerability Advisory Database

This directory contains the offline vulnerability database used by VRAgent's dependency auditor.

The data is sourced from OSV and converted into a local, scanner-friendly layout with:
- per-ecosystem `advisories.json` files
- per-ecosystem `enrichment.json` files for extracted vulnerable-function metadata
- root-level sync metadata in `manifest.json` and `VERSION`

During scan creation, VRAgent snapshots the current `VERSION` value into
`scan_configs.advisory_db_ver` so every report can be traced back to the
exact offline advisory dataset that was used.

## Structure

```
advisories/
├── VERSION                  # Database version string
├── manifest.json            # Sync timestamp, counts, enrichment metadata
├── npm/
│   ├── advisories.json
│   └── enrichment.json
├── pypi/
│   ├── advisories.json
│   └── enrichment.json
├── maven/
│   ├── advisories.json
│   └── enrichment.json
├── go/
│   ├── advisories.json
│   └── enrichment.json
├── crates/
│   ├── advisories.json
│   └── enrichment.json
├── nuget/
│   ├── advisories.json
│   └── enrichment.json
├── rubygems/
│   ├── advisories.json
│   └── enrichment.json
├── packagist/
│   ├── advisories.json
│   └── enrichment.json
├── pub/
│   ├── advisories.json
│   └── enrichment.json
└── hex/
    ├── advisories.json
    └── enrichment.json
```

All 10 supported ecosystems currently ship both `advisories.json` and `enrichment.json`.

## `advisories.json` Format

Each ecosystem's `advisories.json` contains an array of advisory objects:

```json
[
  {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "aliases": ["CVE-2024-12345"],
    "package": "package-name",
    "severity": "high",
    "cvss_score": 8.1,
    "cvss_vector": "CVSS:3.1/...",
    "summary": "Description of the vulnerability",
    "details": "Long-form advisory details",
    "affected_range": ">=1.0.0,<1.5.3",
    "fixed_version": "1.5.3",
    "cwes": ["CWE-79"],
    "published": "2024-01-15T00:00:00Z",
    "modified": "2024-01-20T12:34:56Z",
    "references": ["https://..."],
    "vulnerable_functions": ["dangerous_api"],
    "withdrawn": null
  }
]
```

`vulnerable_functions` may already be present when the source advisory includes structured function-level data.

## `enrichment.json` Format

Each ecosystem's `enrichment.json` stores supplemental metadata extracted during sync:

```json
{
  "generated_at": "2026-04-10T00:39:14.382825",
  "strategy_version": 1,
  "stats": {
    "enriched_advisories": 2460,
    "extracted_vulnerable_functions": 5113
  },
  "advisories": {
    "GHSA-xxxx-xxxx-xxxx": {
      "vulnerable_functions": ["dangerous_api", "helper.method"],
      "sources": ["details_inline_code", "summary_context"]
    }
  }
}
```

VRAgent uses this enrichment to improve vulnerable-function correlation during investigation while keeping the raw advisory records intact.

## Populating

Use the bundled sync script to download and convert data from OSV:

```bash
python -m scripts.sync_advisories --output data/advisories/
```

The sync script must be run on a machine with internet access. It generates:
- root metadata files (`VERSION`, `manifest.json`)
- one ecosystem directory per supported package ecosystem
- advisory enrichment used for vulnerable-function extraction and matching

Copy the resulting `data/advisories/` directory to the air-gapped deployment unchanged.
