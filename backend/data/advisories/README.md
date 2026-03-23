# Offline Vulnerability Advisory Database

This directory contains offline vulnerability advisories in a simplified OSV-compatible format.

## Structure

```
advisories/
├── VERSION           # Database version string
├── npm/              # Node.js / npm advisories
│   └── advisories.json
├── pypi/             # Python / PyPI advisories
│   └── advisories.json
├── maven/            # Java / Maven advisories
│   └── advisories.json
├── nuget/            # .NET / NuGet advisories
│   └── advisories.json
├── crates/           # Rust / Cargo advisories
│   └── advisories.json
├── go/               # Go modules advisories
│   └── advisories.json
└── rubygems/         # Ruby gems advisories
    └── advisories.json
```

## Advisory Format

Each JSON file contains an array of advisory objects:

```json
[
  {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "package": "package-name",
    "severity": "high",
    "cvss_score": 8.1,
    "summary": "Description of the vulnerability",
    "affected_range": ">=1.0.0,<1.5.3",
    "fixed_version": "1.5.3",
    "cwe": "CWE-79",
    "published": "2024-01-15",
    "references": ["https://..."]
  }
]
```

## Populating

Use the bundled sync script to download and convert from OSV or GitHub Advisory Database:

```bash
python -m scripts.sync_advisories --output data/advisories/
```

The sync script must be run on a machine WITH internet access. The resulting
directory is then copied to the air-gapped deployment.
