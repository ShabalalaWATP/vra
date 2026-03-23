#!/usr/bin/env python3
"""
Advisory database sync script — downloads the FULL OSV vulnerability database.

Run on a machine WITH internet access, then copy the output
directory to the air-gapped deployment.

Uses OSV's bulk download (GCS bucket) which is MUCH faster than the API.
Each ecosystem is a single zip file containing one JSON per advisory.

Usage:
    python -m scripts.sync_advisories
    python -m scripts.sync_advisories --output data/advisories/
    python -m scripts.sync_advisories --ecosystems npm pypi  # specific only
"""

import argparse
import io
import json
import sys
import zipfile
from datetime import datetime
from pathlib import Path

try:
    import httpx
except ImportError:
    print("httpx is required: pip install httpx")
    sys.exit(1)

# OSV bulk download URLs (Google Cloud Storage, public, no auth)
OSV_GCS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "crates": "crates.io",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def convert_osv(osv: dict) -> dict | None:
    """Convert a single OSV advisory to VRAgent format."""
    affected_list = osv.get("affected", [])
    if not affected_list:
        return None

    pkg_info = affected_list[0].get("package", {})
    package_name = pkg_info.get("name", "")
    if not package_name:
        return None

    # Extract version ranges
    ranges = affected_list[0].get("ranges", [])
    affected_range = ""
    fixed_version = ""
    for r in ranges:
        events = r.get("events", [])
        introduced = ""
        fixed = ""
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]
        if introduced and fixed:
            affected_range = f">={introduced},<{fixed}"
            fixed_version = fixed
        elif introduced:
            affected_range = f">={introduced}"

    # Severity
    severity_list = osv.get("severity", [])
    cvss_score = None
    cvss_vector = None
    for s in severity_list:
        if s.get("type") == "CVSS_V3":
            score_str = s.get("score", "")
            try:
                cvss_score = float(score_str)
            except (ValueError, TypeError):
                pass
            cvss_vector = s.get("vector", None)

    # Map severity
    db_specific = osv.get("database_specific", {})
    gh_severity = db_specific.get("severity", "MODERATE")
    severity = SEVERITY_MAP.get(gh_severity.upper(), "medium")

    if cvss_score:
        if cvss_score >= 9.0:
            severity = "critical"
        elif cvss_score >= 7.0:
            severity = "high"
        elif cvss_score >= 4.0:
            severity = "medium"
        else:
            severity = "low"

    # CWEs
    cwes = db_specific.get("cwe_ids", [])

    # References
    references = [
        ref.get("url", "") for ref in osv.get("references", [])
        if ref.get("url")
    ][:5]  # Cap at 5

    # Summary and details
    summary = osv.get("summary", "")
    details = osv.get("details", "")
    if not summary and details:
        summary = details[:300]

    # Vulnerable functions (if available from ecosystem_specific)
    vulnerable_functions = []
    for aff in affected_list:
        eco_specific = aff.get("ecosystem_specific", {})
        # Some ecosystems list vulnerable functions
        if "affected_functions" in eco_specific:
            vulnerable_functions.extend(eco_specific["affected_functions"])

    return {
        "id": osv.get("id", ""),
        "aliases": osv.get("aliases", []),  # e.g., ["CVE-2024-1234"]
        "package": package_name,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "summary": summary,
        "details": details[:1000] if details else "",
        "affected_range": affected_range,
        "fixed_version": fixed_version,
        "cwes": cwes,  # List of CWE IDs
        "published": osv.get("published", ""),
        "modified": osv.get("modified", ""),
        "references": references,
        "vulnerable_functions": vulnerable_functions[:10],
        "withdrawn": osv.get("withdrawn", None),
    }


def download_ecosystem(client: httpx.Client, ecosystem_osv: str) -> list[dict]:
    """Download and parse the full advisory ZIP for an ecosystem."""
    url = f"{OSV_GCS_BASE}/{ecosystem_osv}/all.zip"
    print(f"  Downloading {url} ...")

    resp = client.get(url)
    if resp.status_code == 404:
        print(f"  Not found: {url}")
        return []
    resp.raise_for_status()

    advisories = []
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name))
                converted = convert_osv(data)
                if converted and not converted.get("withdrawn"):
                    advisories.append(converted)
            except Exception:
                continue

    return advisories


def main():
    parser = argparse.ArgumentParser(description="Sync offline advisory database from OSV")
    parser.add_argument("--output", type=Path, default=Path("data/advisories"))
    parser.add_argument("--ecosystems", nargs="*", help="Only sync specific ecosystems")
    args = parser.parse_args()

    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    ecosystems = args.ecosystems or list(ECOSYSTEMS.keys())

    client = httpx.Client(timeout=120, follow_redirects=True)
    total = 0

    for local_name in ecosystems:
        if local_name not in ECOSYSTEMS:
            print(f"Unknown ecosystem: {local_name}")
            continue

        osv_name = ECOSYSTEMS[local_name]
        print(f"Syncing {osv_name}...")

        eco_dir = output / local_name
        eco_dir.mkdir(exist_ok=True)

        try:
            advisories = download_ecosystem(client, osv_name)

            # Write as single JSON array (simpler than one-file-per-advisory)
            out_file = eco_dir / "advisories.json"
            out_file.write_text(json.dumps(advisories, indent=None, separators=(",", ":")))

            total += len(advisories)
            print(f"  {len(advisories)} advisories saved")

        except Exception as e:
            print(f"  Error syncing {osv_name}: {e}")

    # Write version
    version = datetime.now().strftime("%Y.%m.%d")
    (output / "VERSION").write_text(version)

    # Write manifest
    manifest = {
        "source": "OSV (https://osv.dev)",
        "license": "CC-BY-4.0",
        "synced_at": datetime.now().isoformat(),
        "total_advisories": total,
        "ecosystems": ecosystems,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"\n{'='*50}")
    print(f"  Total advisories: {total}")
    print(f"  Output: {output}")
    print(f"  Version: {version}")
    print(f"{'='*50}")

    client.close()


if __name__ == "__main__":
    main()
