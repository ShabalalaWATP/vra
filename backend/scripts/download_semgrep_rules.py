#!/usr/bin/env python3
"""
Download Semgrep rules for offline use.

Run on a machine WITH internet access, then copy the resulting
data/semgrep-rules/ directory to the air-gapped deployment.

Downloads the official Semgrep community rules from GitHub,
organised by language and risk category.

Usage:
    python -m scripts.download_semgrep_rules
    python -m scripts.download_semgrep_rules --output data/semgrep-rules/
"""

import argparse
import json
import sys
import tarfile
import tempfile
from pathlib import Path

try:
    import httpx
except ImportError:
    print("httpx is required: pip install httpx")
    sys.exit(1)

# The official semgrep-rules repo (community rules, LGPL-2.1)
RULES_REPO = "semgrep/semgrep-rules"
RULES_ARCHIVE_URL = f"https://github.com/{RULES_REPO}/archive/refs/heads/develop.tar.gz"

# Additional curated rule packs
EXTRA_RULE_SOURCES = [
    {
        "name": "elttam-semgrep-rules",
        "url": "https://github.com/elttam/semgrep-rules/archive/refs/heads/main.tar.gz",
        "desc": "Community security rules from elttam",
    },
]

# Categories we care about (subdirectories in semgrep-rules)
SECURITY_CATEGORIES = [
    "python",
    "javascript",
    "typescript",
    "java",
    "go",
    "ruby",
    "php",
    "csharp",
    "kotlin",
    "scala",
    "rust",
    "swift",
    "generic",
    "yaml",
    "json",
    "terraform",
    "dockerfile",
    "html",
]


def download_and_extract(client: httpx.Client, url: str, output: Path, label: str) -> int:
    """Download a tar.gz archive and extract YAML rule files."""
    print(f"  Downloading {label}...")
    resp = client.get(url, follow_redirects=True)
    resp.raise_for_status()

    count = 0
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp.write(resp.content)
        tmp_path = tmp.name

    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                if not (member.name.endswith(".yaml") or member.name.endswith(".yml")):
                    continue

                # Extract the relative path after the top-level directory
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                rel_path = Path(*parts[1:])  # Skip the root dir

                # Only keep security-relevant rules
                first_dir = rel_path.parts[0] if rel_path.parts else ""
                if first_dir in SECURITY_CATEGORIES or "security" in str(rel_path).lower():
                    dest = output / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)

                    f = tar.extractfile(member)
                    if f:
                        content = f.read()
                        # Validate it looks like a Semgrep rule
                        if b"rules:" in content or b"pattern:" in content or b"patterns:" in content:
                            dest.write_bytes(content)
                            count += 1
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return count


def main():
    parser = argparse.ArgumentParser(description="Download Semgrep rules for offline use")
    parser.add_argument("--output", type=Path, default=Path("data/semgrep-rules"))
    parser.add_argument("--skip-extras", action="store_true",
                        help="Only download official Semgrep rules")
    args = parser.parse_args()

    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    client = httpx.Client(timeout=120, follow_redirects=True)
    total = 0

    # Download official Semgrep rules
    print(f"Downloading official Semgrep community rules...")
    try:
        count = download_and_extract(client, RULES_ARCHIVE_URL, output, "semgrep/semgrep-rules")
        total += count
        print(f"  Extracted {count} rule files")
    except Exception as e:
        print(f"  Error: {e}")

    # Download extra rule packs
    if not args.skip_extras:
        for source in EXTRA_RULE_SOURCES:
            print(f"\nDownloading {source['name']}...")
            try:
                extras_dir = output / "_extras" / source["name"]
                count = download_and_extract(client, source["url"], extras_dir, source["name"])
                total += count
                print(f"  Extracted {count} rule files")
            except Exception as e:
                print(f"  Error: {e}")

    # Write manifest
    rule_files = sorted(str(p.relative_to(output)) for p in output.rglob("*.yaml"))
    rule_files += sorted(str(p.relative_to(output)) for p in output.rglob("*.yml"))
    manifest = {
        "source": RULES_REPO,
        "license": "LGPL-2.1",
        "total_rules": len(rule_files),
        "categories": sorted(set(
            Path(f).parts[0] for f in rule_files if Path(f).parts
        )),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"\n{'='*50}")
    print(f"  Total rule files: {total}")
    print(f"  Output: {output}")
    print(f"{'='*50}")

    client.close()


if __name__ == "__main__":
    main()
