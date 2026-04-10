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
import math
import re
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
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

INLINE_CODE_RE = re.compile(r"`([^`\n]{2,160})`")
FUNCTION_CONTEXT_RE = re.compile(
    r"(?:function|method|api|endpoint|helper|callback|constructor)\s+"
    r"(?:called\s+|named\s+)?`?([A-Za-z_][A-Za-z0-9_:.-]{1,120}(?:\(\))?)`?",
    re.IGNORECASE,
)
GENERIC_FUNCTION_NAMES = {
    "main",
    "new",
    "default",
    "test",
    "example",
    "read",
    "write",
    "open",
    "close",
    "call",
    "run",
    "exec",
}


def _normalise_function_candidate(token: str, *, explicit: bool) -> str | None:
    clean = (token or "").strip().strip("`'\"")
    if not clean or any(ch.isspace() for ch in clean):
        return None

    had_call = "(" in clean
    clean = clean.split("(", 1)[0].strip()
    clean = re.sub(r"<[^>]+>", "", clean).strip()
    clean = clean.rstrip(").,:;")
    if not clean:
        return None
    if clean.lower() in GENERIC_FUNCTION_NAMES:
        return None
    if re.fullmatch(r"v?\d+(?:\.\d+)+", clean):
        return None
    if clean.startswith(("http://", "https://")) or "/" in clean:
        return None
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_:.-]*$", clean):
        return None

    qualified = any(sep in clean for sep in ("::", ".", "->", "#"))
    symbol_like = explicit or qualified or had_call or "_" in clean or any(ch.isupper() for ch in clean[1:])
    return clean if symbol_like else None


def extract_vulnerable_functions(advisory: dict) -> tuple[list[str], list[str]]:
    """Extract function/API symbols from advisory text into a separate enrichment layer."""
    candidates: dict[str, set[str]] = {}

    def add_candidate(token: str, source: str, *, explicit: bool = False) -> None:
        normalised = _normalise_function_candidate(token, explicit=explicit)
        if not normalised:
            return
        candidates.setdefault(normalised, set()).add(source)

    for field_name in ("summary", "details"):
        text = advisory.get(field_name, "") or ""
        if not text:
            continue

        for match in FUNCTION_CONTEXT_RE.finditer(text):
            add_candidate(match.group(1), f"{field_name}_context", explicit=False)

        for match in INLINE_CODE_RE.finditer(text):
            token = match.group(1)
            window = text[max(0, match.start() - 40): min(len(text), match.end() + 40)].lower()
            explicit = any(word in window for word in ("function", "method", "api", "endpoint", "helper", "callback"))
            add_candidate(token, f"{field_name}_inline_code", explicit=explicit)

    extracted = sorted(candidates)
    sources = sorted({source for source_list in candidates.values() for source in source_list})
    return extracted[:20], sources


def build_enrichment_artifact(advisories: list[dict]) -> dict:
    advisories_out: dict[str, dict] = {}
    enriched_count = 0
    extracted_function_count = 0

    for advisory in advisories:
        advisory_id = advisory.get("id", "")
        if not advisory_id:
            continue

        extracted_functions, sources = extract_vulnerable_functions(advisory)
        existing = {
            func for func in (advisory.get("vulnerable_functions") or [])
            if isinstance(func, str) and func
        }
        extra_functions = [func for func in extracted_functions if func not in existing]
        if not extra_functions:
            continue

        advisories_out[advisory_id] = {
            "vulnerable_functions": extra_functions,
            "sources": sources,
        }
        enriched_count += 1
        extracted_function_count += len(extra_functions)

    return {
        "generated_at": datetime.now().isoformat(),
        "strategy_version": 1,
        "stats": {
            "enriched_advisories": enriched_count,
            "extracted_vulnerable_functions": extracted_function_count,
        },
        "advisories": advisories_out,
    }


def _round_up_1(value: float) -> float:
    return math.ceil(value * 10) / 10.0


def _cvss_v3_base_score(vector: str) -> float | None:
    metrics = {}
    for token in (vector or "").split("/"):
        if ":" not in token:
            continue
        key, value = token.split(":", 1)
        metrics[key] = value

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac = {"L": 0.77, "H": 0.44}
    ui = {"N": 0.85, "R": 0.62}
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    scope = metrics["S"]
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}

    try:
        impact_subscore = 1 - (
            (1 - cia[metrics["C"]]) * (1 - cia[metrics["I"]]) * (1 - cia[metrics["A"]])
        )
        if scope == "U":
            impact = 6.42 * impact_subscore
            privilege = pr_u[metrics["PR"]]
        else:
            impact = 7.52 * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)
            privilege = pr_c[metrics["PR"]]
        exploitability = 8.22 * av[metrics["AV"]] * ac[metrics["AC"]] * privilege * ui[metrics["UI"]]
    except KeyError:
        return None

    if impact <= 0:
        return 0.0
    if scope == "U":
        return min(_round_up_1(impact + exploitability), 10.0)
    return min(_round_up_1(1.08 * (impact + exploitability)), 10.0)


def _extract_cvss(severity_list: list[dict]) -> tuple[float | None, str | None]:
    best_score = None
    best_vector = None
    for severity in severity_list or []:
        score_value = severity.get("score", "")
        score_type = severity.get("type", "")
        if not isinstance(score_value, str) or not score_value:
            continue

        parsed_score = None
        if score_value.startswith("CVSS:3"):
            parsed_score = _cvss_v3_base_score(score_value)
        elif score_value.startswith("CVSS:4"):
            parsed_score = None
        else:
            try:
                parsed_score = float(score_value)
            except (TypeError, ValueError):
                parsed_score = None

        if parsed_score is not None and (best_score is None or parsed_score > best_score):
            best_score = parsed_score
            best_vector = score_value if score_type.startswith("CVSS") else None

    return best_score, best_vector


def _severity_from_score(cvss_score: float | None, fallback: str) -> str:
    severity = fallback
    if cvss_score is None:
        return severity
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"


def _extract_ranges(affected: dict) -> tuple[list[str], list[str], list[str]]:
    affected_ranges: list[str] = []
    fixed_versions: list[str] = []
    explicit_versions: list[str] = []

    for range_block in affected.get("ranges", []) or []:
        if not isinstance(range_block, dict):
            continue
        if str(range_block.get("type", "")).upper() == "GIT":
            continue

        parts: list[str] = []
        for event in range_block.get("events", []) or []:
            if not isinstance(event, dict):
                continue
            introduced = event.get("introduced")
            fixed = event.get("fixed")
            last_affected = event.get("last_affected")
            limit = event.get("limit")
            if introduced not in (None, ""):
                parts.append(f">={introduced}")
            if fixed not in (None, ""):
                parts.append(f"<{fixed}")
                fixed_versions.append(str(fixed))
            if last_affected not in (None, ""):
                parts.append(f"<={last_affected}")
            if limit not in (None, ""):
                parts.append(f"<{limit}")
        if parts:
            affected_ranges.append(",".join(parts))

    versions = affected.get("versions", []) or []
    for version in versions:
        if isinstance(version, str) and version:
            explicit_versions.append(version)

    return affected_ranges, fixed_versions, explicit_versions


def convert_osv(osv: dict) -> list[dict]:
    """Convert a single OSV advisory into package-specific VRAgent records."""
    affected_list = osv.get("affected", [])
    if not affected_list:
        return []

    db_specific = osv.get("database_specific", {})
    fallback_severity = SEVERITY_MAP.get(str(db_specific.get("severity", "MODERATE")).upper(), "medium")
    top_level_cvss, top_level_vector = _extract_cvss(osv.get("severity", []))
    references = [
        ref.get("url", "") for ref in osv.get("references", [])
        if ref.get("url")
    ][:10]
    summary = osv.get("summary", "")
    details = osv.get("details", "")
    if not summary and details:
        summary = details[:300]

    package_records: dict[str, dict] = {}

    for affected in affected_list:
        pkg_info = affected.get("package", {})
        package_name = pkg_info.get("name", "")
        if not package_name:
            continue

        affected_ranges, fixed_versions, affected_versions = _extract_ranges(affected)
        package_cvss, package_vector = _extract_cvss(affected.get("severity", []))
        cvss_score = package_cvss if package_cvss is not None else top_level_cvss
        cvss_vector = package_vector or top_level_vector
        severity = _severity_from_score(cvss_score, fallback_severity)
        cwes = (
            affected.get("database_specific", {}).get("cwe_ids")
            or db_specific.get("cwe_ids", [])
        )

        vulnerable_functions = []
        eco_specific = affected.get("ecosystem_specific", {}) if isinstance(affected, dict) else {}
        if isinstance(eco_specific, dict) and "affected_functions" in eco_specific:
            vulnerable_functions.extend(eco_specific.get("affected_functions") or [])

        record = package_records.setdefault(
            package_name,
            {
                "id": osv.get("id", ""),
                "aliases": osv.get("aliases", []),
                "package": package_name,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "summary": summary,
                "details": details[:1000] if details else "",
                "affected_ranges": [],
                "affected_versions": [],
                "fixed_versions": [],
                "cwes": [],
                "published": osv.get("published", ""),
                "modified": osv.get("modified", ""),
                "references": list(references),
                "vulnerable_functions": [],
                "withdrawn": osv.get("withdrawn", None),
            },
        )

        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(record.get("severity", "info"), 0):
            record["severity"] = severity
        if cvss_score is not None and (
            record.get("cvss_score") is None or cvss_score > record.get("cvss_score")
        ):
            record["cvss_score"] = cvss_score
            record["cvss_vector"] = cvss_vector

        for value, key in (
            (affected_ranges, "affected_ranges"),
            (affected_versions, "affected_versions"),
            (fixed_versions, "fixed_versions"),
            (cwes, "cwes"),
            (references, "references"),
            (vulnerable_functions, "vulnerable_functions"),
        ):
            for item in value or []:
                if item and item not in record[key]:
                    record[key].append(item)

    converted_records: list[dict] = []
    for record in package_records.values():
        record["affected_range"] = " || ".join(record.get("affected_ranges", []))
        fixed_versions = record.get("fixed_versions", [])
        record["fixed_version"] = fixed_versions[0] if fixed_versions else None
        converted_records.append(record)

    return converted_records


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
                converted_records = convert_osv(data)
                advisories.extend(
                    record for record in converted_records
                    if record and not record.get("withdrawn")
                )
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

            enrichment = build_enrichment_artifact(advisories)
            (eco_dir / "enrichment.json").write_text(
                json.dumps(enrichment, indent=None, separators=(",", ":"))
            )

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
        "enrichment": {
            "artifact": "enrichment.json",
            "strategy_version": 1,
        },
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
