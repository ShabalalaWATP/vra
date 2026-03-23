"""CVE Correlation Engine — matches findings against the advisory database.

Three correlation strategies:
1. CWE-to-CVE: Match finding CWE IDs against advisory CWEs in the same ecosystem
2. Version fingerprinting: Detect technology versions from code and check against advisories
3. Vulnerable function detection: Match function calls against known vulnerable functions
"""

import json
import logging
import re
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

# ── CWE-to-CVE Index ──────────────────────────────────────────────

_cwe_index: dict[str, list[dict]] | None = None  # CWE-ID -> [advisory_summary per ecosystem]
_func_index: dict[str, list[dict]] | None = None  # function_name_lower -> [advisory_summary]


def _load_cwe_and_func_index() -> tuple[dict, dict]:
    """Build indexes from all advisory ecosystems: CWE->advisories and function->advisories."""
    global _cwe_index, _func_index
    if _cwe_index is not None:
        return _cwe_index, _func_index or {}

    _cwe_index = {}
    _func_index = {}
    advisory_dir = settings.advisory_db_path

    if not advisory_dir.exists():
        logger.warning("Advisory DB not found at %s", advisory_dir)
        return _cwe_index, _func_index

    ecosystems = [d.name for d in advisory_dir.iterdir() if d.is_dir()]

    for ecosystem in ecosystems:
        adv_file = advisory_dir / ecosystem / "advisories.json"
        if not adv_file.exists():
            continue

        try:
            with open(adv_file, "r", encoding="utf-8") as f:
                advisories = json.load(f)
        except Exception as e:
            logger.warning("Failed to load %s advisories: %s", ecosystem, e)
            continue

        for adv in advisories:
            aliases = adv.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
            if not cve_id:
                continue  # Skip advisories without CVE IDs

            summary_entry = {
                "cve_id": cve_id,
                "advisory_id": adv.get("id", ""),
                "package": adv.get("package", ""),
                "ecosystem": ecosystem,
                "severity": adv.get("severity", ""),
                "summary": (adv.get("summary") or "")[:200],
                "fixed_version": adv.get("fixed_version"),
                "affected_range": adv.get("affected_range"),
                "vulnerable_functions": adv.get("vulnerable_functions", []),
            }

            # Index by (CWE, ecosystem) to ensure all ecosystems are represented
            for cwe in adv.get("cwes", []):
                if cwe not in _cwe_index:
                    _cwe_index[cwe] = []
                # Cap per (CWE, ecosystem) pair to avoid memory bloat
                eco_count = sum(1 for e in _cwe_index[cwe] if e["ecosystem"] == ecosystem)
                if eco_count < 10:
                    _cwe_index[cwe].append(summary_entry)

            # Index by vulnerable function
            for func in adv.get("vulnerable_functions", []):
                func_lower = func.lower().split(".")[-1]  # Just the function name
                if func_lower not in _func_index:
                    _func_index[func_lower] = []
                if len(_func_index[func_lower]) < 20:
                    _func_index[func_lower].append(summary_entry)

    logger.info(
        "CVE index built: %d CWE entries, %d vulnerable function entries",
        len(_cwe_index), len(_func_index),
    )
    return _cwe_index, _func_index


# ── Strategy 1: CWE-to-CVE Correlation ────────────────────────────

def correlate_by_cwe(
    cwe_ids: list[str],
    languages: list[str] | None = None,
    max_results: int = 5,
) -> list[dict]:
    """Find CVEs matching the given CWE IDs, optionally filtered by language/ecosystem."""
    cwe_index, _ = _load_cwe_and_func_index()

    # Map languages to ecosystems for filtering
    lang_to_eco = {
        "python": "pypi", "javascript": "npm", "typescript": "npm",
        "java": "maven", "kotlin": "maven", "go": "go",
        "ruby": "rubygems", "php": "packagist", "rust": "crates",
        "csharp": "nuget",
    }
    eco_filter = set()
    if languages:
        for lang in languages:
            eco = lang_to_eco.get(lang.lower())
            if eco:
                eco_filter.add(eco)

    results = []
    seen_cves = set()

    for cwe in cwe_ids:
        matches = cwe_index.get(cwe, [])
        for m in matches:
            if m["cve_id"] in seen_cves:
                continue
            # Filter by ecosystem if languages provided
            if eco_filter and m["ecosystem"] not in eco_filter:
                continue
            seen_cves.add(m["cve_id"])
            results.append(m)
            if len(results) >= max_results:
                return results

    return results


# ── Strategy 2: Version Fingerprinting ─────────────────────────────

# Patterns that extract version numbers from code
VERSION_PATTERNS = [
    # JavaScript: jQuery, React, Angular, etc.
    (re.compile(r"jQuery\s+v?([\d.]+)", re.IGNORECASE), "jquery", "npm"),
    (re.compile(r"(?:React|react)\s+v?([\d.]+)"), "react", "npm"),
    (re.compile(r"angular[./](?:core/)?v?([\d.]+)", re.IGNORECASE), "@angular/core", "npm"),
    (re.compile(r"vue(?:\.js)?[/@\s]v?([\d.]+)", re.IGNORECASE), "vue", "npm"),
    (re.compile(r"bootstrap[/@\s]v?([\d.]+)", re.IGNORECASE), "bootstrap", "npm"),
    (re.compile(r"lodash[/@\s]v?([\d.]+)", re.IGNORECASE), "lodash", "npm"),
    (re.compile(r"moment[/@\s]v?([\d.]+)", re.IGNORECASE), "moment", "npm"),
    # PHP
    (re.compile(r"WordPress\s+([\d.]+)", re.IGNORECASE), "wordpress", "packagist"),
    (re.compile(r"Laravel\s+v?([\d.]+)", re.IGNORECASE), "laravel/framework", "packagist"),
    (re.compile(r"Symfony\s+v?([\d.]+)", re.IGNORECASE), "symfony/symfony", "packagist"),
    # Python
    (re.compile(r"Django[/\s]v?([\d.]+)", re.IGNORECASE), "django", "pypi"),
    (re.compile(r"Flask[/\s]v?([\d.]+)", re.IGNORECASE), "flask", "pypi"),
    (re.compile(r"requests[/\s]v?([\d.]+)", re.IGNORECASE), "requests", "pypi"),
    # Java
    (re.compile(r"Spring\s+(?:Boot\s+)?v?([\d.]+)", re.IGNORECASE), "spring-boot", "maven"),
    (re.compile(r"log4j[/-]v?([\d.]+)", re.IGNORECASE), "log4j-core", "maven"),
]


def fingerprint_versions(repo_path: str, file_contents: dict[str, str] | None = None) -> list[dict]:
    """Detect technology versions from code files.

    Returns list of {package, version, ecosystem, file_path}.
    """
    results = []
    seen = set()  # (package, version) dedup

    repo = Path(repo_path)

    # If we have file contents already, scan those
    if file_contents:
        for path, content in file_contents.items():
            for pattern, pkg, eco in VERSION_PATTERNS:
                for m in pattern.finditer(content[:5000]):
                    key = (pkg, m.group(1))
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "package": pkg,
                            "version": m.group(1),
                            "ecosystem": eco,
                            "file_path": path,
                        })

    # Also check common manifest files for pinned versions
    manifests = [
        ("package.json", "npm", _parse_package_json),
        ("composer.json", "packagist", _parse_composer_json),
        ("requirements.txt", "pypi", _parse_requirements_txt),
    ]

    for manifest_name, eco, parser in manifests:
        for manifest_path in repo.rglob(manifest_name):
            try:
                content = manifest_path.read_text(encoding="utf-8", errors="ignore")[:50000]
                for pkg, version in parser(content):
                    key = (pkg, version)
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "package": pkg,
                            "version": version,
                            "ecosystem": eco,
                            "file_path": str(manifest_path.relative_to(repo)),
                        })
            except Exception:
                continue

    return results


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    """Extract pinned versions from package.json."""
    try:
        data = json.loads(content)
    except Exception:
        return []
    results = []
    for section in ("dependencies", "devDependencies"):
        for pkg, ver in (data.get(section) or {}).items():
            # Strip version prefixes like ^, ~, >=
            clean = re.sub(r"^[\^~>=<]+", "", str(ver)).strip()
            if clean and re.match(r"\d+\.\d+", clean):
                results.append((pkg, clean))
    return results


def _parse_composer_json(content: str) -> list[tuple[str, str]]:
    """Extract pinned versions from composer.json."""
    try:
        data = json.loads(content)
    except Exception:
        return []
    results = []
    for section in ("require", "require-dev"):
        for pkg, ver in (data.get(section) or {}).items():
            if pkg == "php":
                continue
            clean = re.sub(r"^[\^~>=<]+", "", str(ver)).strip()
            if clean and re.match(r"\d+\.\d+", clean):
                results.append((pkg, clean))
    return results


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Extract pinned versions from requirements.txt."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([a-zA-Z0-9_-]+)\s*==\s*([\d.]+)", line)
        if m:
            results.append((m.group(1).lower(), m.group(2)))
    return results


def check_versions_against_advisories(
    detected_versions: list[dict],
) -> list[dict]:
    """Check detected versions against the advisory database.

    Returns list of {package, version, cve_id, severity, summary, fixed_version}.
    """
    from app.scanners.dep_audit import DepAuditAdapter

    adapter = DepAuditAdapter()
    results = []

    for det in detected_versions:
        pkg = det["package"]
        version = det["version"]
        ecosystem = det["ecosystem"]

        # Use dep_audit's matching logic
        matches = adapter.lookup_package(ecosystem, pkg, version)
        for m in matches[:3]:  # Cap per-package
            results.append({
                "package": pkg,
                "version": version,
                "ecosystem": ecosystem,
                "cve_id": m.get("cve_id", ""),
                "severity": m.get("severity", ""),
                "summary": m.get("summary", "")[:200],
                "fixed_version": m.get("fixed_version"),
                "file_path": det.get("file_path", ""),
            })

    return results


# ── Strategy 3: Vulnerable Function Detection ─────────────────────

def find_vulnerable_function_calls(
    file_path: str,
    content: str,
    languages: list[str] | None = None,
) -> list[dict]:
    """Check if a file calls any known vulnerable functions from the advisory DB.

    Returns list of {function, line, cve_id, package, severity, summary}.
    """
    _, func_index = _load_cwe_and_func_index()
    if not func_index:
        return []

    results = []
    seen_cves = set()

    # Extract function calls from the content
    # Match common patterns: function_name(, obj.function_name(, Class::function_name(
    call_pattern = re.compile(r"(?:^|[^a-zA-Z_])(\w+)\s*\(", re.MULTILINE)

    for m in call_pattern.finditer(content):
        func_name = m.group(1).lower()
        if func_name in func_index:
            line_num = content[:m.start()].count("\n") + 1
            for adv in func_index[func_name]:
                if adv["cve_id"] in seen_cves:
                    continue
                seen_cves.add(adv["cve_id"])
                results.append({
                    "function": m.group(1),
                    "line": line_num,
                    "file_path": file_path,
                    "cve_id": adv["cve_id"],
                    "package": adv["package"],
                    "severity": adv["severity"],
                    "summary": adv["summary"],
                })
                if len(results) >= 10:
                    return results

    return results
