"""Advisory correlation engine — matches findings against the advisory database.

Three correlation strategies:
1. CWE-to-advisory: Match finding CWE IDs against advisory CWEs in the same ecosystem
2. Version fingerprinting: Detect technology versions from code and check against advisories
3. Vulnerable function detection: Match function calls against known vulnerable functions
"""

import json
import logging
import re
from pathlib import Path

import yaml

from app.analysis.advisory_db import load_ecosystem_advisories
from app.analysis.package_identity import (
    match_external_import_to_package,
    normalise_package_name,
    package_index_keys,
)
from app.analysis.paths import load_repo_path_policy, should_skip_repo_path
from app.config import settings

logger = logging.getLogger(__name__)

LANGUAGE_TO_ECOSYSTEM = {
    "python": "pypi",
    "javascript": "npm",
    "typescript": "npm",
    "java": "maven",
    "kotlin": "maven",
    "go": "go",
    "ruby": "rubygems",
    "php": "packagist",
    "rust": "crates",
    "csharp": "nuget",
    "dart": "pub",
    "flutter": "pub",
    "elixir": "hex",
    "erlang": "hex",
}

# ── CWE-to-advisory Index ─────────────────────────────────────────

_cwe_index: dict[str, list[dict]] | None = None  # CWE-ID -> [advisory_summary per ecosystem]
_func_index: dict[str, list[dict]] | None = None  # function_name_lower -> [advisory_summary]


def _advisory_summary_entry(adv: dict, ecosystem: str) -> dict | None:
    aliases = adv.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    advisory_id = adv.get("id", "") or cve_id
    display_id = cve_id or advisory_id
    if not display_id:
        return None

    return {
        "cve_id": cve_id,
        "advisory_id": advisory_id,
        "display_id": display_id,
        "match_type": "related_by_cwe",
        "aliases": aliases[:5],
        "package": adv.get("package", ""),
        "ecosystem": ecosystem,
        "severity": adv.get("severity", ""),
        "summary": (adv.get("summary") or "")[:200],
        "fixed_version": adv.get("fixed_version"),
        "affected_range": adv.get("affected_range"),
        "vulnerable_functions": [
            func
            for func in (adv.get("vulnerable_functions") or [])
            if isinstance(func, str) and func
        ],
    }


def _function_index_keys(symbol: str) -> set[str]:
    """Derive searchable keys from a possibly-qualified function symbol."""
    clean = (symbol or "").strip().strip("`'\"")
    if not clean:
        return set()

    clean = re.sub(r"\(.*$", "", clean).strip()
    clean = re.sub(r"<[^>]+>", "", clean).strip()
    clean = clean.rstrip(").,:;")
    if not clean:
        return set()

    dotted = clean.replace("::", ".").replace("->", ".").replace("#", ".")
    keys = {clean.lower(), dotted.lower()}
    keys.update(part.lower() for part in dotted.split(".") if part)
    return {
        key
        for key in keys
        if len(key) >= 2 and re.match(r"^[a-z_][a-z0-9_]*$", key)
    }


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
        try:
            advisories = load_ecosystem_advisories(advisory_dir, ecosystem)
        except Exception as e:
            logger.warning("Failed to load %s advisories: %s", ecosystem, e)
            continue
        if not advisories:
            continue

        for adv in advisories:
            summary_entry = _advisory_summary_entry(adv, ecosystem)
            if not summary_entry:
                continue

            # Index by (CWE, ecosystem) to ensure all ecosystems are represented
            for cwe in adv.get("cwes") or []:
                if cwe not in _cwe_index:
                    _cwe_index[cwe] = []
                # Cap per (CWE, ecosystem) pair to avoid memory bloat
                eco_count = sum(1 for e in _cwe_index[cwe] if e["ecosystem"] == ecosystem)
                if eco_count < 10:
                    _cwe_index[cwe].append(summary_entry)

            # Index by vulnerable function
            for func in adv.get("vulnerable_functions") or []:
                for func_key in _function_index_keys(func):
                    if func_key not in _func_index:
                        _func_index[func_key] = []
                    if len(_func_index[func_key]) < 20:
                        _func_index[func_key].append(summary_entry)

    logger.info(
        "Advisory index built: %d CWE entries, %d vulnerable function entries",
        len(_cwe_index), len(_func_index),
    )
    return _cwe_index, _func_index


# ── Strategy 1: CWE-to-advisory Correlation ───────────────────────

def correlate_by_cwe(
    cwe_ids: list[str],
    languages: list[str] | None = None,
    max_results: int = 5,
) -> list[dict]:
    """Find advisories matching the given CWE IDs, optionally filtered by language/ecosystem."""
    cwe_index, _ = _load_cwe_and_func_index()

    # Map languages to ecosystems for filtering
    eco_filter = set()
    if languages:
        for lang in languages:
            eco = LANGUAGE_TO_ECOSYSTEM.get(lang.lower())
            if eco:
                eco_filter.add(eco)

    results = []
    seen_advisories = set()

    for cwe in cwe_ids:
        matches = cwe_index.get(cwe, [])
        for m in matches:
            advisory_key = m.get("display_id") or m.get("advisory_id") or m.get("cve_id")
            if advisory_key in seen_advisories:
                continue
            # Filter by ecosystem if languages provided
            if eco_filter and m["ecosystem"] not in eco_filter:
                continue
            seen_advisories.add(advisory_key)
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
    policy = load_repo_path_policy(repo)

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
        ("pubspec.lock", "pub", _parse_pubspec_lock),
        ("mix.lock", "hex", _parse_mix_lock),
    ]

    for manifest_name, eco, parser in manifests:
        for manifest_path in repo.rglob(manifest_name):
            if should_skip_repo_path(manifest_path, repo, policy=policy):
                continue
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


def _parse_pubspec_lock(content: str) -> list[tuple[str, str]]:
    """Extract locked package versions from pubspec.lock."""
    try:
        data = yaml.safe_load(content)
    except Exception:
        return []

    packages = data.get("packages", {}) if isinstance(data, dict) else {}
    if not isinstance(packages, dict):
        return []

    results = []
    for package_name, metadata in packages.items():
        if not isinstance(metadata, dict):
            continue
        source = str(metadata.get("source", "")).strip().lower()
        if source in {"path", "git"}:
            continue

        description = metadata.get("description")
        if isinstance(description, dict):
            package_name = description.get("name") or package_name

        version = str(metadata.get("version", "")).strip()
        if package_name and version:
            results.append((package_name, version))
    return results


def _parse_mix_lock(content: str) -> list[tuple[str, str]]:
    """Extract Hex package versions from mix.lock."""
    hex_entry_pattern = re.compile(
        r'"(?P<lock_name>[^"]+)"\s*(?:=>|:)\s*\{\s*:hex\s*,\s*'
        r'(?::"(?P<quoted_atom>[^"]+)"|:(?P<atom>[A-Za-z0-9_]+)|"(?P<quoted_name>[^"]+)")\s*,\s*'
        r'"(?P<version>[^"]+)"',
        re.MULTILINE,
    )

    results = []
    for match in hex_entry_pattern.finditer(content):
        package_name = (
            match.group("quoted_atom")
            or match.group("atom")
            or match.group("quoted_name")
            or match.group("lock_name")
        )
        version = match.group("version")
        if package_name and version:
            results.append((package_name, version))
    return results


def check_versions_against_advisories(
    detected_versions: list[dict],
) -> list[dict]:
    """Check detected versions against the advisory database.

    Returns list of {package, version, advisory_id, cve_id, severity, summary, fixed_version}.
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
                "advisory_id": m.get("advisory_id") or m.get("cve_id", ""),
                "cve_id": m.get("cve_id", ""),
                "severity": m.get("severity", ""),
                "summary": m.get("summary", "")[:200],
                "fixed_version": m.get("fixed_version"),
                "vulnerable_functions": m.get("vulnerable_functions", []),
                "file_path": det.get("file_path", ""),
                "match_type": m.get("match_type", "version_fingerprint_match"),
            })

    return results


# ── Strategy 3: Vulnerable Function Detection ─────────────────────

def _ecosystem_filter_for_languages(languages: list[str] | None) -> set[str]:
    eco_filter = set()
    for lang in languages or []:
        eco = LANGUAGE_TO_ECOSYSTEM.get(str(lang or "").lower())
        if eco:
            eco_filter.add(eco)
    return eco_filter


def _package_names_overlap(package_a: str, package_b: str, ecosystem: str) -> bool:
    eco = (ecosystem or "").strip().lower()
    if not eco:
        return package_a.strip().lower() == package_b.strip().lower()

    keys_a = package_index_keys(package_a, eco)
    keys_b = package_index_keys(package_b, eco)
    if keys_a and keys_b:
        return bool(keys_a & keys_b)

    return normalise_package_name(package_a, eco) == normalise_package_name(package_b, eco)


def _iter_external_imports(import_resolutions) -> list[dict]:
    imports: list[dict] = []
    for res in import_resolutions or []:
        if isinstance(res, dict):
            import_module = res.get("import_module", "")
            imported_names = res.get("imported_names") or []
            is_external = bool(res.get("is_external"))
            line = int(res.get("line", 0) or 0)
        else:
            import_module = getattr(res, "import_module", "")
            imported_names = getattr(res, "imported_names", []) or []
            is_external = bool(getattr(res, "is_external", False))
            line = int(getattr(res, "line", 0) or 0)

        if not is_external or not import_module:
            continue

        imports.append(
            {
                "import_module": str(import_module),
                "imported_names": [
                    str(name).strip()
                    for name in imported_names
                    if isinstance(name, str) and str(name).strip()
                ],
                "line": line,
            }
        )
    return imports


def _best_dependency_context_match(vulnerable_dependencies: list[dict] | None, advisory: dict) -> dict | None:
    advisory_package = advisory.get("package", "")
    advisory_ecosystem = (advisory.get("ecosystem") or "").strip().lower()
    best_match = None
    best_rank = -1

    for dep in vulnerable_dependencies or []:
        if not isinstance(dep, dict):
            continue

        dep_package = dep.get("package", "")
        dep_ecosystem = (dep.get("ecosystem") or "").strip().lower()
        ecosystem = advisory_ecosystem or dep_ecosystem
        if advisory_ecosystem and dep_ecosystem and advisory_ecosystem != dep_ecosystem:
            continue
        if not _package_names_overlap(dep_package, advisory_package, ecosystem):
            continue

        source = dep.get("import_match_source") or dep.get("source") or ""
        rank = 2 if source == "import_graph" else 1
        if rank > best_rank:
            best_rank = rank
            best_match = dep

    if not best_match:
        return None

    return {
        "entry": best_match,
        "strength": "strong" if best_rank >= 2 else "medium",
    }


def _best_import_match(
    import_resolutions,
    package: str,
    ecosystem: str,
    *,
    function_name: str = "",
    call_object: str = "",
) -> dict | None:
    best_match = None
    function_token = (function_name or "").strip().lower()
    object_token = (call_object or "").strip().lower()

    for res in _iter_external_imports(import_resolutions):
        match = match_external_import_to_package(package, ecosystem, res["import_module"])
        if not match:
            continue

        confidence = float(match["confidence"])
        evidence = "module_import"
        imported_names = {name.lower() for name in res["imported_names"]}

        if function_token and function_token in imported_names:
            confidence = max(confidence, 0.99)
            evidence = "imported_symbol"
        elif object_token:
            qualifier_match = match_external_import_to_package(package, ecosystem, object_token)
            if qualifier_match:
                confidence = max(confidence, 0.96)
                evidence = "qualified_call"

        candidate = {
            **match,
            "confidence": round(confidence, 2),
            "import_module": res["import_module"],
            "import_line": res["line"],
            "imported_symbol": function_token if evidence == "imported_symbol" else "",
            "evidence": evidence,
        }

        if best_match is None or candidate["confidence"] > best_match["confidence"]:
            best_match = candidate

    return best_match

def find_vulnerable_function_calls(
    file_path: str,
    content: str,
    languages: list[str] | None = None,
    *,
    import_resolutions=None,
    vulnerable_dependencies: list[dict] | None = None,
) -> list[dict]:
    """Check if a file calls any known vulnerable functions from the advisory DB.

    Strong results require package evidence from the file's imports or vulnerable
    dependency context. Bare function-name overlaps remain weak hints only.
    """
    _, func_index = _load_cwe_and_func_index()
    if not func_index:
        return []

    results_by_advisory: dict[str, dict] = {}
    eco_filter = _ecosystem_filter_for_languages(languages)

    # Extract function calls from the content
    # Match common patterns: function_name(, obj.function_name(, Class::function_name(
    call_pattern = re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?:(?P<object>[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|::|->|#)[A-Za-z_][A-Za-z0-9_]*)*)\s*(?:\.|::|->|#))?"
        r"(?P<function>\w+)\s*\(",
        re.MULTILINE,
    )
    strength_rank = {"strong": 3, "medium": 2, "weak": 1}

    for m in call_pattern.finditer(content):
        func_name = m.group("function").lower()
        if func_name in func_index:
            line_num = content[:m.start("function")].count("\n") + 1
            call_object = (m.group("object") or "").strip()
            for adv in func_index[func_name]:
                advisory_ecosystem = (adv.get("ecosystem") or "").strip().lower()
                if eco_filter and advisory_ecosystem and advisory_ecosystem not in eco_filter:
                    continue

                advisory_key = adv.get("display_id") or adv.get("advisory_id") or adv.get("cve_id")
                if not advisory_key:
                    continue

                dep_match = _best_dependency_context_match(vulnerable_dependencies, adv)
                import_match = None
                if not dep_match or dep_match["strength"] != "strong":
                    import_match = _best_import_match(
                        import_resolutions,
                        adv.get("package", ""),
                        advisory_ecosystem,
                        function_name=func_name,
                        call_object=call_object,
                    )

                if dep_match:
                    evidence_strength = dep_match["strength"]
                    dep_entry = dep_match["entry"]
                    match_type = (
                        "confirmed_vulnerable_dependency_function_match"
                        if evidence_strength == "strong"
                        else "likely_vulnerable_dependency_function_match"
                    )
                    package_evidence_source = dep_entry.get("import_match_source") or dep_entry.get("source") or "dependency_context"
                    package_match_confidence = float(dep_entry.get("import_match_confidence") or 0.85)
                    import_module = dep_entry.get("import_module", "")
                    imported_symbol = ""
                elif import_match:
                    evidence_strength = "medium"
                    match_type = "import_confirmed_function_match"
                    package_evidence_source = "import_graph"
                    package_match_confidence = float(import_match["confidence"])
                    import_module = import_match.get("import_module", "")
                    imported_symbol = import_match.get("imported_symbol", "")
                else:
                    evidence_strength = "weak"
                    match_type = "function_name_overlap"
                    package_evidence_source = "function_name_only"
                    package_match_confidence = 0.25
                    import_module = ""
                    imported_symbol = ""

                candidate = {
                    "function": m.group("function"),
                    "line": line_num,
                    "file_path": file_path,
                    "display_id": advisory_key,
                    "advisory_id": adv.get("advisory_id"),
                    "cve_id": adv.get("cve_id"),
                    "package": adv.get("package", ""),
                    "ecosystem": advisory_ecosystem,
                    "severity": adv.get("severity", "medium"),
                    "summary": adv.get("summary", ""),
                    "fixed_version": adv.get("fixed_version"),
                    "cwe_ids": adv.get("cwes") or adv.get("cwe_ids") or [],
                    "match_type": match_type,
                    "evidence_strength": evidence_strength,
                    "package_evidence_source": package_evidence_source,
                    "package_match_confidence": round(package_match_confidence, 2),
                    "import_module": import_module,
                    "imported_symbol": imported_symbol,
                    "call_object": call_object,
                }

                existing = results_by_advisory.get(advisory_key)
                if not existing:
                    results_by_advisory[advisory_key] = candidate
                    continue

                current_rank = strength_rank.get(candidate["evidence_strength"], 0)
                existing_rank = strength_rank.get(existing.get("evidence_strength", ""), 0)
                if current_rank > existing_rank:
                    results_by_advisory[advisory_key] = candidate
                    continue
                if current_rank == existing_rank:
                    current_conf = float(candidate.get("package_match_confidence") or 0.0)
                    existing_conf = float(existing.get("package_match_confidence") or 0.0)
                    if current_conf > existing_conf or (
                        current_conf == existing_conf and int(candidate.get("line", 0) or 0) < int(existing.get("line", 0) or 0)
                    ):
                        results_by_advisory[advisory_key] = candidate

    results = sorted(
        results_by_advisory.values(),
        key=lambda item: (
            -strength_rank.get(item.get("evidence_strength", ""), 0),
            -float(item.get("package_match_confidence") or 0.0),
            int(item.get("line", 0) or 0),
        ),
    )
    return results[:10]
