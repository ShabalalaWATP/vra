"""Shared package identity helpers for advisory matching and dependency usage."""

import json
import re
from functools import lru_cache
from pathlib import Path

from app.config import settings


PEP503_LIKE_ECOSYSTEMS = {"pypi", "pub", "rubygems", "hex"}
PACKAGE_IMPORT_ALIASES_FILE = "package-import-aliases.json"

DEFAULT_IMPORT_ALIASES = {
    "pypi": {
        "beautifulsoup4": ["bs4"],
        "djangorestframework": ["rest_framework"],
        "google-api-python-client": ["googleapiclient"],
        "mysqlclient": ["mysqldb"],
        "opencv-contrib-python": ["cv2"],
        "opencv-python": ["cv2"],
        "pillow": ["pil"],
        "psycopg2-binary": ["psycopg2"],
        "pycryptodome": ["crypto"],
        "pyjwt": ["jwt"],
        "pyopenssl": ["openssl"],
        "python-dateutil": ["dateutil"],
        "pyyaml": ["yaml"],
        "ruamel-yaml": ["ruamel.yaml"],
        "scikit-image": ["skimage"],
        "scikit-learn": ["sklearn"],
        "setuptools": ["pkg_resources"],
    },
    "maven": {
        "com.fasterxml.jackson.core:jackson-databind": ["com.fasterxml.jackson.databind"],
        "com.fasterxml.jackson.dataformat:jackson-dataformat-yaml": ["com.fasterxml.jackson.dataformat.yaml"],
        "com.google.code.gson:gson": ["com.google.gson"],
        "com.squareup.okhttp3:okhttp": ["okhttp3"],
        "org.apache.logging.log4j:log4j-core": ["org.apache.logging.log4j"],
    },
}


def _clean_name(name: str) -> str:
    return str(name or "").strip().strip("'\"")


def normalise_package_name(name: str, ecosystem: str) -> str:
    """Return the canonical lookup form for a package name in an ecosystem."""
    clean = _clean_name(name)
    if not clean:
        return ""

    ecosystem = (ecosystem or "").strip().lower()
    lowered = clean.lower()

    if ecosystem in PEP503_LIKE_ECOSYSTEMS:
        return re.sub(r"[-_.]+", "-", lowered)

    if ecosystem == "maven":
        if ":" in lowered:
            group, artifact = lowered.split(":", 1)
            return f"{group.strip()}:{artifact.strip()}"
        return lowered

    return lowered


def _merge_aliases(target: dict[str, dict[str, set[str]]], ecosystem: str, package_name: str, aliases: list[str] | set[str]):
    eco = (ecosystem or "").strip().lower()
    canonical = normalise_package_name(package_name, eco)
    if not eco or not canonical:
        return

    bucket = target.setdefault(eco, {})
    package_aliases = bucket.setdefault(canonical, set())
    for alias in aliases or []:
        clean = _clean_name(alias).lower()
        if clean:
            package_aliases.add(clean)


@lru_cache(maxsize=8)
def _load_import_aliases(data_dir: str) -> dict[str, dict[str, set[str]]]:
    alias_map: dict[str, dict[str, set[str]]] = {}

    for ecosystem, packages in DEFAULT_IMPORT_ALIASES.items():
        for package_name, aliases in packages.items():
            _merge_aliases(alias_map, ecosystem, package_name, aliases)

    alias_path = Path(data_dir) / PACKAGE_IMPORT_ALIASES_FILE
    try:
        payload = json.loads(alias_path.read_text(encoding="utf-8"))
    except Exception:
        return alias_map

    if not isinstance(payload, dict):
        return alias_map

    for ecosystem, packages in payload.items():
        if not isinstance(packages, dict):
            continue
        for package_name, aliases in packages.items():
            if isinstance(aliases, str):
                alias_values = [aliases]
            elif isinstance(aliases, list):
                alias_values = aliases
            else:
                continue
            _merge_aliases(alias_map, ecosystem, package_name, alias_values)

    return alias_map


def curated_import_aliases(name: str, ecosystem: str) -> set[str]:
    eco = (ecosystem or "").strip().lower()
    canonical = normalise_package_name(name, eco)
    if not eco or not canonical:
        return set()

    alias_map = _load_import_aliases(str(settings.data_dir))
    return set(alias_map.get(eco, {}).get(canonical, set()))


def package_index_keys(name: str, ecosystem: str) -> set[str]:
    """Return all index keys that should resolve a package advisory."""
    clean = _clean_name(name)
    if not clean:
        return set()

    ecosystem = (ecosystem or "").strip().lower()
    lowered = clean.lower()
    canonical = normalise_package_name(clean, ecosystem)
    keys = {key for key in {lowered, canonical} if key}

    if ecosystem in PEP503_LIKE_ECOSYSTEMS:
        keys.update({
            lowered.replace("_", "-"),
            lowered.replace("-", "_"),
            lowered.replace(".", "-"),
            lowered.replace(".", "_"),
            re.sub(r"[-_.]+", "-", lowered),
        })

    if ecosystem == "maven" and ":" in lowered:
        _group, artifact = lowered.split(":", 1)
        artifact = artifact.strip()
        if artifact:
            keys.add(artifact)

    return {key for key in keys if key}


def package_lookup_keys(name: str, ecosystem: str) -> list[tuple[str, str]]:
    """Return ordered lookup keys with their confidence labels."""
    clean = _clean_name(name)
    if not clean:
        return []

    ecosystem = (ecosystem or "").strip().lower()
    lowered = clean.lower()
    canonical = normalise_package_name(clean, ecosystem)
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(key: str, match_type: str):
        if key and key not in seen:
            seen.add(key)
            ordered.append((key, match_type))

    if ecosystem == "maven":
        if ":" in lowered:
            add(canonical or lowered, "exact_package_match")
            if lowered != canonical:
                add(lowered, "canonical_package_match")
            add(lowered.split(":", 1)[1].strip(), "artifact_alias_match")
            return ordered

        add(lowered, "artifact_alias_match")
        return ordered

    if ecosystem in PEP503_LIKE_ECOSYSTEMS:
        primary_type = "exact_package_match" if lowered == canonical else "canonical_package_match"
        add(lowered, primary_type)
        add(canonical, "canonical_package_match")

        for alias in sorted(package_index_keys(clean, ecosystem)):
            if alias not in {lowered, canonical}:
                add(alias, "canonical_package_match")
        return ordered

    add(canonical or lowered, "exact_package_match")
    if lowered != canonical:
        add(lowered, "canonical_package_match")
    return ordered


def dependency_import_aliases(name: str, ecosystem: str) -> set[str]:
    """Return package-derived aliases likely to appear in source imports."""
    clean = _clean_name(name)
    if not clean:
        return set()

    ecosystem = (ecosystem or "").strip().lower()
    lowered = clean.lower()
    canonical = normalise_package_name(clean, ecosystem)
    aliases = {key for key in {lowered, canonical} if key}
    aliases.update(curated_import_aliases(clean, ecosystem))

    if ecosystem == "npm":
        aliases.add(lowered.replace("-", "_"))

    if ecosystem in PEP503_LIKE_ECOSYSTEMS:
        aliases.update({
            canonical.replace("-", "_"),
            lowered.replace("-", "_"),
        })

    if ecosystem == "pub":
        aliases.update({
            f"package:{canonical}/",
            f"package:{canonical.replace('-', '_')}/",
        })

    if ecosystem == "hex":
        segments = [segment for segment in re.split(r"[-_./]+", canonical or lowered) if segment]
        if segments:
            aliases.add(".".join(segment.capitalize() for segment in segments).lower())
            aliases.add("".join(segment.capitalize() for segment in segments).lower())

    if ecosystem == "maven" and ":" in lowered:
        group, artifact = lowered.split(":", 1)
        aliases.update({group.strip(), artifact.strip()})

    return {alias for alias in aliases if alias}


def external_import_candidates(module: str) -> set[str]:
    """Return progressively less-specific keys that can map an external import."""
    clean = _clean_name(module).lower()
    if not clean:
        return set()

    candidates = {clean}

    if clean.startswith("package:"):
        payload = clean.split("package:", 1)[1]
        package_name = payload.split("/", 1)[0]
        if package_name:
            candidates.add(package_name)
            candidates.add(f"package:{package_name}/")

    if "/" in clean:
        prefix = ""
        for part in clean.split("/"):
            if not part:
                continue
            prefix = part if not prefix else f"{prefix}/{part}"
            candidates.add(prefix)

    if "." in clean:
        prefix = ""
        for part in clean.split("."):
            if not part:
                continue
            prefix = part if not prefix else f"{prefix}.{part}"
            candidates.add(prefix)

    return {candidate for candidate in candidates if candidate}


def match_external_import_to_package(name: str, ecosystem: str, import_module: str) -> dict | None:
    """Score whether an external import likely belongs to a package."""
    module = _clean_name(import_module).lower()
    if not module:
        return None

    eco = (ecosystem or "").strip().lower()
    aliases = dependency_import_aliases(name, eco)
    candidates = external_import_candidates(module)
    best_score = 0.0
    best_alias = ""

    for alias in aliases:
        clean_alias = _clean_name(alias).lower()
        if not clean_alias:
            continue

        score = 0.0
        if module == clean_alias:
            score = 1.0
        elif clean_alias.startswith("package:") and module.startswith(clean_alias):
            score = 0.98
        elif module.startswith(clean_alias + "/"):
            score = 0.95
        elif module.startswith(clean_alias + "."):
            score = 0.72 if eco == "maven" else 0.9
        elif clean_alias in candidates:
            score = 0.82

        if score > best_score:
            best_score = score
            best_alias = clean_alias

    if best_score <= 0.0:
        return None

    return {
        "confidence": round(best_score, 2),
        "kind": "import" if best_score >= 0.85 else "reference",
        "matched_alias": best_alias,
        "import_module": module,
    }
