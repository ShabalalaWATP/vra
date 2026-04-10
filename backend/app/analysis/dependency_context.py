"""Shared helpers for file-level vulnerable dependency context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.analysis.package_identity import dependency_import_aliases, match_external_import_to_package


def dep_cache_entries(ctx: Any) -> list[dict]:
    """Normalise the dependency cache into a flat list of dict entries."""
    cache = getattr(ctx, "_dep_cache", None)
    if not cache:
        return []

    if isinstance(cache, list):
        return [entry for entry in cache if isinstance(entry, dict)]

    if isinstance(cache, dict):
        if isinstance(cache.get("entries"), list):
            return [entry for entry in cache["entries"] if isinstance(entry, dict)]

        entries: list[dict] = []
        for value in cache.values():
            if isinstance(value, list):
                entries.extend(entry for entry in value if isinstance(entry, dict))
        return entries

    return []


def vulnerable_dependency_context_for_file(
    ctx: Any,
    file_path: str,
    *,
    max_matches: int = 5,
    max_content_chars: int = 5000,
) -> list[dict]:
    """Return vulnerable dependency entries whose package use is evidenced in a file."""
    dep_entries = dep_cache_entries(ctx)
    if not dep_entries or not file_path:
        return []

    try:
        full_path = Path(ctx.repo_path) / file_path
        if not full_path.exists():
            return []

        matches: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        file_imports = []
        for res in getattr(ctx, "import_graph", {}).get(file_path, []):
            import_module = getattr(res, "import_module", "")
            if getattr(res, "is_external", False) and import_module:
                file_imports.append(res)

        for dep in dep_entries:
            best_match = None
            for res in file_imports:
                match = match_external_import_to_package(
                    dep.get("package", ""),
                    dep.get("ecosystem", ""),
                    getattr(res, "import_module", ""),
                )
                if not match:
                    continue
                if best_match is None or match["confidence"] > best_match["confidence"]:
                    best_match = {
                        **match,
                        "import_module": getattr(res, "import_module", ""),
                    }

            if not best_match:
                continue

            key = (
                dep.get("package", ""),
                dep.get("advisory_id", ""),
                dep.get("cve_id", ""),
            )
            if key in seen:
                continue
            seen.add(key)

            matches.append(
                {
                    **dep,
                    "import_match_source": "import_graph",
                    "import_match_kind": best_match["kind"],
                    "import_match_confidence": best_match["confidence"],
                    "import_module": best_match["import_module"],
                }
            )

        if matches:
            matches.sort(
                key=lambda item: (
                    -float(item.get("risk_score") or 0.0),
                    -float(item.get("import_match_confidence") or 0.0),
                    str(item.get("package", "")),
                )
            )
            return matches[:max_matches]

        content = full_path.read_text(encoding="utf-8", errors="ignore")[:max_content_chars].lower()
        for dep in dep_entries:
            aliases = dependency_import_aliases(dep.get("package", ""), dep.get("ecosystem", ""))
            variants = {
                alias
                for alias in aliases
                if isinstance(alias, str) and alias
            }
            package_name = str(dep.get("package", "")).lower()
            if package_name:
                variants.update(
                    {
                        package_name,
                        package_name.replace("-", "_"),
                        package_name.replace("_", "-"),
                    }
                )

            matched_variant = next(
                (
                    variant
                    for variant in sorted(variants)
                    if (
                        f"import {variant}" in content
                        or f"from {variant}" in content
                        or f"require('{variant}" in content
                        or f'require("{variant}' in content
                        or f"import '{variant}" in content
                        or f'import "{variant}' in content
                        or f"use {variant}" in content
                        or f"alias {variant}" in content
                    )
                ),
                "",
            )
            if not matched_variant:
                continue

            key = (
                dep.get("package", ""),
                dep.get("advisory_id", ""),
                dep.get("cve_id", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    **dep,
                    "import_match_source": "text_fallback",
                    "import_match_kind": "import",
                    "import_match_confidence": 0.55,
                    "import_module": matched_variant,
                }
            )

        matches.sort(
            key=lambda item: (
                item.get("import_match_source") != "import_graph",
                -float(item.get("risk_score") or 0.0),
                -float(item.get("import_match_confidence") or 0.0),
                str(item.get("package", "")),
            )
        )
        return matches[:max_matches]

    except Exception:
        return []
