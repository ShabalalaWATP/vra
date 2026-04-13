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
import gzip
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
FILE_LIKE_RE = re.compile(
    r"\.(?:js|ts|tsx|jsx|py|go|java|c|cc|cpp|h|hpp|rb|php|rs|md|json|yaml|yml|toml|ini|html|css|scss|exs|txt)$",
    re.IGNORECASE,
)
ENV_LIKE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
HEADER_LIKE_RE = re.compile(r"^[A-Z][A-Za-z0-9-]+(?:-[A-Z][A-Za-z0-9-]+)+$")
VERSION_LIKE_RE = re.compile(r"^v?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9_.-]+)?$")
PYTHON_DEF_RE = re.compile(r"^\s*(?:async\s+def|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
PYTHON_CLASS_RE = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b")
JS_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s*\*)?\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
)
JS_VAR_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:function(?:\s*\*)?\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$]*\s*=>)"
)
JS_CLASS_RE = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\b")
JS_METHOD_RE = re.compile(
    r"^\s*(?:async\s+)?(?:static\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^;=]*\)\s*\{"
)
GITHUB_COMMIT_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/commit/[A-Fa-f0-9]+/?$")
GITHUB_COMPARE_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/compare/.+$")
GITHUB_PULL_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/pull/\d+/?$")
PATCH_SOURCE_ECOSYSTEMS = {"pypi", "npm"}
PATCH_SOURCE_SKIP_DIRS = {
    ".github",
    "__mocks__",
    "__tests__",
    "benchmark",
    "benchmarks",
    "changelog",
    "ci",
    "doc",
    "docs",
    "example",
    "examples",
    "news",
    "release",
    "releases",
    "scripts",
    "spec",
    "specs",
    "test",
    "tests",
}
PATCH_SOURCE_SKIP_FILE_RE = re.compile(
    r"(?:^|[\\/])(?:(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs|py)|[^\\/]+\.(?:spec|test)\.(?:js|jsx|ts|tsx|mjs|cjs|py))$",
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


def write_json_artifacts(path: Path, payload) -> None:
    """Write a JSON payload in both plain and gzip-compressed forms."""
    encoded = json.dumps(payload, indent=None, separators=(",", ":"))
    path.write_text(encoded, encoding="utf-8")
    with gzip.open(path.with_suffix(f"{path.suffix}.gz"), "wt", encoding="utf-8") as handle:
        handle.write(encoded)


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
    if VERSION_LIKE_RE.fullmatch(clean):
        return None
    if clean.startswith(("http://", "https://")) or "/" in clean:
        return None
    if FILE_LIKE_RE.search(clean):
        return None
    if ENV_LIKE_RE.fullmatch(clean):
        return None
    if HEADER_LIKE_RE.fullmatch(clean):
        return None
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_:.-]*$", clean):
        return None

    qualified = any(sep in clean for sep in ("::", ".", "->", "#"))
    symbol_like = explicit or qualified or had_call or "_" in clean or any(ch.isupper() for ch in clean[1:])
    return clean if symbol_like else None


def _dedupe_strings(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values or []:
        if not isinstance(value, str):
            continue
        clean = value.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        deduped.append(clean)
    return deduped


def _normalise_import_path(path: str) -> str | None:
    clean = (path or "").strip().strip("`'\"")
    if not clean or any(ch.isspace() for ch in clean):
        return None
    if clean.startswith(("http://", "https://")):
        return None
    return clean.rstrip(").,:;") or None


def _symbol_confidence_from_sources(sources: list[str]) -> float:
    joined = " ".join(sources)
    if "ecosystem_specific" in joined:
        return 1.0
    if "context" in joined:
        return 0.7
    return 0.45


def _build_symbol_entry(
    symbol: str,
    *,
    source: str,
    import_path: str | None = None,
    confidence: float | None = None,
) -> dict | None:
    normalised = _normalise_function_candidate(symbol, explicit=True)
    if not normalised:
        return None

    entry = {
        "symbol": normalised,
        "sources": [source],
        "confidence": round(float(confidence if confidence is not None else 1.0), 2),
    }
    normalised_path = _normalise_import_path(import_path or "")
    if normalised_path:
        entry["import_path"] = normalised_path
    return entry


def _dedupe_symbol_entries(entries: list[dict] | None) -> list[dict]:
    deduped: dict[tuple[str, str], dict] = {}
    for raw_entry in entries or []:
        if isinstance(raw_entry, str):
            entry = _build_symbol_entry(raw_entry, source="legacy")
            if not entry:
                continue
        elif isinstance(raw_entry, dict):
            sources = _dedupe_strings([*(raw_entry.get("sources") or []), raw_entry.get("source", "")])
            entry = _build_symbol_entry(
                str(raw_entry.get("symbol", "")),
                source=sources[0] if sources else "legacy",
                import_path=str(raw_entry.get("import_path", "") or ""),
                confidence=raw_entry.get("confidence"),
            )
            if not entry:
                continue
            if sources:
                entry["sources"] = sources
        else:
            continue

        key = (entry["symbol"], entry.get("import_path", ""))
        existing = deduped.get(key)
        if not existing:
            deduped[key] = entry
            continue

        existing["sources"] = _dedupe_strings(
            [*(existing.get("sources") or []), *(entry.get("sources") or [])]
        )
        existing["confidence"] = max(
            float(existing.get("confidence") or 0.0),
            float(entry.get("confidence") or 0.0),
        )

    return list(deduped.values())


def _extract_text_symbol_candidates(advisory: dict) -> dict[str, set[str]]:
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

    return candidates


def extract_vulnerable_functions(advisory: dict) -> tuple[list[str], list[str]]:
    """Extract function/API symbols from advisory text into a separate enrichment layer."""
    candidates = _extract_text_symbol_candidates(advisory)
    extracted = sorted(candidates)
    sources = sorted({source for source_list in candidates.values() for source in source_list})
    return extracted[:20], sources


def _extract_text_symbol_entries(advisory: dict) -> list[dict]:
    entries: list[dict] = []
    for symbol, sources in _extract_text_symbol_candidates(advisory).items():
        source_list = sorted(sources)
        entry = {
            "symbol": symbol,
            "sources": source_list,
            "confidence": _symbol_confidence_from_sources(source_list),
        }
        entries.append(entry)
    return _dedupe_symbol_entries(entries)[:20]


def _github_patch_url(url: str) -> str | None:
    clean = str(url or "").strip()
    if GITHUB_COMMIT_RE.match(clean) or GITHUB_COMPARE_RE.match(clean) or GITHUB_PULL_RE.match(clean):
        return f"{clean.rstrip('/')}.patch"
    return None


def _patch_reference_urls(advisory: dict, *, limit: int = 1) -> list[str]:
    commit_urls: list[str] = []
    compare_urls: list[str] = []
    pull_urls: list[str] = []
    seen: set[str] = set()

    for ref in advisory.get("references") or []:
        patch_url = _github_patch_url(ref)
        if not patch_url or patch_url in seen:
            continue
        seen.add(patch_url)
        if GITHUB_COMMIT_RE.match(ref):
            commit_urls.append(patch_url)
        elif GITHUB_COMPARE_RE.match(ref):
            compare_urls.append(patch_url)
        elif GITHUB_PULL_RE.match(ref):
            pull_urls.append(patch_url)

    return [*(commit_urls[:limit]), *(compare_urls[:limit]), *(pull_urls[:limit])][:limit]


def _should_skip_patch_path(path: str) -> bool:
    clean = str(path or "").strip()
    if clean.startswith(("a/", "b/")):
        clean = clean[2:]
    if not clean or clean == "/dev/null":
        return True
    if PATCH_SOURCE_SKIP_FILE_RE.search(clean):
        return True

    parts = [part for part in Path(clean).parts if part]
    if not parts:
        return True

    if any(
        part.lower() in PATCH_SOURCE_SKIP_DIRS
        or re.search(r"(?:^|[-_])(spec|specs|test|tests)$", part.lower())
        for part in parts
    ):
        return True
    if clean.endswith((".pyi", ".pyc")):
        return True
    return False


def _python_import_path_from_patch_path(path: str) -> str | None:
    clean = str(path or "").strip()
    if clean.startswith(("a/", "b/")):
        clean = clean[2:]
    if _should_skip_patch_path(clean) or not clean.endswith(".py"):
        return None

    parts = [part for part in Path(clean).parts if part]
    if parts and parts[0] in {"src", "lib", "python"}:
        parts = parts[1:]
    if not parts:
        return None

    filename = parts[-1]
    module_parts = parts[:-1]
    if filename != "__init__.py":
        module_parts.append(Path(filename).stem)
    if not module_parts:
        return None
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) for part in module_parts):
        return None
    return ".".join(module_parts)


def _patch_path_import_hint(path: str, ecosystem: str) -> str | None:
    eco = (ecosystem or "").strip().lower()
    if eco == "pypi":
        return _python_import_path_from_patch_path(path)
    return None


def _npm_import_hints_from_patch_path(path: str, package_name: str) -> list[str]:
    clean = str(path or "").strip()
    if clean.startswith(("a/", "b/")):
        clean = clean[2:]
    if _should_skip_patch_path(clean) or not clean.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
        return []

    parts = [part for part in Path(clean).parts if part]
    if not parts:
        return []

    if len(parts) >= 3 and parts[0] == "packages":
        parts = parts[2:]

    if not parts:
        return [package_name] if package_name else []

    raw_parts = list(parts)
    trimmed_parts = list(parts)
    if trimmed_parts and trimmed_parts[0] in {"src", "lib", "dist", "app"}:
        trimmed_parts = trimmed_parts[1:]

    filename = raw_parts[-1]
    stem = Path(filename).stem
    raw_module_parts = raw_parts[:-1]
    trimmed_module_parts = trimmed_parts[:-1] if trimmed_parts else []
    if stem != "index":
        raw_module_parts.append(stem)
        trimmed_module_parts.append(stem)

    raw_subpath = "/".join(part for part in raw_module_parts if part)
    trimmed_subpath = "/".join(part for part in trimmed_module_parts if part)
    hints: list[str] = []
    if not raw_subpath and package_name:
        hints.append(package_name)
    if raw_subpath:
        hints.append(f"{package_name}/{raw_subpath}")
    if trimmed_subpath:
        hints.append(f"{package_name}/{trimmed_subpath}")

    return _dedupe_strings(hints)


def _patch_path_import_hints(path: str, ecosystem: str, package_name: str = "") -> list[str]:
    eco = (ecosystem or "").strip().lower()
    if eco == "pypi":
        hint = _python_import_path_from_patch_path(path)
        return [hint] if hint else []
    if eco == "npm":
        return _npm_import_hints_from_patch_path(path, package_name)
    return []


def _extract_python_symbol(
    content: str,
    current_class: str | None,
    current_class_indent: int | None,
) -> str | None:
    match = PYTHON_DEF_RE.match(content)
    if not match:
        return None

    symbol = match.group(1)
    indent = len(content) - len(content.lstrip(" "))
    if current_class and current_class_indent is not None and indent > current_class_indent:
        return f"{current_class}.{symbol}"
    return symbol


def _update_python_class_context(
    content: str,
    current_class: str | None,
    current_class_indent: int | None,
) -> tuple[str | None, int | None]:
    class_match = PYTHON_CLASS_RE.match(content)
    if class_match:
        return class_match.group(1), len(content) - len(content.lstrip(" "))

    if current_class and current_class_indent is not None:
        stripped = content.strip()
        if stripped and not stripped.startswith(("@", "#")):
            indent = len(content) - len(content.lstrip(" "))
            if indent <= current_class_indent and not PYTHON_DEF_RE.match(content):
                return None, None

    return current_class, current_class_indent


def _extract_python_symbols_from_patch(patch_text: str, ecosystem: str) -> list[dict]:
    entries: list[dict] = []
    current_file = ""
    current_class: str | None = None
    current_class_indent: int | None = None

    for raw_line in (patch_text or "").splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("diff --git "):
            current_file = ""
            current_class = None
            current_class_indent = None
            continue
        if line.startswith("+++ "):
            next_file = line[4:].strip()
            if next_file.startswith("b/"):
                next_file = next_file[2:]
            current_file = next_file
            current_class = None
            current_class_indent = None
            continue
        if not current_file or _should_skip_patch_path(current_file):
            continue

        import_hints = _patch_path_import_hints(current_file, ecosystem)
        if line.startswith("@@"):
            context = line.split("@@", 2)[-1].strip()
            current_class, current_class_indent = _update_python_class_context(
                context,
                current_class,
                current_class_indent,
            )
            symbol = _extract_python_symbol(context, current_class, current_class_indent)
            if symbol:
                for import_hint in import_hints or [None]:
                    entry = _build_symbol_entry(
                        symbol,
                        source="patch_hunk_context",
                        import_path=import_hint,
                        confidence=0.78,
                    )
                    if entry:
                        entries.append(entry)
            continue

        if line.startswith(("+++", "---")):
            continue

        prefix = line[:1]
        if prefix not in {"+", "-", " "}:
            continue

        content = line[1:]
        current_class, current_class_indent = _update_python_class_context(
            content,
            current_class,
            current_class_indent,
        )
        if prefix not in {"+", "-"}:
            continue

        symbol = _extract_python_symbol(content, current_class, current_class_indent)
        if symbol:
            for import_hint in import_hints or [None]:
                entry = _build_symbol_entry(
                    symbol,
                    source="patch_fix_ref",
                    import_path=import_hint,
                    confidence=0.86,
                )
                if entry:
                    entries.append(entry)

    deduped = _dedupe_symbol_entries(entries)
    if any("patch_fix_ref" in entry.get("sources", []) for entry in deduped):
        return [entry for entry in deduped if "patch_fix_ref" in entry.get("sources", [])]
    return [
        entry
        for entry in deduped
        if entry.get("import_path") or "." in entry.get("symbol", "")
    ]


def _extract_javascript_symbol(
    content: str,
    current_class: str | None,
) -> str | None:
    for pattern in (JS_FUNCTION_RE, JS_VAR_FUNCTION_RE):
        match = pattern.match(content)
        if match:
            return match.group(1)

    if current_class:
        method_match = JS_METHOD_RE.match(content)
        if method_match:
            return f"{current_class}.{method_match.group(1)}"

    return None


def _extract_javascript_symbols_from_patch(
    patch_text: str,
    ecosystem: str,
    package_name: str,
) -> list[dict]:
    entries: list[dict] = []
    current_file = ""
    current_class: str | None = None
    brace_depth = 0
    class_depth: int | None = None

    for raw_line in (patch_text or "").splitlines():
        line = raw_line.rstrip("\n")
        if line.startswith("diff --git "):
            current_file = ""
            current_class = None
            brace_depth = 0
            class_depth = None
            continue
        if line.startswith("+++ "):
            next_file = line[4:].strip()
            if next_file.startswith("b/"):
                next_file = next_file[2:]
            current_file = next_file
            current_class = None
            brace_depth = 0
            class_depth = None
            continue
        if not current_file or _should_skip_patch_path(current_file):
            continue

        import_hints = _patch_path_import_hints(current_file, ecosystem, package_name)
        if line.startswith("@@"):
            current_class = None
            class_depth = None
            context = line.split("@@", 2)[-1].strip()
            class_match = JS_CLASS_RE.match(context)
            if class_match:
                current_class = class_match.group(1)
                class_depth = max(1, context.count("{") - context.count("}"))
            continue
        if line.startswith(("+++", "---")):
            continue

        prefix = line[:1]
        if prefix not in {"+", "-", " "}:
            continue
        content = line[1:]

        class_match = JS_CLASS_RE.match(content)
        if class_match:
            current_class = class_match.group(1)
            class_depth = brace_depth + content.count("{") - content.count("}")

        symbol = _extract_javascript_symbol(content, current_class)
        if symbol and prefix in {"+", "-"}:
            for import_hint in import_hints or [None]:
                entry = _build_symbol_entry(
                    symbol,
                    source="patch_fix_ref",
                    import_path=import_hint,
                    confidence=0.84,
                )
                if entry:
                    entries.append(entry)

        brace_depth += content.count("{") - content.count("}")
        if current_class and class_depth is not None and brace_depth < class_depth:
            current_class = None
            class_depth = None

    deduped = _dedupe_symbol_entries(entries)
    if any("patch_fix_ref" in entry.get("sources", []) for entry in deduped):
        return [entry for entry in deduped if "patch_fix_ref" in entry.get("sources", [])]
    return [
        entry
        for entry in deduped
        if entry.get("import_path") or "." in entry.get("symbol", "")
    ]


def _extract_symbols_from_patch(
    patch_text: str,
    ecosystem: str,
    package_name: str,
) -> list[dict]:
    eco = (ecosystem or "").strip().lower()
    if eco == "pypi":
        return _extract_python_symbols_from_patch(patch_text, ecosystem)
    if eco == "npm":
        return _extract_javascript_symbols_from_patch(patch_text, ecosystem, package_name)
    return []


def _extract_patch_symbol_entries(
    advisory: dict,
    ecosystem: str,
    patch_fetcher,
) -> tuple[list[dict], dict[str, int]]:
    if ecosystem not in PATCH_SOURCE_ECOSYSTEMS or not callable(patch_fetcher):
        return [], {"patch_fetch_attempts": 0, "patch_fetch_hits": 0}
    if advisory.get("vulnerable_symbols"):
        return [], {"patch_fetch_attempts": 0, "patch_fetch_hits": 0}

    urls = _patch_reference_urls(advisory, limit=1)
    stats = {"patch_fetch_attempts": len(urls), "patch_fetch_hits": 0}
    for patch_url in urls:
        patch_text = patch_fetcher(patch_url)
        if not patch_text:
            continue

        stats["patch_fetch_hits"] += 1
        entries = _extract_symbols_from_patch(
            patch_text,
            ecosystem,
            str(advisory.get("package", "") or ""),
        )
        if entries:
            return entries[:20], stats

    return [], stats


def _iter_string_values(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _extract_structured_symbol_entries(affected: dict) -> list[dict]:
    eco_specific = affected.get("ecosystem_specific", {}) if isinstance(affected, dict) else {}
    if not isinstance(eco_specific, dict):
        return []

    entries: list[dict] = []
    for symbol in _iter_string_values(eco_specific.get("affected_functions")):
        entry = _build_symbol_entry(
            symbol,
            source="ecosystem_specific.affected_functions",
            confidence=1.0,
        )
        if entry:
            entries.append(entry)

    imports = eco_specific.get("imports")
    if isinstance(imports, list):
        for import_item in imports:
            if not isinstance(import_item, dict):
                continue

            import_paths = {
                path
                for path in (
                    *(_normalise_import_path(item) for item in _iter_string_values(import_item.get("modules"))),
                    *(_normalise_import_path(item) for item in _iter_string_values(import_item.get("paths"))),
                    _normalise_import_path(str(import_item.get("path", "") or "")),
                    _normalise_import_path(str(import_item.get("module", "") or "")),
                )
                if path
            }

            symbols = {
                symbol
                for symbol in (
                    *(_iter_string_values(import_item.get("symbols"))),
                    *(_iter_string_values(import_item.get("affected_functions"))),
                    *(_iter_string_values(import_item.get("attributes"))),
                    *(_iter_string_values(import_item.get("attribute"))),
                )
                if isinstance(symbol, str) and symbol.strip()
            }

            if not symbols:
                fallback_symbol = str(import_item.get("name", "") or import_item.get("symbol", "")).strip()
                if fallback_symbol:
                    symbols.add(fallback_symbol)

            for symbol in sorted(symbols):
                if import_paths:
                    for import_path in sorted(import_paths):
                        entry = _build_symbol_entry(
                            symbol,
                            source="ecosystem_specific.imports",
                            import_path=import_path,
                            confidence=1.0,
                        )
                        if entry:
                            entries.append(entry)
                else:
                    entry = _build_symbol_entry(
                        symbol,
                        source="ecosystem_specific.imports",
                        confidence=0.95,
                    )
                    if entry:
                        entries.append(entry)

    return _dedupe_symbol_entries(entries)


def build_enrichment_artifact(
    advisories: list[dict],
    *,
    ecosystem: str = "",
    patch_fetcher=None,
) -> dict:
    advisories_out: dict[str, dict] = {}
    enriched_count = 0
    extracted_function_count = 0
    extracted_symbol_count = 0
    patch_enriched_count = 0
    patch_extracted_symbol_count = 0
    patch_fetch_attempts = 0
    patch_fetch_hits = 0

    for advisory in advisories:
        advisory_id = advisory.get("id", "")
        if not advisory_id:
            continue

        text_entries = _extract_text_symbol_entries(advisory)
        patch_entries, patch_stats = _extract_patch_symbol_entries(
            advisory,
            ecosystem,
            patch_fetcher,
        )
        patch_fetch_attempts += patch_stats["patch_fetch_attempts"]
        patch_fetch_hits += patch_stats["patch_fetch_hits"]

        combined_entries = _dedupe_symbol_entries([*patch_entries, *text_entries])
        extracted_functions = _dedupe_strings([entry["symbol"] for entry in combined_entries])
        sources = _dedupe_strings(
            [source for entry in combined_entries for source in entry.get("sources", [])]
        )
        existing = {
            func for func in (advisory.get("vulnerable_functions") or [])
            if isinstance(func, str) and func
        }
        existing_symbols = {
            (
                entry.get("symbol"),
                entry.get("import_path", ""),
            )
            for entry in (advisory.get("vulnerable_symbols") or [])
            if isinstance(entry, dict) and entry.get("symbol")
        }
        extra_functions = [func for func in extracted_functions if func not in existing]
        extra_symbol_entries = [
            entry
            for entry in combined_entries
            if entry["symbol"] not in existing
            and (entry["symbol"], entry.get("import_path", "")) not in existing_symbols
        ]
        if not extra_functions and not extra_symbol_entries:
            continue

        advisories_out[advisory_id] = {
            "vulnerable_functions": extra_functions,
            "vulnerable_symbols": extra_symbol_entries,
            "sources": sources,
        }
        enriched_count += 1
        extracted_function_count += len(extra_functions)
        extracted_symbol_count += len(extra_symbol_entries)
        patch_only_entries = [entry for entry in extra_symbol_entries if "patch_" in " ".join(entry.get("sources", []))]
        if patch_only_entries:
            patch_enriched_count += 1
            patch_extracted_symbol_count += len(patch_only_entries)

    return {
        "generated_at": datetime.now().isoformat(),
        "strategy_version": 3,
        "stats": {
            "enriched_advisories": enriched_count,
            "extracted_vulnerable_functions": extracted_function_count,
            "extracted_vulnerable_symbols": extracted_symbol_count,
            "patch_enriched_advisories": patch_enriched_count,
            "patch_extracted_vulnerable_symbols": patch_extracted_symbol_count,
            "patch_fetch_attempts": patch_fetch_attempts,
            "patch_fetch_hits": patch_fetch_hits,
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

        vulnerable_symbol_entries = _extract_structured_symbol_entries(affected)
        vulnerable_functions = [entry["symbol"] for entry in vulnerable_symbol_entries]

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
                "vulnerable_symbols": [],
                "vulnerable_import_paths": [],
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
        ):
            for item in value or []:
                if item and item not in record[key]:
                    record[key].append(item)

        record["vulnerable_symbols"] = _dedupe_symbol_entries(
            [*(record.get("vulnerable_symbols") or []), *vulnerable_symbol_entries]
        )
        record["vulnerable_functions"] = _dedupe_strings(
            [*(record.get("vulnerable_functions") or []), *vulnerable_functions]
        )
        record["vulnerable_import_paths"] = _dedupe_strings(
            [
                *(record.get("vulnerable_import_paths") or []),
                *[
                    entry.get("import_path", "")
                    for entry in record.get("vulnerable_symbols") or []
                    if isinstance(entry, dict)
                ],
            ]
        )

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


def make_patch_fetcher(client: httpx.Client):
    cache: dict[str, str | None] = {}

    def fetch(patch_url: str) -> str | None:
        if patch_url in cache:
            return cache[patch_url]

        try:
            resp = client.get(patch_url)
            if resp.status_code != 200:
                cache[patch_url] = None
                return None

            text = resp.text
            cache[patch_url] = text if text.startswith(("diff --git", "From ")) else None
            return cache[patch_url]
        except Exception:
            cache[patch_url] = None
            return None

    return fetch


def main():
    parser = argparse.ArgumentParser(description="Sync offline advisory database from OSV")
    parser.add_argument("--output", type=Path, default=Path("data/advisories"))
    parser.add_argument("--ecosystems", nargs="*", help="Only sync specific ecosystems")
    args = parser.parse_args()

    output = args.output
    output.mkdir(parents=True, exist_ok=True)

    ecosystems = args.ecosystems or list(ECOSYSTEMS.keys())

    client = httpx.Client(timeout=120, follow_redirects=True)
    patch_fetcher = make_patch_fetcher(client)
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

            # Write as single JSON array plus a gzip mirror for plain Git clones.
            out_file = eco_dir / "advisories.json"
            write_json_artifacts(out_file, advisories)

            enrichment = build_enrichment_artifact(
                advisories,
                ecosystem=local_name,
                patch_fetcher=patch_fetcher,
            )
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
            "strategy_version": 3,
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
