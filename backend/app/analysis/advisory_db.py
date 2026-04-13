"""Helpers for loading advisory records and optional enrichment artifacts."""

import gzip
import json
from pathlib import Path


ADVISORIES_FILE = "advisories.json"
ADVISORIES_GZIP_FILE = "advisories.json.gz"
ENRICHMENT_FILE = "enrichment.json"


def _read_json(path: Path):
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                return json.load(handle)
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


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


def _normalise_symbol_entry(entry) -> dict | None:
    if isinstance(entry, str):
        symbol = entry.strip()
        raw_import_path = ""
        raw_sources: list[str] = []
        confidence = None
    elif isinstance(entry, dict):
        symbol = str(entry.get("symbol", "") or "").strip()
        raw_import_path = str(entry.get("import_path", "") or "").strip()
        raw_sources = [
            *(entry.get("sources") or []),
            entry.get("source", ""),
        ]
        confidence = entry.get("confidence")
    else:
        return None

    if not symbol:
        return None

    normalised = {
        "symbol": symbol,
        "sources": _dedupe_strings(raw_sources),
    }
    if raw_import_path:
        normalised["import_path"] = raw_import_path
    try:
        if confidence is not None:
            normalised["confidence"] = round(float(confidence), 2)
    except (TypeError, ValueError):
        pass
    return normalised


def _dedupe_symbol_entries(entries: list | None) -> list[dict]:
    deduped: dict[tuple[str, str], dict] = {}
    for raw_entry in entries or []:
        entry = _normalise_symbol_entry(raw_entry)
        if not entry:
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


def _normalise_enrichment_payload(payload) -> dict[str, dict]:
    if not isinstance(payload, dict):
        return {}

    advisories = payload.get("advisories", payload)
    if not isinstance(advisories, dict):
        return {}

    normalised: dict[str, dict] = {}
    for advisory_id, data in advisories.items():
        if not isinstance(advisory_id, str) or not advisory_id.strip():
            continue
        if not isinstance(data, dict):
            continue
        normalised[advisory_id] = data
    return normalised


def merge_advisories_with_enrichment(advisories: list[dict], enrichment_payload) -> list[dict]:
    """Merge advisory enrichment into the base advisory records."""
    enrichment_by_id = _normalise_enrichment_payload(enrichment_payload)
    merged: list[dict] = []

    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue

        advisory_id = advisory.get("id")
        if not isinstance(advisory_id, str) or not advisory_id:
            combined = dict(advisory)
            combined_symbols = _dedupe_symbol_entries(advisory.get("vulnerable_functions") or [])
            if combined_symbols:
                combined["vulnerable_symbols"] = combined_symbols
            merged.append(combined)
            continue

        extra = enrichment_by_id.get(advisory_id) or {}

        combined = dict(advisory)
        combined_symbols = _dedupe_symbol_entries(
            [
                *(advisory.get("vulnerable_symbols") or []),
                *(extra.get("vulnerable_symbols") or []),
                *(advisory.get("vulnerable_functions") or []),
                *(extra.get("vulnerable_functions") or []),
            ]
        )
        if combined_symbols:
            combined["vulnerable_symbols"] = combined_symbols
            combined["vulnerable_import_paths"] = _dedupe_strings(
                [entry.get("import_path", "") for entry in combined_symbols]
            )

        combined["vulnerable_functions"] = _dedupe_strings(
            [
                *(advisory.get("vulnerable_functions") or []),
                *(extra.get("vulnerable_functions") or []),
                *[entry["symbol"] for entry in combined_symbols],
            ]
        )

        sources = _dedupe_strings(
            [
                *(extra.get("sources") or []),
                *[
                    source
                    for entry in combined_symbols
                    for source in (entry.get("sources") or [])
                ],
            ]
        )
        if sources:
            combined["vulnerable_function_sources"] = sources

        merged.append(combined)

    return merged


def load_ecosystem_advisories(root: Path, ecosystem: str) -> list[dict]:
    """Load advisories for an ecosystem, merging enrichment when present."""
    ecosystem_dir = root / ecosystem
    advisories = _read_json(ecosystem_dir / ADVISORIES_FILE)
    if not isinstance(advisories, list):
        advisories = _read_json(ecosystem_dir / ADVISORIES_GZIP_FILE)
    if not isinstance(advisories, list):
        return []

    enrichment = _read_json(ecosystem_dir / ENRICHMENT_FILE)
    return merge_advisories_with_enrichment(advisories, enrichment)
