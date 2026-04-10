"""Helpers for loading advisory records and optional enrichment artifacts."""

import json
from pathlib import Path


ADVISORIES_FILE = "advisories.json"
ENRICHMENT_FILE = "enrichment.json"


def _read_json(path: Path):
    try:
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
            merged.append(advisory)
            continue

        extra = enrichment_by_id.get(advisory_id)
        if not extra:
            merged.append(advisory)
            continue

        combined = dict(advisory)
        combined["vulnerable_functions"] = _dedupe_strings(
            [
                *(advisory.get("vulnerable_functions") or []),
                *(extra.get("vulnerable_functions") or []),
            ]
        )

        sources = _dedupe_strings(extra.get("sources") or [])
        if sources:
            combined["vulnerable_function_sources"] = sources

        merged.append(combined)

    return merged


def load_ecosystem_advisories(root: Path, ecosystem: str) -> list[dict]:
    """Load advisories for an ecosystem, merging enrichment when present."""
    ecosystem_dir = root / ecosystem
    advisories = _read_json(ecosystem_dir / ADVISORIES_FILE)
    if not isinstance(advisories, list):
        return []

    enrichment = _read_json(ecosystem_dir / ENRICHMENT_FILE)
    return merge_advisories_with_enrichment(advisories, enrichment)
