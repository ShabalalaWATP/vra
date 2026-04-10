"""Shared dependency identity helpers for persistence and reporting."""

from app.analysis.package_identity import normalise_package_name
from app.analysis.paths import normalise_path


def dependency_identity_key(
    *,
    ecosystem: str | None,
    name: str | None,
    version: str | None,
    source_file: str | None,
    is_dev: bool,
) -> tuple[str, str, str, str, bool]:
    ecosystem_key = (ecosystem or "unknown").strip().lower()
    raw_name = (name or "").strip()
    canonical_name = normalise_package_name(raw_name, ecosystem_key) or raw_name.lower()
    return (
        ecosystem_key,
        canonical_name,
        (version or "").strip(),
        normalise_path(source_file or ""),
        bool(is_dev),
    )
