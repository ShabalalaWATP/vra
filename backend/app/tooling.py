"""Helpers for resolving bundled scanner launchers and fallback binaries."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from app.config import settings

BACKEND_ROOT = Path(__file__).resolve().parent.parent
TOOLS_ROOT = BACKEND_ROOT / "tools"
TOOLS_BIN_DIR = TOOLS_ROOT / "bin"
PYTHON_VENDOR_DIR = TOOLS_ROOT / "python_vendor"

SEMGREP_LAUNCHER = TOOLS_BIN_DIR / "run_semgrep.py"
BANDIT_LAUNCHER = TOOLS_BIN_DIR / "run_bandit.py"


def resolve_configured_binary(binary: str | None) -> str | None:
    """Resolve a configured binary name or path to an executable path."""
    if not binary:
        return None

    candidate = Path(binary)
    if candidate.exists():
        return str(candidate.resolve())

    return shutil.which(binary)


def bundled_semgrep_ready() -> bool:
    return SEMGREP_LAUNCHER.exists() and (PYTHON_VENDOR_DIR / "semgrep").exists()


def bundled_bandit_ready() -> bool:
    return BANDIT_LAUNCHER.exists() and (PYTHON_VENDOR_DIR / "bandit").exists()


def get_semgrep_command() -> list[str]:
    """Return the command used to invoke Semgrep, preferring the bundled copy."""
    if bundled_semgrep_ready():
        return [sys.executable, str(SEMGREP_LAUNCHER)]

    binary = resolve_configured_binary(settings.semgrep_binary)
    return [binary] if binary else []


def get_bandit_command() -> list[str]:
    """Return the command used to invoke Bandit, preferring the bundled copy."""
    if bundled_bandit_ready():
        return [sys.executable, str(BANDIT_LAUNCHER)]

    binary = resolve_configured_binary(settings.bandit_binary)
    return [binary] if binary else []


def get_semgrep_display_path() -> str | None:
    if bundled_semgrep_ready():
        return str(SEMGREP_LAUNCHER)
    return resolve_configured_binary(settings.semgrep_binary)


def get_bandit_display_path() -> str | None:
    if bundled_bandit_ready():
        return str(BANDIT_LAUNCHER)
    return resolve_configured_binary(settings.bandit_binary)
