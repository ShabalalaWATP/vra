"""Project-local Semgrep launcher using vendored Python packages."""

from __future__ import annotations

import sys
from pathlib import Path

PYTHON_VENDOR_DIR = Path(__file__).resolve().parent.parent / "python_vendor"
PYWIN32_DIRS = [
    PYTHON_VENDOR_DIR / "win32",
    PYTHON_VENDOR_DIR / "win32" / "lib",
    PYTHON_VENDOR_DIR / "pywin32_system32",
]

if str(PYTHON_VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_VENDOR_DIR))
for path in PYWIN32_DIRS:
    if path.exists() and str(path) not in sys.path:
        sys.path.insert(0, str(path))

from semgrep.console_scripts.pysemgrep import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
