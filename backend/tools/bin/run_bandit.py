"""Project-local Bandit launcher using vendored Python packages."""

from __future__ import annotations

import sys
from pathlib import Path

PYTHON_VENDOR_DIR = Path(__file__).resolve().parent.parent / "python_vendor"

if str(PYTHON_VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_VENDOR_DIR))

from bandit.cli.main import main


if __name__ == "__main__":
    raise SystemExit(main())
