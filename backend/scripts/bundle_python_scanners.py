"""Vendor Semgrep and Bandit into a project-local tools directory.

This keeps scanner binaries with the project instead of relying on per-user
Python script locations such as AppData/Roaming.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS_ROOT = Path(__file__).resolve().parent.parent / "tools"
DEFAULT_VENDOR_DIR = TOOLS_ROOT / "python_vendor"

PACKAGES = [
    "semgrep==1.156.0",
    "bandit==1.9.4",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Vendor Semgrep and Bandit into a local tools dir.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_VENDOR_DIR,
        help="Where to install the vendored packages (default: backend/tools/python_vendor)",
    )
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="Optional wheelhouse to install from",
    )
    parser.add_argument(
        "--no-index",
        action="store_true",
        help="Disallow network access and install only from --wheelhouse",
    )
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--target",
        str(output_dir),
        *PACKAGES,
    ]
    if args.no_index:
        cmd.insert(4, "--no-index")
    if args.wheelhouse:
        cmd[4:4] = ["--find-links", str(args.wheelhouse.resolve())]

    print("Bundling scanners into", output_dir)
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
