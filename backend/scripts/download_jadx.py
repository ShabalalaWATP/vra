#!/usr/bin/env python3
"""
Download jadx (Android APK decompiler) for offline use.

jadx converts APK/DEX files to readable Java source code.
Run on a machine WITH internet, copy tools/jadx/ to air-gapped deployment.

Usage:
    cd backend
    python -m scripts.download_jadx
    python -m scripts.download_jadx --output tools/jadx

Manual install:
    1. Go to: https://github.com/skylot/jadx/releases/latest
    2. Download: jadx-<version>.zip (platform-independent, requires Java 11+)
    3. Extract to: backend/tools/jadx/
    4. Binary: backend/tools/jadx/bin/jadx (or jadx.bat on Windows)
"""

import argparse
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    import httpx
except ImportError:
    print("httpx required: pip install httpx")
    sys.exit(1)

DEFAULT_OUTPUT = Path(__file__).parent.parent / "tools" / "jadx"
RELEASES_API = "https://api.github.com/repos/skylot/jadx/releases/latest"


def main():
    parser = argparse.ArgumentParser(description="Download jadx for VRAgent APK analysis")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    output = args.output

    # Check if already installed
    jadx_bin = output / "bin" / ("jadx.bat" if platform.system() == "Windows" else "jadx")
    if jadx_bin.exists() and not args.force:
        print(f"jadx already installed at: {jadx_bin}")
        _verify(jadx_bin)
        return

    # Get latest release URL
    print("Finding latest jadx release...")
    client = httpx.Client(timeout=60, follow_redirects=True)

    try:
        resp = client.get(RELEASES_API)
        resp.raise_for_status()
        release = resp.json()
        version = release["tag_name"]

        # Find the zip asset (platform-independent)
        zip_url = None
        for asset in release.get("assets", []):
            name = asset["name"]
            if name.endswith(".zip") and "jadx-" in name and "gui" not in name.lower():
                zip_url = asset["browser_download_url"]
                break

        if not zip_url:
            # Fallback: construct URL
            zip_url = f"https://github.com/skylot/jadx/releases/download/{version}/jadx-{version.lstrip('v')}.zip"

        print(f"Version: {version}")
        print(f"URL: {zip_url}")

    except Exception as e:
        print(f"Failed to find release: {e}")
        print("Download manually from: https://github.com/skylot/jadx/releases")
        sys.exit(1)

    # Download
    print("Downloading jadx...")
    try:
        with client.stream("GET", zip_url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))

            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                downloaded = 0
                for chunk in resp.iter_bytes(1024 * 1024):
                    tmp.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        print(f"\r  {downloaded/1024/1024:.0f}/{total/1024/1024:.0f} MB ({downloaded/total*100:.0f}%)", end="", flush=True)
                tmp_path = Path(tmp.name)
                print()
    except Exception as e:
        print(f"Download failed: {e}")
        sys.exit(1)
    finally:
        client.close()

    # Extract
    print("Extracting...")
    output.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(str(tmp_path)) as zf:
            zf.extractall(str(output))
    except Exception as e:
        print(f"Extraction failed: {e}")
        sys.exit(1)
    finally:
        tmp_path.unlink(missing_ok=True)

    # Make executable on Unix
    if platform.system() != "Windows":
        jadx_bin = output / "bin" / "jadx"
        if jadx_bin.exists():
            jadx_bin.chmod(jadx_bin.stat().st_mode | 0o755)

    _verify(jadx_bin)


def _verify(binary: Path):
    """Verify jadx installation."""
    print(f"\nVerifying...")
    print(f"  Binary: {binary}")

    # Check Java is available (jadx needs Java 11+)
    java = shutil.which("java")
    if not java:
        print("  WARNING: Java not found in PATH. jadx requires Java 11+.")
        print("  Install Java and ensure 'java' is in PATH.")
    else:
        try:
            result = subprocess.run(
                [java, "-version"], capture_output=True, text=True, timeout=10,
            )
            version_line = (result.stderr or result.stdout).splitlines()[0]
            print(f"  Java: {version_line}")
        except Exception:
            pass

    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            print(f"  jadx version: {result.stdout.strip()}")
    except Exception as e:
        print(f"  WARNING: Could not run jadx: {e}")

    print(f"\n  jadx installed successfully!")
    print(f"  VRAgent will auto-detect this installation.")


if __name__ == "__main__":
    main()
