#!/usr/bin/env python3
"""
Download and install CodeQL CLI bundle for offline/air-gapped use.

Run this script on the deployment system (GitHub is accessible via internal
mirrors) or on any machine with internet access. If run externally, copy the
resulting tools/codeql/ directory to the deployment system.

The bundle includes:
  - CodeQL CLI binary
  - All language extractors (Python, JavaScript, Java, Go, Ruby, C#, C/C++, Swift)
  - All pre-compiled security query packs (~2,000 security queries)
  - Total size: ~500MB–1GB depending on platform

CodeQL is NOT available via pip or npm. It is a standalone binary distributed
by GitHub as a compressed tarball.

Usage:
    # Download into backend/tools/codeql/ (default):
    cd backend
    python -m scripts.download_codeql

    # Download into a custom location:
    python -m scripts.download_codeql --output /opt/codeql

    # Force re-download even if already installed:
    python -m scripts.download_codeql --force

Manual installation (if this script cannot be used):
    1. Go to: https://github.com/github/codeql-action/releases/latest
    2. Download the correct bundle:
       - Windows:     codeql-bundle-win64.tar.gz
       - Linux x64:   codeql-bundle-linux64.tar.gz
       - Linux ARM64: codeql-bundle-linux-arm64.tar.gz
       - macOS:       codeql-bundle-osx64.tar.gz
    3. Extract into backend/tools/codeql/
       - The binary should be at: backend/tools/codeql/codeql (or codeql.exe)
    4. Verify: backend/tools/codeql/codeql version
    5. VRAgent auto-detects this location. Or set VRAGENT_CODEQL_BINARY env var.

Air-gapped deployment:
    1. Run this script on an internet-connected machine
    2. Transfer the entire backend/tools/codeql/ directory to the air-gapped system
       (use USB, internal file share, or approved transfer method)
    3. Place it at the same relative path: backend/tools/codeql/
    4. VRAgent will auto-detect it on startup
"""

import argparse
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

try:
    import httpx
except ImportError:
    print("ERROR: httpx is required to download CodeQL.")
    print("Install it: pip install httpx")
    print()
    print("Or download CodeQL manually — see the docstring at the top of this script.")
    sys.exit(1)

# Default install location: backend/tools/codeql/
DEFAULT_OUTPUT = Path(__file__).parent.parent / "tools" / "codeql"

# CodeQL bundle download URLs (redirects to the latest release)
BUNDLE_BASE = "https://github.com/github/codeql-action/releases/latest/download"

# Platform-specific bundle filenames
BUNDLE_MAP = {
    ("linux", "x86_64"): "codeql-bundle-linux64.tar.gz",
    ("linux", "amd64"): "codeql-bundle-linux64.tar.gz",
    ("linux", "aarch64"): "codeql-bundle-linux-arm64.tar.gz",
    ("linux", "arm64"): "codeql-bundle-linux-arm64.tar.gz",
    ("darwin", "x86_64"): "codeql-bundle-osx64.tar.gz",
    ("darwin", "arm64"): "codeql-bundle-osx64.tar.gz",
    ("windows", "amd64"): "codeql-bundle-win64.tar.gz",
    ("windows", "x86_64"): "codeql-bundle-win64.tar.gz",
}


def get_bundle_filename() -> str:
    """Get the correct bundle filename for this platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    key = (system, machine)

    if key in BUNDLE_MAP:
        return BUNDLE_MAP[key]

    print(f"ERROR: Unsupported platform: {system}/{machine}")
    print()
    print("Supported platforms:")
    print("  - Linux x86_64 / ARM64")
    print("  - macOS x86_64 / ARM64")
    print("  - Windows x86_64")
    print()
    print("Download manually from: https://github.com/github/codeql-action/releases")
    sys.exit(1)


def find_binary(install_dir: Path) -> Path | None:
    """Find the CodeQL binary in the installation directory."""
    suffix = ".exe" if platform.system() == "Windows" else ""
    candidates = [
        install_dir / f"codeql{suffix}",
        install_dir / "codeql" / f"codeql{suffix}",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def verify_installation(binary: Path) -> bool:
    """Verify CodeQL installation by running version and pack checks."""
    print(f"\nVerifying installation...")
    print(f"  Binary: {binary}")

    ok = True

    # Version check
    try:
        result = subprocess.run(
            [str(binary), "version", "--format=terse"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"  Version: {version}")
        else:
            print(f"  WARNING: Version check returned code {result.returncode}")
            if result.stderr:
                print(f"  stderr: {result.stderr.strip()[:200]}")
            ok = False
    except FileNotFoundError:
        print(f"  ERROR: Binary not executable. Try: chmod +x {binary}")
        ok = False
    except subprocess.TimeoutExpired:
        print(f"  WARNING: Version check timed out")
        ok = False
    except Exception as e:
        print(f"  WARNING: Could not run version check: {e}")
        ok = False

    # Query pack check
    try:
        result = subprocess.run(
            [str(binary), "resolve", "qlpacks"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            security_packs = [p for p in lines if "security" in p.lower()]
            print(f"  Query packs: {len(lines)} total, {len(security_packs)} security-related")

            if security_packs:
                print(f"  Security packs found:")
                for p in security_packs[:10]:
                    print(f"    - {p}")
                if len(security_packs) > 10:
                    print(f"    ... and {len(security_packs) - 10} more")
        else:
            print(f"  WARNING: Could not list query packs")
            ok = False
    except Exception:
        pass

    # Supported languages
    try:
        result = subprocess.run(
            [str(binary), "resolve", "languages"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            langs = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            print(f"  Languages: {', '.join(langs)}")
    except Exception:
        pass

    return ok


def main():
    parser = argparse.ArgumentParser(
        description="Download and install CodeQL CLI for VRAgent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m scripts.download_codeql                    # Install to tools/codeql/
  python -m scripts.download_codeql --output /opt/codeql  # Custom location
  python -m scripts.download_codeql --force            # Re-download

For air-gapped deployment:
  1. Run this script on a machine with internet access
  2. Copy the tools/codeql/ directory to the air-gapped system
  3. VRAgent auto-detects it, or set VRAGENT_CODEQL_BINARY
        """,
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT,
        help=f"Installation directory (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite existing installation",
    )
    args = parser.parse_args()

    output = args.output

    # Check if already installed
    existing = find_binary(output)
    if existing and not args.force:
        print(f"CodeQL already installed at: {existing}")
        print(f"Use --force to re-download.")
        print()
        verify_installation(existing)
        return

    # Determine download URL
    filename = get_bundle_filename()
    url = f"{BUNDLE_BASE}/{filename}"

    print("=" * 60)
    print("  CodeQL CLI Download for VRAgent")
    print("=" * 60)
    print(f"  Platform:    {platform.system()} {platform.machine()}")
    print(f"  Bundle:      {filename}")
    print(f"  Install to:  {output}")
    print(f"  Source:       github.com/github/codeql-action/releases")
    print("=" * 60)
    print()

    # Stream download with progress
    print("Downloading CodeQL bundle (~500MB, please wait)...")
    client = httpx.Client(timeout=600, follow_redirects=True)

    try:
        with client.stream("GET", url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))

            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                downloaded = 0
                for chunk in resp.iter_bytes(chunk_size=1024 * 1024):
                    tmp.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        mb_done = downloaded / 1024 / 1024
                        mb_total = total / 1024 / 1024
                        bar_len = 30
                        filled = int(bar_len * downloaded / total)
                        bar = "#" * filled + "-" * (bar_len - filled)
                        print(
                            f"\r  [{bar}] {mb_done:.0f}/{mb_total:.0f} MB ({pct:.0f}%)",
                            end="", flush=True,
                        )
                    else:
                        mb = downloaded / 1024 / 1024
                        print(f"\r  {mb:.0f} MB downloaded...", end="", flush=True)

                tmp_path = Path(tmp.name)
                print()

    except httpx.HTTPStatusError as e:
        print(f"\nDownload failed: HTTP {e.response.status_code}")
        print(f"URL: {url}")
        print()
        print("Try downloading manually:")
        print(f"  1. Go to: https://github.com/github/codeql-action/releases/latest")
        print(f"  2. Download: {filename}")
        print(f"  3. Extract to: {output}")
        sys.exit(1)
    except Exception as e:
        print(f"\nDownload failed: {e}")
        sys.exit(1)
    finally:
        client.close()

    # Extract
    print("Extracting (this takes a minute)...")
    output.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(str(tmp_path), "r:gz") as tar:
            tar.extractall(path=str(output.parent))

        # The bundle extracts to a 'codeql' subdirectory
        # Handle potential nested codeql/codeql structure
        nested = output.parent / "codeql"
        if nested.exists() and nested.resolve() != output.resolve():
            if output.exists():
                shutil.rmtree(output)
            nested.rename(output)

    except tarfile.TarError as e:
        print(f"Extraction failed: {e}")
        print("The download may be corrupt. Try again with --force.")
        sys.exit(1)
    finally:
        tmp_path.unlink(missing_ok=True)

    # Make binary executable on Unix
    binary = find_binary(output)
    if binary and platform.system() != "Windows":
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

    # Verify
    if binary:
        success = verify_installation(binary)

        print()
        print("=" * 60)
        if success:
            print("  CodeQL installed successfully!")
        else:
            print("  CodeQL installed with warnings (see above)")
        print()
        print(f"  Binary:  {binary}")
        print(f"  Size:    {sum(f.stat().st_size for f in output.rglob('*') if f.is_file()) / 1024 / 1024:.0f} MB")
        print()
        print("  VRAgent will auto-detect this installation.")
        print(f"  Or set: VRAGENT_CODEQL_BINARY={binary}")
        print()
        print("  For air-gapped deployment:")
        print(f"    Copy the entire {output}/ directory to the target system")
        print(f"    at the same relative path within the VRAgent installation.")
        print("=" * 60)
    else:
        print()
        print(f"WARNING: Could not find CodeQL binary in {output}")
        print("The directory structure may be unexpected.")
        print(f"Contents of {output}:")
        for item in sorted(output.iterdir()):
            print(f"  {item.name}{'/' if item.is_dir() else ''}")
        print()
        print("Look for 'codeql' or 'codeql.exe' and set VRAGENT_CODEQL_BINARY to its path.")


if __name__ == "__main__":
    main()
