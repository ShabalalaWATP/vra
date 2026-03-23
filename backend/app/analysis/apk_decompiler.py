"""APK decompilation — extract source code from Android APK files for analysis.

Uses jadx (https://github.com/skylot/jadx) to decompile APK/DEX to readable
Java source. jadx is a standalone binary (not pip/npm) — similar to CodeQL.

The decompiled source is placed in a temp directory and scanned like any
other codebase through the normal pipeline.

Offline setup:
  1. Download jadx release (on internet machine):
     python -m scripts.download_jadx
  2. Copy jadx/ directory to the air-gapped deployment
  3. Binary: backend/tools/jadx/bin/jadx (or jadx.bat on Windows)

jadx produces:
  - Java source files (.java) from DEX bytecode
  - AndroidManifest.xml (parsed)
  - Resources (res/ directory)
  - Gradle/build files (if present in APK)
"""

import asyncio
import logging
import platform
import shutil
import tempfile
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

# Default jadx location within the project
DEFAULT_JADX_PATH = Path(__file__).parent.parent.parent / "tools" / "jadx"


def _find_jadx_binary() -> str | None:
    """Find the jadx binary, checking project tools dir first, then PATH."""
    # Check project tools directory
    if platform.system() == "Windows":
        candidates = [
            DEFAULT_JADX_PATH / "bin" / "jadx.bat",
            DEFAULT_JADX_PATH / "bin" / "jadx.exe",
        ]
    else:
        candidates = [
            DEFAULT_JADX_PATH / "bin" / "jadx",
        ]

    for c in candidates:
        if c.exists():
            return str(c)

    # Check if jadx is configured in settings
    jadx_setting = getattr(settings, "jadx_binary", None)
    if jadx_setting:
        if Path(jadx_setting).exists():
            return jadx_setting
        found = shutil.which(jadx_setting)
        if found:
            return found

    # Check PATH
    return shutil.which("jadx")


async def is_jadx_available() -> bool:
    """Check if jadx is installed and accessible."""
    binary = _find_jadx_binary()
    if not binary:
        return False

    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode == 0
    except Exception:
        return False


async def get_jadx_version() -> str | None:
    """Get jadx version string."""
    binary = _find_jadx_binary()
    if not binary:
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        return stdout.decode().strip()
    except Exception:
        return None


async def decompile_apk(
    apk_path: Path,
    output_dir: Path | None = None,
    *,
    timeout: int = 600,
    show_bad_code: bool = True,
    deobfuscate: bool = False,
    threads: int = 4,
) -> dict:
    """
    Decompile an APK file to Java source code using jadx.

    Args:
        apk_path: Path to the .apk file
        output_dir: Where to write decompiled source (temp dir if None)
        timeout: Max seconds to wait for decompilation
        show_bad_code: Include decompilation of methods that failed cleanly
        deobfuscate: Attempt to rename obfuscated classes/methods
        threads: Number of decompilation threads

    Returns:
        {
            "success": bool,
            "output_dir": str,  # Path to decompiled source
            "source_dir": str,  # Path to Java source specifically
            "resources_dir": str,  # Path to resources
            "manifest_path": str | None,  # Path to AndroidManifest.xml
            "stats": {
                "java_files": int,
                "xml_files": int,
                "total_files": int,
                "size_bytes": int,
            },
            "errors": list[str],
            "jadx_version": str | None,
        }
    """
    binary = _find_jadx_binary()
    if not binary:
        return {
            "success": False,
            "output_dir": "",
            "source_dir": "",
            "resources_dir": "",
            "manifest_path": None,
            "stats": {},
            "errors": [
                "jadx not found. Install it to backend/tools/jadx/ or add to PATH. "
                "Download from: https://github.com/skylot/jadx/releases"
            ],
            "jadx_version": None,
        }

    apk_path = Path(apk_path)
    if not apk_path.exists():
        return {
            "success": False,
            "errors": [f"APK file not found: {apk_path}"],
            "output_dir": "", "source_dir": "", "resources_dir": "",
            "manifest_path": None, "stats": {}, "jadx_version": None,
        }

    if not apk_path.suffix.lower() in (".apk", ".aab", ".dex", ".jar"):
        return {
            "success": False,
            "errors": [f"Unsupported file type: {apk_path.suffix}. Expected .apk, .aab, .dex, or .jar"],
            "output_dir": "", "source_dir": "", "resources_dir": "",
            "manifest_path": None, "stats": {}, "jadx_version": None,
        }

    # Create output directory
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="vragent-apk-"))
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Build jadx command
    cmd = [
        binary,
        str(apk_path),
        "--output-dir", str(output_dir),
        "--threads-count", str(threads),
        "--no-imports",  # Don't add import statements (cleaner for analysis)
    ]

    if show_bad_code:
        cmd.append("--show-bad-code")  # Show code even if decompilation partially fails

    if deobfuscate:
        cmd.extend(["--deobf", "--deobf-min", "2"])  # Rename short obfuscated names

    logger.info("Decompiling APK: %s -> %s", apk_path.name, output_dir)

    errors = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0:
            stderr_text = stderr.decode(errors="replace")[:1000] if stderr else ""
            errors.append(f"jadx exited with code {proc.returncode}: {stderr_text}")
            # jadx may still produce partial output even on non-zero exit
            if not any(output_dir.iterdir()):
                return {
                    "success": False,
                    "errors": errors,
                    "output_dir": str(output_dir), "source_dir": "", "resources_dir": "",
                    "manifest_path": None, "stats": {}, "jadx_version": await get_jadx_version(),
                }

        # Parse stderr for warnings (jadx reports issues to stderr)
        if stderr:
            stderr_lines = stderr.decode(errors="replace").splitlines()
            warn_count = sum(1 for l in stderr_lines if "WARN" in l or "ERROR" in l)
            if warn_count > 0:
                errors.append(f"jadx reported {warn_count} warnings/errors during decompilation")

    except asyncio.TimeoutError:
        errors.append(f"Decompilation timed out after {timeout}s")
        return {
            "success": False,
            "errors": errors,
            "output_dir": str(output_dir), "source_dir": "", "resources_dir": "",
            "manifest_path": None, "stats": {}, "jadx_version": await get_jadx_version(),
        }
    except Exception as e:
        errors.append(f"Decompilation failed: {e}")
        return {
            "success": False,
            "errors": errors,
            "output_dir": str(output_dir), "source_dir": "", "resources_dir": "",
            "manifest_path": None, "stats": {}, "jadx_version": await get_jadx_version(),
        }

    # Analyse output structure
    source_dir = output_dir / "sources"
    resources_dir = output_dir / "resources"

    # Find AndroidManifest.xml
    manifest_path = None
    manifest_candidates = [
        resources_dir / "AndroidManifest.xml",
        output_dir / "AndroidManifest.xml",
    ]
    for mc in manifest_candidates:
        if mc.exists():
            manifest_path = str(mc)
            break

    # Count files
    java_files = list(source_dir.rglob("*.java")) if source_dir.exists() else []
    xml_files = list(output_dir.rglob("*.xml"))
    all_files = list(output_dir.rglob("*"))
    total_size = sum(f.stat().st_size for f in all_files if f.is_file())

    stats = {
        "java_files": len(java_files),
        "xml_files": len(xml_files),
        "total_files": sum(1 for f in all_files if f.is_file()),
        "size_bytes": total_size,
    }

    # Determine the best directory to scan
    # jadx outputs to sources/ for Java, but we want the whole output
    scan_dir = str(source_dir) if source_dir.exists() else str(output_dir)

    logger.info(
        "APK decompiled: %d Java files, %d XML files, %d total (%d MB)",
        stats["java_files"], stats["xml_files"], stats["total_files"],
        total_size // 1024 // 1024,
    )

    return {
        "success": True,
        "output_dir": str(output_dir),
        "source_dir": scan_dir,
        "resources_dir": str(resources_dir) if resources_dir.exists() else "",
        "manifest_path": manifest_path,
        "stats": stats,
        "errors": errors,
        "jadx_version": await get_jadx_version(),
    }


def cleanup_decompiled(output_dir: str | Path):
    """Remove decompiled output directory."""
    output_dir = Path(output_dir)
    if output_dir.exists() and str(output_dir).startswith(tempfile.gettempdir()):
        try:
            shutil.rmtree(output_dir)
        except Exception as e:
            logger.warning("Failed to cleanup decompiled output: %s", e)
