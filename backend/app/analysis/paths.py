"""Cross-platform path utilities — safe, OS-aware path handling.

All internal path storage uses forward slashes (POSIX style).
Conversion to OS-native paths happens only at I/O boundaries.
"""

import os
import platform
import re
from pathlib import Path, PurePosixPath


PLATFORM = platform.system().lower()  # 'windows', 'linux', 'darwin'


def normalise_path(path: str) -> str:
    """
    Normalise a file path to forward-slash POSIX style for internal storage.
    Strips leading ./ and trailing slashes.
    """
    normalised = path.replace("\\", "/")
    normalised = normalised.strip("/")
    if normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised


def to_native_path(posix_path: str, base: Path | None = None) -> Path:
    """Convert an internally-stored POSIX path to an OS-native Path object."""
    if base:
        return base / posix_path.replace("/", os.sep)
    return Path(posix_path.replace("/", os.sep))


def relative_to_repo(file_path: Path, repo_path: Path) -> str:
    """
    Get the repo-relative path in POSIX style.
    Handles both Windows and Linux paths.
    """
    try:
        rel = file_path.relative_to(repo_path)
        return str(rel).replace("\\", "/")
    except ValueError:
        # Not relative — return normalised absolute
        return normalise_path(str(file_path))


def is_safe_path(path: str, repo_root: Path) -> bool:
    """
    Check if a path is safe (doesn't escape the repo root).
    Prevents path traversal attacks in user-supplied paths.
    """
    try:
        resolved_root = repo_root.resolve()
        resolved = (resolved_root / path).resolve()
        resolved.relative_to(resolved_root)
        return True
    except (ValueError, OSError):
        return False


def match_glob(path: str, pattern: str) -> bool:
    """Match a POSIX-style path against a glob pattern."""
    return PurePosixPath(path).match(pattern)


def get_extension(path: str) -> str:
    """Get the file extension from a path, lowercased."""
    return PurePosixPath(path).suffix.lower()


def is_binary_extension(path: str) -> bool:
    """Check if a file extension suggests binary content."""
    BINARY_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp3", ".mp4", ".wav", ".avi", ".mkv", ".mov",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".bin", ".exe", ".dll", ".so", ".dylib",
        ".pyc", ".pyo", ".class", ".o", ".obj",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".sqlite", ".db", ".sqlite3",
        ".wasm",
    }
    return get_extension(path) in BINARY_EXTS


def should_skip_dir(dir_name: str) -> bool:
    """Check if a directory should be skipped during scanning."""
    SKIP_DIRS = {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", "target", "vendor", ".tox",
        ".mypy_cache", ".pytest_cache", ".gradle", ".idea",
        ".vscode", "coverage", ".terraform", ".serverless",
        "bower_components", ".nuxt", ".svelte-kit", "out",
        ".angular", ".parcel-cache", ".turbo",
    }
    return dir_name in SKIP_DIRS


def scanner_command(binary: str) -> str:
    """
    Get the platform-appropriate command for a scanner binary.
    On Windows, .cmd/.bat wrappers may be needed.
    """
    if PLATFORM == "windows":
        # Many Node.js tools install as .cmd on Windows
        import shutil
        for ext in ("", ".cmd", ".bat", ".exe"):
            full = binary + ext
            if shutil.which(full):
                return full
    return binary


def safe_read_file(file_path: Path, max_size: int = 1_000_000) -> str | None:
    """
    Safely read a text file with size limits and encoding detection.
    Returns None if the file can't be read.
    """
    try:
        if not file_path.exists() or not file_path.is_file():
            return None
        if file_path.stat().st_size > max_size:
            return None

        # Try UTF-8 first (most common)
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            pass

        # Try with replacement
        return file_path.read_text(encoding="utf-8", errors="replace")

    except (OSError, PermissionError):
        return None


def collect_source_files(
    repo_path: Path,
    *,
    max_files: int = 10_000,
    max_file_size: int = 1_000_000,
) -> list[Path]:
    """
    Collect source files from a repository, respecting skip rules
    and size limits. Returns OS-native Path objects.
    """
    files = []
    for path in repo_path.rglob("*"):
        if len(files) >= max_files:
            break
        if not path.is_file():
            continue
        if any(should_skip_dir(part) for part in path.relative_to(repo_path).parts):
            continue
        if is_binary_extension(str(path)):
            continue
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue
        files.append(path)
    return files
