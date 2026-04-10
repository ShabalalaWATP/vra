"""Cross-platform path utilities — safe, OS-aware path handling.

All internal path storage uses forward slashes (POSIX style).
Conversion to OS-native paths happens only at I/O boundaries.
"""

import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


PLATFORM = platform.system().lower()  # 'windows', 'linux', 'darwin'
IGNORE_FILE_NAME = ".vragentignore"
DEFAULT_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target", "vendor", ".tox",
    ".mypy_cache", ".pytest_cache", ".gradle", ".idea",
    ".vscode", "coverage", ".terraform", ".serverless",
    "bower_components", ".nuxt", ".svelte-kit", "out",
    ".angular", ".parcel-cache", ".turbo",
}


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
    return dir_name in DEFAULT_SKIP_DIRS


@dataclass
class RepoPathPolicy:
    """Repo-specific path exclusions including managed assets and .vragentignore."""

    managed_prefixes: list[str] = field(default_factory=list)
    ignored_prefixes: list[str] = field(default_factory=list)
    ignored_globs: list[str] = field(default_factory=list)
    ignore_file: str | None = None

    @property
    def ignored_paths(self) -> list[str]:
        return [*self.managed_prefixes, *self.ignored_prefixes, *self.ignored_globs]


def _has_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[]")


def _normalise_ignore_pattern(pattern: str) -> str:
    return normalise_path(pattern.strip())


def _prefix_matches(rel_path: str, prefix: str) -> bool:
    clean = prefix.rstrip("/")
    return rel_path == clean or rel_path.startswith(f"{clean}/")


def _pattern_matches(rel_path: str, pattern: str) -> bool:
    if _has_glob(pattern):
        return match_glob(rel_path, pattern) or match_glob(rel_path, f"**/{pattern}")
    return _prefix_matches(rel_path, pattern)


def load_repo_path_policy(repo_root: Path) -> RepoPathPolicy:
    """Load repo-local ignore rules and VRAgent-managed path exclusions."""
    repo_root = repo_root.resolve()
    policy = RepoPathPolicy()

    ignore_file = repo_root / IGNORE_FILE_NAME
    if ignore_file.exists():
        policy.ignore_file = str(ignore_file)
        try:
            for raw_line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                pattern = _normalise_ignore_pattern(line)
                if not pattern:
                    continue
                if _has_glob(pattern):
                    policy.ignored_globs.append(pattern)
                else:
                    policy.ignored_prefixes.append(pattern.rstrip("/"))
        except OSError:
            pass

    try:
        from app.config import settings

        managed_candidates = [
            settings.data_dir,
            settings.upload_dir,
            settings.export_dir,
            settings.data_dir.parent / "tools",
        ]
        for candidate in managed_candidates:
            try:
                rel = candidate.resolve().relative_to(repo_root)
            except (ValueError, OSError):
                continue
            policy.managed_prefixes.append(normalise_path(str(rel)))
    except Exception:
        pass

    policy.managed_prefixes = sorted(set(p for p in policy.managed_prefixes if p))
    policy.ignored_prefixes = sorted(set(p for p in policy.ignored_prefixes if p))
    policy.ignored_globs = sorted(set(p for p in policy.ignored_globs if p))
    return policy


def should_skip_repo_path(
    path: Path,
    repo_root: Path,
    *,
    policy: RepoPathPolicy | None = None,
) -> bool:
    """Check whether a path should be excluded from scanning for this repo."""
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return False

    if any(should_skip_dir(part) for part in rel.parts):
        return True

    rel_path = normalise_path(str(rel))
    if rel_path == IGNORE_FILE_NAME:
        return True
    active_policy = policy or load_repo_path_policy(repo_root)

    for prefix in active_policy.managed_prefixes:
        if _prefix_matches(rel_path, prefix):
            return True
    for prefix in active_policy.ignored_prefixes:
        if _prefix_matches(rel_path, prefix):
            return True
    for pattern in active_policy.ignored_globs:
        if _pattern_matches(rel_path, pattern):
            return True
    return False


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
    policy = load_repo_path_policy(repo_path)
    for path in repo_path.rglob("*"):
        if len(files) >= max_files:
            break
        if not path.is_file():
            continue
        if should_skip_repo_path(path, repo_path, policy=policy):
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
