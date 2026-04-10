"""Shared policy for which files should receive deep AI security review."""

from pathlib import PurePosixPath


REVIEWABLE_EXTENSIONS = frozenset({
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".xml",
    ".html",
    ".htm",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".tf",
    ".tfvars",
    ".j2",
    ".jinja",
    ".jinja2",
    ".tpl",
    ".tmpl",
})

REVIEWABLE_FILENAMES = frozenset({
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pipfile.lock",
    "poetry.lock",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "packages.config",
    "composer.json",
    "composer.lock",
})

SKIP_EXTENSIONS = frozenset({
    ".md",
    ".txt",
    ".rst",
    ".csv",
    ".css",
    ".scss",
    ".less",
    ".sass",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".bmp",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".rar",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wav",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".pid",
})

SKIP_FILENAMES = frozenset({
    "license",
    "licence",
    "copying",
    "changelog",
    "changes",
    "authors",
    "contributors",
    "notice",
    "makefile",
})

SKIP_SUFFIXES = frozenset({
    ".min.js",
    ".min.css",
    ".map",
    ".dist",
    ".sample",
    ".bak",
    ".orig",
    ".swp",
})


def _parts(file_path: str) -> tuple[str, str, str]:
    lowered = str(file_path or "").replace("\\", "/").strip().lower()
    basename = PurePosixPath(lowered).name
    suffixes = PurePosixPath(lowered).suffixes
    ext = suffixes[-1] if suffixes else ""
    return lowered, basename, ext


def is_security_reviewable_non_code_path(file_path: str) -> bool:
    lowered, basename, ext = _parts(file_path)
    if not lowered:
        return False
    if basename in REVIEWABLE_FILENAMES:
        return True
    if basename.startswith(".env") and basename not in {".env.example", ".env.sample"}:
        return True
    if ext in REVIEWABLE_EXTENSIONS:
        return True
    return False


def should_investigate_file_path(file_path: str) -> bool:
    lowered, basename, ext = _parts(file_path)
    if not lowered:
        return False
    if is_security_reviewable_non_code_path(lowered):
        return True
    if basename in SKIP_FILENAMES:
        return False
    if ext in SKIP_EXTENSIONS:
        return False
    if any(lowered.endswith(suffix) for suffix in SKIP_SUFFIXES):
        return False
    return True
