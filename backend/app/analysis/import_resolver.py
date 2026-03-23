"""Import resolution engine — maps import statements to actual files in the repo.

Given a file's imports and the full repo file index, resolves each import to
the actual source file it refers to. Supports Python, JavaScript/TypeScript,
Java, Go, Ruby, PHP, and Rust with language-specific resolution logic.

External packages (npm modules, pip packages) are marked as is_external=True
so the dependency agent can correlate them with CVE data.
"""

import logging
from dataclasses import dataclass, field
from pathlib import PurePosixPath

logger = logging.getLogger(__name__)


@dataclass
class ImportResolution:
    """Result of resolving a single import statement."""

    import_module: str  # Original import string
    imported_names: list[str] = field(default_factory=list)  # Specific names imported
    resolved_path: str | None = None  # Resolved file path (None if external)
    is_external: bool = False  # True for third-party packages
    confidence: float = 0.0  # 0.0 = unresolved, 0.5 = heuristic, 1.0 = exact
    source_file: str = ""  # File containing the import
    line: int = 0


# Common JS/TS file extensions to try when resolving
JS_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
JS_INDEX_FILES = [f"index{ext}" for ext in JS_EXTENSIONS]

# Python source extensions
PY_EXTENSIONS = [".py", ".pyi"]


class ImportResolver:
    """Resolves import statements to file paths within a repository."""

    def __init__(self, file_paths: set[str]):
        """
        Args:
            file_paths: Set of all normalised file paths in the repo (forward slashes).
        """
        self._paths = file_paths

        # Build basename lookup: filename -> [full paths]
        self._basename_map: dict[str, list[str]] = {}
        for p in file_paths:
            basename = p.rsplit("/", 1)[-1]
            if basename not in self._basename_map:
                self._basename_map[basename] = []
            self._basename_map[basename].append(p)

        # Build directory set for quick containment checks
        self._dirs: set[str] = set()
        for p in file_paths:
            parts = p.split("/")
            for i in range(1, len(parts)):
                self._dirs.add("/".join(parts[:i]))

    def resolve_all(
        self,
        imports: list,  # list of TSImport
        source_file: str,
        language: str,
    ) -> list[ImportResolution]:
        """Resolve all imports for a file."""
        results = []
        for imp in imports:
            res = self.resolve(imp, source_file, language)
            results.append(res)
        return results

    def resolve(self, imp, source_file: str, language: str) -> ImportResolution:
        """Resolve a single import."""
        module = imp.module
        imported_names = getattr(imp, "imported_names", [])
        line = getattr(imp, "line", 0)

        base = ImportResolution(
            import_module=module,
            imported_names=imported_names,
            source_file=source_file,
            line=line,
        )

        if not module:
            return base

        if language == "python":
            return self._resolve_python(base, source_file)
        elif language in ("javascript", "typescript"):
            return self._resolve_js(base, source_file)
        elif language == "java":
            return self._resolve_java(base, source_file)
        elif language == "kotlin":
            return self._resolve_kotlin(base, source_file)
        elif language == "go":
            return self._resolve_go(base, source_file)
        elif language == "ruby":
            return self._resolve_ruby(base, source_file)
        elif language == "php":
            return self._resolve_php(base, source_file)
        elif language == "rust":
            return self._resolve_rust(base, source_file)
        else:
            return self._resolve_heuristic(base)

    # ── Python ────────────────────────────────────────────────────

    def _resolve_python(self, res: ImportResolution, source_file: str) -> ImportResolution:
        """
        Resolve Python imports:
        - `import app.models.user` → app/models/user.py or app/models/user/__init__.py
        - `from app.models import User` → app/models.py or app/models/__init__.py
        - `from . import utils` → relative to source file's directory
        - `from ..common import X` → parent directory
        """
        module = res.import_module

        # Relative imports
        if module.startswith("."):
            return self._resolve_python_relative(res, source_file, module)

        # Absolute import: convert dots to slashes
        module_path = module.replace(".", "/")

        # Try: module_path.py
        for ext in PY_EXTENSIONS:
            candidate = f"{module_path}{ext}"
            if candidate in self._paths:
                res.resolved_path = candidate
                res.confidence = 1.0
                return res

        # Try: module_path/__init__.py
        candidate = f"{module_path}/__init__.py"
        if candidate in self._paths:
            res.resolved_path = candidate
            res.confidence = 0.9
            return res

        # Try: parent package (for `from app.models import User`)
        parts = module_path.rsplit("/", 1)
        if len(parts) == 2:
            parent = parts[0]
            for ext in PY_EXTENSIONS:
                candidate = f"{parent}{ext}"
                if candidate in self._paths:
                    res.resolved_path = candidate
                    res.confidence = 0.8
                    return res
            candidate = f"{parent}/__init__.py"
            if candidate in self._paths:
                res.resolved_path = candidate
                res.confidence = 0.7
                return res

        # External package
        res.is_external = True
        res.confidence = 0.0
        return res

    def _resolve_python_relative(
        self, res: ImportResolution, source_file: str, module: str
    ) -> ImportResolution:
        """Resolve Python relative imports (., .., ...)."""
        # Count dots
        dots = 0
        while dots < len(module) and module[dots] == ".":
            dots += 1
        relative_module = module[dots:]

        # Navigate up from source file's directory
        source_dir = source_file.rsplit("/", 1)[0] if "/" in source_file else ""
        for _ in range(dots - 1):
            source_dir = source_dir.rsplit("/", 1)[0] if "/" in source_dir else ""

        if relative_module:
            target = f"{source_dir}/{relative_module.replace('.', '/')}" if source_dir else relative_module.replace(".", "/")
        else:
            target = source_dir

        for ext in PY_EXTENSIONS:
            candidate = f"{target}{ext}"
            if candidate in self._paths:
                res.resolved_path = candidate
                res.confidence = 1.0
                return res

        candidate = f"{target}/__init__.py"
        if candidate in self._paths:
            res.resolved_path = candidate
            res.confidence = 0.9
            return res

        res.is_external = False
        res.confidence = 0.3
        return res

    # ── JavaScript / TypeScript ───────────────────────────────────

    def _resolve_js(self, res: ImportResolution, source_file: str) -> ImportResolution:
        """
        Resolve JS/TS imports:
        - `import X from './utils'` → utils.js, utils.ts, utils/index.js
        - `import X from '../lib/auth'` → relative path resolution
        - `import X from 'express'` → external (no ./ or ../)
        """
        module = res.import_module

        # External package (no relative path prefix)
        if not module.startswith(".") and not module.startswith("/"):
            res.is_external = True
            res.confidence = 0.0
            return res

        # Resolve relative to source file
        source_dir = source_file.rsplit("/", 1)[0] if "/" in source_file else ""
        target = str(PurePosixPath(source_dir) / module) if source_dir else module
        # Normalise ../
        parts = target.split("/")
        normalised = []
        for part in parts:
            if part == "..":
                if normalised:
                    normalised.pop()
            elif part != ".":
                normalised.append(part)
        target = "/".join(normalised)

        # Try exact path with extensions
        for ext in JS_EXTENSIONS:
            candidate = f"{target}{ext}"
            if candidate in self._paths:
                res.resolved_path = candidate
                res.confidence = 1.0
                return res

        # Try as directory with index file
        for idx in JS_INDEX_FILES:
            candidate = f"{target}/{idx}"
            if candidate in self._paths:
                res.resolved_path = candidate
                res.confidence = 0.9
                return res

        # Try exact path (might already have extension)
        if target in self._paths:
            res.resolved_path = target
            res.confidence = 1.0
            return res

        res.confidence = 0.2
        return res

    # ── Java ──────────────────────────────────────────────────────

    def _resolve_java(self, res: ImportResolution, source_file: str) -> ImportResolution:
        """
        Resolve Java imports:
        - `import com.app.service.UserService` → find UserService.java
        """
        module = res.import_module

        # Convert to path: com.app.service.UserService → com/app/service/UserService.java
        path = module.replace(".", "/") + ".java"

        # Search for suffix match (Java projects have src/main/java/ prefix)
        for repo_path in self._paths:
            if repo_path.endswith(path):
                res.resolved_path = repo_path
                res.confidence = 0.9
                return res

        # Wildcard import: com.app.service.* → just resolve the directory
        if module.endswith(".*"):
            dir_path = module[:-2].replace(".", "/")
            if dir_path in self._dirs:
                res.resolved_path = dir_path
                res.confidence = 0.7
                return res

        res.is_external = True
        res.confidence = 0.0
        return res

    # ── Kotlin ────────────────────────────────────────────────────

    def _resolve_kotlin(self, res: ImportResolution, source_file: str) -> ImportResolution:
        """
        Resolve Kotlin imports — similar to Java but also checks .kt files.
        """
        module = res.import_module

        # Try .kt first, then .java (Kotlin can import Java classes)
        for ext in (".kt", ".java"):
            path = module.replace(".", "/") + ext
            for repo_path in self._paths:
                if repo_path.endswith(path):
                    res.resolved_path = repo_path
                    res.confidence = 0.9
                    return res

        # Wildcard import
        if module.endswith(".*"):
            dir_path = module[:-2].replace(".", "/")
            if dir_path in self._dirs:
                res.resolved_path = dir_path
                res.confidence = 0.7
                return res

        # Android/Kotlin stdlib packages are external
        if module.startswith(("android.", "androidx.", "kotlin.", "kotlinx.", "com.google.android.")):
            res.is_external = True
            res.confidence = 0.0
            return res

        res.is_external = True
        res.confidence = 0.0
        return res

    # ── Go ────────────────────────────────────────────────────────

    def _resolve_go(self, res: ImportResolution, source_file: str) -> ImportResolution:
        """
        Resolve Go imports:
        - Internal: matches a directory in the repo
        - External: github.com/*, etc.
        """
        module = res.import_module.strip('"')

        # Check if any directory in the repo matches the import suffix
        for d in self._dirs:
            if module.endswith(d) or d.endswith(module.rsplit("/", 1)[-1]):
                res.resolved_path = d
                res.confidence = 0.7
                return res

        # Check if module is a relative path within the repo
        if module in self._dirs:
            res.resolved_path = module
            res.confidence = 0.8
            return res

        res.is_external = True
        res.confidence = 0.0
        return res

    # ── Ruby ──────────────────────────────────────────────────────

    def _resolve_ruby(self, res: ImportResolution, source_file: str) -> ImportResolution:
        module = res.import_module

        # Relative require
        if module.startswith("./") or module.startswith("../"):
            source_dir = source_file.rsplit("/", 1)[0] if "/" in source_file else ""
            target = f"{source_dir}/{module}" if source_dir else module
            for ext in [".rb", ""]:
                candidate = f"{target}{ext}"
                if candidate in self._paths:
                    res.resolved_path = candidate
                    res.confidence = 1.0
                    return res

        # Search by basename
        for ext in [".rb"]:
            candidates = self._basename_map.get(f"{module}{ext}", [])
            if len(candidates) == 1:
                res.resolved_path = candidates[0]
                res.confidence = 0.6
                return res

        res.is_external = True
        return res

    # ── PHP ───────────────────────────────────────────────────────

    def _resolve_php(self, res: ImportResolution, source_file: str) -> ImportResolution:
        module = res.import_module
        # Convert namespace separators to path
        path = module.replace("\\", "/") + ".php"

        for repo_path in self._paths:
            if repo_path.endswith(path) or repo_path.endswith(path.lower()):
                res.resolved_path = repo_path
                res.confidence = 0.8
                return res

        res.is_external = True
        return res

    # ── Rust ──────────────────────────────────────────────────────

    def _resolve_rust(self, res: ImportResolution, source_file: str) -> ImportResolution:
        module = res.import_module

        if module.startswith("crate::"):
            # crate:: means root of the current crate
            parts = module[7:].split("::")
            # Try: src/parts.join("/").rs
            path = "/".join(parts)
            for prefix in ["src/", ""]:
                candidate = f"{prefix}{path}.rs"
                if candidate in self._paths:
                    res.resolved_path = candidate
                    res.confidence = 0.9
                    return res
                candidate = f"{prefix}{path}/mod.rs"
                if candidate in self._paths:
                    res.resolved_path = candidate
                    res.confidence = 0.8
                    return res

        if module.startswith("super::"):
            source_dir = source_file.rsplit("/", 1)[0] if "/" in source_file else ""
            parent = source_dir.rsplit("/", 1)[0] if "/" in source_dir else ""
            parts = module[7:].split("::")
            path = f"{parent}/{'/'.join(parts)}.rs"
            if path in self._paths:
                res.resolved_path = path
                res.confidence = 0.9
                return res

        res.is_external = True
        return res

    # ── Heuristic fallback ────────────────────────────────────────

    def _resolve_heuristic(self, res: ImportResolution) -> ImportResolution:
        """Last-resort: search for a file whose name matches the import."""
        module = res.import_module
        # Extract the last component
        name = module.rsplit(".", 1)[-1].rsplit("/", 1)[-1].rsplit("::", 1)[-1]

        for ext in [".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".php"]:
            candidates = self._basename_map.get(f"{name}{ext}", [])
            if len(candidates) == 1:
                res.resolved_path = candidates[0]
                res.confidence = 0.4
                return res

        res.is_external = True
        return res
