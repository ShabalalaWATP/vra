"""Repository fingerprinting — detect languages, frameworks, and project shape."""

import json
from collections import Counter
from pathlib import Path

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".swift": "swift",
    ".m": "objectivec",
    ".scala": "scala",
    ".r": "r",
    ".R": "r",
    ".lua": "lua",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".vue": "vue",
    ".svelte": "svelte",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".zig": "zig",
}

FRAMEWORK_INDICATORS = {
    # Python
    "requirements.txt": {"python"},
    "pyproject.toml": {"python"},
    "setup.py": {"python"},
    "manage.py": {"django"},
    "wsgi.py": {"django"},
    "asgi.py": {"django", "fastapi"},
    "Pipfile": {"python"},
    # JavaScript/TypeScript
    "package.json": {"javascript"},
    "next.config.js": {"nextjs"},
    "next.config.mjs": {"nextjs"},
    "next.config.ts": {"nextjs"},
    "nuxt.config.js": {"nuxtjs"},
    "nuxt.config.ts": {"nuxtjs"},
    "angular.json": {"angular"},
    "vite.config.ts": {"vite"},
    "vite.config.js": {"vite"},
    "svelte.config.js": {"svelte"},
    "tailwind.config.js": {"tailwind"},
    "tailwind.config.ts": {"tailwind"},
    # Java/JVM
    "pom.xml": {"maven", "java"},
    "build.gradle": {"gradle", "java"},
    "build.gradle.kts": {"gradle", "kotlin"},
    # Go
    "go.mod": {"go"},
    # Rust
    "Cargo.toml": {"rust"},
    # Ruby
    "Gemfile": {"ruby"},
    "Rakefile": {"ruby"},
    # Docker / Infra
    "Dockerfile": {"docker"},
    "docker-compose.yml": {"docker"},
    "docker-compose.yaml": {"docker"},
    "terraform.tf": {"terraform"},
    "serverless.yml": {"serverless"},
    # Mobile
    "AndroidManifest.xml": {"android"},
    "Info.plist": {"ios"},
    "pubspec.yaml": {"flutter"},
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", "target", "vendor", ".tox", ".mypy_cache",
    ".pytest_cache", ".gradle", ".idea", ".vscode", "coverage",
}


def fingerprint_repo(repo_path: Path) -> dict:
    """Analyze a repository and return its fingerprint."""
    lang_counter = Counter()
    frameworks = set()
    file_count = 0
    total_size = 0
    manifests_found = []

    for path in repo_path.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue

        if path.is_file():
            file_count += 1
            total_size += path.stat().st_size
            ext = path.suffix.lower()
            if ext in LANGUAGE_EXTENSIONS:
                lang_counter[LANGUAGE_EXTENSIONS[ext]] += 1

            # Check framework indicators (exact filename match)
            name = path.name
            if name in FRAMEWORK_INDICATORS:
                frameworks.update(FRAMEWORK_INDICATORS[name])
                manifests_found.append(str(path.relative_to(repo_path)))
            # Extension-based detection (.csproj, .sln)
            if ext in (".csproj", ".sln"):
                frameworks.add("dotnet")
        else:
            # Directory-based framework detection
            dir_name = path.name
            if dir_name == "k8s":
                frameworks.add("kubernetes")
            elif dir_name == "helm":
                frameworks.add("helm")

    # Detect frameworks from package.json if present
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            pkg = json.loads(pkg_json.read_text())
            all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            if "react" in all_deps:
                frameworks.add("react")
            if "vue" in all_deps:
                frameworks.add("vue")
            if "express" in all_deps:
                frameworks.add("express")
            if "fastify" in all_deps:
                frameworks.add("fastify")
            if "@angular/core" in all_deps:
                frameworks.add("angular")
            if "svelte" in all_deps:
                frameworks.add("svelte")
            if "django" in all_deps or "Django" in all_deps:
                frameworks.add("django")
            if "flask" in all_deps or "Flask" in all_deps:
                frameworks.add("flask")
        except Exception:
            pass

    # Detect Python frameworks from requirements/pyproject
    for req_file in ["requirements.txt", "pyproject.toml"]:
        req_path = repo_path / req_file
        if req_path.exists():
            try:
                content = req_path.read_text().lower()
                if "django" in content:
                    frameworks.add("django")
                if "flask" in content:
                    frameworks.add("flask")
                if "fastapi" in content:
                    frameworks.add("fastapi")
                if "sqlalchemy" in content:
                    frameworks.add("sqlalchemy")
            except Exception:
                pass

    languages = [
        {"name": lang, "file_count": count}
        for lang, count in lang_counter.most_common()
    ]

    # ── Monorepo / workspace detection ────────────────────────────
    workspaces = detect_workspaces(repo_path)
    is_monorepo = len(workspaces) > 1

    # ── Repo size warnings ────────────────────────────────────────
    size_warnings = []
    if file_count > 10000:
        size_warnings.append(f"Large repository: {file_count} files. Analysis capped at 10,000 files.")
    if file_count > 50000:
        size_warnings.append(f"Very large repository ({file_count} files). Many files will be excluded from analysis.")
    if total_size > 500_000_000:
        size_warnings.append(f"Repository is {total_size / 1_000_000:.0f} MB. Large files will be skipped.")

    return {
        "languages": languages,
        "primary_language": languages[0]["name"] if languages else None,
        "frameworks": sorted(frameworks),
        "file_count": file_count,
        "total_size_bytes": total_size,
        "manifests": manifests_found,
        "is_monorepo": is_monorepo,
        "workspaces": workspaces,
        "size_warnings": size_warnings,
    }


def detect_workspaces(repo_path: Path) -> list[dict]:
    """
    Detect monorepo workspaces and sub-applications.

    Identifies:
    - npm/yarn/pnpm workspaces
    - Lerna packages
    - Multiple independent package.json / pyproject.toml / go.mod at different levels
    - apps/ and packages/ directory conventions
    """
    workspaces: list[dict] = []

    # ── npm/yarn/pnpm workspace detection ─────────────────────────
    root_pkg = repo_path / "package.json"
    if root_pkg.exists():
        try:
            pkg = json.loads(root_pkg.read_text())
            ws = pkg.get("workspaces", [])
            # Yarn/npm workspaces can be a list or {"packages": [...]}
            if isinstance(ws, dict):
                ws = ws.get("packages", [])
            if ws:
                for pattern in ws:
                    # Resolve glob patterns like "packages/*"
                    for match in repo_path.glob(pattern):
                        if match.is_dir() and (match / "package.json").exists():
                            try:
                                sub_pkg = json.loads((match / "package.json").read_text())
                                workspaces.append({
                                    "name": sub_pkg.get("name", match.name),
                                    "path": str(match.relative_to(repo_path)),
                                    "type": "npm_workspace",
                                    "manifest": "package.json",
                                })
                            except Exception:
                                workspaces.append({
                                    "name": match.name,
                                    "path": str(match.relative_to(repo_path)),
                                    "type": "npm_workspace",
                                    "manifest": "package.json",
                                })
        except Exception:
            pass

    # ── pnpm workspace detection ──────────────────────────────────
    pnpm_ws = repo_path / "pnpm-workspace.yaml"
    if pnpm_ws.exists():
        try:
            content = pnpm_ws.read_text()
            # Simple YAML parsing for packages list
            import re as _re
            patterns = _re.findall(r"-\s+['\"]?([^'\"#\n]+)", content)
            for pattern in patterns:
                pattern = pattern.strip().rstrip("/")
                for match in repo_path.glob(pattern):
                    if match.is_dir() and (match / "package.json").exists():
                        workspaces.append({
                            "name": match.name,
                            "path": str(match.relative_to(repo_path)),
                            "type": "pnpm_workspace",
                            "manifest": "package.json",
                        })
        except Exception:
            pass

    # ── Lerna detection ────────────────────────────────────────────
    lerna_json = repo_path / "lerna.json"
    if lerna_json.exists():
        try:
            lerna = json.loads(lerna_json.read_text())
            for pattern in lerna.get("packages", ["packages/*"]):
                for match in repo_path.glob(pattern):
                    if match.is_dir() and (match / "package.json").exists():
                        workspaces.append({
                            "name": match.name,
                            "path": str(match.relative_to(repo_path)),
                            "type": "lerna_package",
                            "manifest": "package.json",
                        })
        except Exception:
            pass

    # ── Convention-based detection (apps/, packages/, services/) ──
    if not workspaces:
        for convention_dir in ("apps", "packages", "services", "modules", "libs", "projects"):
            conv_path = repo_path / convention_dir
            if conv_path.is_dir():
                for sub in conv_path.iterdir():
                    if not sub.is_dir():
                        continue
                    # Check for any manifest file
                    manifest = None
                    for mf in ("package.json", "pyproject.toml", "setup.py", "go.mod", "Cargo.toml", "pom.xml", "build.gradle"):
                        if (sub / mf).exists():
                            manifest = mf
                            break
                    if manifest:
                        workspaces.append({
                            "name": sub.name,
                            "path": str(sub.relative_to(repo_path)),
                            "type": f"{convention_dir}_convention",
                            "manifest": manifest,
                        })

    # ── Python namespace packages ─────────────────────────────────
    # Multiple pyproject.toml at different levels
    if not workspaces:
        pyprojects = list(repo_path.rglob("pyproject.toml"))
        # Exclude root and skip dirs
        pyprojects = [
            p for p in pyprojects
            if p.parent != repo_path
            and not any(skip in p.parts for skip in SKIP_DIRS)
        ]
        for pp in pyprojects[:20]:
            workspaces.append({
                "name": pp.parent.name,
                "path": str(pp.parent.relative_to(repo_path)),
                "type": "python_subproject",
                "manifest": "pyproject.toml",
            })

    # ── Go multi-module ───────────────────────────────────────────
    if not workspaces:
        go_mods = list(repo_path.rglob("go.mod"))
        go_mods = [
            g for g in go_mods
            if g.parent != repo_path
            and not any(skip in g.parts for skip in SKIP_DIRS)
        ]
        for gm in go_mods[:20]:
            workspaces.append({
                "name": gm.parent.name,
                "path": str(gm.parent.relative_to(repo_path)),
                "type": "go_module",
                "manifest": "go.mod",
            })

    # Deduplicate by path
    seen = set()
    unique = []
    for ws in workspaces:
        if ws["path"] not in seen:
            seen.add(ws["path"])
            unique.append(ws)

    return unique
