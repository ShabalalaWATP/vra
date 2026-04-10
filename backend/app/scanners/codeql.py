"""CodeQL scanner adapter — deep semantic analysis with taint tracking.

CodeQL creates a database of the code's semantic structure (types, data flow,
control flow) and runs queries against it. This provides deterministic taint
tracking that our lightweight call graph can't match.

Offline setup:
  1. Download CodeQL bundle (on internet machine):
     python -m scripts.download_codeql
  2. Copy the codeql/ directory to the air-gapped deployment
  3. Set VRAGENT_CODEQL_BINARY to the path of the codeql binary

The CodeQL database is created once per language during triage and cached
in a temp directory for reuse by the rule_selector in targeted follow-ups.
"""

import asyncio
import json
import logging
import shutil
import tempfile
import time
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)
from pathlib import Path

from app.analysis.paths import (
    load_repo_path_policy,
    normalise_path,
    relative_to_repo,
    should_skip_repo_path,
)
from app.config import settings
from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

# CodeQL language identifiers
CODEQL_LANGUAGES = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",  # CodeQL uses 'javascript' for both JS and TS
    "java": "java",
    "go": "go",
    "ruby": "ruby",
    "csharp": "csharp",
    "c": "cpp",
    "cpp": "cpp",
    "kotlin": "java",  # CodeQL analyses Kotlin via Java extractor
    "swift": "swift",
}
COMPILED_CODEQL_LANGUAGES = {"cpp", "csharp", "go", "java", "swift"}
DEFAULT_BASELINE_QUERY_SUFFIXES = {
    "light": ["security-extended.qls"],
    "regular": ["security-extended.qls", "security-and-quality.qls"],
    "heavy": ["security-extended.qls", "security-and-quality.qls", "security-experimental.qls"],
}
DEFAULT_TARGETED_QUERY_SUFFIXES = ["security-experimental.qls", "security-and-quality.qls"]
MAX_WORKSPACE_BUILD_COMMANDS = 6

# SARIF severity mapping
SARIF_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

# SARIF security-severity to our severity
def _sarif_security_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class CodeQLAdapter(ScannerAdapter):
    """CodeQL scanner adapter with database caching for targeted reuse."""

    def __init__(self):
        self._db_paths: dict[str, Path] = {}  # language -> database path
        self._db_metadata: dict[str, dict] = {}
        self._temp_dir: Path | None = None
        self._current_target: Path | None = None  # Track which repo DBs belong to

    @property
    def name(self) -> str:
        return "codeql"

    async def is_available(self) -> bool:
        return shutil.which(settings.codeql_binary) is not None

    async def get_version(self) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.codeql_binary, "version", "--format=terse",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except Exception:
            return None

    async def run(
        self,
        target_path: Path,
        *,
        languages: list[str] | None = None,
        rules: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> ScannerOutput:
        """
        Run CodeQL analysis. Creates databases for detected languages,
        analyses with default query suites, returns hits.
        """
        start = time.monotonic()
        all_hits = []
        all_errors = []

        # Invalidate cached databases if target repo changed
        if self._current_target and self._current_target != target_path:
            self.cleanup()
            self._db_paths = {}
            self._db_metadata = {}
            self._temp_dir = None
        self._current_target = target_path

        # Determine which CodeQL languages to analyse
        codeql_langs = set()
        if languages:
            for lang in languages:
                cql = CODEQL_LANGUAGES.get(lang)
                if cql:
                    codeql_langs.add(cql)

        if not codeql_langs:
            # Auto-detect: try the main languages
            codeql_langs = {"python", "javascript", "java"}

        # Create temp directory for databases
        if not self._temp_dir:
            self._temp_dir = Path(tempfile.mkdtemp(prefix="vragent-codeql-"))

        scan_mode = self._extract_scan_mode(rules)
        requested_queries = [
            rule for rule in (rules or [])
            if isinstance(rule, str) and rule.strip() and not rule.startswith("baseline:")
        ]

        for cql_lang in codeql_langs:
            try:
                # Create database
                db_path, warnings = await self._create_database(target_path, cql_lang)
                all_errors.extend(warnings)
                if not db_path:
                    continue

                self._db_paths[cql_lang] = db_path

                queries = (
                    self._canonicalise_queries(cql_lang, requested_queries)
                    if requested_queries
                    else self._baseline_queries_for_mode(cql_lang, scan_mode)
                )
                self._db_metadata.setdefault(cql_lang, {})["baseline_queries"] = list(queries)

                # Analyse with the query plan for this scan mode.
                hits = await self._analyse_database(db_path, cql_lang, target_path, queries)
                all_hits.extend(hits)

            except Exception as e:
                all_errors.append(f"CodeQL {cql_lang}: {e}")

        duration = int((time.monotonic() - start) * 1000)
        # Only report success if we actually created at least one database
        succeeded = len(self._db_paths) > 0 or not codeql_langs
        return ScannerOutput(
            scanner_name=self.name,
            success=succeeded,
            hits=all_hits,
            errors=all_errors,
            duration_ms=duration,
        )

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        """Run targeted CodeQL queries using cached databases."""
        start = time.monotonic()
        all_hits = []
        all_errors = []
        attempted = 0

        if not self._db_paths:
            return ScannerOutput(
                scanner_name=self.name,
                success=False,
                errors=["No CodeQL databases available. Run a baseline scan first."],
                duration_ms=0,
            )

        requested_files = {normalise_path(f) for f in files}

        for cql_lang, db_path in self._db_paths.items():
            if not db_path.exists():
                all_errors.append(f"CodeQL database missing for {cql_lang}: {db_path}")
                continue

            try:
                query_plan = self._plan_targeted_queries(cql_lang, rules)
                if not query_plan:
                    continue

                attempted += len(query_plan)
                hits = await self._run_queries(
                    db_path,
                    query_plan,
                    target_path,
                    output_label=f"targeted-{cql_lang}",
                    timeout_s=300,
                )
                if requested_files:
                    hits = [
                        hit for hit in hits
                        if normalise_path(hit.file_path) in requested_files
                    ]
                all_hits.extend(hits)
            except Exception as e:
                all_errors.append(f"CodeQL targeted {cql_lang}: {e}")

        duration = int((time.monotonic() - start) * 1000)
        if attempted == 0:
            all_errors.append("No applicable CodeQL query suites for cached language databases.")
        return ScannerOutput(
            scanner_name=self.name,
            success=attempted > 0,
            hits=self._dedupe_hits(all_hits),
            errors=all_errors,
            duration_ms=duration,
        )

    @staticmethod
    def _query_matches_language(language: str, query_suite: str) -> bool:
        """Best-effort filter so we don't run Python suites against JS databases."""
        suite = query_suite.lower()
        suite_prefixes = {language}
        if language == "javascript":
            suite_prefixes.add("typescript")
        return any(
            suite.startswith(f"{prefix}-") or f"/{prefix}-" in suite or f"\\{prefix}-" in suite
            for prefix in suite_prefixes
        )

    @staticmethod
    def _extract_scan_mode(rules: list[str] | None) -> str:
        for rule in rules or []:
            if not isinstance(rule, str):
                continue
            if rule.startswith("baseline:"):
                mode = rule.split(":", 1)[1].strip().lower()
                if mode in DEFAULT_BASELINE_QUERY_SUFFIXES:
                    return mode
        mode = (settings.default_scan_mode or "regular").strip().lower()
        return mode if mode in DEFAULT_BASELINE_QUERY_SUFFIXES else "regular"

    @staticmethod
    def _canonical_query_suite(language: str, query_suite: str) -> str:
        query = (query_suite or "").strip()
        if not query:
            return ""

        # Bare built-in suite names can be normalized safely.
        if "/" not in query and "\\" not in query:
            query = query.lower()
            if language == "javascript" and query.startswith("typescript-"):
                query = "javascript-" + query[len("typescript-"):]
        return query

    def _canonicalise_queries(self, language: str, queries: list[str] | None) -> list[str]:
        canonical: list[str] = []
        seen: set[str] = set()
        for query in queries or []:
            normalized = self._canonical_query_suite(language, query)
            if not normalized or not self._query_matches_language(language, normalized):
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            canonical.append(normalized)
        return canonical

    def _baseline_queries_for_mode(self, language: str, mode: str) -> list[str]:
        suffixes = DEFAULT_BASELINE_QUERY_SUFFIXES.get(mode, DEFAULT_BASELINE_QUERY_SUFFIXES["regular"])
        queries = [f"{language}-{suffix}" for suffix in suffixes]
        return self._canonicalise_queries(language, queries)

    def _default_targeted_queries(self, language: str) -> list[str]:
        queries = [f"{language}-{suffix}" for suffix in DEFAULT_TARGETED_QUERY_SUFFIXES]
        return self._canonicalise_queries(language, queries)

    def _plan_targeted_queries(self, language: str, rules: list[str] | None) -> list[str]:
        requested = self._canonicalise_queries(language, rules or [])
        if requested:
            return requested

        defaults = self._default_targeted_queries(language)
        baseline = {
            q.lower()
            for q in self._db_metadata.get(language, {}).get("baseline_queries", [])
        }
        uncovered = [query for query in defaults if query.lower() not in baseline]
        return uncovered or defaults

    @staticmethod
    def _quote_command_path(path: Path, root: Path) -> str:
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        value = normalise_path(str(rel)).replace('"', '\\"')
        return f'"{value}"'

    @staticmethod
    def _first_existing(root: Path, patterns: list[str]) -> Path | None:
        for pattern in patterns:
            for match in root.glob(pattern):
                return match
        return None

    @classmethod
    def _resolve_build_strategy(cls, target_path: Path, language: str) -> dict:
        build_command = (settings.codeql_build_command or "").strip()
        if build_command:
            return {
                "kind": "command",
                "value": build_command,
                "degraded": False,
                "warnings": [],
                "retry_with_none": False,
            }

        build_mode = (settings.codeql_build_mode or "auto").strip().lower()
        if build_mode == "none":
            return {
                "kind": "build-mode",
                "value": "none",
                "degraded": True,
                "warnings": [f"CodeQL {language}: degraded coverage using build-mode=none"],
                "retry_with_none": False,
            }
        if build_mode == "autobuild":
            return {
                "kind": "build-mode",
                "value": "autobuild",
                "degraded": False,
                "warnings": [],
                "retry_with_none": False,
            }

        if language == "java":
            gradle_wrapper = cls._first_existing(target_path, ["gradlew", "gradlew.bat"])
            if gradle_wrapper:
                return {
                    "kind": "command",
                    "value": f"{cls._quote_command_path(gradle_wrapper, target_path)} build -x test --no-daemon",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            gradle_root_settings = cls._first_existing(target_path, ["settings.gradle", "settings.gradle.kts"])
            if gradle_root_settings:
                return {
                    "kind": "command",
                    "value": "gradle build -x test --no-daemon",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            gradle_modules = cls._collect_manifest_paths(
                target_path,
                ["build.gradle", "build.gradle.kts"],
            )
            gradle_command = cls._compose_gradle_commands(target_path, gradle_modules, use_wrapper=False)
            if gradle_command:
                return {
                    "kind": "command",
                    "value": gradle_command,
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            if cls._first_existing(target_path, ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"]):
                return {
                    "kind": "command",
                    "value": "gradle build -x test --no-daemon",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            maven_wrapper = cls._first_existing(target_path, ["mvnw", "mvnw.cmd"])
            if maven_wrapper:
                return {
                    "kind": "command",
                    "value": f"{cls._quote_command_path(maven_wrapper, target_path)} -q -DskipTests compile",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            root_pom = target_path / "pom.xml"
            if cls._pom_looks_aggregator(root_pom):
                return {
                    "kind": "command",
                    "value": "mvn -q -DskipTests compile",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            maven_modules = cls._collect_manifest_paths(target_path, ["pom.xml"])
            maven_command = cls._compose_maven_commands(target_path, maven_modules, use_wrapper=False)
            if maven_command:
                return {
                    "kind": "command",
                    "value": maven_command,
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            if cls._first_existing(target_path, ["pom.xml"]):
                return {
                    "kind": "command",
                    "value": "mvn -q -DskipTests compile",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }

        if language == "csharp":
            solution = cls._first_existing(target_path, ["*.sln", "**/*.sln"])
            if solution:
                return {
                    "kind": "command",
                    "value": f"dotnet build {cls._quote_command_path(solution, target_path)} --nologo",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            solutions = cls._collect_manifest_paths(target_path, ["*.sln"])
            if solutions:
                solution_commands = [
                    f"dotnet build {cls._quote_command_path(solution, target_path)} --nologo"
                    for solution in solutions[:MAX_WORKSPACE_BUILD_COMMANDS]
                ]
                return {
                    "kind": "command",
                    "value": " && ".join(solution_commands),
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            project = cls._first_existing(target_path, ["*.csproj", "**/*.csproj"])
            if project:
                return {
                    "kind": "command",
                    "value": f"dotnet build {cls._quote_command_path(project, target_path)} --nologo",
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }
            projects = cls._collect_manifest_paths(target_path, ["*.csproj"])
            if projects:
                project_commands = [
                    f"dotnet build {cls._quote_command_path(project, target_path)} --nologo"
                    for project in projects[:MAX_WORKSPACE_BUILD_COMMANDS]
                ]
                return {
                    "kind": "command",
                    "value": " && ".join(project_commands),
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }

        if language == "swift":
            swift_packages = cls._collect_manifest_paths(target_path, ["Package.swift"])
            if swift_packages:
                if any(pkg.parent == target_path for pkg in swift_packages):
                    return {
                        "kind": "command",
                        "value": "swift build",
                        "degraded": False,
                        "warnings": [],
                        "retry_with_none": True,
                    }
                swift_commands = [
                    f"swift build --package-path {cls._quote_command_path(pkg.parent, target_path)}"
                    for pkg in swift_packages[:MAX_WORKSPACE_BUILD_COMMANDS]
                ]
                return {
                    "kind": "command",
                    "value": " && ".join(swift_commands),
                    "degraded": False,
                    "warnings": [],
                    "retry_with_none": True,
                }

        return {
            "kind": "build-mode",
            "value": "autobuild",
            "degraded": False,
            "warnings": [],
            "retry_with_none": True,
        }

    @staticmethod
    def _pom_looks_aggregator(pom_path: Path) -> bool:
        if not pom_path.exists():
            return False
        try:
            root = ET.parse(pom_path).getroot()
        except Exception:
            return False

        packaging = (root.findtext("{*}packaging", default="") or "").strip().lower()
        modules = root.findall(".//{*}modules/{*}module")
        return bool(modules) or packaging == "pom"

    @staticmethod
    def _collect_manifest_paths(target_path: Path, names: list[str]) -> list[Path]:
        policy = load_repo_path_policy(target_path)
        manifests: list[Path] = []
        seen: set[Path] = set()

        for pattern in names:
            for match in target_path.rglob(pattern):
                if should_skip_repo_path(match, target_path, policy=policy):
                    continue
                if match in seen or not match.is_file():
                    continue
                seen.add(match)
                manifests.append(match)

        manifests.sort(key=lambda path: (len(path.parts), str(path).lower()))
        return manifests

    @classmethod
    def _compose_gradle_commands(cls, target_path: Path, manifests: list[Path], *, use_wrapper: bool) -> str | None:
        roots = cls._select_workspace_roots(target_path, manifests)
        if not roots:
            return None

        commands = []
        wrapper_name = "gradlew.bat" if (target_path / "gradlew.bat").exists() else "gradlew"
        wrapper = target_path / wrapper_name
        for root in roots[:MAX_WORKSPACE_BUILD_COMMANDS]:
            if use_wrapper and wrapper.exists():
                command = f"{cls._quote_command_path(wrapper, target_path)} -p {cls._quote_command_path(root, target_path)} build -x test --no-daemon"
            else:
                command = f"gradle -p {cls._quote_command_path(root, target_path)} build -x test --no-daemon"
            commands.append(command)

        return " && ".join(commands) if commands else None

    @classmethod
    def _compose_maven_commands(cls, target_path: Path, manifests: list[Path], *, use_wrapper: bool) -> str | None:
        modules = cls._select_workspace_manifests(target_path, manifests)
        if not modules:
            return None

        wrapper_name = "mvnw.cmd" if (target_path / "mvnw.cmd").exists() else "mvnw"
        wrapper = target_path / wrapper_name
        commands = []
        for pom in modules[:MAX_WORKSPACE_BUILD_COMMANDS]:
            if use_wrapper and wrapper.exists():
                command = (
                    f"{cls._quote_command_path(wrapper, target_path)} "
                    f"-q -DskipTests -f {cls._quote_command_path(pom, target_path)} compile"
                )
            else:
                command = f"mvn -q -DskipTests -f {cls._quote_command_path(pom, target_path)} compile"
            commands.append(command)

        return " && ".join(commands) if commands else None

    @staticmethod
    def _select_workspace_roots(target_path: Path, manifests: list[Path]) -> list[Path]:
        roots: list[Path] = []
        seen: set[Path] = set()
        for manifest in manifests:
            root = manifest.parent
            if root == target_path:
                continue
            if root in seen:
                continue
            seen.add(root)
            roots.append(root)
        roots.sort(key=lambda path: (len(path.parts), str(path).lower()))
        return roots

    @staticmethod
    def _select_workspace_manifests(target_path: Path, manifests: list[Path]) -> list[Path]:
        selected: list[Path] = []
        seen_dirs: set[Path] = set()
        for manifest in manifests:
            if manifest.parent == target_path:
                continue
            if manifest.parent in seen_dirs:
                continue
            seen_dirs.add(manifest.parent)
            selected.append(manifest)
        selected.sort(key=lambda path: (len(path.parts), str(path).lower()))
        return selected

    async def _create_database(self, target_path: Path, language: str) -> tuple[Path | None, list[str]]:
        """Create a CodeQL database for the given language."""
        db_path = self._temp_dir / f"db-{language}"
        warnings: list[str] = []

        if db_path.exists():
            # Reuse existing database
            return db_path, warnings

        cmd = [
            settings.codeql_binary,
            "database", "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={target_path}",
            "--overwrite",
            "--no-calculate-baseline",
        ]

        if language in COMPILED_CODEQL_LANGUAGES:
            strategy = self._resolve_build_strategy(target_path, language)
            warnings.extend(strategy.get("warnings", []))
            if strategy["kind"] == "command":
                cmd.append(f"--command={strategy['value']}")
            else:
                cmd.append(f"--build-mode={strategy['value']}")

            db_result, stderr_text = await self._execute_database_create(cmd, language)
            if db_result:
                self._db_metadata[language] = {
                    "build_strategy": strategy["kind"],
                    "build_value": strategy["value"],
                    "degraded": bool(strategy.get("degraded", False)),
                }
                return db_path, warnings

            if "No source code was seen" in stderr_text:
                logger.info("CodeQL: no %s source code found in repo", language)
                return None, warnings

            if strategy.get("retry_with_none"):
                fallback_cmd = [part for part in cmd if not part.startswith(("--command=", "--build-mode="))]
                fallback_cmd.append("--build-mode=none")
                fallback_ok, fallback_stderr = await self._execute_database_create(fallback_cmd, language)
                if fallback_ok:
                    warn = (
                        f"CodeQL {language}: falling back to build-mode=none after "
                        f"{strategy['kind']} {strategy['value']} failed"
                    )
                    warnings.append(warn[:500])
                    self._db_metadata[language] = {
                        "build_strategy": "build-mode",
                        "build_value": "none",
                        "degraded": True,
                    }
                    return db_path, warnings
                stderr_text = fallback_stderr or stderr_text

            logger.warning("CodeQL database creation failed for %s: %s", language, stderr_text)
            return None, warnings + ([f"CodeQL {language}: {stderr_text[:300]}"] if stderr_text else [])

        db_result, stderr_text = await self._execute_database_create(cmd, language)
        if db_result:
            self._db_metadata[language] = {
                "build_strategy": "interpreted",
                "build_value": "",
                "degraded": False,
            }
            return db_path, warnings

        if "No source code was seen" in stderr_text:
            logger.info("CodeQL: no %s source code found in repo", language)
            return None, warnings
        logger.warning("CodeQL database creation failed for %s: %s", language, stderr_text)
        return None, warnings + ([f"CodeQL {language}: {stderr_text[:300]}"] if stderr_text else [])

    async def _execute_database_create(self, cmd: list[str], language: str) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            stderr_text = stderr.decode()[:1000] if stderr else ""
            return proc.returncode == 0, stderr_text
        except asyncio.TimeoutError:
            logger.warning("CodeQL database creation timed out for %s (300s limit)", language)
            return False, "database creation timed out"
        except Exception as e:
            logger.warning("CodeQL database creation error for %s: %s", language, e)
            return False, str(e)

    async def _analyse_database(
        self, db_path: Path, language: str, target_path: Path, queries: list[str]
    ) -> list[ScannerHit]:
        """Analyse a CodeQL database with the planned baseline query suites."""
        return await self._run_queries(
            db_path,
            queries,
            target_path,
            output_label=f"results-{language}",
            timeout_s=600,
        )

    async def _run_queries(
        self,
        db_path: Path,
        queries: list[str],
        target_path: Path,
        *,
        output_label: str,
        timeout_s: int,
    ) -> list[ScannerHit]:
        """Run one or more CodeQL query suites and dedupe overlapping hits."""
        planned = [query for query in queries if query]
        if not planned:
            return []

        output_file = self._temp_dir / f"{output_label}.sarif"

        cmd = [
            settings.codeql_binary,
            "database", "analyze",
            str(db_path),
            *planned,
            f"--format=sarif-latest",
            f"--output={output_file}",
            "--no-print-metrics-summary",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout_s)

            if not output_file.exists():
                return []

            hits = self._parse_sarif(output_file, target_path)
            for hit in hits:
                hit.metadata = dict(hit.metadata or {})
                hit.metadata["query_suites"] = list(planned)
            return self._dedupe_hits(hits)
        except Exception:
            return []

    def _parse_sarif(self, sarif_path: Path, target_path: Path) -> list[ScannerHit]:
        """Parse SARIF output into ScannerHit records."""
        try:
            data = json.loads(sarif_path.read_text())
        except Exception:
            return []

        hits = []

        for run in data.get("runs", []):
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                message = result.get("message", {}).get("text", "")
                level = result.get("level", "warning")

                # Get location
                locations = result.get("locations", [])
                file_path = ""
                start_line = 0
                end_line = None
                snippet = ""

                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    file_path = artifact.get("uri", "")
                    # Strip file:// prefix and make relative
                    if file_path.startswith("file:///"):
                        file_path = file_path[8:]  # file:///C:/path -> C:/path
                    elif file_path.startswith("file://"):
                        file_path = file_path[7:]  # file://path -> path
                    try:
                        file_path = normalise_path(relative_to_repo(Path(file_path), target_path))
                    except (ValueError, TypeError):
                        file_path = normalise_path(file_path)

                    region = phys.get("region", {})
                    start_line = region.get("startLine", 0)
                    end_line = region.get("endLine")
                    snippet = region.get("snippet", {}).get("text", "")

                # Get severity from security-severity tag or level
                properties = result.get("properties", {})
                security_severity = properties.get("security-severity")
                if security_severity:
                    try:
                        severity = _sarif_security_severity(float(security_severity))
                    except (ValueError, TypeError):
                        severity = SARIF_SEVERITY_MAP.get(level, "medium")
                else:
                    severity = SARIF_SEVERITY_MAP.get(level, "medium")

                # Get CWE tags
                tags = properties.get("tags", [])
                cwes = [t for t in tags if t.startswith("external/cwe/")]

                # Get data flow path if available (CodeQL's key advantage)
                code_flows = result.get("codeFlows", [])
                flow_steps = []
                if code_flows:
                    for flow in code_flows[:1]:  # Take first flow
                        for thread in flow.get("threadFlows", [])[:1]:
                            for loc in thread.get("locations", []):
                                step_loc = loc.get("location", {}).get("physicalLocation", {})
                                step_file = step_loc.get("artifactLocation", {}).get("uri", "")
                                if step_file.startswith("file:///"):
                                    step_file = step_file[8:]
                                elif step_file.startswith("file://"):
                                    step_file = step_file[7:]
                                try:
                                    step_file = normalise_path(relative_to_repo(Path(step_file), target_path))
                                except (ValueError, TypeError):
                                    step_file = normalise_path(step_file)
                                step_line = step_loc.get("region", {}).get("startLine", 0)
                                step_msg = loc.get("location", {}).get("message", {}).get("text", "")
                                flow_steps.append({
                                    "file": step_file,
                                    "line": step_line,
                                    "message": step_msg[:100],
                                })

                fingerprints = result.get("fingerprints") or result.get("partialFingerprints") or {}
                fingerprint = "|".join(
                    f"{key}={value}"
                    for key, value in sorted(fingerprints.items())
                    if isinstance(value, str) and value
                )

                hits.append(
                    ScannerHit(
                        rule_id=f"codeql/{rule_id}",
                        severity=severity,
                        message=message[:500],
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        snippet=snippet[:300],
                        metadata={
                            "scanner": "codeql",
                            "cwes": cwes,
                            "tags": tags,
                            "security_severity": security_severity,
                            "data_flow_steps": flow_steps[:10],
                            "has_data_flow": len(flow_steps) > 0,
                            "fingerprint": fingerprint,
                        },
                    )
                )

        return hits

    @staticmethod
    def _dedupe_hits(hits: list[ScannerHit]) -> list[ScannerHit]:
        deduped: dict[str, ScannerHit] = {}

        for hit in hits:
            metadata = dict(hit.metadata or {})
            key = metadata.get("fingerprint") or "|".join(
                [
                    hit.rule_id,
                    normalise_path(hit.file_path),
                    str(hit.start_line),
                    str(hit.end_line or 0),
                    hit.message,
                ]
            )

            if key not in deduped:
                metadata["matched_suites"] = list(metadata.get("query_suites", []))
                hit.metadata = metadata
                deduped[key] = hit
                continue

            existing = deduped[key]
            existing_meta = dict(existing.metadata or {})
            suites = set(existing_meta.get("matched_suites", []))
            suites.update(metadata.get("query_suites", []))
            existing_meta["matched_suites"] = sorted(suites)
            existing_meta["query_suites"] = sorted(suites)

            tags = set(existing_meta.get("tags", []))
            tags.update(metadata.get("tags", []))
            existing_meta["tags"] = sorted(tags)

            cwes = set(existing_meta.get("cwes", []))
            cwes.update(metadata.get("cwes", []))
            existing_meta["cwes"] = sorted(cwes)

            if not existing_meta.get("has_data_flow") and metadata.get("has_data_flow"):
                existing_meta["has_data_flow"] = True
                existing_meta["data_flow_steps"] = metadata.get("data_flow_steps", [])

            existing.metadata = existing_meta

        return list(deduped.values())

    def cleanup(self):
        """Remove temporary CodeQL databases."""
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass
        self._db_metadata = {}
        self._db_paths = {}
        self._temp_dir = None
        self._current_target = None
