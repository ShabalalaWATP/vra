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

logger = logging.getLogger(__name__)
from pathlib import Path

from app.analysis.paths import normalise_path, relative_to_repo
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

        for cql_lang in codeql_langs:
            try:
                # Create database
                db_path = await self._create_database(target_path, cql_lang)
                if not db_path:
                    continue

                self._db_paths[cql_lang] = db_path

                # Analyse with default security queries
                hits = await self._analyse_database(db_path, cql_lang, target_path)
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
                # Run specific query suites
                for query_suite in rules:
                    hits = await self._run_query(db_path, query_suite, target_path)
                    if requested_files:
                        hits = [
                            hit for hit in hits
                            if normalise_path(hit.file_path) in requested_files
                        ]
                    all_hits.extend(hits)
            except Exception as e:
                all_errors.append(f"CodeQL targeted {cql_lang}: {e}")

        duration = int((time.monotonic() - start) * 1000)
        return ScannerOutput(
            scanner_name=self.name,
            success=True,
            hits=all_hits,
            errors=all_errors,
            duration_ms=duration,
        )

    async def _create_database(self, target_path: Path, language: str) -> Path | None:
        """Create a CodeQL database for the given language."""
        db_path = self._temp_dir / f"db-{language}"

        if db_path.exists():
            # Reuse existing database
            return db_path

        cmd = [
            settings.codeql_binary,
            "database", "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={target_path}",
            "--overwrite",
            "--no-calculate-baseline",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            if proc.returncode != 0:
                stderr_text = stderr.decode()[:500] if stderr else ""
                if "No source code was seen" in stderr_text:
                    logger.info("CodeQL: no %s source code found in repo", language)
                    return None
                logger.warning("CodeQL database creation failed for %s: %s", language, stderr_text)
                return None

            return db_path

        except asyncio.TimeoutError:
            logger.warning("CodeQL database creation timed out for %s (300s limit)", language)
            return None
        except Exception as e:
            logger.warning("CodeQL database creation error for %s: %s", language, e)
            return None

    async def _analyse_database(
        self, db_path: Path, language: str, target_path: Path
    ) -> list[ScannerHit]:
        """Analyse a CodeQL database with default security query suite."""
        output_file = self._temp_dir / f"results-{language}.sarif"

        # Use the built-in security query suite
        query_suite = f"{language}-security-extended.qls"

        cmd = [
            settings.codeql_binary,
            "database", "analyze",
            str(db_path),
            query_suite,
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
            await asyncio.wait_for(proc.communicate(), timeout=600)

            if not output_file.exists():
                return []

            return self._parse_sarif(output_file, target_path)

        except asyncio.TimeoutError:
            logger.warning("CodeQL analysis timed out for %s (600s limit)", language)
            return []
        except Exception as e:
            logger.warning("CodeQL analysis error for %s: %s", language, e)
            return []

    async def _run_query(
        self, db_path: Path, query: str, target_path: Path
    ) -> list[ScannerHit]:
        """Run a specific CodeQL query or query suite."""
        output_file = self._temp_dir / f"targeted-{query.replace('/', '-')}.sarif"

        cmd = [
            settings.codeql_binary,
            "database", "analyze",
            str(db_path),
            query,
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
            await asyncio.wait_for(proc.communicate(), timeout=300)

            if not output_file.exists():
                return []

            return self._parse_sarif(output_file, target_path)
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
                        },
                    )
                )

        return hits

    def cleanup(self):
        """Remove temporary CodeQL databases."""
        if self._temp_dir and self._temp_dir.exists():
            try:
                shutil.rmtree(self._temp_dir)
            except Exception:
                pass
