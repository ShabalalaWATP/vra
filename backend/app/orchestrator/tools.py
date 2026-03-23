"""Agent tool registry — shared capabilities available to all agents.

This provides a structured set of tools that agents can call during
their execution. Instead of reimplementing file reading, scanning,
and database queries in each agent, all capabilities are centralised here.

Tools:
  - read_file: Read a source file (with line limits)
  - read_file_range: Read specific lines from a file
  - search_code: Grep for a pattern across the repo (regex)
  - list_directory: List files in a directory
  - get_file_symbols: Get Tree-sitter symbols for a file
  - get_scanner_hits: Get scanner results for a file
  - get_all_scanner_hits: Get all scanner results for the scan
  - run_semgrep: Run Semgrep on specific files with specific rules
  - run_bandit: Run Bandit on specific files
  - query_findings: Get current candidate findings
  - query_taint_flows: Get discovered taint flows
  - get_file_imports: Get imports/requires from a file
  - check_file_exists: Check if a file exists in the repo
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.analysis.paths import (
    is_binary_extension,
    is_safe_path,
    normalise_path,
    relative_to_repo,
    safe_read_file,
    should_skip_dir,
)
from app.analysis.treesitter import parse_file, is_available as ts_available
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)
READ_PREVIEW_BYTES = 200_000


@dataclass
class ToolResult:
    """Result of a tool invocation."""

    success: bool
    data: str | list | dict = ""
    error: str = ""
    tokens_estimate: int = 0  # Estimated tokens consumed by this result


class AgentToolkit:
    """
    Shared toolkit that agents use to interact with the codebase,
    scanners, and scan state.
    """

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.repo = Path(ctx.repo_path)
        self._resolved_repo = self.repo.resolve()

    # ── File Tools ────────────────────────────────────────────────

    def _safe_path(self, file_path: str) -> Path | None:
        """Resolve a file path and verify it stays within the repo directory."""
        if not file_path or not is_safe_path(file_path, self.repo):
            return None
        try:
            full = (self.repo / file_path).resolve()
            full.relative_to(self._resolved_repo)
            return full
        except (ValueError, OSError):
            return None

    def _safe_dir(self, dir_path: str = "") -> Path | None:
        """Resolve a directory path and verify it stays within the repo directory."""
        raw = dir_path or "."
        if not is_safe_path(raw, self.repo):
            return None
        try:
            full = (self.repo / raw).resolve()
            full.relative_to(self._resolved_repo)
            return full
        except (ValueError, OSError):
            return None

    def _read_text_preview(self, full_path: Path, *, max_bytes: int = READ_PREVIEW_BYTES) -> tuple[str, bool]:
        """Read a bounded preview of a text file, avoiding full reads of huge files."""
        size = full_path.stat().st_size
        if size <= max_bytes:
            return full_path.read_text(encoding="utf-8", errors="replace"), False

        with full_path.open("rb") as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="replace"), True

    def normalise_repo_files(self, files: list[str]) -> list[str]:
        """Keep only existing repo-local files and return normalised repo-relative paths."""
        normalised: list[str] = []
        seen: set[str] = set()

        for file_path in files:
            full = self._safe_path(file_path)
            if not full or not full.exists() or not full.is_file():
                continue
            rel_path = normalise_path(relative_to_repo(full, self.repo))
            if rel_path in seen:
                continue
            seen.add(rel_path)
            normalised.append(rel_path)

        return normalised

    async def read_file(self, file_path: str, *, max_lines: int = 800) -> ToolResult:
        """Read a source file, optionally truncated."""
        full_path = self._safe_path(file_path)
        if not full_path:
            return ToolResult(success=False, error=f"Path traversal blocked: {file_path}")
        if not full_path.exists():
            return ToolResult(success=False, error=f"File not found: {file_path}")
        if not full_path.is_file():
            return ToolResult(success=False, error=f"Not a file: {file_path}")

        try:
            content, preview_truncated = self._read_text_preview(full_path)
            lines = content.splitlines()
            truncated = preview_truncated
            if len(lines) > max_lines:
                content = "\n".join(lines[:max_lines])
                content += f"\n\n[... truncated at {max_lines}/{len(lines)} preview lines ...]"
                truncated = True
            elif preview_truncated:
                content += (
                    f"\n\n[... truncated at {READ_PREVIEW_BYTES:,} bytes; "
                    f"file is {full_path.stat().st_size:,} bytes ...]"
                )
            return ToolResult(
                success=True,
                data=content,
                tokens_estimate=len(content) // 3,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def read_file_range(
        self, file_path: str, start_line: int, end_line: int
    ) -> ToolResult:
        """Read specific lines from a file."""
        full_path = self._safe_path(file_path)
        if not full_path:
            return ToolResult(success=False, error=f"Path traversal blocked: {file_path}")
        if not full_path.exists():
            return ToolResult(success=False, error=f"File not found: {file_path}")

        try:
            start_line = max(1, int(start_line))
            end_line = max(start_line, int(end_line))
            content, preview_truncated = self._read_text_preview(full_path)
            lines = content.splitlines()
            selected = lines[max(0, start_line - 1):end_line]
            numbered = "\n".join(
                f"{i}: {line}" for i, line in enumerate(selected, start=max(1, start_line))
            )
            if preview_truncated:
                numbered += (
                    f"\n[preview truncated at {READ_PREVIEW_BYTES:,} bytes; "
                    "requested line range may be incomplete]"
                )
            return ToolResult(success=True, data=numbered, tokens_estimate=len(numbered) // 3)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def search_code(
        self, pattern: str, *, file_glob: str = "*", max_results: int = 30
    ) -> ToolResult:
        """
        Search for a regex pattern across the repo.
        Returns matching lines with file paths and line numbers.
        """
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return ToolResult(success=False, error=f"Invalid regex: {e}")

        matches = []
        skip_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".next", "target", "vendor",
        }

        for path in self.repo.rglob(file_glob):
            if len(matches) >= max_results:
                break
            if not path.is_file():
                continue
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if is_binary_extension(str(path)):
                continue
            if path.stat().st_size > 500_000:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                for line_num, line in enumerate(content.splitlines(), 1):
                    if compiled.search(line):
                        rel = normalise_path(str(path.relative_to(self.repo)))
                        matches.append({
                            "file": rel,
                            "line": line_num,
                            "content": line.strip()[:200],
                        })
                        if len(matches) >= max_results:
                            break
            except Exception:
                continue

        return ToolResult(
            success=True,
            data=matches,
            tokens_estimate=sum(len(m["content"]) for m in matches) // 3,
        )

    async def list_directory(self, dir_path: str = "", *, max_entries: int = 100) -> ToolResult:
        """List files and directories in a path."""
        target = self._safe_dir(dir_path)
        if not target:
            return ToolResult(success=False, error=f"Path traversal blocked: {dir_path}")

        if not target.exists():
            return ToolResult(success=False, error=f"Directory not found: {dir_path}")
        if not target.is_dir():
            return ToolResult(success=False, error=f"Not a directory: {dir_path}")

        entries = []
        try:
            for item in sorted(target.iterdir()):
                if item.name.startswith(".") and item.name != ".env":
                    continue
                if should_skip_dir(item.name):
                    continue

                rel = normalise_path(relative_to_repo(item, self.repo))
                entries.append({
                    "name": item.name,
                    "path": rel,
                    "type": "dir" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else None,
                })
                if len(entries) >= max_entries:
                    break
        except Exception as e:
            return ToolResult(success=False, error=str(e))

        return ToolResult(success=True, data=entries)

    async def check_file_exists(self, file_path: str) -> ToolResult:
        """Check if a file exists in the repo."""
        full = self._safe_path(file_path)
        if not full:
            return ToolResult(success=False, error=f"Path traversal blocked: {file_path}")
        exists = full.exists() and full.is_file()
        return ToolResult(success=True, data={"exists": exists, "path": file_path})

    # ── Code Analysis Tools ───────────────────────────────────────

    async def get_file_symbols(self, file_path: str) -> ToolResult:
        """Get Tree-sitter parsed symbols (functions, classes, routes) for a file."""
        full_path = self._safe_path(file_path)
        if not full_path:
            return ToolResult(success=False, error=f"Path traversal blocked: {file_path}")
        if not full_path.exists():
            return ToolResult(success=False, error=f"File not found: {file_path}")

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            # Determine language from extension
            ext_map = {
                ".py": "python", ".js": "javascript", ".ts": "typescript",
                ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
                ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
            }
            ext = full_path.suffix.lower()
            language = ext_map.get(ext, "")

            if not language:
                return ToolResult(success=True, data={"symbols": [], "language": "unknown"})

            analysis = parse_file(content, language)
            symbols = [
                {
                    "name": s.name,
                    "kind": s.kind,
                    "start_line": s.start_line,
                    "end_line": s.end_line,
                    "signature": s.signature,
                    "tags": s.tags,
                }
                for s in analysis.symbols
            ]
            return ToolResult(success=True, data={
                "symbols": symbols,
                "imports": [{"module": i.module, "line": i.line} for i in analysis.imports],
                "routes": analysis.routes,
                "has_main": analysis.has_main,
                "language": language,
            })
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def get_file_imports(self, file_path: str) -> ToolResult:
        """Get imports/requires from a file."""
        result = await self.get_file_symbols(file_path)
        if not result.success:
            return result
        imports = result.data.get("imports", []) if isinstance(result.data, dict) else []
        return ToolResult(success=True, data=imports)

    # ── Scanner Tools ─────────────────────────────────────────────

    async def get_scanner_hits(self, file_path: str) -> ToolResult:
        """Get all scanner results for a specific file."""
        from sqlalchemy import select
        from app.database import async_session
        from app.models.file import File
        from app.models.scanner_result import ScannerResult

        try:
            async with async_session() as session:
                file_result = await session.execute(
                    select(File).where(
                        File.scan_id == self.ctx.scan_id, File.path == file_path
                    )
                )
                file_rec = file_result.scalar_one_or_none()
                if not file_rec:
                    return ToolResult(success=True, data=[])

                result = await session.execute(
                    select(ScannerResult)
                    .where(ScannerResult.file_id == file_rec.id)
                    .order_by(ScannerResult.created_at.desc(), ScannerResult.id.desc())
                    .limit(50)
                )
                hits = [
                    {
                        "scanner": sr.scanner,
                        "rule_id": sr.rule_id or "",
                        "severity": sr.severity or "info",
                        "message": sr.message or "",
                        "start_line": sr.start_line or 0,
                        "end_line": sr.end_line,
                        "snippet": (sr.snippet or "")[:200],
                        "metadata": sr.extra_data or {},
                    }
                    for sr in result.scalars().all()
                ]
                return ToolResult(success=True, data=hits)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def get_all_scanner_hits(
        self, *, scanner: str | None = None, severity: str | None = None, limit: int = 50
    ) -> ToolResult:
        """Get scanner results across the whole scan, optionally filtered."""
        from sqlalchemy import select
        from app.database import async_session
        from app.models.scanner_result import ScannerResult
        from app.models.file import File

        try:
            async with async_session() as session:
                query = (
                    select(ScannerResult, File.path)
                    .outerjoin(File, ScannerResult.file_id == File.id)
                    .where(ScannerResult.scan_id == self.ctx.scan_id)
                )
                if scanner:
                    query = query.where(ScannerResult.scanner == scanner)
                if severity:
                    query = query.where(ScannerResult.severity == severity)
                query = query.order_by(ScannerResult.created_at.desc(), ScannerResult.id.desc()).limit(limit)

                result = await session.execute(query)
                hits = [
                    {
                        "scanner": sr.scanner,
                        "rule_id": sr.rule_id or "",
                        "severity": sr.severity or "info",
                        "message": sr.message or "",
                        "file": file_path or "",
                        "line": sr.start_line or 0,
                        "metadata": sr.extra_data or {},
                    }
                    for sr, file_path in result.all()
                ]
                return ToolResult(success=True, data=hits)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def run_semgrep_on_files(
        self, files: list[str], rules: list[str] | None = None
    ) -> ToolResult:
        """Run Semgrep on specific files with optional rule filter."""
        scanners = self.ctx.scanners
        if not scanners:
            from app.scanners.registry import get_available_scanners
            scanners = await get_available_scanners()
        if "semgrep" not in scanners:
            return ToolResult(success=False, error="Semgrep not available")

        try:
            safe_files = self.normalise_repo_files(files)
            if not safe_files:
                return ToolResult(success=False, error="No valid repo files supplied")
            if rules:
                output = await scanners["semgrep"].run_targeted(self.repo, safe_files, rules)
            else:
                output = await scanners["semgrep"].run(self.repo, file_filter=safe_files)

            hits = [
                {
                    "rule_id": h.rule_id,
                    "severity": h.severity,
                    "message": h.message,
                    "file": h.file_path,
                    "line": h.start_line,
                    "snippet": (h.snippet or "")[:200],
                }
                for h in output.hits
            ]
            return ToolResult(
                success=output.success,
                data=hits,
                error="; ".join(output.errors) if output.errors else "",
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def run_bandit_on_files(self, files: list[str], rules: list[str] | None = None) -> ToolResult:
        """Run Bandit on specific Python files."""
        scanners = self.ctx.scanners
        if not scanners:
            from app.scanners.registry import get_available_scanners
            scanners = await get_available_scanners()
        if "bandit" not in scanners:
            return ToolResult(success=False, error="Bandit not available")

        try:
            safe_files = self.normalise_repo_files(files)
            if not safe_files:
                return ToolResult(success=False, error="No valid repo files supplied")
            output = await scanners["bandit"].run_targeted(self.repo, safe_files, rules or [])
            hits = [
                {
                    "rule_id": h.rule_id,
                    "severity": h.severity,
                    "message": h.message,
                    "file": h.file_path,
                    "line": h.start_line,
                    "snippet": (h.snippet or "")[:200],
                }
                for h in output.hits
            ]
            return ToolResult(success=output.success, data=hits)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    # ── State Query Tools ─────────────────────────────────────────

    async def query_findings(
        self, *, status: str | None = None, severity: str | None = None
    ) -> ToolResult:
        """Query current candidate findings from the scan context."""
        findings = self.ctx.candidate_findings
        if status:
            findings = [f for f in findings if f.status == status]
        if severity:
            findings = [f for f in findings if f.severity == severity]

        data = [
            {
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "status": f.status,
                "hypothesis": f.hypothesis[:200],
                "input_sources": f.input_sources[:3],
                "sinks": f.sinks[:3],
            }
            for f in findings
        ]
        return ToolResult(success=True, data=data)

    async def query_taint_flows(self, *, unsanitised_only: bool = False) -> ToolResult:
        """Query discovered taint flows."""
        flows = self.ctx.taint_flows
        if unsanitised_only:
            flows = [f for f in flows if not f.sanitised]

        data = [
            {
                "source_file": f.source_file,
                "source_line": f.source_line,
                "source_type": f.source_type,
                "sink_file": f.sink_file,
                "sink_line": f.sink_line,
                "sink_type": f.sink_type,
                "sanitised": f.sanitised,
                "sanitiser_location": f.sanitiser_location,
                "intermediaries": f.intermediaries,
                "confidence": f.confidence,
                "graph_verified": f.graph_verified,
                "call_chain_hops": len(f.call_chain or []),
                "call_chain": (f.call_chain[:6] if f.call_chain else []),
            }
            for f in flows
        ]
        return ToolResult(success=True, data=data)

    async def query_dependency_findings(
        self, *, severity: str | None = None, relevance: str | None = None
    ) -> ToolResult:
        """Query vulnerable dependency findings with CVE details and AI assessments."""
        from app.database import async_session
        from app.models.dependency import Dependency, DependencyFinding

        try:
            async with async_session() as session:
                query = (
                    select(DependencyFinding, Dependency)
                    .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                    .where(DependencyFinding.scan_id == self.ctx.scan_id)
                )
                if severity:
                    query = query.where(DependencyFinding.severity == severity)
                if relevance:
                    query = query.where(DependencyFinding.relevance == relevance)

                result = await session.execute(query)
                data = [
                    {
                        "package": dep.name,
                        "ecosystem": dep.ecosystem,
                        "installed_version": dep.version,
                        "advisory_id": df.advisory_id,
                        "severity": df.severity,
                        "cvss_score": df.cvss_score,
                        "summary": df.summary,
                        "affected_range": df.affected_range,
                        "fixed_version": df.fixed_version,
                        "relevance": df.relevance,
                        "ai_assessment": df.ai_assessment,
                        "source_file": dep.source_file,
                        "is_dev": dep.is_dev,
                    }
                    for df, dep in result.all()
                ]
                return ToolResult(success=True, data=data)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    # ── Call Graph Tools ─────────────────────────────────────────

    async def get_call_graph_for_file(self, file_path: str) -> ToolResult:
        """Get incoming and outgoing call edges for a file."""
        cg = self.ctx.call_graph
        if not cg:
            return ToolResult(success=False, error="Call graph not available")

        callers = cg.get_file_callers(file_path)
        callees = cg.get_file_callees(file_path)

        data = {
            "incoming": [
                {
                    "caller_file": e.caller_file,
                    "caller_symbol": e.caller_symbol,
                    "caller_line": e.caller_line,
                    "callee_symbol": e.callee_symbol,
                    "confidence": e.confidence,
                }
                for e in callers[:20]
            ],
            "outgoing": [
                {
                    "callee_file": e.callee_file,
                    "callee_symbol": e.callee_symbol,
                    "caller_symbol": e.caller_symbol,
                    "caller_line": e.caller_line,
                    "confidence": e.confidence,
                }
                for e in callees[:20]
            ],
            "total_incoming": len(callers),
            "total_outgoing": len(callees),
        }
        return ToolResult(success=True, data=data)

    async def trace_call_chain(
        self, from_file: str, from_symbol: str, to_file: str, to_symbol: str
    ) -> ToolResult:
        """Find a call chain between two functions. Returns the path or None."""
        cg = self.ctx.call_graph
        if not cg:
            return ToolResult(success=False, error="Call graph not available")

        path = cg.find_path(from_file, from_symbol, to_file, to_symbol)
        if path is None:
            return ToolResult(success=True, data={"reachable": False, "chain": []})

        chain = [
            {
                "caller": f"{e.caller_file}::{e.caller_symbol} (line {e.caller_line})",
                "callee": f"{e.callee_file}::{e.callee_symbol}",
                "type": e.resolution_type,
                "confidence": e.confidence,
            }
            for e in path
        ]
        return ToolResult(success=True, data={"reachable": True, "chain": chain, "hops": len(chain)})

    async def get_callers_of(self, file_path: str, symbol_name: str) -> ToolResult:
        """Find all functions that call a specific function."""
        cg = self.ctx.call_graph
        if not cg:
            return ToolResult(success=False, error="Call graph not available")

        callers = cg.callers_of(file_path, symbol_name)
        data = [
            {
                "caller_file": e.caller_file,
                "caller_symbol": e.caller_symbol,
                "caller_line": e.caller_line,
                "confidence": e.confidence,
            }
            for e in callers
        ]
        return ToolResult(success=True, data=data)

    async def get_entry_points_reaching(self, file_path: str, symbol_name: str) -> ToolResult:
        """Find entry points (route handlers, main) that can reach a function."""
        cg = self.ctx.call_graph
        if not cg:
            return ToolResult(success=False, error="Call graph not available")

        paths = cg.get_entry_points_reaching(file_path, symbol_name)
        data = [
            [
                {
                    "caller": f"{e.caller_file}::{e.caller_symbol}",
                    "callee": f"{e.callee_file}::{e.callee_symbol}",
                }
                for e in path
            ]
            for path in paths[:5]
        ]
        return ToolResult(success=True, data={"paths": data, "total_paths": len(paths)})

    # ── Import Graph Tools ─────────────────────────────────────────

    async def get_resolved_imports(self, file_path: str) -> ToolResult:
        """Get resolved import targets for a file from the pre-built import graph."""
        resolutions = self.ctx.import_graph.get(file_path, [])
        if not resolutions:
            return ToolResult(success=True, data={"imports": [], "note": "No resolved imports for this file"})

        data = []
        for res in resolutions:
            data.append({
                "module": res.import_module,
                "resolved_file": res.resolved_path or None,
                "is_external": res.is_external,
                "confidence": res.confidence,
            })
        return ToolResult(success=True, data={"imports": data, "total": len(data)})

    async def find_files_importing(self, module_or_file: str) -> ToolResult:
        """Find all files that import a given module or file path."""
        importers = []
        search = module_or_file.lower()

        for file_path, resolutions in self.ctx.import_graph.items():
            for res in resolutions:
                match = (
                    search in (res.import_module or "").lower()
                    or search in (res.resolved_path or "").lower()
                )
                if match:
                    importers.append({
                        "file": file_path,
                        "import_module": res.import_module,
                        "resolved_to": res.resolved_path,
                    })
                    break  # One match per file is enough

        return ToolResult(success=True, data=importers[:30])

    # ── Android / APK Tools ─────────────────────────────────────────

    async def get_android_manifest(self) -> ToolResult:
        """Get parsed AndroidManifest.xml data: permissions, exported components, security flags."""
        manifest = self.ctx.fingerprint.get("android_manifest")
        if not manifest:
            # Try to find and parse it on-demand
            import xml.etree.ElementTree as ET
            candidates = [
                self.repo / "resources" / "AndroidManifest.xml",
                self.repo / "AndroidManifest.xml",
                self.repo.parent / "resources" / "AndroidManifest.xml",
            ]
            for c in candidates:
                if c.exists():
                    try:
                        content = c.read_text(encoding="utf-8", errors="replace")
                        return ToolResult(success=True, data={"raw_xml": content[:5000]})
                    except Exception:
                        pass
            return ToolResult(success=False, error="AndroidManifest.xml not found")

        return ToolResult(success=True, data=manifest)

    async def find_android_component(self, component_name: str) -> ToolResult:
        """Find the Java/Kotlin source file for an Android component (Activity, Service, etc.)."""
        # Component names in manifest are like com.example.app.MainActivity
        # Convert to file path: com/example/app/MainActivity.java
        name = component_name.strip()
        if name.startswith("."):
            # Relative name — needs package prefix from manifest
            manifest = self.ctx.fingerprint.get("android_manifest", {})
            pkg = manifest.get("package", "")
            if pkg:
                name = pkg + name

        path_base = name.replace(".", "/")

        results = []
        for ext in (".java", ".kt"):
            search_path = path_base + ext
            for repo_path in self.ctx.import_graph.keys():
                if repo_path.endswith(search_path) or repo_path.endswith(search_path.split("/")[-1]):
                    results.append(repo_path)

        if not results:
            # Fallback: search by class name only
            class_name = name.rsplit(".", 1)[-1]
            search = await self.search_code(
                f"class\\s+{class_name}\\s",
                file_glob="*.java",
                max_results=5,
            )
            if search.success and search.data:
                results = [m["file"] for m in search.data]

        if results:
            return ToolResult(success=True, data={
                "component": component_name,
                "files": results,
                "count": len(results),
            })
        return ToolResult(success=True, data={
            "component": component_name,
            "files": [],
            "count": 0,
            "note": "Component source not found — may be in an obfuscated class",
        })

    async def find_webview_usage(self) -> ToolResult:
        """Find all WebView instances, JavaScript bridges, and URL loading across the codebase."""
        patterns = [
            ("WebView creation", r"WebView|new\s+WebView|findViewById.*WebView"),
            ("JavaScript enabled", r"setJavaScriptEnabled\s*\(\s*true"),
            ("JS bridge", r"addJavascriptInterface"),
            ("URL loading", r"loadUrl\s*\(|loadData\s*\(|loadDataWithBaseURL"),
            ("File access", r"setAllowFileAccess\s*\(\s*true|setAllowUniversalAccessFromFileURLs"),
            ("SSL error bypass", r"onReceivedSslError.*proceed|SslErrorHandler.*proceed"),
        ]

        findings = []
        for label, pattern in patterns:
            result = await self.search_code(pattern, file_glob="*.java", max_results=10)
            if result.success and result.data:
                for match in result.data:
                    findings.append({
                        "type": label,
                        "file": match["file"],
                        "line": match["line"],
                        "code": match["content"],
                    })

            # Also search Kotlin
            result_kt = await self.search_code(pattern, file_glob="*.kt", max_results=10)
            if result_kt.success and result_kt.data:
                for match in result_kt.data:
                    findings.append({
                        "type": label,
                        "file": match["file"],
                        "line": match["line"],
                        "code": match["content"],
                    })

        return ToolResult(success=True, data={
            "webview_findings": findings,
            "total": len(findings),
            "has_javascript_bridge": any(f["type"] == "JS bridge" for f in findings),
            "has_ssl_bypass": any(f["type"] == "SSL error bypass" for f in findings),
        })

    async def find_insecure_storage(self) -> ToolResult:
        """Find insecure data storage patterns in Android code."""
        patterns = [
            ("SharedPreferences (plaintext)", r"getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences"),
            ("SQLite raw query", r"rawQuery\s*\(|execSQL\s*\("),
            ("External storage write", r"getExternalStorageDirectory|getExternalFilesDir|Environment\.DIRECTORY"),
            ("Logging sensitive data", r"Log\.(d|i|v|w|e)\s*\([^)]*(?i)(password|token|key|secret|credential)"),
            ("Clipboard usage", r"ClipboardManager|setPrimaryClip|getPrimaryClip"),
            ("World-readable file", r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|openFileOutput.*MODE_WORLD"),
        ]

        findings = []
        for label, pattern in patterns:
            for ext in ("*.java", "*.kt"):
                result = await self.search_code(pattern, file_glob=ext, max_results=8)
                if result.success and result.data:
                    for match in result.data:
                        findings.append({
                            "type": label,
                            "file": match["file"],
                            "line": match["line"],
                            "code": match["content"],
                        })

        return ToolResult(success=True, data={
            "storage_findings": findings,
            "total": len(findings),
        })

    async def find_network_security_issues(self) -> ToolResult:
        """Find network security issues: cert pinning bypass, cleartext traffic, custom TrustManagers."""
        patterns = [
            ("Custom TrustManager", r"X509TrustManager|TrustManagerFactory|checkServerTrusted"),
            ("Empty TrustManager", r"getAcceptedIssuers.*return\s+null|checkServerTrusted.*\{\s*\}"),
            ("HostnameVerifier bypass", r"HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|verify.*return\s+true"),
            ("HTTP cleartext", r"http://(?!localhost|127\.|10\.|192\.168)"),
            ("Cert pinning", r"CertificatePinner|NetworkSecurityConfig|sha256/"),
            ("OkHttp unsafe", r"sslSocketFactory|hostnameVerifier.*\{"),
        ]

        findings = []
        for label, pattern in patterns:
            for ext in ("*.java", "*.kt", "*.xml"):
                result = await self.search_code(pattern, file_glob=ext, max_results=8)
                if result.success and result.data:
                    for match in result.data:
                        findings.append({
                            "type": label,
                            "file": match["file"],
                            "line": match["line"],
                            "code": match["content"],
                        })

        return ToolResult(success=True, data={
            "network_findings": findings,
            "total": len(findings),
            "has_custom_trust_manager": any(f["type"] == "Custom TrustManager" for f in findings),
            "has_cleartext": any(f["type"] == "HTTP cleartext" for f in findings),
        })

    async def get_android_exported_components(self) -> ToolResult:
        """Get all exported Android components with their source file locations."""
        manifest = self.ctx.fingerprint.get("android_manifest", {})
        exported = manifest.get("exported_components", [])

        if not exported:
            return ToolResult(success=True, data={"components": [], "note": "No exported components found in manifest"})

        # Resolve each component to its source file
        resolved = []
        for comp in exported:
            name = comp.get("name", "")
            result = await self.find_android_component(name)
            resolved.append({
                **comp,
                "source_files": result.data.get("files", []) if result.success else [],
            })

        return ToolResult(success=True, data={
            "components": resolved,
            "total": len(resolved),
            "dangerous_permissions": manifest.get("dangerous_permissions", []),
            "security_flags": manifest.get("security_flags", {}),
        })

    async def execute_tool_call(self, name: str, args: dict | None = None) -> ToolResult:
        """Execute a tool call by name for scan-time LLM tool use."""
        args = args or {}
        method = getattr(self, name, None)
        if not method or not callable(method):
            return ToolResult(success=False, error=f"Unknown tool: {name}")

        try:
            return await method(**args)
        except TypeError as exc:
            return ToolResult(success=False, error=f"Invalid arguments for {name}: {exc}")
        except Exception as exc:
            return ToolResult(success=False, error=f"{name} failed: {exc}")

    @staticmethod
    def get_openai_tools(source_type: str = "codebase", tool_names: list[str] | None = None) -> list[dict]:
        """Return OpenAI-compatible function tool definitions for scan agents."""
        schemas = {
            "read_file": {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a source file from the repository.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                            "max_lines": {"type": "integer"},
                        },
                        "required": ["file_path"],
                    },
                },
            },
            "read_file_range": {
                "type": "function",
                "function": {
                    "name": "read_file_range",
                    "description": "Read a specific line range from a source file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                            "start_line": {"type": "integer"},
                            "end_line": {"type": "integer"},
                        },
                        "required": ["file_path", "start_line", "end_line"],
                    },
                },
            },
            "search_code": {
                "type": "function",
                "function": {
                    "name": "search_code",
                    "description": "Regex search across the repository.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string"},
                            "file_glob": {"type": "string"},
                            "max_results": {"type": "integer"},
                        },
                        "required": ["pattern"],
                    },
                },
            },
            "list_directory": {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List files and directories inside the repository.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "dir_path": {"type": "string"},
                            "max_entries": {"type": "integer"},
                        },
                    },
                },
            },
            "get_file_symbols": {
                "type": "function",
                "function": {
                    "name": "get_file_symbols",
                    "description": "Get parsed functions, classes, routes, and imports for a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                    },
                },
            },
            "check_file_exists": {
                "type": "function",
                "function": {
                    "name": "check_file_exists",
                    "description": "Check whether a repository file exists.",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                    },
                },
            },
            "get_file_imports": {
                "type": "function",
                "function": {
                    "name": "get_file_imports",
                    "description": "Get imports or requires for a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                    },
                },
            },
            "get_scanner_hits": {
                "type": "function",
                "function": {
                    "name": "get_scanner_hits",
                    "description": "Get scanner hits for a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                    },
                },
            },
            "get_all_scanner_hits": {
                "type": "function",
                "function": {
                    "name": "get_all_scanner_hits",
                    "description": "Get scanner hits across the scan.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "scanner": {"type": "string"},
                            "severity": {"type": "string"},
                            "limit": {"type": "integer"},
                        },
                    },
                },
            },
            "query_findings": {
                "type": "function",
                "function": {
                    "name": "query_findings",
                    "description": "Query current candidate findings.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string"},
                            "severity": {"type": "string"},
                        },
                    },
                },
            },
            "query_taint_flows": {
                "type": "function",
                "function": {
                    "name": "query_taint_flows",
                    "description": "Query taint flows discovered so far.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "unsanitised_only": {"type": "boolean"},
                        },
                    },
                },
            },
            "query_dependency_findings": {
                "type": "function",
                "function": {
                    "name": "query_dependency_findings",
                    "description": "Query vulnerable dependencies and related advisories.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string"},
                            "relevance": {"type": "string"},
                        },
                    },
                },
            },
            "get_call_graph_for_file": {
                "type": "function",
                "function": {
                    "name": "get_call_graph_for_file",
                    "description": "Get incoming and outgoing call-graph edges for a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                    },
                },
            },
            "trace_call_chain": {
                "type": "function",
                "function": {
                    "name": "trace_call_chain",
                    "description": "Find a call chain between two functions across files.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "from_file": {"type": "string"},
                            "from_symbol": {"type": "string"},
                            "to_file": {"type": "string"},
                            "to_symbol": {"type": "string"},
                        },
                        "required": ["from_file", "from_symbol", "to_file", "to_symbol"],
                    },
                },
            },
            "get_callers_of": {
                "type": "function",
                "function": {
                    "name": "get_callers_of",
                    "description": "Find all functions that call a specific function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                            "symbol_name": {"type": "string"},
                        },
                        "required": ["file_path", "symbol_name"],
                    },
                },
            },
            "get_entry_points_reaching": {
                "type": "function",
                "function": {
                    "name": "get_entry_points_reaching",
                    "description": "Find entry points that can reach a function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                            "symbol_name": {"type": "string"},
                        },
                        "required": ["file_path", "symbol_name"],
                    },
                },
            },
            "get_resolved_imports": {
                "type": "function",
                "function": {
                    "name": "get_resolved_imports",
                    "description": "Get the resolved internal imports for a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                    },
                },
            },
            "find_files_importing": {
                "type": "function",
                "function": {
                    "name": "find_files_importing",
                    "description": "Find files importing a given module or file.",
                    "parameters": {
                        "type": "object",
                        "properties": {"module_or_file": {"type": "string"}},
                        "required": ["module_or_file"],
                    },
                },
            },
            "run_semgrep_on_files": {
                "type": "function",
                "function": {
                    "name": "run_semgrep_on_files",
                    "description": "Run Semgrep on specific files with optional rules.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "files": {"type": "array", "items": {"type": "string"}},
                            "rules": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["files"],
                    },
                },
            },
            "run_bandit_on_files": {
                "type": "function",
                "function": {
                    "name": "run_bandit_on_files",
                    "description": "Run Bandit on specific Python files.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "files": {"type": "array", "items": {"type": "string"}},
                            "rules": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["files"],
                    },
                },
            },
            "get_android_manifest": {
                "type": "function",
                "function": {
                    "name": "get_android_manifest",
                    "description": "Get parsed AndroidManifest.xml data.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            "find_android_component": {
                "type": "function",
                "function": {
                    "name": "find_android_component",
                    "description": "Find the source file for an Android component.",
                    "parameters": {
                        "type": "object",
                        "properties": {"component_name": {"type": "string"}},
                        "required": ["component_name"],
                    },
                },
            },
            "find_webview_usage": {
                "type": "function",
                "function": {
                    "name": "find_webview_usage",
                    "description": "Find WebView usage, JavaScript bridges, and related risks.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            "find_insecure_storage": {
                "type": "function",
                "function": {
                    "name": "find_insecure_storage",
                    "description": "Find insecure Android storage patterns.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            "find_network_security_issues": {
                "type": "function",
                "function": {
                    "name": "find_network_security_issues",
                    "description": "Find Android network security issues.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            "get_android_exported_components": {
                "type": "function",
                "function": {
                    "name": "get_android_exported_components",
                    "description": "Get exported Android components with source-file resolution.",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
        }

        ordered = [
            "read_file",
            "read_file_range",
            "search_code",
            "list_directory",
            "check_file_exists",
            "get_file_symbols",
            "get_file_imports",
            "get_scanner_hits",
            "get_all_scanner_hits",
            "query_findings",
            "query_taint_flows",
            "query_dependency_findings",
            "get_call_graph_for_file",
            "trace_call_chain",
            "get_callers_of",
            "get_entry_points_reaching",
            "get_resolved_imports",
            "find_files_importing",
            "run_semgrep_on_files",
            "run_bandit_on_files",
        ]
        if source_type in ("apk", "aab", "dex", "jar"):
            ordered.extend([
                "get_android_manifest",
                "find_android_component",
                "find_webview_usage",
                "find_insecure_storage",
                "find_network_security_issues",
                "get_android_exported_components",
            ])

        if tool_names:
            ordered = [name for name in ordered if name in set(tool_names)]

        return [schemas[name] for name in ordered if name in schemas]

    # ── Tool Manifest ─────────────────────────────────────────────

    @staticmethod
    def get_tool_descriptions(source_type: str = "codebase") -> list[dict]:
        """
        Return tool descriptions for the LLM prompt.
        Includes Android-specific tools when scanning APK/AAB.
        """
        tools = [
            {"name": "read_file", "description": "Read a source file from the repo", "params": "file_path, max_lines=800"},
            {"name": "read_file_range", "description": "Read specific line range from a file", "params": "file_path, start_line, end_line"},
            {"name": "search_code", "description": "Regex search across the repo, returns matching lines with file paths", "params": "pattern, file_glob='*', max_results=30"},
            {"name": "list_directory", "description": "List files and dirs in a path", "params": "dir_path='', max_entries=100"},
            {"name": "get_file_symbols", "description": "Get parsed functions, classes, routes, imports for a file", "params": "file_path"},
            {"name": "get_scanner_hits", "description": "Get Semgrep/Bandit/ESLint results for a specific file", "params": "file_path"},
            {"name": "get_all_scanner_hits", "description": "Get all scanner results across the scan", "params": "scanner=None, severity=None, limit=50"},
            {"name": "run_semgrep_on_files", "description": "Run Semgrep on specific files with optional rules", "params": "files, rules=None"},
            {"name": "run_bandit_on_files", "description": "Run Bandit on specific Python files", "params": "files, rules=None"},
            {"name": "query_findings", "description": "Get current candidate findings", "params": "status=None, severity=None"},
            {"name": "query_taint_flows", "description": "Get discovered taint flows", "params": "unsanitised_only=False"},
            {"name": "query_dependency_findings", "description": "Get vulnerable dependencies with CVE details", "params": "severity=None, relevance=None"},
            {"name": "check_file_exists", "description": "Check if a file exists in the repo", "params": "file_path"},
            {"name": "get_file_imports", "description": "Get imports/requires from a file", "params": "file_path"},
            {"name": "get_call_graph_for_file", "description": "Get callers and callees for a file from the static call graph", "params": "file_path"},
            {"name": "trace_call_chain", "description": "Find a call chain between two functions across files", "params": "from_file, from_symbol, to_file, to_symbol"},
            {"name": "get_callers_of", "description": "Find all functions that call a specific function", "params": "file_path, symbol_name"},
            {"name": "get_entry_points_reaching", "description": "Find HTTP endpoints that can reach a function", "params": "file_path, symbol_name"},
            {"name": "get_resolved_imports", "description": "Get resolved import targets for a file (what files does it depend on?)", "params": "file_path"},
            {"name": "find_files_importing", "description": "Find all files that import a given module or file", "params": "module_or_file"},
        ]

        # Android-specific tools (only shown for APK/AAB scans)
        if source_type in ("apk", "aab", "dex", "jar"):
            tools.extend([
                {"name": "get_android_manifest", "description": "Get parsed AndroidManifest.xml: permissions, exported components, security flags (debuggable, allowBackup, cleartext)", "params": ""},
                {"name": "find_android_component", "description": "Find the source file for an Android component by its manifest name", "params": "component_name"},
                {"name": "find_webview_usage", "description": "Find all WebView instances, JavaScript bridges (addJavascriptInterface), URL loading, SSL error bypasses", "params": ""},
                {"name": "find_insecure_storage", "description": "Find insecure storage: plaintext SharedPreferences, raw SQL, external storage, world-readable files, sensitive logging", "params": ""},
                {"name": "find_network_security_issues", "description": "Find network security: custom TrustManagers, hostname verifier bypasses, cleartext HTTP, cert pinning", "params": ""},
                {"name": "get_android_exported_components", "description": "Get all exported components with their source files, dangerous permissions, and security flags", "params": ""},
            ])

        return tools
