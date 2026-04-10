"""Triage Agent — repo fingerprinting, scanner execution, initial prioritisation."""

import asyncio
import logging
import uuid
from pathlib import Path

from app.analysis.dependency_inventory import dependency_identity_key
from app.analysis.file_scorer import score_file
from app.analysis.fingerprint import SKIP_DIRS, fingerprint_repo
from app.analysis.investigation_scope import should_investigate_file_path
from app.analysis.obfuscation import detect_obfuscation, summarise_obfuscation, ObfuscationResult
from app.analysis.paths import (
    is_binary_extension,
    load_repo_path_policy,
    normalise_path,
    relative_to_repo,
    safe_read_file,
    should_skip_repo_path,
)
from app.analysis.treesitter import parse_file as ts_parse_file, is_available as ts_available
from app.config import settings
from app.database import async_session
from app.models.file import File
from app.models.scanner_result import ScannerResult
from app.models.secret_candidate import SecretCandidate
from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import FileScore, ScanContext, TaintFlow
from app.scanners.registry import get_available_scanners

logger = logging.getLogger(__name__)

# Language extension map (abbreviated)
LANG_MAP = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".kt": "kotlin", ".c": "c", ".cpp": "cpp",
    ".swift": "swift", ".scala": "scala", ".vue": "vue",
    ".svelte": "svelte", ".dart": "dart",
}


class TriageAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "triage"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_phase = "triage"
        repo = Path(ctx.repo_path)

        # Step 1: Fingerprint
        ctx.current_task = "Fingerprinting repository"
        await self.emit(ctx, "Fingerprinting repository...")
        fp = fingerprint_repo(repo)
        ctx.fingerprint = fp
        ctx.languages = [l["name"] for l in fp["languages"]]
        ctx.frameworks = fp["frameworks"]
        ctx.is_monorepo = fp.get("is_monorepo", False)
        ctx.workspaces = fp.get("workspaces", [])
        ctx.size_warnings = fp.get("size_warnings", [])
        ctx.repo_ignore_file = fp.get("repo_ignore_file")
        ctx.ignored_paths = fp.get("ignored_paths", [])
        ctx.managed_paths_ignored = fp.get("managed_paths_ignored", [])
        ctx.ignored_file_count = fp.get("ignored_file_count", 0)
        await self.emit(ctx, f"Detected: {', '.join(ctx.languages[:5])} | Frameworks: {', '.join(ctx.frameworks[:5])}")

        if ctx.is_monorepo:
            ws_names = [w["name"] for w in ctx.workspaces[:8]]
            await self.emit(ctx, f"Monorepo detected: {len(ctx.workspaces)} workspaces ({', '.join(ws_names)})")

        for warning in ctx.size_warnings:
            await self.emit(ctx, warning, level="warn")
        if ctx.ignored_file_count > 0:
            await self.emit(
                ctx,
                f"Repo scope excludes {ctx.ignored_file_count} files via default skips, managed paths, or .vragentignore",
            )
        if ctx.repo_ignore_file:
            await self.emit(ctx, f"Using repo ignore file: {ctx.repo_ignore_file}")

        # APK-specific: parse AndroidManifest.xml if present
        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            await self.emit(ctx, "Decompiled Android app detected — parsing manifest...")
            manifest_info = await self._parse_android_manifest(repo)
            if manifest_info:
                ctx.fingerprint["android_manifest"] = manifest_info
                if "android" not in [f.lower() for f in ctx.frameworks]:
                    ctx.frameworks.append("Android")
                await self.emit(
                    ctx,
                    f"Android manifest: {manifest_info.get('package', '?')}, "
                    f"{len(manifest_info.get('permissions', []))} permissions, "
                    f"{len(manifest_info.get('exported_components', []))} exported components",
                )

        # Step 2: Walk and index files + detect obfuscation
        ctx.current_task = "Indexing files"
        await self.emit(ctx, "Indexing source files...")
        file_records = await self._index_files(ctx, repo)
        ctx.files_total = len(file_records)
        await self.emit(ctx, f"Indexed {ctx.files_total} files")

        if ctx.files_skipped_size > 0:
            await self.emit(ctx, f"{ctx.files_skipped_size} files skipped (exceeded {settings.max_file_size_bytes // 1_000_000}MB limit)", level="warn")
        if ctx.files_skipped_cap > 0:
            await self.emit(ctx, f"{ctx.files_skipped_cap} files not indexed (exceeded {settings.max_files_per_scan} file cap)", level="warn")

        # Step 2b: Obfuscation detection
        ctx.current_task = "Detecting obfuscation"
        await self.emit(ctx, "Scanning for obfuscated/minified code...")
        obfuscation_results = await self._detect_obfuscation(ctx, repo, file_records)
        ctx.obfuscation_summary = summarise_obfuscation(obfuscation_results)

        if ctx.obfuscation_summary.get("obfuscated_count", 0) > 0:
            pct = ctx.obfuscation_summary.get("obfuscated_percentage", 0)
            heavy = ctx.obfuscation_summary.get("heavily_obfuscated", 0)
            moderate = ctx.obfuscation_summary.get("moderately_obfuscated", 0)
            await self.emit(
                ctx,
                f"Obfuscation detected: {heavy} heavily + {moderate} moderately obfuscated files ({pct:.1f}% of codebase)",
                level="warn" if pct > 20 else "info",
            )

        # Step 2c: Discover documentation files
        ctx.current_task = "Reading project documentation"
        doc_files = self._discover_doc_files(repo)
        ctx.doc_files_found = doc_files
        if doc_files:
            await self.emit(ctx, f"Found {len(doc_files)} documentation files: {', '.join(f.split('/')[-1] for f in doc_files[:5])}")

        # Step 3: Run scanners in parallel
        ctx.current_task = "Running scanners"
        available = ctx.scanners if ctx.scanners else await get_available_scanners()
        scanner_tasks = []

        if "semgrep" in available:
            ctx.current_task = "Running Semgrep"
            try:
                baseline_configs = available["semgrep"]._get_baseline_configs(
                    settings.semgrep_rules_path,
                    ctx.languages,
                    repo,
                    frameworks=ctx.frameworks,
                )
                ctx.baseline_rule_dirs = available["semgrep"].describe_config_paths(
                    baseline_configs,
                    rules_path=settings.semgrep_rules_path,
                )
                ctx.baseline_rule_count = available["semgrep"].count_rules(baseline_configs)
            except Exception:
                ctx.baseline_rule_dirs = []
                ctx.baseline_rule_count = 0
            baseline_hint = ""
            if ctx.baseline_rule_dirs:
                baseline_hint = f"; {len(ctx.baseline_rule_dirs)} rule packs (~{ctx.baseline_rule_count} rules)"
            await self.emit(
                ctx,
                f"Running Semgrep baseline scan (languages: {', '.join(ctx.languages[:5])}{baseline_hint})...",
            )
            scanner_tasks.append((
                "semgrep",
                available["semgrep"].run(repo, languages=ctx.languages, frameworks=ctx.frameworks),
            ))

        if "bandit" in available and "python" in ctx.languages:
            await self.emit(ctx, "Running Bandit...")
            scanner_tasks.append(("bandit", available["bandit"].run(repo)))

        if "eslint" in available and any(l in ctx.languages for l in ("javascript", "typescript")):
            await self.emit(ctx, "Running ESLint...")
            scanner_tasks.append(("eslint", available["eslint"].run(repo)))

        if "codeql" in available:
            await self.emit(ctx, f"Running CodeQL semantic analysis...")
            scanner_tasks.append(
                (
                    "codeql",
                    available["codeql"].run(
                        repo,
                        languages=ctx.languages,
                        rules=[f"baseline:{ctx.mode}"],
                    ),
                )
            )

        if "secrets" in available:
            await self.emit(ctx, "Scanning for secrets...")
            scanner_tasks.append(("secrets", available["secrets"].run(repo)))

        if "dep_audit" in available:
            await self.emit(ctx, "Checking dependencies...")
            scanner_tasks.append(("dep_audit", available["dep_audit"].run(repo)))

        # Execute all scanners concurrently
        if scanner_tasks:
            results = await asyncio.gather(
                *[task for _, task in scanner_tasks],
                return_exceptions=True,
            )

            for (scanner_name, _), result in zip(scanner_tasks, results):
                if isinstance(result, Exception):
                    summary = ctx.record_scanner_run(
                        scanner_name,
                        success=False,
                        hit_count=0,
                        duration_ms=0,
                        errors=[str(result)],
                    )
                    await self.emit(
                        ctx,
                        f"{scanner_name} failed before producing results",
                        level="error",
                        detail=summary,
                    )
                    continue

                summary = ctx.record_scanner_run(
                    scanner_name,
                    success=result.success,
                    hit_count=len(result.hits),
                    duration_ms=result.duration_ms,
                    errors=result.errors,
                )
                level = "warn" if summary["status"] == "degraded" else ("error" if summary["status"] == "failed" else "info")
                error_suffix = f" ({len(summary['errors'])} errors)" if summary["errors"] else ""
                await self.emit(
                    ctx,
                    f"{scanner_name}: {len(result.hits)} findings in {result.duration_ms}ms [{summary['status']}]"
                    f"{error_suffix}",
                    level=level,
                    detail=summary,
                )

                # Persist scanner results
                await self._persist_scanner_results(ctx, scanner_name, result.hits, file_records)

        # Step 3b: Summarise documentation with AI (if docs found and LLM available)
        if ctx.doc_files_found and self.llm:
            ctx.current_task = "Analysing project documentation"
            await self.emit(ctx, "AI reading project documentation...")
            await self._summarise_documentation(ctx, repo)
            if ctx.doc_intelligence:
                await self.emit(ctx, f"Documentation intelligence extracted ({len(ctx.doc_intelligence)} chars)")

        # Progress update after scanners complete
        await self.emit_progress(ctx, task="Scoring and prioritising files")

        # Step 4: Score and prioritise files
        await self.emit(ctx, "Scoring files for priority...")
        await self._score_files(ctx, file_records)

        # Build the priority queue
        sorted_files = sorted(file_records.items(), key=lambda x: x[1].get("score", 0), reverse=True)
        ctx.file_queue = [
            path for path, meta in sorted_files
            if not _get(meta, "is_test")
            and should_investigate_file_path(path)
        ]

        # Step 5: Build call graph (deterministic, no LLM needed)
        ctx.current_task = "Building call graph"
        await self.emit(ctx, "Building call graph and resolving imports...")
        await self._build_call_graph(ctx, repo, file_records)

        # Step 6: Technology version fingerprinting for CVE matching
        try:
            from app.analysis.cve_correlator import fingerprint_versions, check_versions_against_advisories
            ctx.current_task = "Fingerprinting technology versions"
            detected = fingerprint_versions(str(repo))
            if detected:
                await self.emit(ctx, f"Detected {len(detected)} technology versions for CVE checking")
                vuln_versions = check_versions_against_advisories(detected)
                if vuln_versions:
                    await self.emit(ctx, f"Found {len(vuln_versions)} vulnerable technology versions!")
                    # Store in context for investigator and reporter
                    ctx.fingerprint["vulnerable_versions"] = vuln_versions
                    # Boost files that use vulnerable versions
                    for v in vuln_versions:
                        if v.get("file_path"):
                            ctx.boost_file(v["file_path"], 10.0, f"vulnerable: {v['package']}@{v['version']} ({v['cve_id']})")
        except Exception as e:
            await self.emit(ctx, f"Version fingerprinting failed: {e}", level="warn")

        await self.emit(
            ctx,
            f"Triage complete. {sum(ctx.scanner_hit_counts.values())} total scanner hits. "
            f"Top files: {', '.join(ctx.file_queue[:5])}",
        )
        await self.emit_progress(ctx, task="Triage complete")

        await self.log_decision(
            ctx,
            action="triage_complete",
            output_summary=f"Languages: {ctx.languages}, Frameworks: {ctx.frameworks}, "
            f"Files: {ctx.files_total}, Scanner hits: {ctx.scanner_hit_counts}, "
            f"Call graph edges: {len(ctx.call_graph.edges) if ctx.call_graph else 0}",
        )

    async def _build_call_graph(
        self, ctx: ScanContext, repo: Path, file_map: dict
    ):
        """Parse all files for symbols + call sites, resolve imports, build call graph."""
        from app.analysis.call_graph import CallGraphBuilder
        from app.analysis.import_resolver import ImportResolver
        from app.analysis.treesitter import parse_file as ts_parse

        try:
            # Build file path set for import resolution
            all_paths = set(file_map.keys())
            resolver = ImportResolver(all_paths)

            # Parse all files with known languages
            file_analyses = {}
            import_resolutions = {}

            for rel_path, info in file_map.items():
                language = info.get("language")
                if not language:
                    continue

                # Skip obfuscated files
                if rel_path in ctx.non_analysable_files:
                    continue

                full_path = repo / rel_path
                content = safe_read_file(full_path, max_size=settings.max_file_size_bytes)
                if not content:
                    continue

                # Parse for symbols, imports, and call sites
                analysis = ts_parse(content, language)
                file_analyses[rel_path] = analysis

                # Resolve imports
                resolutions = resolver.resolve_all(analysis.imports, rel_path, language)
                import_resolutions[rel_path] = resolutions

            ctx.import_graph = import_resolutions

            # Build the call graph
            builder = CallGraphBuilder(file_analyses, import_resolutions)
            ctx.call_graph = builder.build()
            ctx.file_analyses = file_analyses

            edge_count = len(ctx.call_graph.edges)
            file_count = len(file_analyses)
            await self.emit(
                ctx,
                f"Call graph: {edge_count} edges across {file_count} files",
            )

            # Boost files with high in-degree (many callers = shared critical code)
            high_indegree = ctx.call_graph.get_high_indegree_files(limit=10)
            for file_path, caller_count in high_indegree:
                if caller_count >= 3:
                    ctx.boost_file(file_path, caller_count * 2.0, f"call graph: {caller_count} callers")

        except Exception as e:
            logger.warning("Call graph construction failed: %s", e)
            await self.emit(ctx, f"Call graph construction failed: {e}", level="warn")
            # Non-fatal — scan continues without call graph

    async def _detect_obfuscation(
        self, ctx: ScanContext, repo: Path, file_map: dict
    ) -> dict[str, ObfuscationResult]:
        """Detect obfuscation/minification across indexed files."""
        results: dict[str, ObfuscationResult] = {}

        # Only check JS/TS/CSS files and files that scored high enough to matter
        check_extensions = {".js", ".jsx", ".ts", ".tsx", ".css", ".mjs", ".cjs"}

        for rel_path, info in file_map.items():
            ext = "." + rel_path.rsplit(".", 1)[-1] if "." in rel_path else ""
            if ext not in check_extensions:
                continue

            full_path = repo / rel_path
            content = safe_read_file(full_path, max_size=settings.max_file_size_bytes)
            if not content:
                continue

            result = detect_obfuscation(content, rel_path, info.get("language"))
            results[rel_path] = result

            if result.score >= 0.7:
                ctx.non_analysable_files.add(rel_path)
                ctx.obfuscated_files.add(rel_path)
                ctx.boost_file(rel_path, -50.0, "obfuscation penalty")
            elif result.score >= 0.4:
                ctx.obfuscated_files.add(rel_path)
                ctx.boost_file(rel_path, -20.0, "obfuscation penalty")

            # Mark generated files
            if result.label in ("minified", "vendor_bundle", "source_map"):
                info["is_generated"] = True

        return results

    async def _index_files(self, ctx: ScanContext, repo: Path) -> dict[str, dict]:
        """Walk the repo, create File records, return path->metadata mapping."""
        file_map = {}
        total_seen = 0
        policy = load_repo_path_policy(repo)

        async with async_session() as session:
            for path in repo.rglob("*"):
                if not path.is_file():
                    continue
                if should_skip_repo_path(path, repo, policy=policy):
                    continue
                if is_binary_extension(str(path)):
                    continue
                try:
                    fsize = path.stat().st_size
                    if fsize > settings.max_file_size_bytes:
                        ctx.files_skipped_size += 1
                        continue
                except OSError:
                    continue

                total_seen += 1

                rel_path = normalise_path(str(path.relative_to(repo)))
                ext = path.suffix.lower()
                language = LANG_MAP.get(ext)

                try:
                    line_count = len(path.read_bytes().splitlines())
                except Exception:
                    line_count = 0

                is_test = any(t in rel_path.lower() for t in (
                    "test", "spec", "__test__", "fixture", "mock",
                ))

                file_rec = File(
                    id=uuid.uuid4(),
                    scan_id=ctx.scan_id,
                    path=rel_path,
                    language=language,
                    size_bytes=path.stat().st_size,
                    line_count=line_count,
                    is_test=is_test,
                    is_config=ext in (".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".cfg"),
                )
                session.add(file_rec)

                file_map[rel_path] = {
                    "id": file_rec.id,
                    "language": language,
                    "line_count": line_count,
                    "is_test": is_test,
                    "score": 0.0,
                    "scanner_hits": 0,
                }

                if len(file_map) >= settings.max_files_per_scan:
                    # Estimate remaining files without full rglob (too slow on huge repos)
                    ctx.files_skipped_cap = max(0, ctx.fingerprint.get("file_count", 0) - total_seen)
                    break

            await session.commit()

        return file_map

    @staticmethod
    def scanner_summary(result) -> dict:
        """Return a serialisable scanner run summary for UI and reporting."""
        errors = [e.strip() for e in getattr(result, "errors", []) if isinstance(e, str) and e.strip()]
        if not getattr(result, "success", False):
            status = "failed"
        elif errors:
            status = "degraded"
        else:
            status = "completed"
        return {
            "status": status,
            "success": getattr(result, "success", False),
            "hit_count": len(getattr(result, "hits", [])),
            "duration_ms": getattr(result, "duration_ms", 0),
            "errors": errors,
        }

    async def _persist_scanner_results(
        self, ctx: ScanContext, scanner_name: str, hits: list, file_map: dict
    ):
        """Save scanner hits to the database."""
        async with async_session() as session:
            dependency_cache: dict[tuple[str, str, str, str, bool], object] = {}
            dependency_finding_keys: set[tuple[tuple[str, str, str, str, bool], str, str, str]] = set()

            if scanner_name == "dep_audit":
                from app.models.dependency import Dependency, DependencyFinding

                dep_rows = await session.execute(
                    select(Dependency).where(Dependency.scan_id == ctx.scan_id)
                )
                for dep in dep_rows.scalars().all():
                    dependency_cache[
                        dependency_identity_key(
                            ecosystem=dep.ecosystem,
                            name=dep.name,
                            version=dep.version,
                            source_file=dep.source_file,
                            is_dev=dep.is_dev,
                        )
                    ] = dep

                finding_rows = await session.execute(
                    select(
                        Dependency.ecosystem,
                        Dependency.name,
                        Dependency.version,
                        Dependency.source_file,
                        Dependency.is_dev,
                        DependencyFinding.advisory_id,
                        DependencyFinding.cve_id,
                        DependencyFinding.summary,
                    )
                    .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                    .where(DependencyFinding.scan_id == ctx.scan_id)
                )
                for row in finding_rows.all():
                    dep_key = dependency_identity_key(
                        ecosystem=row.ecosystem,
                        name=row.name,
                        version=row.version,
                        source_file=row.source_file,
                        is_dev=row.is_dev,
                    )
                    dependency_finding_keys.add(
                        (
                            dep_key,
                            row.advisory_id or "",
                            row.cve_id or "",
                            row.summary or "",
                        )
                    )

            for hit in hits:
                # Resolve file_id from file_map
                norm_path = self._normalise_hit_path(repo=Path(ctx.repo_path), raw_path=hit.file_path, file_map=file_map)
                file_info = file_map.get(norm_path, {})
                file_id = file_info.get("id")

                # Track hits per file for scoring
                if norm_path in file_map:
                    file_map[norm_path]["scanner_hits"] = file_map[norm_path].get("scanner_hits", 0) + 1

                if scanner_name == "codeql":
                    self._ingest_codeql_flow(ctx, hit, norm_path or hit.file_path)

                if scanner_name == "secrets":
                    # Store as secret candidates
                    sc = SecretCandidate(
                        scan_id=ctx.scan_id,
                        file_id=file_id,
                        type=hit.metadata.get("type", "unknown"),
                        value_preview=hit.metadata.get("value_preview", ""),
                        line_number=hit.start_line,
                        confidence=hit.metadata.get("confidence", 0.5),
                        context=hit.snippet,
                    )
                    session.add(sc)
                elif scanner_name == "dep_audit":
                    # Persist as Dependency + DependencyFinding (not generic ScannerResult)
                    from app.models.dependency import Dependency, DependencyFinding

                    meta = hit.metadata or {}
                    dep_key = dependency_identity_key(
                        ecosystem=meta.get("ecosystem", "unknown"),
                        name=meta.get("package", ""),
                        version=meta.get("installed_version", ""),
                        source_file=norm_path or hit.file_path,
                        is_dev=meta.get("is_dev", False),
                    )
                    dep = dependency_cache.get(dep_key)
                    if dep is None:
                        dep = Dependency(
                            scan_id=ctx.scan_id,
                            ecosystem=meta.get("ecosystem", "unknown"),
                            name=meta.get("package", ""),
                            version=meta.get("installed_version", ""),
                            source_file=norm_path or hit.file_path,
                            is_dev=meta.get("is_dev", False),
                        )
                        session.add(dep)
                        await session.flush()  # Get dep.id for finding rows
                        dependency_cache[dep_key] = dep

                    finding_key = (
                        dep_key,
                        meta.get("advisory_id") or "",
                        meta.get("cve_id") or "",
                        hit.message or "",
                    )
                    if finding_key not in dependency_finding_keys:
                        df = DependencyFinding(
                            dependency_id=dep.id,
                            scan_id=ctx.scan_id,
                            advisory_id=meta.get("advisory_id"),
                            cve_id=meta.get("cve_id"),
                            severity=hit.severity,
                            cvss_score=meta.get("cvss"),
                            summary=hit.message,
                            details=meta.get("details"),
                            affected_range=meta.get("affected_range", ""),
                            fixed_version=meta.get("fixed_version"),
                            cwes=meta.get("cwes"),
                            references=meta.get("references"),
                            vulnerable_functions=meta.get("vulnerable_functions"),
                            evidence_type=meta.get("match_type", "exact_package_match"),
                        )
                        session.add(df)
                        dependency_finding_keys.add(finding_key)

                    # Also save as ScannerResult so it shows up in scanner hit queries
                    sr = ScannerResult(
                        scan_id=ctx.scan_id,
                        file_id=file_id,
                        scanner=scanner_name,
                        rule_id=hit.rule_id,
                        severity=hit.severity,
                        message=hit.message,
                        start_line=0,
                        extra_data=meta,
                    )
                    session.add(sr)
                else:
                    sr = ScannerResult(
                        scan_id=ctx.scan_id,
                        file_id=file_id,
                        scanner=scanner_name,
                        rule_id=hit.rule_id,
                        severity=hit.severity,
                        message=hit.message,
                        start_line=hit.start_line,
                        end_line=hit.end_line,
                        snippet=hit.snippet,
                        extra_data=hit.metadata,
                    )
                    session.add(sr)

            await session.commit()

    async def _score_files(self, ctx: ScanContext, file_map: dict):
        """Apply deterministic scoring to all files."""
        async with async_session() as session:
            for path, info in file_map.items():
                total, reasons = score_file(
                    path,
                    language=info.get("language"),
                    line_count=info.get("line_count", 0),
                    scanner_hit_count=info.get("scanner_hits", 0),
                )
                info["score"] = total
                file_score = ctx.file_scores.get(path)
                if file_score:
                    file_score.static_score = total
                    file_score.scanner_hits = info.get("scanner_hits", 0)
                else:
                    ctx.file_scores[path] = FileScore(
                        path=path,
                        static_score=total,
                        scanner_hits=info.get("scanner_hits", 0),
                    )

                file_rec = await session.get(File, info["id"])
                if file_rec:
                    file_rec.priority_score = total
                    file_rec.score_reasons = reasons

            await session.commit()

    @staticmethod
    def _normalise_hit_path(repo: Path, raw_path: str, file_map: dict) -> str:
        """Convert scanner output paths to the repo-relative normalised path used internally."""
        if not raw_path:
            return ""

        path = raw_path.replace("file:///", "").replace("file://", "")
        norm_path = normalise_path(path)
        if norm_path in file_map:
            return norm_path

        try:
            candidate = Path(path)
            if candidate.is_absolute():
                rel_path = normalise_path(relative_to_repo(candidate, repo))
                if rel_path in file_map:
                    return rel_path
        except Exception:
            pass

        basename = Path(path).name
        matches = [fp for fp in file_map if fp.endswith(f"/{basename}") or fp == basename]
        if len(matches) == 1:
            return matches[0]

        return norm_path

    @staticmethod
    def _ingest_codeql_flow(ctx: ScanContext, hit, default_file: str):
        """Promote CodeQL data-flow hits into structured taint flows for downstream agents."""
        metadata = hit.metadata or {}
        steps = metadata.get("data_flow_steps") or []
        if not steps:
            return

        source = steps[0]
        sink = steps[-1]
        flow = TaintFlow(
            source_file=normalise_path(source.get("file") or default_file),
            source_line=source.get("line", 0) or 0,
            source_type="codeql_source",
            sink_file=normalise_path(sink.get("file") or default_file),
            sink_line=sink.get("line", 0) or hit.start_line or 0,
            sink_type="codeql_sink",
            intermediaries=[
                f"{step.get('file', default_file)}:{step.get('line', 0)}"
                for step in steps[1:-1]
            ],
            confidence=0.95,
            call_chain=steps,
            graph_verified=True,
        )

        for existing in ctx.taint_flows:
            if (
                existing.source_file == flow.source_file
                and existing.source_line == flow.source_line
                and existing.sink_file == flow.sink_file
                and existing.sink_line == flow.sink_line
            ):
                return

        ctx.taint_flows.append(flow)
        ctx.boost_file(flow.source_file, 6.0, f"codeql flow: {hit.rule_id}")
        ctx.boost_file(flow.sink_file, 10.0, f"codeql flow sink: {hit.rule_id}")


    async def _parse_android_manifest(self, repo: Path) -> dict | None:
        """Parse AndroidManifest.xml for security-relevant metadata."""
        import xml.etree.ElementTree as ET

        # Find manifest — jadx puts it in resources/
        candidates = [
            repo / "resources" / "AndroidManifest.xml",
            repo / "AndroidManifest.xml",
            repo.parent / "resources" / "AndroidManifest.xml",
        ]
        manifest_path = None
        for c in candidates:
            if c.exists():
                manifest_path = c
                break

        if not manifest_path:
            return None

        try:
            tree = ET.parse(str(manifest_path))
            root = tree.getroot()

            # Android namespace
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            package = root.get("package", "")

            # Extract permissions
            permissions = []
            for perm in root.findall(".//uses-permission"):
                name = perm.get(f"{{{ns['android']}}}name", perm.get("name", ""))
                if name:
                    permissions.append(name)

            # Extract exported components (security-critical)
            exported = []
            for tag in ("activity", "service", "receiver", "provider"):
                for comp in root.findall(f".//{tag}"):
                    name = comp.get(f"{{{ns['android']}}}name", comp.get("name", ""))
                    exp = comp.get(f"{{{ns['android']}}}exported", comp.get("exported", ""))
                    has_filter = len(comp.findall("intent-filter")) > 0
                    # Components with intent-filters are implicitly exported
                    if exp == "true" or (has_filter and exp != "false"):
                        exported.append({"type": tag, "name": name, "has_intent_filter": has_filter})

            # Security flags
            app_elem = root.find("application")
            flags = {}
            if app_elem is not None:
                flags["debuggable"] = app_elem.get(f"{{{ns['android']}}}debuggable", "false") == "true"
                flags["allowBackup"] = app_elem.get(f"{{{ns['android']}}}allowBackup", "true") == "true"
                flags["usesCleartextTraffic"] = app_elem.get(
                    f"{{{ns['android']}}}usesCleartextTraffic", "false"
                ) == "true"
                flags["networkSecurityConfig"] = app_elem.get(
                    f"{{{ns['android']}}}networkSecurityConfig", ""
                )

            return {
                "package": package,
                "permissions": permissions,
                "exported_components": exported,
                "security_flags": flags,
                "dangerous_permissions": [
                    p for p in permissions
                    if any(d in p for d in (
                        "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS",
                        "SEND_SMS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
                        "RECORD_AUDIO", "READ_PHONE_STATE", "READ_EXTERNAL_STORAGE",
                        "WRITE_EXTERNAL_STORAGE", "READ_CALL_LOG", "WRITE_CALL_LOG",
                    ))
                ],
            }
        except Exception as e:
            logger.warning("Failed to parse AndroidManifest.xml: %s", e)
            return None


    # ── Documentation Discovery ────────────────────────────────────

    # Patterns that indicate documentation files worth reading
    _DOC_PATTERNS = [
        "README.md", "README.rst", "README.txt", "README",
        "SECURITY.md", "SECURITY.txt",
        "ARCHITECTURE.md", "DESIGN.md",
        "INSTALL.md", "INSTALLATION.md", "SETUP.md",
        "CONTRIBUTING.md",  # Often has architecture context
        "API.md", "api.md",
        "CHANGELOG.md", "CHANGES.md",
        "docs/README.md", "doc/README.md",
        "docs/architecture.md", "docs/security.md",
        "docs/deployment.md", "docs/setup.md",
        "docs/api.md", "docs/getting-started.md",
        ".env.example", ".env.sample",  # Shows expected env vars
    ]

    # Files to explicitly skip (generated, not useful)
    _DOC_SKIP = {
        "LICENSE", "LICENSE.md", "LICENSE.txt",
        "CODE_OF_CONDUCT.md", "CODEOWNERS",
        "PULL_REQUEST_TEMPLATE.md", "ISSUE_TEMPLATE.md",
    }

    def _discover_doc_files(self, repo: Path) -> list[str]:
        """Fast filesystem scan for documentation files. No LLM needed."""
        found = []
        policy = load_repo_path_policy(repo)

        # Check explicit patterns first
        for pattern in self._DOC_PATTERNS:
            candidate = repo / pattern
            if candidate.exists() and candidate.is_file() and not should_skip_repo_path(candidate, repo, policy=policy):
                rel = str(candidate.relative_to(repo)).replace("\\", "/")
                found.append(rel)

        # Also look for case-insensitive README variants at root and one level deep
        for item in repo.iterdir():
            if should_skip_repo_path(item, repo, policy=policy):
                continue
            if item.is_file() and item.name.lower().startswith("readme"):
                rel = str(item.relative_to(repo)).replace("\\", "/")
                if rel not in found and item.name not in self._DOC_SKIP:
                    found.append(rel)

        # Check docs/ and doc/ directories for .md files (limit to 10)
        for docs_dir in ["docs", "doc", "documentation"]:
            docs_path = repo / docs_dir
            if docs_path.is_dir():
                md_files = sorted(docs_path.glob("*.md"))[:10]
                for md_file in md_files:
                    if should_skip_repo_path(md_file, repo, policy=policy):
                        continue
                    rel = str(md_file.relative_to(repo)).replace("\\", "/")
                    if rel not in found and md_file.name not in self._DOC_SKIP:
                        found.append(rel)

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for f in found:
            if f not in seen:
                seen.add(f)
                deduped.append(f)

        return deduped[:15]  # Cap at 15 doc files max

    async def _summarise_documentation(self, ctx: ScanContext, repo: Path) -> None:
        """Read discovered documentation files and produce a compact AI summary.

        This summary is ~500-1000 tokens and gets injected into downstream agent
        prompts (architecture, investigator) to give the AI contextual awareness
        of what the developers have documented about the application.
        """
        if not ctx.doc_files_found or not self.llm:
            return

        # Read doc files, respecting a total size limit
        MAX_DOC_CHARS = 30_000  # ~7500 tokens — enough for AI to summarise
        doc_contents: list[tuple[str, str]] = []
        total_chars = 0

        # Prioritise: README first, then SECURITY, then others
        priority_order = []
        for f in ctx.doc_files_found:
            lower = f.lower()
            if "readme" in lower:
                priority_order.insert(0, f)
            elif "security" in lower or "architecture" in lower:
                priority_order.insert(min(1, len(priority_order)), f)
            else:
                priority_order.append(f)

        for doc_path in priority_order:
            if total_chars >= MAX_DOC_CHARS:
                break
            full_path = repo / doc_path
            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
                # Truncate individual files if too long
                remaining = MAX_DOC_CHARS - total_chars
                if len(content) > remaining:
                    content = content[:remaining] + "\n\n[... truncated ...]"
                doc_contents.append((doc_path, content))
                total_chars += len(content)
            except Exception:
                continue

        if not doc_contents:
            return

        # Build the summarisation prompt
        doc_text = ""
        for path, content in doc_contents:
            doc_text += f"\n\n=== {path} ===\n{content}"

        system_prompt = (
            "You are a security researcher performing initial reconnaissance on a codebase. "
            "You have been given the project's documentation files (READMEs, setup guides, API docs, etc.). "
            "Extract ONLY security-relevant intelligence from these documents.\n\n"
            "Respond with JSON:\n"
            "{\n"
            '  "app_description": "1-2 sentence summary of what this app does (from the docs)",\n'
            '  "environment_variables": ["list of env var names mentioned (e.g., SECRET_KEY, DATABASE_URL)"],\n'
            '  "api_endpoints": ["list of API routes/endpoints described in docs"],\n'
            '  "auth_description": "how authentication/authorisation works according to docs, or empty string",\n'
            '  "deployment_info": "how the app is deployed (Docker, K8s, serverless, etc.), or empty string",\n'
            '  "external_services": ["databases, APIs, queues, cloud services mentioned"],\n'
            '  "security_notes": ["any security warnings, known issues, or security considerations mentioned by developers"],\n'
            '  "default_credentials": ["any default usernames, passwords, API keys, or tokens shown as examples"],\n'
            '  "interesting_config_files": ["config files referenced that we should inspect (e.g., nginx.conf, docker-compose.yml)"],\n'
            '  "investigation_hints": ["specific things worth investigating based on what the docs reveal — be concrete"]\n'
            "}"
        )

        try:
            result = await self.llm.chat_json(system_prompt, doc_text, max_tokens=1500)
            ctx.ai_calls_made += 1

            # Build compact summary string for injection into other prompts
            parts = []

            desc = result.get("app_description", "")
            if desc:
                parts.append(f"App (from docs): {desc}")

            env_vars = result.get("environment_variables", [])
            if env_vars:
                parts.append(f"Environment variables: {', '.join(env_vars[:20])}")

            endpoints = result.get("api_endpoints", [])
            if endpoints:
                parts.append(f"Documented API endpoints: {', '.join(endpoints[:15])}")

            auth = result.get("auth_description", "")
            if auth:
                parts.append(f"Auth (from docs): {auth}")

            deploy = result.get("deployment_info", "")
            if deploy:
                parts.append(f"Deployment: {deploy}")

            services = result.get("external_services", [])
            if services:
                parts.append(f"External services: {', '.join(services[:10])}")

            sec_notes = result.get("security_notes", [])
            if sec_notes:
                parts.append("Security notes from developers:")
                for note in sec_notes[:5]:
                    parts.append(f"  - {note}")

            creds = result.get("default_credentials", [])
            if creds:
                parts.append(f"Default credentials/tokens in docs: {', '.join(creds[:5])}")
                # Boost investigation of files related to auth/credentials
                ctx.key_observations.append(
                    f"Documentation contains default credentials/tokens: {', '.join(creds[:3])}. "
                    "Investigate whether these are used in production code."
                )

            config_files = result.get("interesting_config_files", [])
            if config_files:
                parts.append(f"Config files to inspect: {', '.join(config_files[:10])}")
                # Boost these files in the priority queue if they exist
                for cf in config_files:
                    ctx.boost_file(cf, 6.0, "doc_intelligence: referenced config file")

            hints = result.get("investigation_hints", [])
            if hints:
                parts.append("Investigation hints from documentation:")
                for hint in hints[:5]:
                    parts.append(f"  - {hint}")
                # Add hints to key observations so the planner sees them
                for hint in hints[:3]:
                    ctx.key_observations.append(f"[From docs] {hint}")

            ctx.doc_intelligence = "\n".join(parts)

            # Boost env file patterns based on discovered env vars
            if env_vars:
                for env_pattern in [".env", ".env.local", ".env.production", "config.py", "settings.py"]:
                    ctx.boost_file(env_pattern, 4.0, "doc_intelligence: env vars mentioned in docs")

        except Exception as e:
            logger.warning("Documentation summarisation failed: %s", e)
            # Non-fatal — scan continues without doc intelligence


def _get(d, key, default=None):
    return d.get(key, default)
