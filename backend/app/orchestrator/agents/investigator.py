"""Code Investigation Agent — multi-pass adaptive vulnerability investigation.

Key improvements over naive single-pass:
- Re-prioritises the file queue after each pass based on findings
- Tracks taint flows (input source → sink) across files
- Boosts files dynamically when referenced by findings or taint flows
- Mixes priority queue files with "hot" files (dynamically boosted)
- Provides scanner hits as context to the AI for each file
- Fuzzy-matches related file suggestions from the AI
- Deeper context windows (800 lines instead of 500)
"""

import logging
from pathlib import Path

from app.analysis.investigation_scope import should_investigate_file_path
from app.analysis.dependency_context import dep_cache_entries, vulnerable_dependency_context_for_file
from app.scanners.registry import get_available_scanners

from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.flow_verifier import format_call_chain, verify_taint_flow_graph
from app.orchestrator.scan_context import CandidateFinding, ScanContext, TaintFlow

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior application security researcher performing a code review.
You are inspecting source code files for security vulnerabilities.

Your task:
1. Read the provided code carefully
2. Identify potential security vulnerabilities
3. Trace data flows from input sources to dangerous sinks
4. Consider the application context and architecture
5. Collect supporting AND opposing evidence
6. Decide what related files you need to inspect next

Non-executable files can still be security-critical. Treat configuration, manifests,
lockfiles, templates, HTML/XML/YAML/JSON/TOML, container files, and IaC as part of
the attack surface when they influence secrets, trust boundaries, dependency risk,
runtime behavior, templating, or policy enforcement.

For each potential finding, assess:
- Is the input actually user-controlled? Trace the data source.
- Is there validation or sanitisation between source and sink?
- Is there framework-level protection?
- Is this code reachable in production?
- Is this test-only or dead code?

For data flow tracing, identify:
- INPUT SOURCES: request parameters, form data, file uploads, environment variables, database reads, API responses
- SINKS: SQL queries, OS commands, template rendering, file I/O, HTTP requests, serialisation, logging

When taint flow or interprocedural reachability is ambiguous, use targeted CodeQL scans for semantic confirmation.

Respond with JSON:
{
  "findings": [
    {
      "title": "...",
      "category": "sqli|xss|auth_bypass|idor|ssrf|rce|path_traversal|crypto|info_disclosure|deserialization|csrf|open_redirect|xxe|prototype_pollution|log_injection|other",
      "severity": "critical|high|medium|low|info",
      "file_path": "...",
      "line_range": "10-25",
      "code_snippet": "the vulnerable code lines",
      "hypothesis": "why this is likely a real vulnerability",
      "input_sources": ["where user data enters — e.g. request.args.get('id')"],
      "sinks": ["where tainted data is consumed — e.g. cursor.execute(sql)"],
      "supporting_evidence": ["evidence supporting the finding"],
      "opposing_evidence": ["evidence that argues against it"],
      "confidence": 0.0-1.0,
      "cwe_ids": ["CWE-89", "CWE-564"]
    }
  ],
  "taint_flows": [
    {
      "source_file": "path",
      "source_line": 10,
      "source_type": "request_param",
      "sink_file": "path",
      "sink_line": 45,
      "sink_type": "sql_exec",
      "intermediaries": ["function_name in file"],
      "sanitised": false
    }
  ],
  "related_files_needed": ["paths to files that would help verify findings"],
  "files_to_boost": ["paths that appear security-critical based on what was seen"],
  "observations": ["general security observations about this code"],
  "recommended_scanner_rules": ["specific semgrep or bandit rules to run"]
}"""


class InvestigatorAgent(BaseAgent):
    _MAX_TOOL_ROUNDS = 4
    _SCANNER_CONTEXT_LIMIT = 40
    _INLINE_SCANNER_HITS = 15

    @property
    def name(self) -> str:
        return "investigator"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_phase = "investigation"
        budget = ctx.iteration_budget
        max_hops = budget["related_file_hops"]
        max_ai_calls = budget.get("max_ai_calls", 100)

        # Import planner for agentic loop
        from app.orchestrator.agents.planner import PlannerAgent
        planner = PlannerAgent(self.llm)

        # Pre-load dependency CVE cache so _get_dep_context_for_file is fast
        await self._load_dep_cache(ctx)

        # The agentic loop: the planner decides what to do next.
        # It runs until the planner says STOP, the AI budget is exhausted,
        # or we hit a hard iteration ceiling (safety valve).
        max_iterations = budget["phase3_passes"] * budget["phase3_files_per_pass"]
        iteration = 0
        consecutive_empty = 0  # Track stalls for convergence detection

        while iteration < max_iterations:
            if ctx.cancelled:
                return
            if ctx.ai_calls_made >= max_ai_calls:
                await self.emit(ctx, f"AI call budget reached ({max_ai_calls})")
                break

            iteration += 1
            ctx.current_pass = iteration

            # ── Ask the planner what to do ────────────────────────
            # In light mode or early passes, skip the planner to save AI calls
            if ctx.mode == "light" or iteration <= 2:
                action = self._default_action(ctx, budget)
            else:
                ctx.current_task = "Planning next investigation step"
                action = await planner.plan_next_action(ctx)
                await self.emit(
                    ctx,
                    f"Planner: {action.get('action', '?')} — {action.get('reasoning', '')[:100]}",
                )

            act = action.get("action", "STOP")

            # ── STOP: investigation has converged ─────────────────
            if act == "STOP":
                await self.emit(ctx, f"Investigation converged after {iteration} iterations")
                break

            # ── INVESTIGATE_FILES ─────────────────────────────────
            elif act == "INVESTIGATE_FILES":
                files = action.get("params", {}).get("files", [])
                if not files:
                    files = self._pick_default_files(ctx, budget["phase3_files_per_pass"])
                if not files:
                    consecutive_empty += 1
                    if consecutive_empty >= 2:
                        await self.emit(ctx, "No more files to investigate — converging")
                        break
                    continue

                consecutive_empty = 0
                ctx.current_task = f"Investigating {len(files)} files (iteration {iteration})"
                await self.emit(ctx, f"Investigating {len(files)} files")

                for fp in files:
                    if ctx.cancelled or ctx.ai_calls_made >= max_ai_calls:
                        break
                    await self._investigate_file(ctx, fp, hops_remaining=max_hops)
                    ctx.files_processed += 1

            # ── TRACE_FLOW: follow a data flow across files ───────
            elif act == "TRACE_FLOW":
                params = action.get("params", {})
                source_file = params.get("source_file", "")
                sink_file = params.get("sink_file", "")
                question = params.get("question", "Is this data flow exploitable?")

                if source_file and sink_file:
                    ctx.current_task = f"Tracing flow: {source_file} → {sink_file}"
                    await self.emit(ctx, f"Tracing data flow: {source_file} → {sink_file}")
                    await self._trace_flow(ctx, source_file, sink_file, question)
                    consecutive_empty = 0
                else:
                    await self.emit(ctx, "Planner requested TRACE_FLOW but params were incomplete", level="warn")

            # ── DEEP_DIVE: re-read a file with specific questions ─
            elif act == "DEEP_DIVE":
                params = action.get("params", {})
                file_path = params.get("file_path", "")
                questions = params.get("questions", [])

                if file_path:
                    ctx.current_task = f"Deep dive: {file_path}"
                    await self.emit(ctx, f"Deep dive on {file_path}: {', '.join(questions[:2])}")
                    await self._deep_dive(ctx, file_path, questions)
                    consecutive_empty = 0
                else:
                    await self.emit(ctx, "Planner requested DEEP_DIVE but no file specified", level="warn")

            # ── CROSS_REFERENCE: compare two files ────────────────
            elif act == "CROSS_REFERENCE":
                params = action.get("params", {})
                file_a = params.get("file_a", "")
                file_b = params.get("file_b", "")
                question = params.get("question", "How do these files interact?")

                if file_a and file_b:
                    ctx.current_task = f"Cross-referencing: {file_a} ↔ {file_b}"
                    await self.emit(ctx, f"Cross-referencing {file_a} and {file_b}")
                    await self._cross_reference(ctx, file_a, file_b, question)
                    consecutive_empty = 0
                else:
                    await self.emit(ctx, "Planner requested CROSS_REFERENCE but files incomplete", level="warn")

            # ── VERIFY_EARLY: urgent verification of a specific finding
            elif act == "VERIFY_EARLY":
                params = action.get("params", {})
                finding_title = params.get("finding_title", "")
                verify_questions = params.get("questions", [])
                matching = [f for f in ctx.candidate_findings if f.title == finding_title]
                if matching:
                    f = matching[0]
                    ctx.current_task = f"Early verification: {f.title}"
                    await self.emit(ctx, f"Early verification of critical finding: {f.title}")
                    await self._deep_dive(ctx, f.file_path, verify_questions or [
                        f"Is this vulnerability real: {f.hypothesis}?",
                        "What input reaches this code?",
                        "What sanitisation exists?",
                    ])
                    consecutive_empty = 0

            # ── TARGETED_SCAN: run scanner on specific files ──────
            elif act == "TARGETED_SCAN":
                # Delegate to the rule_selector's logic via direct scanner call
                params = action.get("params", {})
                scan_files = params.get("files", [])
                scan_rules = params.get("rule_ids", [])
                if scan_files:
                    scan_files = self.get_tools(ctx).normalise_repo_files(scan_files)
                if scan_files:
                    scanners = ctx.scanners if ctx.scanners else await get_available_scanners()
                    if "semgrep" in scanners:
                        ctx.current_task = f"Targeted scan: {len(scan_files)} files"
                        await self.emit(ctx, f"Running targeted scan on {len(scan_files)} files")
                        output = await scanners["semgrep"].run_targeted(
                            Path(ctx.repo_path), files=scan_files, rules=scan_rules or [],
                        )
                        if output.hits:
                            ctx.scanner_hit_counts["semgrep_targeted"] = (
                                ctx.scanner_hit_counts.get("semgrep_targeted", 0) + len(output.hits)
                            )
                            await self._persist_targeted_scan_hits(
                                ctx,
                                "semgrep",
                                output.hits,
                                source="planner_targeted",
                            )
                            for hit in output.hits:
                                ctx.boost_file(hit.file_path, 8.0, f"planner-targeted hit: {hit.rule_id}")
                            await self.emit(ctx, f"Targeted scan found {len(output.hits)} hits")
                        elif output.errors:
                            await self.emit(
                                ctx,
                                f"Targeted scan completed with errors: {'; '.join(output.errors[:2])}",
                                level="warn",
                            )
                        consecutive_empty = 0
                else:
                    await self.emit(ctx, "Planner requested TARGETED_SCAN with no valid repo files", level="warn")

            else:
                # Unknown action — fall back to default
                files = self._pick_default_files(ctx, budget["phase3_files_per_pass"])
                if not files:
                    break
                for fp in files:
                    if ctx.cancelled or ctx.ai_calls_made >= max_ai_calls:
                        break
                    await self._investigate_file(ctx, fp, hops_remaining=max_hops)
                    ctx.files_processed += 1

            # ── Post-action: boost files referenced by new findings
            self._boost_from_findings(ctx)

            # Re-prioritise queue after every action
            ctx.reprioritise_queue()

            # ── Emit real-time progress to frontend ───────────────
            strong = len([f for f in ctx.candidate_findings if f.confidence >= 0.6])
            weak = len([f for f in ctx.candidate_findings if f.confidence < 0.6])
            status_msg = (
                f"Iteration {iteration}: {strong} strong + {weak} weak candidates, "
                f"{len(ctx.taint_flows)} taint flows, "
                f"{len(ctx.files_inspected)}/{ctx.files_total} files inspected"
            )
            # Log event (goes to terminal log)
            await self.emit(ctx, status_msg)
            # Progress update (goes to stats bar + progress bar + DB)
            await self.emit_progress(
                ctx,
                task=f"Iteration {iteration} [{act}] — {strong} strong, {weak} weak findings",
            )

        await self.log_decision(
            ctx,
            action="investigation_complete",
            output_summary=(
                f"{len(ctx.candidate_findings)} candidate findings, "
                f"{len(ctx.taint_flows)} taint flows after "
                f"{ctx.current_pass} passes, {len(ctx.files_inspected)} files inspected"
            ),
        )

    async def _investigate_file(
        self, ctx: ScanContext, file_path: str, *, hops_remaining: int = 0
    ):
        # Skip only obviously irrelevant assets/docs; keep security-relevant config
        # and template files in scope for deep review.
        if not should_investigate_file_path(file_path):
            ctx.files_inspected.add(file_path)
            return

        # Skip files that are too obfuscated to analyse
        if file_path in ctx.non_analysable_files:
            await self.emit(ctx, f"Skipping {file_path} (heavily obfuscated/minified)", level="debug")
            ctx.files_inspected.add(file_path)
            return
        ctx.current_task = f"Investigating {file_path}"
        await self.emit(ctx, f"Inspecting: {file_path}")

        content = await self.read_file(ctx, file_path, max_lines=800)
        ctx.files_inspected.add(file_path)

        # Multi-file context: include directly connected files (callers/callees)
        # so the AI can trace flows without separate TRACE_FLOW calls
        related_snippets = await self._get_related_file_snippets(ctx, file_path)

        scanner_context = await self._get_scanner_hits(ctx, file_path)
        dep_context = self._get_dep_context_for_file(ctx, file_path)

        # Check for calls to known vulnerable functions (CVE-linked)
        vuln_func_context = []
        try:
            from app.analysis.cve_correlator import find_vulnerable_function_calls
            vuln_funcs = find_vulnerable_function_calls(
                file_path,
                content,
                languages=list(ctx.languages) if ctx.languages else None,
                import_resolutions=ctx.import_graph.get(file_path, []),
                vulnerable_dependencies=dep_context,
            )
            vuln_func_context = vuln_funcs
        except Exception:
            pass

        user_content = self._build_investigation_prompt(
            ctx, file_path, content, scanner_context,
            related_files=related_snippets,
            vuln_functions=vuln_func_context,
            dep_context=dep_context,
        )

        try:
            result = await self.ask_json(
                ctx,
                SYSTEM_PROMPT,
                user_content,
                max_tokens=4096,
                allow_tools=True,
                tool_names=[
                    "read_file",
                    "read_file_range",
                    "search_code",
                    "list_directory",
                    "check_file_exists",
                    "get_file_symbols",
                    "get_file_imports",
                    "get_scanner_hits",
                    "query_findings",
                    "query_taint_flows",
                    "get_call_graph_for_file",
                    "trace_call_chain",
                    "get_callers_of",
                    "get_entry_points_reaching",
                    "get_resolved_imports",
                    "find_files_importing",
                    "run_semgrep_on_files",
                    "run_bandit_on_files",
                    "run_codeql_on_files",
                ],
                max_tool_rounds=self._MAX_TOOL_ROUNDS,
            )
        except Exception as e:
            await self.emit(ctx, f"Investigation failed for {file_path}: {e}", level="warn")
            return

        # Process findings
        for fd in result.get("findings", []):
            ctx.candidate_findings.append(CandidateFinding(
                title=fd.get("title", "Untitled"),
                category=fd.get("category", "other"),
                severity=fd.get("severity", "medium"),
                file_path=fd.get("file_path", file_path),
                line_range=fd.get("line_range"),
                code_snippet=fd.get("code_snippet"),
                hypothesis=fd.get("hypothesis", ""),
                supporting_evidence=fd.get("supporting_evidence", []),
                opposing_evidence=fd.get("opposing_evidence", []),
                confidence=fd.get("confidence", 0.5),
                input_sources=fd.get("input_sources", []),
                sinks=fd.get("sinks", []),
                cwe_ids=fd.get("cwe_ids", []),
            ))

        # Process taint flows
        for tf in result.get("taint_flows", []):
            self._record_taint_flow(
                ctx,
                TaintFlow(
                    source_file=tf.get("source_file", file_path),
                    source_line=tf.get("source_line", 0),
                    source_type=tf.get("source_type", "unknown"),
                    sink_file=tf.get("sink_file", file_path),
                    sink_line=tf.get("sink_line", 0),
                    sink_type=tf.get("sink_type", "unknown"),
                    intermediaries=tf.get("intermediaries", []),
                    sanitised=tf.get("sanitised", False),
                ),
            )

        # Boost recommended files
        for bp in result.get("files_to_boost", []):
            ctx.boost_file(bp, 4.0, "AI-identified critical")

        ctx.key_observations.extend(result.get("observations", []))

        # Follow related files
        if hops_remaining > 0:
            for related_path in result.get("related_files_needed", [])[:5]:
                if related_path in ctx.files_inspected:
                    continue
                full = Path(ctx.repo_path) / related_path
                if full.exists() and full.is_file():
                    await self._investigate_file(ctx, related_path, hops_remaining=hops_remaining - 1)
                else:
                    matched = self._fuzzy_find_file(ctx, related_path)
                    if matched and matched not in ctx.files_inspected:
                        await self._investigate_file(ctx, matched, hops_remaining=hops_remaining - 1)

    async def _get_scanner_hits(self, ctx: ScanContext, file_path: str) -> list[dict]:
        """Get scanner results for a specific file from the database."""
        from sqlalchemy import select
        from app.database import async_session
        from app.models.file import File
        from app.models.scanner_result import ScannerResult

        hits = []
        try:
            async with async_session() as session:
                # Find the file record
                file_result = await session.execute(
                    select(File).where(File.scan_id == ctx.scan_id, File.path == file_path)
                )
                file_rec = file_result.scalar_one_or_none()
                if not file_rec:
                    return []

                result = await session.execute(
                    select(ScannerResult)
                    .where(ScannerResult.file_id == file_rec.id)
                    .order_by(ScannerResult.created_at.desc(), ScannerResult.id.desc())
                    .limit(60)
                )
                for sr in result.scalars().all():
                    metadata = sr.extra_data or {}
                    hits.append({
                        "scanner": sr.scanner,
                        "rule_id": sr.rule_id or "",
                        "message": sr.message or "",
                        "line": sr.start_line or 0,
                        "end_line": sr.end_line,
                        "severity": sr.severity or "info",
                        "snippet": self._summarise_scanner_snippet(sr.snippet),
                        "metadata": metadata,
                        "metadata_summary": self._summarise_scanner_metadata(sr.scanner, metadata),
                    })
        except Exception:
            pass
        hits.sort(key=self._scanner_context_sort_key)
        return hits[:self._SCANNER_CONTEXT_LIMIT]

    @staticmethod
    def _scanner_context_sort_key(hit: dict) -> tuple[int, int, int, int]:
        scanner_rank = {
            "codeql": 0,
            "dep_audit": 1,
            "semgrep": 2,
            "bandit": 3,
            "eslint": 4,
            "secrets": 5,
        }
        severity_rank = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        metadata = hit.get("metadata") or {}
        richness = 0 if (metadata.get("data_flow_steps") or metadata.get("vulnerable_functions")) else 1
        return (
            scanner_rank.get(hit.get("scanner", ""), 9),
            severity_rank.get(hit.get("severity", "info"), 4),
            richness,
            int(hit.get("line") or 0),
        )

    @staticmethod
    def _summarise_scanner_snippet(snippet: str | None, max_lines: int = 6, max_chars: int = 320) -> str:
        text = (snippet or "").strip()
        if not text:
            return ""
        lines = text.splitlines()[:max_lines]
        trimmed = "\n".join(lines)
        if len(trimmed) > max_chars:
            trimmed = trimmed[: max_chars - 3].rstrip() + "..."
        return trimmed

    @staticmethod
    def _summarise_scanner_metadata(scanner: str, metadata: dict | None) -> str:
        if not isinstance(metadata, dict) or not metadata:
            return ""

        scanner_name = (scanner or "").lower()
        details: list[str] = []

        if scanner_name == "codeql":
            suites = metadata.get("matched_suites") or metadata.get("query_suites") or []
            if suites:
                details.append(f"Suites: {', '.join(str(s) for s in suites[:3])}")
            cwes = metadata.get("cwes") or []
            if cwes:
                details.append(f"CWEs: {', '.join(str(cwe) for cwe in cwes[:4])}")
            flow_steps = metadata.get("data_flow_steps") or []
            if flow_steps:
                rendered = []
                for step in flow_steps[:5]:
                    if not isinstance(step, dict):
                        continue
                    step_file = str(step.get("file", "?")).replace("\\", "/")
                    rendered.append(f"{step_file}:{int(step.get('line') or 0)}")
                if rendered:
                    suffix = " -> ..." if len(flow_steps) > len(rendered) else ""
                    details.append(f"Flow: {' -> '.join(rendered)}{suffix}")
        elif scanner_name == "dep_audit":
            package = metadata.get("package")
            version = metadata.get("installed_version")
            if package:
                label = f"{package}@{version}" if version else str(package)
                details.append(f"Dependency: {label}")
            advisory_id = metadata.get("cve_id") or metadata.get("advisory_id")
            if advisory_id:
                details.append(f"Advisory: {advisory_id}")
            if metadata.get("affected_range"):
                details.append(f"Affected: {metadata['affected_range']}")
            if metadata.get("fixed_version"):
                details.append(f"Fixed in: {metadata['fixed_version']}")
            if metadata.get("match_type"):
                details.append(f"Evidence: {metadata['match_type']}")
            vulnerable_functions = metadata.get("vulnerable_functions") or []
            if vulnerable_functions:
                details.append(
                    f"Vulnerable functions: {', '.join(str(fn) for fn in vulnerable_functions[:4])}"
                )
        elif scanner_name == "bandit":
            if metadata.get("test_name"):
                details.append(f"Test: {metadata['test_name']}")
            if metadata.get("confidence"):
                details.append(f"Confidence: {metadata['confidence']}")
            cwe = metadata.get("cwe")
            if isinstance(cwe, dict) and cwe.get("id"):
                details.append(f"CWE: CWE-{cwe['id']}")
        else:
            tags = metadata.get("tags") or []
            if tags:
                details.append(f"Tags: {', '.join(str(tag) for tag in tags[:4])}")
            cwes = metadata.get("cwes") or metadata.get("cwe_ids") or []
            if cwes:
                details.append(f"CWEs: {', '.join(str(cwe) for cwe in cwes[:4])}")
            if metadata.get("owasp"):
                details.append(f"OWASP: {metadata['owasp']}")

        return " | ".join(part for part in details if part)

    async def _persist_targeted_scan_hits(
        self,
        ctx: ScanContext,
        scanner_name: str,
        hits: list,
        *,
        source: str,
    ):
        """Persist follow-up scanner hits so later tools and APIs can see them."""
        from sqlalchemy import select

        from app.database import async_session
        from app.models.file import File
        from app.models.scanner_result import ScannerResult
        from app.orchestrator.agents.triage import TriageAgent

        if not hits:
            return

        async with async_session() as session:
            file_rows = await session.execute(
                select(File.id, File.path).where(File.scan_id == ctx.scan_id)
            )
            file_map = {row.path: {"id": row.id} for row in file_rows.all()}

            for hit in hits:
                norm_path = TriageAgent._normalise_hit_path(
                    repo=Path(ctx.repo_path),
                    raw_path=hit.file_path,
                    file_map=file_map,
                )
                file_info = file_map.get(norm_path, {})
                file_id = file_info.get("id")

                existing = await session.execute(
                    select(ScannerResult.id).where(
                        ScannerResult.scan_id == ctx.scan_id,
                        ScannerResult.file_id == file_id,
                        ScannerResult.scanner == scanner_name,
                        ScannerResult.rule_id == hit.rule_id,
                        ScannerResult.start_line == hit.start_line,
                        ScannerResult.message == hit.message,
                    )
                )
                if existing.scalar_one_or_none():
                    continue

                metadata = dict(hit.metadata or {})
                metadata["targeted"] = True
                metadata["source"] = source

                session.add(
                    ScannerResult(
                        scan_id=ctx.scan_id,
                        file_id=file_id,
                        scanner=scanner_name,
                        rule_id=hit.rule_id,
                        severity=hit.severity,
                        message=hit.message,
                        start_line=hit.start_line,
                        end_line=hit.end_line,
                        snippet=hit.snippet,
                        extra_data=metadata,
                    )
                )

            await session.commit()

    def _fuzzy_find_file(self, ctx: ScanContext, target_path: str) -> str | None:
        """Try to find a file by matching the filename part in the file queue."""
        target_name = target_path.rsplit("/", 1)[-1]
        for path in ctx.file_queue:
            if path.endswith(target_name):
                return path
        return None

    # ── Agentic action methods ─────────────────────────────────────

    def _default_action(self, ctx: ScanContext, budget: dict) -> dict:
        """Fallback action when not using the planner (light mode or early passes)."""
        files = self._pick_default_files(ctx, budget["phase3_files_per_pass"])
        if not files:
            return {"action": "STOP", "reasoning": "No uninspected files remain", "params": {}}
        return {"action": "INVESTIGATE_FILES", "reasoning": "Default queue order", "params": {"files": files}}

    def _pick_default_files(self, ctx: ScanContext, count: int) -> list[str]:
        """Pick files from the queue + hot files."""
        queue_files = [f for f in ctx.file_queue if f not in ctx.files_inspected][:count]
        hot_files = ctx.get_hot_files(limit=5)
        hot_new = [f for f in hot_files if f not in set(queue_files)]
        return queue_files + hot_new[:max(0, count - len(queue_files))]

    def _boost_from_findings(self, ctx: ScanContext):
        """Boost files referenced by NEW findings only (avoids unbounded score inflation)."""
        if not hasattr(self, '_boosted_finding_count'):
            self._boosted_finding_count = 0
        start = self._boosted_finding_count
        for finding in ctx.candidate_findings[start:]:
            if finding.status == "investigating":
                ctx.boost_file(finding.file_path, 5.0, f"finding: {finding.title}")
                for src in finding.input_sources:
                    for part in src.split():
                        if "/" in part or "." in part:
                            ctx.boost_file(part.strip("'\"(),"), 3.0, "input source")
        self._boosted_finding_count = len(ctx.candidate_findings)

    async def _trace_flow(
        self, ctx: ScanContext, source_file: str, sink_file: str, question: str
    ):
        """Read both source and sink files and ask the AI to trace the data flow between them."""
        source_content = await self.read_file(ctx, source_file, max_lines=400)
        sink_content = await self.read_file(ctx, sink_file, max_lines=400)
        graph_context = []
        for flow in ctx.taint_flows:
            if flow.source_file == source_file and flow.sink_file == sink_file:
                verify_taint_flow_graph(flow, ctx.call_graph, ctx.file_analyses)
                if flow.graph_verified:
                    graph_context.append(format_call_chain(flow))

        prompt = (
            f"## Data Flow Trace\n"
            f"Question: {question}\n\n"
            f"### Source file: {source_file}\n```\n{source_content}\n```\n\n"
            f"### Sink file: {sink_file}\n```\n{sink_content}\n```\n\n"
            f"{'### Static Call-Graph Evidence\\n' + chr(10).join(graph_context) + chr(10) + chr(10) if graph_context else ''}"
            f"Trace the data flow from the source to the sink. "
            f"Identify: what data enters, how it transforms, what validation exists, "
            f"and whether the flow is exploitable.\n\n"
            f"Respond with the same JSON format as a standard investigation."
        )

        try:
            result = await self.ask_json(
                ctx,
                SYSTEM_PROMPT,
                prompt,
                max_tokens=3000,
                allow_tools=True,
                tool_names=[
                    "read_file",
                    "read_file_range",
                    "search_code",
                    "check_file_exists",
                    "get_file_symbols",
                    "get_file_imports",
                    "get_call_graph_for_file",
                    "trace_call_chain",
                    "get_callers_of",
                    "get_entry_points_reaching",
                    "get_resolved_imports",
                    "run_codeql_on_files",
                ],
                max_tool_rounds=self._MAX_TOOL_ROUNDS,
            )
            self._process_investigation_result(ctx, result, source_file)
        except Exception as e:
            await self.emit(ctx, f"Flow trace failed: {e}", level="warn")

    async def _deep_dive(self, ctx: ScanContext, file_path: str, questions: list[str]):
        """Re-read a file with specific targeted questions."""
        content = await self.read_file(ctx, file_path, max_lines=800)
        questions_text = "\n".join(f"- {q}" for q in questions)

        prompt = (
            f"## Deep Dive: {file_path}\n\n"
            f"You are re-examining this file to answer specific security questions:\n"
            f"{questions_text}\n\n"
            f"### File content:\n```\n{content}\n```\n\n"
            f"Answer each question with evidence from the code. "
            f"Report any new findings or taint flows discovered.\n\n"
            f"Respond with the same JSON format as a standard investigation."
        )

        try:
            result = await self.ask_json(
                ctx,
                SYSTEM_PROMPT,
                prompt,
                max_tokens=3000,
                allow_tools=True,
                tool_names=[
                    "read_file",
                    "read_file_range",
                    "search_code",
                    "list_directory",
                    "check_file_exists",
                    "get_file_symbols",
                    "get_file_imports",
                    "get_scanner_hits",
                    "query_findings",
                    "query_taint_flows",
                    "trace_call_chain",
                    "get_callers_of",
                    "get_entry_points_reaching",
                    "run_codeql_on_files",
                ],
                max_tool_rounds=self._MAX_TOOL_ROUNDS,
            )
            self._process_investigation_result(ctx, result, file_path)
        except Exception as e:
            await self.emit(ctx, f"Deep dive failed on {file_path}: {e}", level="warn")

    async def _cross_reference(
        self, ctx: ScanContext, file_a: str, file_b: str, question: str
    ):
        """Compare two files to understand their security-relevant interaction."""
        content_a = await self.read_file(ctx, file_a, max_lines=400)
        content_b = await self.read_file(ctx, file_b, max_lines=400)

        prompt = (
            f"## Cross-Reference Analysis\n"
            f"Question: {question}\n\n"
            f"### File A: {file_a}\n```\n{content_a}\n```\n\n"
            f"### File B: {file_b}\n```\n{content_b}\n```\n\n"
            f"Analyse how these two files interact. Look for:\n"
            f"- Data passed between them\n"
            f"- Shared state or configuration\n"
            f"- Authentication/authorization boundaries\n"
            f"- Trust assumptions one makes about the other\n"
            f"- Combined vulnerabilities that neither file has alone\n\n"
            f"Respond with the same JSON format as a standard investigation."
        )

        try:
            result = await self.ask_json(
                ctx,
                SYSTEM_PROMPT,
                prompt,
                max_tokens=3000,
                allow_tools=True,
                tool_names=[
                    "read_file",
                    "read_file_range",
                    "search_code",
                    "check_file_exists",
                    "get_file_symbols",
                    "get_file_imports",
                    "get_scanner_hits",
                    "trace_call_chain",
                    "get_callers_of",
                    "get_entry_points_reaching",
                    "get_resolved_imports",
                    "find_files_importing",
                    "run_codeql_on_files",
                ],
                max_tool_rounds=self._MAX_TOOL_ROUNDS,
            )
            self._process_investigation_result(ctx, result, file_a)
        except Exception as e:
            await self.emit(ctx, f"Cross-reference failed: {e}", level="warn")

    async def _load_dep_cache(self, ctx: ScanContext):
        """Load vulnerable dependency details into a cache on first call."""
        if hasattr(ctx, '_dep_cache') and ctx._dep_cache:
            return

        ctx._dep_cache = {"entries": [], "by_package": {}}
        try:
            from app.database import async_session
            from app.models.dependency import Dependency, DependencyFinding

            async with async_session() as session:
                result = await session.execute(
                    select(DependencyFinding, Dependency)
                    .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                    .where(DependencyFinding.scan_id == ctx.scan_id)
                )
                for df, dep in result.all():
                    key = dep.name.lower().replace("-", "_")
                    entry = {
                        "package": dep.name,
                        "version": dep.version,
                        "ecosystem": dep.ecosystem,
                        "advisory_id": df.advisory_id or "",
                        "cve_id": df.cve_id or "",
                        "severity": df.severity or "medium",
                        "summary": df.summary or "",
                        "details": (df.details or "")[:300],
                        "fixed_version": df.fixed_version,
                        "cwes": df.cwes or [],
                        "references": (df.references or [])[:2],
                        "vulnerable_functions": df.vulnerable_functions or [],
                        "evidence_type": df.evidence_type,
                        "ai_assessment": df.ai_assessment or "",
                        "relevance": df.relevance,
                        "reachability_status": df.reachability_status,
                        "risk_score": df.risk_score,
                    }
                    ctx._dep_cache["entries"].append(entry)
                    ctx._dep_cache["by_package"].setdefault(key, []).append(entry)
        except Exception:
            pass

    @staticmethod
    def _dep_cache_entries(ctx: ScanContext) -> list[dict]:
        return dep_cache_entries(ctx)

    async def _get_related_file_snippets(
        self, ctx: ScanContext, file_path: str, max_files: int = 3, max_lines: int = 150
    ) -> list[dict]:
        """
        Get snippets of files directly connected via call graph or imports.
        This gives the AI multi-file context without needing separate TRACE_FLOW calls.
        """
        related = []

        if not ctx.call_graph:
            return related

        # Get callers (files that call into this file)
        callers = ctx.call_graph.get_file_callers(file_path)
        # Get callees (files this file calls)
        callees = ctx.call_graph.get_file_callees(file_path)

        # Prioritise: uninspected callers/callees with high confidence edges
        candidates = []
        seen = {file_path}

        for edge in callers:
            if edge.caller_file not in seen and edge.confidence >= 0.6:
                candidates.append((edge.caller_file, f"calls {edge.callee_symbol}() in this file", edge.confidence))
                seen.add(edge.caller_file)

        for edge in callees:
            if edge.callee_file not in seen and edge.confidence >= 0.6:
                candidates.append((edge.callee_file, f"called by {edge.caller_symbol}() from this file", edge.confidence))
                seen.add(edge.callee_file)

        # Sort by confidence, take top N
        candidates.sort(key=lambda x: x[2], reverse=True)

        for rel_path, relationship, conf in candidates[:max_files]:
            try:
                snippet = await self.read_file(ctx, rel_path, max_lines=max_lines)
                if snippet and not snippet.startswith("["):
                    related.append({
                        "path": rel_path,
                        "relationship": relationship,
                        "snippet": snippet,
                    })
            except Exception:
                continue

        return related

    def _get_dep_context_for_file(self, ctx: ScanContext, file_path: str) -> list[dict]:
        """
        Check if this file imports any packages that have known CVEs.
        Uses the cached dep findings (loaded once per scan).
        """
        return vulnerable_dependency_context_for_file(ctx, file_path)

    def _process_investigation_result(self, ctx: ScanContext, result: dict, default_file: str):
        """Process findings and taint flows from any investigation action."""
        for fd in result.get("findings", []):
            ctx.candidate_findings.append(CandidateFinding(
                title=fd.get("title", "Untitled"),
                category=fd.get("category", "other"),
                severity=fd.get("severity", "medium"),
                file_path=fd.get("file_path", default_file),
                line_range=fd.get("line_range"),
                code_snippet=fd.get("code_snippet"),
                hypothesis=fd.get("hypothesis", ""),
                supporting_evidence=fd.get("supporting_evidence", []),
                opposing_evidence=fd.get("opposing_evidence", []),
                confidence=fd.get("confidence", 0.5),
                input_sources=fd.get("input_sources", []),
                sinks=fd.get("sinks", []),
                cwe_ids=fd.get("cwe_ids", []),
            ))

        for tf in result.get("taint_flows", []):
            src_file = tf.get("source_file") or default_file
            snk_file = tf.get("sink_file") or default_file
            self._record_taint_flow(
                ctx,
                TaintFlow(
                    source_file=src_file,
                    source_line=tf.get("source_line", 0),
                    source_type=tf.get("source_type", "unknown"),
                    sink_file=snk_file,
                    sink_line=tf.get("sink_line", 0),
                    sink_type=tf.get("sink_type", "unknown"),
                    intermediaries=tf.get("intermediaries", []),
                    sanitised=tf.get("sanitised", False),
                ),
            )

        for bp in result.get("files_to_boost", []):
            ctx.boost_file(bp, 4.0, "AI-identified critical")

        ctx.key_observations.extend(result.get("observations", []))

    def _record_taint_flow(self, ctx: ScanContext, flow: TaintFlow):
        """Deduplicate, ground, and enqueue taint flows for later verification."""
        for existing in ctx.taint_flows:
            if (
                existing.source_file == flow.source_file
                and existing.source_line == flow.source_line
                and existing.sink_file == flow.sink_file
                and existing.sink_line == flow.sink_line
                and existing.source_type == flow.source_type
                and existing.sink_type == flow.sink_type
            ):
                existing.sanitised = existing.sanitised or flow.sanitised
                if flow.intermediaries and not existing.intermediaries:
                    existing.intermediaries = flow.intermediaries
                verify_taint_flow_graph(existing, ctx.call_graph, ctx.file_analyses)
                return

        verify_taint_flow_graph(flow, ctx.call_graph, ctx.file_analyses)
        ctx.taint_flows.append(flow)
        if flow.source_file:
            ctx.boost_file(flow.source_file, 5.0, "taint source")
        if flow.sink_file:
            ctx.boost_file(flow.sink_file, 8.0, "taint sink")

    def _build_investigation_prompt(
        self, ctx: ScanContext, file_path: str, content: str, scanner_hits: list[dict],
        *, related_files: list[dict] | None = None,
        vuln_functions: list[dict] | None = None,
        dep_context: list[dict] | None = None,
    ) -> str:
        parts = [
            "## Application Context",
            f"App type: {ctx.app_type or 'unknown'}",
            f"Languages: {', '.join(ctx.languages)}",
            f"Frameworks: {', '.join(ctx.frameworks)}",
        ]

        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            parts.append(
                "\n## DECOMPILED ANDROID APP — "
                "This is jadx-decompiled code. Ignore decompilation artifacts (goto, synthetic accessors, "
                "renamed variables). Focus on: Intent handling, exported components, WebView bridges, "
                "insecure storage (SharedPreferences without encryption), certificate validation, "
                "hardcoded secrets, SQL injection via ContentProvider, path traversal, and IPC abuse."
            )

        if ctx.app_summary:
            parts.append(f"\nApp Summary:\n{ctx.app_summary[:1500]}")

        # Documentation intelligence — what the developers documented
        if ctx.doc_intelligence:
            parts.append(f"\nDeveloper Documentation Intel:\n{ctx.doc_intelligence[:1000]}")

        if ctx.attack_surface:
            parts.append("\nKnown attack surface:")
            for a in ctx.attack_surface[:15]:
                parts.append(f"- {a}")

        if ctx.trust_boundaries:
            parts.append("\nTrust boundaries:")
            for t in ctx.trust_boundaries[:10]:
                parts.append(f"- {t}")

        if ctx.entry_points:
            parts.append("\nEntry points:")
            for ep in ctx.entry_points[:10]:
                parts.append(f"- {ep.get('type', '?')}: {ep.get('function', '?')} in {ep.get('file', '?')}")

        if ctx.candidate_findings:
            strong = [f for f in ctx.candidate_findings if f.confidence >= 0.6][:8]
            if strong:
                parts.append(f"\nPrior strong findings ({len(strong)}):")
                for f in strong:
                    parts.append(f"- [{f.severity}] {f.title} in {f.file_path} ({f.confidence:.0%})")

        if ctx.taint_flows:
            parts.append(f"\nKnown taint flows ({len(ctx.taint_flows)}):")
            for tf in ctx.taint_flows[-5:]:
                san = " (SANITISED)" if tf.sanitised else ""
                parts.append(
                    f"- {tf.source_type} @ {tf.source_file}:{tf.source_line} "
                    f"→ {tf.sink_type} @ {tf.sink_file}:{tf.sink_line}{san}"
                )

        if scanner_hits:
            parts.append(f"\nScanner signals for {file_path}:")
            parts.append(
                "Treat these as leads, not proof. Use them together with direct code reading, "
                "call-graph evidence, and tool lookups if more scanner detail is needed."
            )
            for h in scanner_hits[:self._INLINE_SCANNER_HITS]:
                line = int(h.get("line") or 0)
                end_line = int(h.get("end_line") or 0)
                location = f"lines {line}-{end_line}" if end_line and end_line > line else f"line {line}"
                label = h.get("rule_id") or "finding"
                parts.append(
                    f"- [{str(h.get('severity', 'info')).upper()}] "
                    f"{h.get('scanner', 'scanner')}::{label} at {location} — {h.get('message', '')}"
                )
                if h.get("metadata_summary"):
                    parts.append(f"  Context: {h['metadata_summary']}")
                if h.get("snippet"):
                    parts.append(f"  Snippet:\n```text\n{h['snippet']}\n```")
            remaining_hits = len(scanner_hits) - self._INLINE_SCANNER_HITS
            if remaining_hits > 0:
                parts.append(
                    f"- ... {remaining_hits} additional scanner hits are available through the scanner tools."
                )

        # Known vulnerable function calls detected in this file (from advisory database)
        if vuln_functions:
            confirmed = [vf for vf in vuln_functions if vf.get("evidence_strength") == "strong"]
            package_linked = [vf for vf in vuln_functions if vf.get("evidence_strength") == "medium"]
            weak = [vf for vf in vuln_functions if vf.get("evidence_strength") == "weak"]

            def add_vuln_group(title: str, intro: str, items: list[dict], *, limit: int = 5):
                if not items:
                    return
                parts.append(f"\n### {title}")
                parts.append(intro)
                for vf in items[:limit]:
                    advisory_id = vf.get("display_id") or vf.get("cve_id") or vf.get("advisory_id") or "advisory"
                    evidence_bits = []
                    if vf.get("import_module"):
                        evidence_bits.append(f"via `{vf['import_module']}`")
                    source = vf.get("package_evidence_source")
                    if source and source not in {"function_name_only", ""}:
                        evidence_bits.append(f"source: {source}")
                    confidence = vf.get("package_match_confidence")
                    if confidence is not None:
                        evidence_bits.append(f"match {float(confidence):.2f}")
                    evidence_suffix = f" [{'; '.join(evidence_bits)}]" if evidence_bits else ""
                    parts.append(
                        f"- **{vf['function']}()** at line {vf['line']} — "
                        f"{advisory_id} ({vf.get('severity', 'medium').upper()}) in {vf.get('package', 'package')}: "
                        f"{vf.get('summary', '')}{evidence_suffix}"
                    )

            add_vuln_group(
                "Package-Confirmed Vulnerable Function Calls",
                "These matches line up with a dependency already identified as vulnerable and imported by this file. Treat them as high-signal evidence, then verify reachability and guards.",
                confirmed,
            )
            add_vuln_group(
                "Imported-Package Vulnerable Function Leads",
                "These matches line up with a package imported by this file, but the vulnerable version is not independently confirmed here. Treat them as hypotheses, not proof.",
                package_linked,
            )
            add_vuln_group(
                "Weak Advisory Function-Name Overlaps",
                "These only match a known vulnerable symbol name. The vulnerable package is not confirmed as imported in this file, so do not treat them as proof without package evidence.",
                weak,
                limit=3,
            )

        # Vulnerable technology versions detected in the codebase
        vuln_versions = ctx.fingerprint.get("vulnerable_versions", [])
        if vuln_versions:
            relevant = [v for v in vuln_versions if v.get("file_path") == file_path]
            if relevant:
                parts.append(f"\n### Vulnerable Technology Versions in This File")
                for v in relevant:
                    advisory_id = v.get("cve_id") or v.get("advisory_id") or "advisory"
                    parts.append(
                        f"- **{v['package']}** v{v['version']} — {advisory_id} ({v['severity'].upper()}): "
                        f"{v['summary']}"
                    )
                    if v.get("vulnerable_functions"):
                        parts.append(
                            f"  Vulnerable functions: {', '.join(v['vulnerable_functions'][:5])}"
                        )

        # Vulnerable dependency context — tell the AI about specific advisories
        # so it can check if vulnerable functions are actually called
        dep_context = dep_context if dep_context is not None else self._get_dep_context_for_file(ctx, file_path)
        if dep_context:
            parts.append(f"\n### Vulnerable Dependencies Imported by This File")
            for dc in dep_context:
                cve = dc.get("cve_id") or dc.get("advisory_id", "")
                parts.append(
                    f"- **{dc['package']}** v{dc['version']} — "
                    f"{dc['severity'].upper()} — {cve}"
                )
                parts.append(f"  Summary: {dc['summary']}")
                if dc.get("cwes"):
                    parts.append(f"  CWEs: {', '.join(dc['cwes'])}")
                if dc.get("vulnerable_functions"):
                    parts.append(f"  Vulnerable functions: {', '.join(dc['vulnerable_functions'])}")
                if dc.get("import_module"):
                    parts.append(
                        f"  Imported via: {dc['import_module']} "
                        f"({dc.get('import_match_source', 'unknown')}, match {float(dc.get('import_match_confidence', 0.0)):.2f})"
                    )
                if dc.get("details"):
                    parts.append(f"  Details: {dc['details'][:250]}")
                if dc.get("fixed_version"):
                    parts.append(f"  Fixed in: {dc['fixed_version']}")
                if dc.get("ai_assessment"):
                    parts.append(f"  Assessment: {dc['ai_assessment'][:150]}")
            parts.append(
                "\n**IMPORTANT**: Package-confirmed vulnerable-function matches are high-signal leads. "
                "Imported-package matches still need vulnerable-version confirmation. "
                "Symbol-only overlaps are weak hints and must not be treated as proof. "
                "For all of them, verify whether the vulnerable functions/features are actually called "
                "and whether user-controlled input can reach them."
            )

        if ctx.key_observations:
            parts.append("\nRecent observations:")
            for obs in ctx.key_observations[-8:]:
                parts.append(f"- {obs}")

        # Call graph context
        if ctx.call_graph:
            file_callers = ctx.call_graph.get_file_callers(file_path)
            file_callees = ctx.call_graph.get_file_callees(file_path)

            if file_callers or file_callees:
                parts.append(f"\n### Call Graph for {file_path}")

            if file_callers:
                parts.append(f"**Called by ({len(file_callers)} edges):**")
                for edge in file_callers[:10]:
                    parts.append(f"- {edge.caller_symbol}() in `{edge.caller_file}` → {edge.callee_symbol}()")

            if file_callees:
                parts.append(f"**Calls out to ({len(file_callees)} edges):**")
                for edge in file_callees[:10]:
                    parts.append(f"- {edge.caller_symbol}() → {edge.callee_symbol}() in `{edge.callee_file}`")

        # Import graph — what does this file depend on?
        file_imports = ctx.import_graph.get(file_path, [])
        internal_imports = [r for r in file_imports if not r.is_external and r.resolved_path]
        if internal_imports:
            parts.append(f"\n### This file imports ({len(internal_imports)} internal):")
            for imp in internal_imports[:10]:
                parts.append(f"- `{imp.import_module}` → `{imp.resolved_path}`")

        # Android manifest context for APK scans
        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            manifest = ctx.fingerprint.get("android_manifest", {})
            if manifest:
                exported = manifest.get("exported_components", [])
                # Check if this file implements an exported component
                for comp in exported:
                    comp_path = comp.get("name", "").replace(".", "/")
                    if comp_path and file_path.endswith(comp_path + ".java"):
                        parts.append(
                            f"\n**EXPORTED COMPONENT**: This file implements `{comp['name']}` "
                            f"({comp['type']}) which is exported in AndroidManifest.xml"
                            f"{' with intent-filter' if comp.get('has_intent_filter') else ''}. "
                            f"This means external apps can invoke it — check for input validation."
                        )
                flags = manifest.get("security_flags", {})
                if flags.get("debuggable"):
                    parts.append("**WARNING: App is debuggable** — debug builds may have weaker security.")
                if flags.get("usesCleartextTraffic"):
                    parts.append("**WARNING: Cleartext traffic is allowed** — check for HTTP URLs.")

        # Obfuscation warning
        if file_path in ctx.obfuscated_files:
            parts.append(
                f"\n**WARNING: This file appears to be obfuscated or minified. "
                f"Variable names and structure may not reflect the original source. "
                f"Lower your confidence for any findings in this file.**"
            )

        # Monorepo context
        if ctx.is_monorepo and ctx.workspaces:
            for ws in ctx.workspaces:
                if file_path.startswith(ws["path"]):
                    parts.append(f"\nThis file belongs to workspace: **{ws['name']}** ({ws['type']})")
                    break

        # Related files — multi-file context for cross-file flow tracing
        if related_files:
            parts.append(f"\n## Related Files ({len(related_files)} connected via call graph)")
            parts.append("These files are directly connected to the main file. Use them to trace data flows.")
            for rf in related_files:
                parts.append(f"\n### {rf['path']} ({rf['relationship']})")
                parts.append(f"```\n{rf['snippet']}\n```")

        # Route/handler detection from Tree-sitter (sync — uses cached parse data)
        try:
            from app.analysis.treesitter import parse_file as ts_parse
            full_path = Path(ctx.repo_path) / file_path
            if full_path.exists() and full_path.is_file():
                file_content = full_path.read_text(encoding="utf-8", errors="ignore")[:50000]
                # Detect language from file extension
                ext_to_lang = {
                    ".py": "python", ".js": "javascript", ".ts": "typescript",
                    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
                    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
                    ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".kt": "kotlin",
                    ".scala": "scala", ".swift": "swift",
                }
                ext = full_path.suffix.lower()
                lang = ext_to_lang.get(ext, "")
                if lang and file_content:
                    parsed = ts_parse(file_content, lang)
                    if parsed and parsed.routes:
                        parts.append(f"\n### Detected Routes/Endpoints in {file_path}:")
                        for route in parsed.routes[:10]:
                            parts.append(f"- {route}")
        except Exception:
            pass

        parts.append(f"\n## Primary File: {file_path}")
        parts.append(f"```\n{content}\n```")

        return "\n".join(parts)
