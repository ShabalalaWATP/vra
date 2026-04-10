"""Planning Agent — AI-driven decision making for what to investigate next.

This is the brain of the agentic loop. Instead of running fixed passes,
the planner looks at the current state of the investigation and decides:
1. What action to take next
2. Which files to focus on
3. What investigation strategy to use
4. When to stop (convergence detection)

The planner is called between investigation passes and can choose from:
- INVESTIGATE_FILES: Read and analyse specific files
- TRACE_FLOW: Follow a specific data flow across files
- DEEP_DIVE: Re-read a file with specific questions
- CROSS_REFERENCE: Compare two files for interaction patterns
- TARGETED_SCAN: Run specific scanner rules on specific files
- VERIFY_EARLY: Challenge a specific finding before full verification
- STOP: Investigation has converged, proceed to verification

This replaces the fixed `for pass_num in range(max_passes)` loop.
"""

import logging

from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)

PLANNER_SYSTEM = """You are the planning brain of a security research agent. You are deciding
what to investigate next in a vulnerability scan.

You have access to the current scan state including:
- What files have been inspected
- What findings have been discovered so far
- What taint flows (input → sink) have been traced
- What scanner hits exist for uninspected files
- What hot files (dynamically boosted) exist
- How much budget remains

Your goal is to maximise the quality and completeness of the security assessment
within the remaining budget.

Decide what to do next. You can choose ONE of these actions:

1. INVESTIGATE_FILES — Read and analyse a set of files for vulnerabilities
   Use when: uninspected high-priority or hot files exist
   Provide: list of file paths (up to 8)

2. TRACE_FLOW — Follow a specific data flow path across multiple files
   Use when: a taint flow was identified but not fully traced
   Provide: source file+line, sink file+line, question to answer

3. DEEP_DIVE — Re-read an already-inspected file with specific questions
   Use when: a finding references code you want to understand deeper
   Provide: file path, list of specific questions to answer

4. CROSS_REFERENCE — Compare two files to understand their interaction
   Use when: findings suggest two files interact in security-relevant ways
   Provide: file_a, file_b, interaction question

5. TARGETED_SCAN — Run specific scanner rules on specific files
   Use when: you suspect specific vulnerability types in specific files
   Provide: rule_ids, file paths

6. VERIFY_EARLY — Challenge a specific high-severity finding immediately
   Use when: a critical/high finding needs urgent verification
   Provide: finding title, specific verification questions

7. STOP — Investigation has converged, no more useful work to do
   Use when: all high-priority files inspected AND findings are stable AND
             no untraced taint flows remain

Respond with JSON:
{
  "action": "INVESTIGATE_FILES|TRACE_FLOW|DEEP_DIVE|CROSS_REFERENCE|TARGETED_SCAN|VERIFY_EARLY|STOP",
  "reasoning": "Why you chose this action",
  "params": {
    // action-specific parameters
  },
  "confidence": 0.0-1.0  // how confident you are this is the right next step
}"""


class PlannerAgent(BaseAgent):
    """Decides what the investigation should do next."""

    @property
    def name(self) -> str:
        return "planner"

    async def plan_next_action(self, ctx: ScanContext) -> dict:
        """
        Ask the AI what to do next. Returns an action dict with:
        {action, reasoning, params, confidence}
        """
        user_prompt = await self._build_state_summary(ctx)

        try:
            result = await self.ask_json(
                ctx,
                PLANNER_SYSTEM, user_prompt,
                max_tokens=1000,
                temperature=0.3,
                allow_tools=True,
                tool_names=[
                    "query_findings",
                    "query_taint_flows",
                    "get_all_scanner_hits",
                    "query_dependency_findings",
                    "check_file_exists",
                    "get_call_graph_for_file",
                    "trace_call_chain",
                    "get_callers_of",
                    "get_entry_points_reaching",
                    "get_file_imports",
                    "get_resolved_imports",
                    "find_files_importing",
                ],
                max_tool_rounds=2,
            )
            return result
        except Exception as e:
            logger.warning("Planner failed: %s", e)
            # Fallback: if there are uninspected files, investigate them
            uninspected = [f for f in ctx.file_queue if f not in ctx.files_inspected]
            if uninspected:
                return {
                    "action": "INVESTIGATE_FILES",
                    "reasoning": "Planner failed, falling back to queue order",
                    "params": {"files": uninspected[:8]},
                    "confidence": 0.3,
                }
            return {"action": "STOP", "reasoning": "Planner failed, no uninspected files", "params": {}, "confidence": 1.0}

    async def execute(self, ctx: ScanContext) -> None:
        """Not used directly — the planner is called by the agentic loop in the engine."""
        pass

    async def _build_state_summary(self, ctx: ScanContext) -> str:
        parts = [
            "## Current Scan State",
            f"Mode: {ctx.mode}",
            f"AI calls used: {ctx.ai_calls_made} / {ctx.iteration_budget.get('max_ai_calls', 100)}",
            f"Files total: {ctx.files_total}",
            f"Files inspected: {len(ctx.files_inspected)}",
            f"Current pass: {ctx.current_pass}",
            "",
        ]

        # Findings summary
        investigating = [f for f in ctx.candidate_findings if f.status == "investigating"]
        confirmed = [f for f in ctx.candidate_findings if f.status == "confirmed"]
        dismissed = [f for f in ctx.candidate_findings if f.status == "dismissed"]
        parts.append(f"## Findings: {len(investigating)} investigating, {len(confirmed)} confirmed, {len(dismissed)} dismissed")

        for f in investigating[:10]:
            parts.append(f"- [{f.severity}|{f.confidence:.0%}] {f.title} in {f.file_path}")

        # Taint flows
        unsanitised = [t for t in ctx.taint_flows if not t.sanitised]
        verified = [t for t in ctx.taint_flows if t.graph_verified]
        parts.append(
            f"\n## Taint Flows: {len(ctx.taint_flows)} total, "
            f"{len(unsanitised)} unsanitised, {len(verified)} call-graph verified"
        )
        for t in unsanitised[:5]:
            verified_tag = " [verified]" if t.graph_verified else ""
            parts.append(
                f"- {t.source_type}@{t.source_file}:{t.source_line} → "
                f"{t.sink_type}@{t.sink_file}:{t.sink_line}{verified_tag}"
            )

        # Uninspected high-priority files
        uninspected = [f for f in ctx.file_queue if f not in ctx.files_inspected][:15]
        parts.append(f"\n## Top Uninspected Files ({len(uninspected)} shown of {len([f for f in ctx.file_queue if f not in ctx.files_inspected])} remaining):")
        for fp in uninspected:
            score = ctx.file_scores.get(fp)
            score_str = f"score={score.effective_score:.0f}" if score else "unscored"
            parts.append(f"- {fp} ({score_str})")

        # Hot files (dynamically boosted)
        hot = ctx.get_hot_files(limit=5)
        if hot:
            parts.append(f"\n## Hot Files (dynamically boosted, uninspected):")
            for fp in hot:
                score = ctx.file_scores.get(fp)
                boost = f"boost={score.dynamic_boost:.0f}" if score else ""
                parts.append(f"- {fp} ({boost})")

        # Component criticality — prioritise critical/high components
        if ctx.components:
            critical_uninspected = []
            for comp in ctx.components:
                if comp.get("criticality") in ("critical", "high"):
                    for cf in comp.get("files", []):
                        if cf not in ctx.files_inspected:
                            critical_uninspected.append((cf, comp.get("name", "?"), comp.get("criticality", "?")))
            if critical_uninspected:
                parts.append(f"\n## Critical Component Files (uninspected):")
                for fp, comp_name, crit in critical_uninspected[:8]:
                    parts.append(f"- {fp} (component: {comp_name}, criticality: {crit})")
                parts.append("PRIORITY: Investigate these before lower-criticality files.")

        # Partial exploit chains — can we complete them?
        chains_in_progress = []
        confirmed = [f for f in ctx.candidate_findings if f.status == "confirmed"]
        if len(confirmed) >= 2:
            # Look for findings that could chain together
            categories = {}
            for f in confirmed:
                categories.setdefault(f.category, []).append(f)

            # Common chain patterns
            chain_starters = {"xss", "csrf", "open_redirect", "ssrf", "info_disclosure", "path_traversal"}
            chain_completers = {"sqli", "rce", "auth_bypass", "privilege_escalation", "deserialization"}
            found_starters = chain_starters & set(categories.keys())
            found_completers = chain_completers & set(categories.keys())

            if found_starters and not found_completers:
                chains_in_progress.append(
                    f"Found {', '.join(found_starters)} but no escalation findings yet. "
                    f"Look for auth bypass, privilege escalation, or RCE to complete a chain."
                )
            if found_starters and found_completers:
                chains_in_progress.append(
                    f"POTENTIAL CHAIN: {', '.join(found_starters)} + {', '.join(found_completers)}. "
                    f"Consider using CROSS_REFERENCE to verify chain viability."
                )

        if chains_in_progress:
            parts.append(f"\n## Exploit Chain Opportunities:")
            for c in chains_in_progress:
                parts.append(f"- {c}")

        # Key observations
        if ctx.key_observations:
            parts.append(f"\n## Recent Observations:")
            for obs in ctx.key_observations[-5:]:
                parts.append(f"- {obs}")

        # Documentation intelligence hints
        if ctx.doc_intelligence:
            # Only show the investigation hints to the planner, not the full doc dump
            hint_lines = [l for l in ctx.doc_intelligence.split("\n") if l.strip().startswith("- ")]
            if hint_lines:
                parts.append(f"\n## Investigation Hints (from documentation):")
                for h in hint_lines[:5]:
                    parts.append(h)

        # Attack surface
        if ctx.attack_surface:
            parts.append(f"\n## Known Attack Surface:")
            for a in ctx.attack_surface[:8]:
                parts.append(f"- {a}")

        # Call graph context — show the planner which files are most interconnected
        if ctx.call_graph and hasattr(ctx.call_graph, 'get_high_indegree_files'):
            high_indegree = ctx.call_graph.get_high_indegree_files(limit=8)
            uninspected_central = [
                (f, count) for f, count in high_indegree
                if f not in ctx.files_inspected
            ]
            if uninspected_central:
                parts.append(f"\n## Central Files (many callers, not yet inspected):")
                for fp, caller_count in uninspected_central[:5]:
                    parts.append(f"- {fp} ({caller_count} callers)")
                parts.append("These files are called by many others — vulnerabilities here have wide impact.")

        # Show unverified taint flows that could benefit from call graph tracing
        unverified_taint = [t for t in ctx.taint_flows if not t.graph_verified and not t.sanitised]
        if unverified_taint:
            parts.append(f"\n## Unverified Taint Flows ({len(unverified_taint)}):")
            for t in unverified_taint[:5]:
                parts.append(
                    f"- {t.source_type}@{t.source_file}:{t.source_line} → "
                    f"{t.sink_type}@{t.sink_file}:{t.sink_line} "
                    f"(NOT call-graph verified — use TRACE_FLOW to confirm)"
                )

        # Scanner hit summary
        if ctx.scanner_hit_counts:
            parts.append(f"\n## Scanner Results Summary:")
            for scanner, count in ctx.scanner_hit_counts.items():
                parts.append(f"- {scanner}: {count} hits")

        # Vulnerable dependencies (so planner can prioritise files using them)
        tools = self.get_tools(ctx)
        try:
            dep_result = None
            # Use a synchronous check to avoid nested async
            # The planner needs this data inline, not as a tool call
            from sqlalchemy import select as _select
            from app.database import async_session as _async_session
            from app.models.dependency import Dependency, DependencyFinding
            from app.orchestrator.agents.dependency import ACTIVE_DEPENDENCY_RELEVANCE
            async with _async_session() as session:
                result = await session.execute(
                    _select(DependencyFinding, Dependency)
                    .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                    .where(
                        DependencyFinding.scan_id == ctx.scan_id,
                        DependencyFinding.relevance.in_(ACTIVE_DEPENDENCY_RELEVANCE),
                    )
                    .limit(10)
                )
                dep_rows = result.all()
                if dep_rows:
                    parts.append(f"\n## Vulnerable Dependencies in Use ({len(dep_rows)}):")
                    for df, dep in dep_rows:
                        parts.append(
                            f"- **{dep.name}** v{dep.version} ({dep.ecosystem}) — "
                            f"{df.severity} — {df.summary or df.advisory_id}"
                        )
                        if df.ai_assessment:
                            parts.append(f"  Assessment: {df.ai_assessment[:150]}")
                    parts.append(
                        "Consider using DEEP_DIVE on files that import these packages "
                        "to check if the vulnerable functions are called."
                    )
        except Exception:
            pass  # Non-critical; planner works without this

        # Available tools reminder (includes Android tools for APK scans)
        from app.orchestrator.tools import AgentToolkit
        parts.append(f"\n## Available Tools (for your reference):")
        for tool in AgentToolkit.get_tool_descriptions(source_type=ctx.source_type):
            parts.append(f"- **{tool['name']}**: {tool['description']}")

        return "\n".join(parts)
