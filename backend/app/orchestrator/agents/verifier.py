"""Verifier Agent — challenge findings, reduce false positives, detect exploit chains.

Key improvements:
- Cross-finding correlation: detects when multiple findings together form a chain
- Exploit chain detection: identifies multi-step attack paths
- Taint flow verification: checks if discovered taint flows are actually exploitable
- Deeper verification for high-severity findings
- Adaptive batch size based on finding complexity
"""

import logging
import re
from pathlib import Path

from app.analysis.dependency_context import vulnerable_dependency_context_for_file
from app.database import async_session
from app.models.finding import Evidence, Finding, FindingFile
from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.flow_verifier import format_call_chain, verify_taint_flow_graph
from app.orchestrator.scan_context import CandidateFinding, ScanContext

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior security reviewer verifying potential vulnerability findings.
Your job is to critically evaluate each finding and determine if it is real.

For each candidate finding, rigorously assess:
1. REACHABILITY: Is this code actually executed in production? Not test/dead/commented code?
2. INPUT CONTROL: Does user input actually reach the vulnerable sink? Trace the full data path.
3. VALIDATION: Is there input validation, sanitisation, or escaping that prevents exploitation?
4. FRAMEWORK PROTECTION: Does the framework provide automatic protection (ORM params, CSRF tokens, auto-escaping, CSP)?
5. CONFIGURATION: Could secure configuration make this unexploitable?
6. ATTACKER MODEL: What would an attacker need? Is it realistic?
7. MITIGATIONS: Are there other defensive layers (WAF, rate limiting, auth requirements)?
8. EXPLOITATION DIFFICULTY: How difficult would actual exploitation be?

ALSO: Look for EXPLOIT CHAINS — can multiple findings be combined?
For example:
- Information disclosure → CSRF → privilege escalation
- Path traversal → file read → credential theft
- SSRF → internal service access → data exfiltration
- Authentication bypass → SQL injection → data breach

Be SKEPTICAL. Challenge each finding. False positives waste analyst time.
But do not dismiss real vulnerabilities — if evidence is strong, confirm.

Respond with JSON:
{
  "verified_findings": [
    {
      "original_title": "...",
      "is_valid": true/false,
      "adjusted_severity": "critical|high|medium|low|info",
      "adjusted_confidence": 0.0-1.0,
      "verification_notes": "Detailed explanation of your assessment",
      "counter_evidence": ["Any counter-evidence discovered"],
      "remediation": "Specific, actionable fix recommendation",
      "exploitability": "easy|moderate|difficult|theoretical",
      "prerequisites": ["What an attacker needs — e.g. authenticated, same network"]
    }
  ],
  "exploit_chains": [
    {
      "chain_title": "Descriptive name for the attack chain",
      "severity": "critical|high|medium",
      "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      "findings_involved": ["finding title 1", "finding title 2"],
      "combined_impact": "What the full chain achieves",
      "likelihood": "How likely this chain is to be exploited"
    }
  ],
  "additional_observations": ["New observations from verification"]
}"""


class VerifierAgent(BaseAgent):
    _MAX_TOOL_ROUNDS = 4

    @property
    def name(self) -> str:
        return "verifier"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_phase = "verification"
        ctx.current_task = "Verifying findings"

        if not ctx.candidate_findings:
            await self.emit(ctx, "No candidate findings to verify")
            return

        await self.emit(ctx, f"Verifying {len(ctx.candidate_findings)} candidate findings...")

        # ── Phase 1: Verify findings in batches ───────────────────
        verification_depth = ctx.iteration_budget.get("verification_depth", "standard")

        # Adaptive batch size: smaller batches for deep verification
        batch_size = {"shallow": 8, "standard": 5, "deep": 3}.get(verification_depth, 5)

        total_findings = len(ctx.candidate_findings)
        for i in range(0, total_findings, batch_size):
            if ctx.cancelled:
                return

            batch = ctx.candidate_findings[i:i + batch_size]
            batch_label = f"Verifying findings {i + 1}-{min(i + batch_size, total_findings)} of {total_findings}"
            ctx.current_task = batch_label

            await self._verify_batch(ctx, batch)
            await self.emit_progress(ctx, task=batch_label)

        # ── Phase 2: Cross-finding correlation ────────────────────
        await self.emit_progress(ctx, task="Analysing exploit chains")
        await self.emit(ctx, "Checking for exploit chains across findings...")

        confirmed = [f for f in ctx.candidate_findings if f.status == "confirmed"]
        if len(confirmed) >= 2:
            await self._detect_chains(ctx, confirmed)

        # ── Phase 3: Taint flow verification ──────────────────────
        if ctx.taint_flows and verification_depth in ("standard", "deep"):
            ctx.current_task = "Verifying taint flows"
            await self.emit(ctx, f"Verifying {len(ctx.taint_flows)} taint flows...")
            await self._verify_taint_flows(ctx)

        # ── Phase 4: Exploit evidence generation ─────────────────
        if verification_depth in ("standard", "deep"):
            exploitable = self._eligible_exploit_evidence_findings(ctx, verification_depth)
            if exploitable:
                await self.emit_progress(ctx, task=f"Generating exploit evidence for {len(exploitable)} findings")
                await self.emit(ctx, f"Generating PoC for {len(exploitable)} confirmed findings...")
                await self._generate_exploit_evidence(ctx, exploitable)

        # ── CVE Correlation ────────────────────────────────────────
        await self.emit_progress(ctx, task="Correlating findings with CVE database")
        await self.emit(ctx, "Correlating findings against CVE/advisory database...")
        await self._correlate_cves(ctx)

        deduped_count, merged_count = self._finalise_verified_findings(ctx)
        if merged_count:
            await self.emit(
                ctx,
                f"Deduplicated verified findings: {deduped_count} canonical findings, {merged_count} duplicates merged",
            )

        # ── Persist confirmed findings ────────────────────────────
        await self.emit(ctx, "Persisting findings to database...")
        try:
            await self._persist_findings(ctx)
            await self.emit(ctx, f"Successfully persisted {ctx.findings_count} findings to database")
        except Exception as e:
            logger.error("Failed to persist findings: %s", e, exc_info=True)
            await self.emit(ctx, f"ERROR persisting findings: {e}", level="error")

        confirmed_count = len([f for f in ctx.candidate_findings if f.status == "confirmed"])
        dismissed_count = len([f for f in ctx.candidate_findings if f.status == "dismissed"])
        ctx.findings_count = confirmed_count

        await self.emit(
            ctx,
            f"Verification complete. {confirmed_count} confirmed, {dismissed_count} dismissed.",
        )

        await self.log_decision(
            ctx,
            action="verification_complete",
            output_summary=f"Confirmed: {confirmed_count}, Dismissed: {dismissed_count}",
        )

    async def _verify_batch(self, ctx: ScanContext, batch: list[CandidateFinding]):
        """Verify a batch of findings with full code context."""
        file_contents = {}
        for finding in batch:
            if finding.file_path not in file_contents:
                content = await self.read_file(ctx, finding.file_path, max_lines=600)
                file_contents[finding.file_path] = content

        user_content = self._build_verify_prompt(ctx, batch, file_contents)

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
                ],
                max_tool_rounds=self._MAX_TOOL_ROUNDS,
            )
        except Exception as e:
            await self.emit(ctx, f"Verification batch failed: {e}", level="warn")
            return

        # Update findings
        for v in result.get("verified_findings", []):
            title = v.get("original_title", "")
            for finding in batch:
                if finding.title == title:
                    verification_notes = str(v.get("verification_notes", "")).strip()
                    if v.get("is_valid", False):
                        finding.status = "confirmed"
                        finding.severity = v.get("adjusted_severity", finding.severity)
                        finding.confidence = v.get("adjusted_confidence", finding.confidence)
                        finding.verification_level = "statically_verified"
                        finding.verification_notes = verification_notes or finding.verification_notes
                        finding.supporting_evidence = self._merge_string_lists(
                            finding.supporting_evidence,
                            [verification_notes] if verification_notes else [],
                        )
                        finding.opposing_evidence = self._merge_string_lists(
                            finding.opposing_evidence,
                            v.get("counter_evidence", []),
                        )
                        # Store exploitability and prereqs in hypothesis
                        exploitability = v.get("exploitability", "")
                        prereqs = v.get("prerequisites", [])
                        if exploitability:
                            finding.hypothesis += f"\n\nExploitability: {exploitability}"
                        if prereqs:
                            finding.hypothesis += f"\nPrerequisites: {', '.join(prereqs)}"
                    else:
                        finding.status = "dismissed"
                        finding.verification_level = "dismissed"
                        finding.verification_notes = verification_notes or finding.verification_notes
                        finding.confidence = v.get("adjusted_confidence", 0.1)
                    break

        # Process exploit chains from this batch
        for chain in result.get("exploit_chains", []):
            ctx.key_observations.append(
                f"EXPLOIT CHAIN: {chain.get('chain_title', 'Unknown')} — "
                f"{chain.get('combined_impact', 'Unknown impact')} "
                f"({chain.get('severity', 'medium')} severity)"
            )
            # Create a synthetic finding for the chain (skip if already exists)
            chain_title = f"Exploit Chain: {chain.get('chain_title', 'Multi-step attack')}"
            already_exists = any(
                f.title == chain_title for f in ctx.candidate_findings
            )
            if not already_exists:
                involved = chain.get("findings_involved", [])
                ctx.candidate_findings.append(CandidateFinding(
                    title=chain_title,
                    category="exploit_chain",
                    severity=chain.get("severity", "high"),
                    file_path=batch[0].file_path if batch else "",
                    hypothesis=chain.get("combined_impact", ""),
                    supporting_evidence=chain.get("steps", []),
                    confidence=0.7,
                    status="confirmed",
                    provenance="hybrid",
                    verification_level="strongly_verified",
                    verification_notes=chain.get("combined_impact", ""),
                    related_findings=involved,
                ))

    async def _detect_chains(self, ctx: ScanContext, confirmed: list[CandidateFinding]):
        """Use AI to detect exploit chains across confirmed findings."""
        if not self.llm or len(confirmed) < 2:
            return

        findings_summary = []
        for f in confirmed[:15]:  # Cap to avoid prompt bloat
            findings_summary.append(
                f"- [{f.severity}] {f.title} ({f.category}) in {f.file_path}"
                f"\n  Inputs: {', '.join(f.input_sources[:3]) if f.input_sources else 'unknown'}"
                f"\n  Sinks: {', '.join(f.sinks[:3]) if f.sinks else 'unknown'}"
            )

        taint_summary = []
        for tf in ctx.taint_flows[:10]:
            taint_summary.append(
                f"- {tf.source_type} → {tf.sink_type} "
                f"({tf.source_file}:{tf.source_line} → {tf.sink_file}:{tf.sink_line})"
                f"{' [SANITISED]' if tf.sanitised else ''}"
            )

        prompt = (
            "## Confirmed Findings\n"
            + "\n".join(findings_summary)
            + "\n\n## Known Data Flows\n"
            + "\n".join(taint_summary)
            + "\n\n## Task\n"
            "Analyse these confirmed findings and data flows. "
            "Identify any EXPLOIT CHAINS where multiple findings can be combined "
            "to achieve a greater impact than any single finding alone. "
            "Respond with JSON: {\"exploit_chains\": [...]}"
        )

        try:
            result = await self.llm.chat_json(
                "You are a security researcher identifying multi-step attack chains.",
                prompt,
                max_tokens=2000,
            )
            ctx.ai_calls_made += 1

            for chain in result.get("exploit_chains", []):
                ctx.candidate_findings.append(CandidateFinding(
                    title=f"Exploit Chain: {chain.get('chain_title', 'Multi-step attack')}",
                    category="exploit_chain",
                    severity=chain.get("severity", "high"),
                    file_path="(multiple files)",
                    hypothesis=chain.get("combined_impact", ""),
                    supporting_evidence=chain.get("steps", []),
                    confidence=0.65,
                    status="confirmed",
                    provenance="hybrid",
                    verification_level="strongly_verified",
                    verification_notes=chain.get("combined_impact", ""),
                    related_findings=chain.get("findings_involved", []),
                ))
                await self.emit(
                    ctx,
                    f"Exploit chain detected: {chain.get('chain_title', 'Unknown')}",
                )
        except Exception as e:
            await self.emit(ctx, f"Chain detection failed: {e}", level="warn")

    async def _verify_taint_flows(self, ctx: ScanContext):
        """Verify key taint flows by reading source and sink files."""
        unsanitised = [tf for tf in ctx.taint_flows if not tf.sanitised][:5]

        for flow in unsanitised:
            if ctx.cancelled:
                return

            verify_taint_flow_graph(flow, ctx.call_graph, ctx.file_analyses)

            source_content = await self.read_file_range(
                ctx, flow.source_file,
                max(1, flow.source_line - 10), flow.source_line + 10,
            )
            sink_content = await self.read_file_range(
                ctx, flow.sink_file,
                max(1, flow.sink_line - 10), flow.sink_line + 10,
            )

            if "[File not found" in source_content or "[File not found" in sink_content:
                continue

            prompt = (
                f"## Taint Flow Verification\n"
                f"Source ({flow.source_type}): {flow.source_file}:{flow.source_line}\n"
                f"```\n{source_content}\n```\n\n"
                f"Sink ({flow.sink_type}): {flow.sink_file}:{flow.sink_line}\n"
                f"```\n{sink_content}\n```\n\n"
                f"Intermediaries: {', '.join(flow.intermediaries) if flow.intermediaries else 'direct'}\n\n"
                f"{'Static call-graph chain:\\n' + format_call_chain(flow) + '\\n\\n' if flow.graph_verified else ''}"
                f"Is this taint flow real? Is there sanitisation between source and sink? "
                f"Respond with JSON: {{\"valid\": true/false, \"sanitised\": true/false, "
                f"\"sanitiser_location\": \"file:line or null\", \"notes\": \"...\"}}"
            )

            try:
                result = await self.ask_json(
                    ctx,
                    "You are verifying a data flow path from user input to a security-sensitive operation.",
                    prompt,
                    max_tokens=500,
                    allow_tools=True,
                    tool_names=[
                        "read_file",
                        "read_file_range",
                        "search_code",
                        "check_file_exists",
                        "get_file_symbols",
                        "get_call_graph_for_file",
                        "trace_call_chain",
                        "get_callers_of",
                        "get_entry_points_reaching",
                    ],
                    max_tool_rounds=self._MAX_TOOL_ROUNDS,
                )

                if result.get("sanitised"):
                    flow.sanitised = True
                    flow.sanitiser_location = result.get("sanitiser_location")
            except Exception:
                pass

    @staticmethod
    def _eligible_exploit_evidence_findings(
        ctx: ScanContext,
        verification_depth: str,
    ) -> list[CandidateFinding]:
        eligible: list[CandidateFinding] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for finding in ctx.candidate_findings:
            if finding.status != "confirmed":
                continue

            severity = str(finding.severity or "").lower()
            confidence = float(finding.confidence or 0.0)
            has_supporting_context = bool(
                finding.related_cves
                or finding.attack_scenario
                or finding.exploit_template
                or finding.related_findings
            )

            qualifies = (
                severity in {"critical", "high"}
                and confidence >= 0.55
            ) or (
                verification_depth == "deep"
                and severity == "medium"
                and (confidence >= 0.75 or has_supporting_context)
            )
            if not qualifies:
                continue

            dedupe_key = (
                str(finding.title or ""),
                str(finding.file_path or ""),
                severity,
            )
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            eligible.append(finding)

        return sorted(
            eligible,
            key=lambda item: (
                item.severity != "critical",
                item.severity != "high",
                -(item.confidence or 0.0),
                str(item.title or ""),
            ),
        )

    async def _generate_exploit_evidence(self, ctx: ScanContext, findings: list):
        """Generate PoC templates and exploit evidence for confirmed findings."""
        POC_SYSTEM = """You are a security researcher generating proof-of-concept evidence
for a confirmed vulnerability. Your goal is to help analysts validate the finding.

Rules:
1. Generate SAFE detection payloads only — NO destructive exploits
2. Use benign probes: sleep-based SQLi, harmless XSS (alert), file existence checks, DNS lookups
3. The exploit template MUST be real runnable code or commands, not pseudocode
4. The exploit template MUST include setup/auth placeholders, the exact request method/path or invocation route when it can be inferred, the parameters/payload/body, and inline comments showing the expected safe validation signal
5. The attack scenario MUST include: route or entry point, prerequisites, step-by-step execution, expected validation result, and cleanup notes if applicable
6. If some details are uncertain, use explicit placeholders such as <BASE_URL>, <TOKEN>, <ROUTE>, or <ID> rather than omitting them
7. Assess difficulty and prerequisites honestly

Respond with JSON:
{
  "exploit_difficulty": "easy|moderate|difficult|theoretical",
  "prerequisites": ["list of what attacker needs — e.g. authenticated, same network, admin role"],
  "target_route": "HTTP method/path or local invocation route",
  "validation_steps": ["How the analyst confirms the issue safely"],
  "cleanup_notes": ["Any clean-up or state reset guidance"],
  "exploit_template": "The actual PoC code — curl command, Python script, or test case",
  "attack_scenario": "Step-by-step attack flow with explicit setup, execution, and expected result."
}"""

        for finding in findings:
            if ctx.cancelled:
                return

            code_context = await self.read_file(ctx, finding.file_path, max_lines=200)
            user_prompt = await self._build_exploit_evidence_prompt(ctx, finding, code_context)

            try:
                result = await self.llm.chat_json(POC_SYSTEM, user_prompt, max_tokens=1500)
                ctx.ai_calls_made += 1

                finding.exploit_difficulty = result.get("exploit_difficulty", "")
                finding.exploit_prerequisites = result.get("prerequisites", [])
                finding.exploit_template = result.get("exploit_template", "")
                finding.attack_scenario = self._format_attack_scenario(result)
                finding.exploit_evidence = self._build_structured_exploit_evidence(ctx, finding, result)

                await self.emit(
                    ctx,
                    f"PoC generated for: {finding.title} (difficulty: {finding.exploit_difficulty})",
                )

            except Exception as e:
                await self.emit(ctx, f"PoC generation failed for {finding.title}: {e}", level="warn")

    async def _build_exploit_evidence_prompt(
        self,
        ctx: ScanContext,
        finding: CandidateFinding,
        code_context: str,
    ) -> str:
        entry_points = self._relevant_entry_points(ctx, finding)
        related_taint_flows = self._relevant_taint_flows(ctx, finding)
        components = self._components_for_finding(ctx, finding)
        caller_hints: list[str] = []
        if ctx.call_graph:
            for edge in ctx.call_graph.get_file_callers(finding.file_path)[:5]:
                caller_hints.append(
                    f"{edge.caller_symbol} in {edge.caller_file} -> {edge.callee_symbol} "
                    f"(confidence {edge.confidence:.2f})"
                )

        related_file_contexts: list[str] = []
        seen_files = {finding.file_path}
        for ep in entry_points[:2]:
            ep_file = str(ep.get("file") or "").strip()
            if not ep_file or ep_file in seen_files:
                continue
            seen_files.add(ep_file)
            ep_content = await self.read_file(ctx, ep_file, max_lines=120)
            related_file_contexts.append(
                f"### Entry point file: {ep_file}\n```\n{ep_content[:1400]}\n```"
            )

        parts = [
            f"## Vulnerability: {finding.title}",
            f"Severity: {finding.severity} | Category: {finding.category}",
            f"File: {finding.file_path}",
            f"Description: {finding.hypothesis}",
            "",
            "## Analyst Output Requirements",
            "- Generate actual code or commands, not pseudocode.",
            "- Provide the likely route, handler, or invocation path when you can infer it.",
            "- Include authentication/setup assumptions, exact payload parameters or body fields, expected safe validation signals, and cleanup notes.",
            "- Use explicit placeholders when repository context is still incomplete.",
        ]

        if components:
            parts.append("\n## Component Context")
            parts.append("- Components: " + ", ".join(components))

        if finding.code_snippet:
            parts.append(f"\nVulnerable code:\n```\n{finding.code_snippet[:700]}\n```")
        if finding.input_sources:
            parts.append(f"\nInput sources: {', '.join(finding.input_sources[:5])}")
        if finding.sinks:
            parts.append(f"Sinks: {', '.join(finding.sinks[:5])}")

        if entry_points:
            parts.append("\n## Likely Entry Points / Routes")
            for ep in entry_points[:6]:
                label = ep.get("path") or ep.get("function") or ep.get("file") or "entry point"
                ep_type = ep.get("type") or ep.get("method") or "entry point"
                ep_file = ep.get("file") or finding.file_path
                parts.append(f"- {ep_type}: {label} ({ep_file})")

        if caller_hints:
            parts.append("\n## Static Call-Graph Hints")
            for hint in caller_hints:
                parts.append(f"- {hint}")

        if related_taint_flows:
            parts.append("\n## Related Taint Flows")
            for flow in related_taint_flows[:4]:
                parts.append(f"- {flow}")

        parts.append(f"\n## Full File Context\n```\n{code_context[:2600]}\n```")
        if related_file_contexts:
            parts.append("\n## Additional Reachability Context")
            parts.extend(related_file_contexts)

        return "\n".join(parts)

    def _build_structured_exploit_evidence(
        self,
        ctx: ScanContext,
        finding: CandidateFinding,
        result: dict,
    ) -> dict:
        prerequisites = self._clean_string_list(result.get("prerequisites"))
        validation_steps = self._clean_string_list(result.get("validation_steps"))
        cleanup_notes = self._clean_string_list(result.get("cleanup_notes"))
        related_entry_points = [
            self._format_entry_point_hint(entry_point)
            for entry_point in self._relevant_entry_points(ctx, finding)[:4]
        ]
        related_taint_flows = self._relevant_taint_flows(ctx, finding)[:4]
        target_route = str(result.get("target_route") or "").strip()
        if not target_route and related_entry_points:
            target_route = related_entry_points[0]

        payload = {
            "difficulty": str(result.get("exploit_difficulty") or "").strip() or None,
            "target_route": target_route or None,
            "prerequisites": prerequisites,
            "validation_steps": validation_steps,
            "cleanup_notes": cleanup_notes,
            "exploit_template": str(result.get("exploit_template") or "").strip() or None,
            "attack_scenario": str(result.get("attack_scenario") or "").strip() or None,
            "components": self._components_for_finding(ctx, finding),
            "related_entry_points": related_entry_points,
            "related_taint_flows": related_taint_flows,
        }
        return {
            key: value
            for key, value in payload.items()
            if value not in (None, [], "")
        }

    @staticmethod
    def _format_attack_scenario(result: dict) -> str:
        parts: list[str] = []
        route = str(result.get("target_route") or "").strip()
        if route:
            parts.append(f"Route or entry point: {route}")

        scenario = str(result.get("attack_scenario") or "").strip()
        if scenario:
            parts.append(scenario)

        validation_steps = [
            str(step).strip()
            for step in (result.get("validation_steps") or [])
            if str(step).strip()
        ]
        if validation_steps:
            parts.append("Validation:\n" + "\n".join(f"- {step}" for step in validation_steps))

        cleanup_notes = [
            str(step).strip()
            for step in (result.get("cleanup_notes") or [])
            if str(step).strip()
        ]
        if cleanup_notes:
            parts.append("Cleanup:\n" + "\n".join(f"- {step}" for step in cleanup_notes))

        return "\n\n".join(parts)

    @staticmethod
    def _clean_string_list(values) -> list[str]:
        if not isinstance(values, list):
            return []
        cleaned: list[str] = []
        for value in values:
            text = str(value).strip()
            if text:
                cleaned.append(text)
        return cleaned

    @staticmethod
    def _format_entry_point_hint(entry_point: dict) -> str:
        method = str(entry_point.get("method") or "").strip()
        path = str(entry_point.get("path") or "").strip()
        entry_type = str(entry_point.get("type") or "").strip()
        file_path = str(entry_point.get("file") or "").strip()
        function = str(entry_point.get("function") or "").strip()

        headline = " ".join(part for part in [method, path] if part).strip()
        if not headline:
            headline = entry_type or function or file_path or "entry point"

        location_bits = []
        if file_path:
            location_bits.append(file_path)
        if function:
            location_bits.append(function)
        if location_bits:
            headline += f" in {'::'.join(location_bits)}"
        if entry_type and entry_type not in headline:
            headline += f" [{entry_type}]"
        return headline

    @staticmethod
    def _components_for_finding(ctx: ScanContext, finding: CandidateFinding) -> list[str]:
        names: list[str] = []
        for component in ctx.components:
            for path in component.get("files", []):
                if finding.file_path.startswith(path) or finding.file_path == path:
                    name = str(component.get("name") or "component")
                    if name not in names:
                        names.append(name)
                    break
        return names

    @staticmethod
    def _relevant_entry_points(ctx: ScanContext, finding: CandidateFinding) -> list[dict]:
        matches: list[dict] = []
        file_dir = finding.file_path.rsplit("/", 1)[0] if "/" in finding.file_path else finding.file_path
        for entry_point in ctx.entry_points:
            ep_file = str(entry_point.get("file") or "").strip()
            ep_function = str(entry_point.get("function") or "").strip()
            if ep_file == finding.file_path:
                matches.append(entry_point)
                continue
            if ep_file and file_dir and ep_file.startswith(file_dir):
                matches.append(entry_point)
                continue
            if ep_function and (
                ep_function in (finding.code_snippet or "")
                or ep_function in finding.hypothesis
            ):
                matches.append(entry_point)
        return matches

    @staticmethod
    def _relevant_taint_flows(ctx: ScanContext, finding: CandidateFinding) -> list[str]:
        flows: list[str] = []
        for flow in ctx.taint_flows:
            if finding.file_path not in {flow.source_file, flow.sink_file}:
                continue
            verified = " [CALL GRAPH VERIFIED]" if flow.graph_verified else ""
            flows.append(
                f"{flow.source_type} {flow.source_file}:{flow.source_line} -> "
                f"{flow.sink_type} {flow.sink_file}:{flow.sink_line}{verified}"
            )
        return flows

    async def _correlate_cves(self, ctx: ScanContext):
        """Correlate findings with advisory data and persist strong package evidence."""
        from app.analysis.cve_correlator import correlate_by_cwe, find_vulnerable_function_calls

        correlated = 0
        for finding in ctx.candidate_findings:
            if finding.status == "dismissed":
                continue

            cwe_matches = []
            if finding.cwe_ids:
                cwe_matches = correlate_by_cwe(
                    finding.cwe_ids,
                    languages=list(ctx.languages) if ctx.languages else None,
                    max_results=5,
                )

            function_matches = []
            if finding.file_path:
                content = self._read_repo_file(ctx, finding.file_path)
                if content:
                    dep_context = vulnerable_dependency_context_for_file(ctx, finding.file_path)
                    function_matches = [
                        match
                        for match in find_vulnerable_function_calls(
                            finding.file_path,
                            content,
                            languages=list(ctx.languages) if ctx.languages else None,
                            import_resolutions=ctx.import_graph.get(finding.file_path, []),
                            vulnerable_dependencies=dep_context,
                        )
                        if match.get("evidence_strength") in {"strong", "medium"}
                    ]

            merged = self._merge_related_advisories(cwe_matches, function_matches)
            if merged:
                finding.related_cves = merged
                correlated += 1

        if correlated:
            await self.emit(ctx, f"Advisory correlation: {correlated} findings matched with known advisories")
        else:
            await self.emit(ctx, "Advisory correlation: no matches found in advisory database")

    @staticmethod
    def _read_repo_file(ctx: ScanContext, file_path: str, max_chars: int = 20000) -> str:
        try:
            full_path = Path(ctx.repo_path) / file_path
            if not full_path.exists():
                return ""
            return full_path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
        except Exception:
            return ""

    @staticmethod
    def _normalise_related_advisory(match: dict) -> dict:
        display_id = match.get("display_id") or match.get("cve_id") or match.get("advisory_id")
        evidence_type = match.get("match_type") or match.get("evidence_type") or "related_by_cwe"
        evidence_source = match.get("package_evidence_source")
        if not evidence_source and evidence_type == "related_by_cwe":
            evidence_source = "cwe_correlation"

        return {
            "display_id": display_id,
            "cve_id": match.get("cve_id"),
            "advisory_id": match.get("advisory_id"),
            "package": match.get("package", ""),
            "ecosystem": match.get("ecosystem"),
            "severity": match.get("severity", "medium"),
            "summary": match.get("summary", ""),
            "fixed_version": match.get("fixed_version"),
            "evidence_type": evidence_type,
            "evidence_strength": match.get("evidence_strength") or "contextual",
            "package_evidence_source": evidence_source,
            "package_match_confidence": match.get("package_match_confidence"),
            "import_module": match.get("import_module"),
            "imported_symbol": match.get("imported_symbol"),
            "call_object": match.get("call_object"),
            "function": match.get("function"),
            "line": match.get("line"),
            "cwe_ids": match.get("cwe_ids") or match.get("cwes") or [],
            "evidence_types": [evidence_type],
            "evidence_sources": [evidence_source] if evidence_source else [],
        }

    @classmethod
    def _merge_related_advisories(
        cls,
        cwe_matches: list[dict],
        function_matches: list[dict],
        *,
        max_results: int = 5,
    ) -> list[dict]:
        strength_rank = {"strong": 3, "medium": 2, "weak": 1, "contextual": 0}
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        merged: dict[str, dict] = {}

        for raw_match in [*cwe_matches, *function_matches]:
            entry = cls._normalise_related_advisory(raw_match)
            key = (
                entry.get("display_id")
                or entry.get("advisory_id")
                or entry.get("cve_id")
                or f"{entry.get('package', '')}:{entry.get('summary', '')}"
            )
            existing = merged.get(key)
            if not existing:
                merged[key] = entry
                continue

            current_score = (
                strength_rank.get(entry.get("evidence_strength", ""), 0),
                float(entry.get("package_match_confidence") or 0.0),
                severity_rank.get(str(entry.get("severity", "")).lower(), 0),
            )
            existing_score = (
                strength_rank.get(existing.get("evidence_strength", ""), 0),
                float(existing.get("package_match_confidence") or 0.0),
                severity_rank.get(str(existing.get("severity", "")).lower(), 0),
            )

            winner = entry if current_score > existing_score else existing
            loser = existing if winner is entry else entry

            winner["evidence_types"] = sorted(
                {
                    *(winner.get("evidence_types") or []),
                    *(loser.get("evidence_types") or []),
                    winner.get("evidence_type"),
                    loser.get("evidence_type"),
                }
                - {None, ""}
            )
            winner["evidence_sources"] = sorted(
                {
                    *(winner.get("evidence_sources") or []),
                    *(loser.get("evidence_sources") or []),
                    winner.get("package_evidence_source"),
                    loser.get("package_evidence_source"),
                }
                - {None, ""}
            )

            for field in (
                "summary",
                "fixed_version",
                "import_module",
                "imported_symbol",
                "call_object",
                "function",
                "line",
            ):
                if not winner.get(field) and loser.get(field):
                    winner[field] = loser[field]

            combined_cwes = {
                *(winner.get("cwe_ids") or []),
                *(loser.get("cwe_ids") or []),
            }
            if combined_cwes:
                winner["cwe_ids"] = sorted(combined_cwes)

            merged[key] = winner

        ranked = sorted(
            merged.values(),
            key=lambda item: (
                -strength_rank.get(item.get("evidence_strength", ""), 0),
                -float(item.get("package_match_confidence") or 0.0),
                -severity_rank.get(str(item.get("severity", "")).lower(), 0),
                str(item.get("display_id") or item.get("package") or ""),
            ),
        )
        return ranked[:max_results]

    @staticmethod
    def _severity_rank(severity: str | None) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(str(severity or "").lower(), 0)

    @staticmethod
    def _verification_rank(level: str | None) -> int:
        return {
            "dismissed": -1,
            "hypothesis": 0,
            "statically_verified": 1,
            "strongly_verified": 2,
            "runtime_validated": 3,
        }.get(str(level or "").lower(), 0)

    @staticmethod
    def _normalise_text(value: str | None, *, limit: int = 160) -> str:
        text = re.sub(r"\s+", " ", str(value or "").strip()).lower()
        return text[:limit]

    @staticmethod
    def _normalise_path(value: str | None) -> str:
        return str(value or "").replace("\\", "/").strip().lstrip("./").lower()

    @staticmethod
    def _parse_line_range(line_range: str | None) -> tuple[int | None, int | None]:
        text = str(line_range or "").strip()
        if not text:
            return None, None
        parts = text.split("-", 1)
        try:
            start = int(parts[0].strip())
        except (TypeError, ValueError):
            return None, None
        end = start
        if len(parts) > 1:
            try:
                end = int(parts[1].strip())
            except (TypeError, ValueError):
                end = start
        if end < start:
            start, end = end, start
        return start, end

    @staticmethod
    def _token_set(value: str | None) -> set[str]:
        return {
            token
            for token in re.split(r"[^a-z0-9]+", str(value or "").lower())
            if len(token) >= 3
        }

    @classmethod
    def _build_canonical_key(cls, finding: CandidateFinding) -> str:
        path_key = cls._normalise_path(finding.file_path)
        category_key = cls._normalise_text(finding.category, limit=60)
        line_start, _line_end = cls._parse_line_range(finding.line_range)
        cwe_key = "|".join(sorted(str(cwe).upper() for cwe in (finding.cwe_ids or [])[:3]))
        sink_key = cls._normalise_text((finding.sinks or [""])[0], limit=60)
        title_key = cls._normalise_text(finding.title, limit=80)
        anchor = cwe_key or sink_key or (str(line_start) if line_start else title_key)
        return "|".join(part for part in [path_key, category_key, anchor] if part)

    @classmethod
    def _line_ranges_overlap(cls, finding_a: CandidateFinding, finding_b: CandidateFinding) -> bool:
        start_a, end_a = cls._parse_line_range(finding_a.line_range)
        start_b, end_b = cls._parse_line_range(finding_b.line_range)
        if not start_a or not start_b:
            return False
        return start_a <= (end_b or start_b) and start_b <= (end_a or start_a)

    @classmethod
    def _title_similarity(cls, left: str | None, right: str | None) -> float:
        left_tokens = cls._token_set(left)
        right_tokens = cls._token_set(right)
        if not left_tokens or not right_tokens:
            return 0.0
        return len(left_tokens & right_tokens) / max(len(left_tokens | right_tokens), 1)

    @classmethod
    def _is_probable_duplicate(cls, canonical: CandidateFinding, candidate: CandidateFinding) -> bool:
        if cls._build_canonical_key(canonical) == cls._build_canonical_key(candidate):
            return True

        if cls._normalise_path(canonical.file_path) != cls._normalise_path(candidate.file_path):
            return False

        if cls._normalise_text(canonical.category, limit=60) != cls._normalise_text(candidate.category, limit=60):
            return False

        if cls._line_ranges_overlap(canonical, candidate):
            return True

        if set(canonical.cwe_ids or []) & set(candidate.cwe_ids or []):
            return True

        if set(canonical.sinks or []) & set(candidate.sinks or []):
            return True

        if set(canonical.input_sources or []) & set(candidate.input_sources or []):
            return True

        return cls._title_similarity(canonical.title, candidate.title) >= 0.55

    @staticmethod
    def _merge_string_lists(existing: list[str] | None, new_values: list[str] | None) -> list[str]:
        seen: set[str] = set()
        merged: list[str] = []
        for value in [*(existing or []), *(new_values or [])]:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            merged.append(text)
        return merged

    @staticmethod
    def _merge_dict_list(
        existing: list[dict] | None,
        new_values: list[dict] | None,
        *,
        key_fields: tuple[str, ...],
    ) -> list[dict]:
        merged: list[dict] = []
        seen: set[tuple] = set()
        for item in [*(existing or []), *(new_values or [])]:
            if not isinstance(item, dict):
                continue
            key = tuple(str(item.get(field) or "").strip().lower() for field in key_fields)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    @classmethod
    def _merge_provenance(cls, left: str | None, right: str | None) -> str:
        values = {str(left or "").strip().lower(), str(right or "").strip().lower()} - {""}
        if "hybrid" in values or values == {"llm", "scanner"}:
            return "hybrid"
        if "scanner" in values and len(values) == 1:
            return "scanner"
        if "llm" in values and len(values) == 1:
            return "llm"
        return "hybrid" if len(values) > 1 else (values.pop() if values else "llm")

    @classmethod
    def _merge_findings(cls, canonical: CandidateFinding, duplicate: CandidateFinding) -> CandidateFinding:
        if cls._severity_rank(duplicate.severity) > cls._severity_rank(canonical.severity):
            canonical.severity = duplicate.severity
        canonical.confidence = max(float(canonical.confidence or 0.0), float(duplicate.confidence or 0.0))
        if duplicate.code_snippet and not canonical.code_snippet:
            canonical.code_snippet = duplicate.code_snippet
        if duplicate.hypothesis and len(str(duplicate.hypothesis)) > len(str(canonical.hypothesis or "")):
            canonical.hypothesis = duplicate.hypothesis
        canonical.supporting_evidence = cls._merge_string_lists(
            canonical.supporting_evidence,
            duplicate.supporting_evidence,
        )
        canonical.opposing_evidence = cls._merge_string_lists(
            canonical.opposing_evidence,
            duplicate.opposing_evidence,
        )
        canonical.input_sources = cls._merge_string_lists(canonical.input_sources, duplicate.input_sources)
        canonical.sinks = cls._merge_string_lists(canonical.sinks, duplicate.sinks)
        canonical.cwe_ids = cls._merge_string_lists(canonical.cwe_ids, duplicate.cwe_ids)
        canonical.related_findings = cls._merge_string_lists(
            canonical.related_findings,
            duplicate.related_findings,
        )
        canonical.source_scanners = cls._merge_string_lists(
            canonical.source_scanners,
            duplicate.source_scanners,
        )
        canonical.source_rules = cls._merge_string_lists(canonical.source_rules, duplicate.source_rules)
        canonical.source_scanner_hits = cls._merge_dict_list(
            canonical.source_scanner_hits,
            duplicate.source_scanner_hits,
            key_fields=("scanner", "rule_id", "message", "line"),
        )
        canonical.related_cves = cls._merge_dict_list(
            canonical.related_cves,
            duplicate.related_cves,
            key_fields=("display_id", "cve_id", "advisory_id", "package"),
        )
        canonical.exploit_prerequisites = cls._merge_string_lists(
            canonical.exploit_prerequisites,
            duplicate.exploit_prerequisites,
        )
        canonical.provenance = cls._merge_provenance(canonical.provenance, duplicate.provenance)
        if cls._verification_rank(duplicate.verification_level) > cls._verification_rank(canonical.verification_level):
            canonical.verification_level = duplicate.verification_level
        canonical.verification_notes = "\n\n".join(
            cls._merge_string_lists(
                [canonical.verification_notes] if canonical.verification_notes else [],
                [duplicate.verification_notes] if duplicate.verification_notes else [],
            )
        )
        if not canonical.exploit_evidence and duplicate.exploit_evidence:
            canonical.exploit_evidence = duplicate.exploit_evidence
        if not canonical.exploit_template and duplicate.exploit_template:
            canonical.exploit_template = duplicate.exploit_template
        if not canonical.attack_scenario and duplicate.attack_scenario:
            canonical.attack_scenario = duplicate.attack_scenario
        if not canonical.exploit_difficulty and duplicate.exploit_difficulty:
            canonical.exploit_difficulty = duplicate.exploit_difficulty
        merged_titles = cls._merge_string_lists(
            list((canonical.merge_metadata or {}).get("merged_titles") or [canonical.title]),
            list((duplicate.merge_metadata or {}).get("merged_titles") or [duplicate.title]),
        )
        merged_provenance = cls._merge_string_lists(
            list((canonical.merge_metadata or {}).get("merged_provenance") or [canonical.provenance]),
            list((duplicate.merge_metadata or {}).get("merged_provenance") or [duplicate.provenance]),
        )
        canonical.merge_metadata = {
            "merged_count": len(merged_titles),
            "merged_titles": merged_titles,
            "merged_provenance": merged_provenance,
            "source_file": canonical.file_path,
        }
        canonical.canonical_key = cls._build_canonical_key(canonical)
        return canonical

    def _relevant_taint_flows_for_finding(self, ctx: ScanContext, finding: CandidateFinding) -> list:
        flows = []
        path_key = self._normalise_path(finding.file_path)
        for flow in ctx.taint_flows:
            if self._normalise_path(flow.source_file) == path_key or self._normalise_path(flow.sink_file) == path_key:
                flows.append(flow)
        return flows

    def _finalise_verified_findings(self, ctx: ScanContext) -> tuple[int, int]:
        confirmed = [finding for finding in ctx.candidate_findings if finding.status != "dismissed"]
        dismissed = [finding for finding in ctx.candidate_findings if finding.status == "dismissed"]

        for finding in confirmed:
            strong_signals = 0
            if finding.exploit_evidence or finding.exploit_template:
                strong_signals += 1
            if any(
                str(advisory.get("evidence_strength") or "").lower() in {"strong", "medium"}
                or "confirmed" in str(advisory.get("evidence_type") or "").lower()
                for advisory in (finding.related_cves or [])
                if isinstance(advisory, dict)
            ):
                strong_signals += 1
            if any(flow.graph_verified and not flow.sanitised for flow in self._relevant_taint_flows_for_finding(ctx, finding)):
                strong_signals += 1
            if float(finding.confidence or 0.0) >= 0.9:
                strong_signals += 1

            if self._verification_rank(finding.verification_level) < self._verification_rank("statically_verified"):
                finding.verification_level = "statically_verified"
            if strong_signals >= 2:
                finding.verification_level = "strongly_verified"

            if (
                str(finding.severity or "").lower() in {"critical", "high"}
                and strong_signals == 0
                and float(finding.confidence or 0.0) < 0.65
            ):
                original = str(finding.severity or "").lower()
                finding.severity = "high" if original == "critical" else "medium"
                downgrade_note = (
                    f"Severity downgraded from {original} because verification remained purely static "
                    "and supporting signals were limited."
                )
                finding.verification_notes = "\n\n".join(
                    self._merge_string_lists(
                        [finding.verification_notes] if finding.verification_notes else [],
                        [downgrade_note],
                    )
                )

            finding.canonical_key = self._build_canonical_key(finding)

        confirmed.sort(
            key=lambda item: (
                -self._severity_rank(item.severity),
                -float(item.confidence or 0.0),
                self._normalise_text(item.title),
            )
        )

        canonical_findings: list[CandidateFinding] = []
        merged_count = 0
        for finding in confirmed:
            duplicate_of = next(
                (existing for existing in canonical_findings if self._is_probable_duplicate(existing, finding)),
                None,
            )
            if duplicate_of is None:
                canonical_findings.append(finding)
                if not finding.merge_metadata:
                    finding.merge_metadata = {
                        "merged_count": 1,
                        "merged_titles": [finding.title],
                        "merged_provenance": [finding.provenance],
                        "source_file": finding.file_path,
                    }
                continue
            self._merge_findings(duplicate_of, finding)
            merged_count += 1

        ctx.candidate_findings = [*canonical_findings, *dismissed]
        return len(canonical_findings), merged_count

    @staticmethod
    def _candidate_attack_text(candidate: CandidateFinding) -> str | None:
        if not candidate.attack_scenario:
            return None
        if isinstance(candidate.attack_scenario, list):
            return "\n".join(str(s) for s in candidate.attack_scenario)
        return str(candidate.attack_scenario)

    @staticmethod
    def _candidate_description(candidate: CandidateFinding) -> str:
        description = candidate.hypothesis or candidate.title or "No description"
        if isinstance(description, list):
            return "\n".join(str(s) for s in description)
        return str(description)

    @staticmethod
    def _candidate_confidence(candidate: CandidateFinding) -> float:
        confidence = candidate.confidence
        if isinstance(confidence, str):
            try:
                return float(confidence)
            except (TypeError, ValueError):
                return 0.5
        return float(confidence or 0.0)

    def _build_finding_model(self, ctx: ScanContext, candidate: CandidateFinding) -> Finding:
        return Finding(
            scan_id=ctx.scan_id,
            title=str(candidate.title or "Untitled")[:500],
            severity=str(candidate.severity or "medium")[:20],
            confidence=self._candidate_confidence(candidate),
            category=str(candidate.category or "general")[:100] if candidate.category else None,
            description=self._candidate_description(candidate),
            code_snippet=str(candidate.code_snippet) if candidate.code_snippet else None,
            status=str(candidate.status or "confirmed")[:20],
            provenance=str(candidate.provenance or "llm")[:20],
            source_scanners=candidate.source_scanners if isinstance(candidate.source_scanners, list) else None,
            source_rules=candidate.source_rules if isinstance(candidate.source_rules, list) else None,
            verification_level=str(candidate.verification_level or "hypothesis")[:32],
            verification_notes=str(candidate.verification_notes) if candidate.verification_notes else None,
            canonical_key=str(candidate.canonical_key)[:255] if candidate.canonical_key else None,
            merge_metadata=candidate.merge_metadata if isinstance(candidate.merge_metadata, dict) else None,
            cwe_ids=candidate.cwe_ids if isinstance(candidate.cwe_ids, list) else None,
            related_cves=candidate.related_cves if isinstance(candidate.related_cves, list) else None,
            exploit_difficulty=str(candidate.exploit_difficulty)[:20] if candidate.exploit_difficulty else None,
            exploit_prerequisites=candidate.exploit_prerequisites if isinstance(candidate.exploit_prerequisites, list) else None,
            exploit_template=str(candidate.exploit_template) if candidate.exploit_template else None,
            attack_scenario=self._candidate_attack_text(candidate),
            exploit_evidence=candidate.exploit_evidence if isinstance(candidate.exploit_evidence, dict) else None,
        )

    @staticmethod
    def _resolve_file_id(candidate: CandidateFinding, path_to_file_id: dict) -> object | None:
        if not candidate.file_path:
            return None
        fp = candidate.file_path.replace("\\", "/")
        file_id = path_to_file_id.get(fp)
        if not file_id and fp.startswith("/"):
            file_id = path_to_file_id.get(fp.lstrip("/"))
        if not file_id:
            for db_path, fid in path_to_file_id.items():
                if db_path.endswith(fp) or fp.endswith(db_path):
                    file_id = fid
                    break
        return file_id

    def _attach_candidate_evidence(self, session, finding: Finding, candidate: CandidateFinding) -> None:
        for hit in candidate.source_scanner_hits or []:
            scanner_name = str(hit.get("scanner") or "").strip()
            rule_id = str(hit.get("rule_id") or "").strip()
            message = str(hit.get("message") or "").strip()
            if not any([scanner_name, rule_id, message]):
                continue
            line = hit.get("line")
            end_line = hit.get("end_line")
            line_range = None
            if isinstance(line, int) and line > 0:
                line_range = f"{line}-{end_line}" if isinstance(end_line, int) and end_line and end_line != line else str(line)
            description_bits = [bit for bit in [rule_id, message] if bit]
            session.add(
                Evidence(
                    finding_id=finding.id,
                    type="contextual",
                    description=" | ".join(description_bits) if description_bits else scanner_name,
                    line_range=line_range,
                    source=scanner_name or "scanner",
                )
            )

        for ev_text in (candidate.supporting_evidence or []):
            if ev_text:
                session.add(
                    Evidence(
                        finding_id=finding.id,
                        type="supporting",
                        description=str(ev_text),
                        source="ai_inspection",
                    )
                )

        for ev_text in (candidate.opposing_evidence or []):
            if ev_text:
                session.add(
                    Evidence(
                        finding_id=finding.id,
                        type="opposing",
                        description=str(ev_text),
                        source="ai_inspection",
                    )
                )

    async def _persist_findings(self, ctx: ScanContext):
        """Save confirmed findings to the database."""
        from sqlalchemy import select
        from app.models.file import File

        persisted = 0
        async with async_session() as session:
            # Pre-load file path→id map for this scan
            file_rows = (await session.execute(
                select(File.id, File.path).where(File.scan_id == ctx.scan_id)
            )).all()
            path_to_file_id = {row.path: row.id for row in file_rows}
            logger.info("File path map has %d entries for scan %s", len(path_to_file_id), ctx.scan_id)

            for idx, candidate in enumerate(ctx.candidate_findings):
                if candidate.status == "dismissed":
                    continue

                try:
                    finding = self._build_finding_model(ctx, candidate)
                    session.add(finding)
                    await session.flush()
                    candidate.finding_id = str(finding.id)
                    persisted += 1

                    # Link finding to its source file
                    file_id = self._resolve_file_id(candidate, path_to_file_id)
                    if file_id:
                        session.add(FindingFile(
                            finding_id=finding.id,
                            file_id=file_id,
                        ))

                    self._attach_candidate_evidence(session, finding, candidate)

                except Exception as e:
                    logger.error(
                        "Failed to build finding %d '%s': %s",
                        idx, getattr(candidate, 'title', '?'), e, exc_info=True,
                    )

            try:
                await session.commit()
                logger.info("Committed %d findings to database for scan %s", persisted, ctx.scan_id)
            except Exception as e:
                logger.error("Batch commit failed: %s — retrying one-by-one", e)
                await session.rollback()
                # Fallback: persist one at a time
                persisted = await self._persist_findings_one_by_one(ctx, path_to_file_id)

        ctx.findings_count = persisted

    async def _persist_findings_one_by_one(
        self, ctx: ScanContext, path_to_file_id: dict
    ) -> int:
        """Fallback: persist findings individually so one bad row doesn't block all."""
        persisted = 0
        for candidate in ctx.candidate_findings:
            if candidate.status == "dismissed":
                continue
            try:
                async with async_session() as session:
                    finding = self._build_finding_model(ctx, candidate)
                    session.add(finding)
                    await session.flush()
                    candidate.finding_id = str(finding.id)

                    file_id = self._resolve_file_id(candidate, path_to_file_id)
                    if file_id:
                        session.add(FindingFile(finding_id=finding.id, file_id=file_id))

                    self._attach_candidate_evidence(session, finding, candidate)

                    await session.commit()
                    persisted += 1
            except Exception as e:
                logger.error("Failed to persist finding '%s': %s", getattr(candidate, 'title', '?'), e)
        return persisted

    def _build_verify_prompt(
        self, ctx: ScanContext, batch: list[CandidateFinding], file_contents: dict
    ) -> str:
        parts = [
            "## Application Context",
            f"App: {ctx.app_summary[:800]}" if ctx.app_summary else "",
            f"Frameworks: {', '.join(ctx.frameworks)}",
        ]

        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            parts.append(
                "\n## DECOMPILED ANDROID APP — "
                "This is jadx-decompiled code. When verifying findings:\n"
                "- Do NOT flag decompilation artifacts (goto, synthetic methods, renamed vars) as vulnerabilities\n"
                "- DO verify Android-specific issues: exported components, insecure WebView, "
                "plaintext SharedPreferences, disabled cert validation, debuggable flag, backup=true\n"
                "- PoC templates should use adb/intent commands where appropriate\n"
                "- Assess exploit difficulty considering the APK context (device access, rooted device, network MITM)"
            )

        if ctx.taint_flows:
            parts.append(f"\nKnown taint flows: {len(ctx.taint_flows)}")
            for tf in ctx.taint_flows[:5]:
                san = " [SANITISED]" if tf.sanitised else ""
                parts.append(f"- {tf.source_type} → {tf.sink_type}{san}")

        parts.append("\n## Candidate Findings to Verify")

        for i, f in enumerate(batch, 1):
            parts.append(f"\n### Finding {i}: {f.title}")
            parts.append(f"Category: {f.category}")
            parts.append(f"Severity: {f.severity}")
            parts.append(f"File: {f.file_path}")
            parts.append(f"Hypothesis: {f.hypothesis}")
            parts.append(f"Current confidence: {f.confidence}")
            parts.append(f"Current verification level: {f.verification_level}")
            if f.provenance:
                parts.append(f"Provenance: {f.provenance}")
            if f.source_scanners:
                parts.append(f"Source scanners: {'; '.join(f.source_scanners[:5])}")
            if f.source_rules:
                parts.append(f"Source rules: {'; '.join(f.source_rules[:5])}")
            if f.input_sources:
                parts.append(f"Input sources: {'; '.join(f.input_sources[:5])}")
            if f.sinks:
                parts.append(f"Sinks: {'; '.join(f.sinks[:5])}")
            if f.supporting_evidence:
                parts.append(f"Supporting evidence: {'; '.join(f.supporting_evidence[:3])}")
            if f.opposing_evidence:
                parts.append(f"Opposing evidence: {'; '.join(f.opposing_evidence[:3])}")

        # Call graph context for reachability verification
        if ctx.call_graph:
            parts.append("\n## Call Graph Context (for reachability verification)")
            for path in file_contents:
                callers = ctx.call_graph.get_file_callers(path)
                if callers:
                    parts.append(f"**{path}** is called by:")
                    for e in callers[:5]:
                        parts.append(f"- {e.caller_symbol}() in `{e.caller_file}`")

        parts.append("\n## Source Code")
        for path, content in file_contents.items():
            parts.append(f"\n### {path}")
            parts.append(f"```\n{content[:5000]}\n```")

        return "\n".join(parts)
