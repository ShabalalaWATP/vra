"""Verifier Agent — challenge findings, reduce false positives, detect exploit chains.

Key improvements:
- Cross-finding correlation: detects when multiple findings together form a chain
- Exploit chain detection: identifies multi-step attack paths
- Taint flow verification: checks if discovered taint flows are actually exploitable
- Deeper verification for high-severity findings
- Adaptive batch size based on finding complexity
"""

import logging

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
            confirmed_high = [
                f for f in ctx.candidate_findings
                if f.status == "confirmed"
                and f.severity in ("critical", "high")
                and f.confidence >= 0.7
            ]
            if confirmed_high:
                await self.emit_progress(ctx, task=f"Generating exploit evidence for {len(confirmed_high)} findings")
                await self.emit(ctx, f"Generating PoC for {len(confirmed_high)} critical/high findings...")
                await self._generate_exploit_evidence(ctx, confirmed_high)

        # ── CVE Correlation ────────────────────────────────────────
        await self.emit_progress(ctx, task="Correlating findings with CVE database")
        await self.emit(ctx, "Correlating findings against CVE/advisory database...")
        await self._correlate_cves(ctx)

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
                max_tool_rounds=2,
            )
        except Exception as e:
            await self.emit(ctx, f"Verification batch failed: {e}", level="warn")
            return

        # Update findings
        for v in result.get("verified_findings", []):
            title = v.get("original_title", "")
            for finding in batch:
                if finding.title == title:
                    if v.get("is_valid", False):
                        finding.status = "confirmed"
                        finding.severity = v.get("adjusted_severity", finding.severity)
                        finding.confidence = v.get("adjusted_confidence", finding.confidence)
                        finding.opposing_evidence.extend(v.get("counter_evidence", []))
                        # Store exploitability and prereqs in hypothesis
                        exploitability = v.get("exploitability", "")
                        prereqs = v.get("prerequisites", [])
                        if exploitability:
                            finding.hypothesis += f"\n\nExploitability: {exploitability}"
                        if prereqs:
                            finding.hypothesis += f"\nPrerequisites: {', '.join(prereqs)}"
                    else:
                        finding.status = "dismissed"
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
                    max_tool_rounds=2,
                )

                if result.get("sanitised"):
                    flow.sanitised = True
                    flow.sanitiser_location = result.get("sanitiser_location")
            except Exception:
                pass

    async def _generate_exploit_evidence(self, ctx: ScanContext, findings: list):
        """Generate PoC templates and exploit evidence for confirmed high-severity findings."""
        POC_SYSTEM = """You are a security researcher generating proof-of-concept evidence
for a confirmed vulnerability. Your goal is to help analysts validate the finding.

Rules:
1. Generate SAFE detection payloads only — NO destructive exploits
2. Use benign probes: sleep-based SQLi, harmless XSS (alert), file existence checks, DNS lookups
3. Provide practical reproduction steps (curl, Python, browser)
4. Assess difficulty and prerequisites honestly

Respond with JSON:
{
  "exploit_difficulty": "easy|moderate|difficult|theoretical",
  "prerequisites": ["list of what attacker needs — e.g. authenticated, same network, admin role"],
  "exploit_template": "The actual PoC code — curl command, Python script, or test case",
  "attack_scenario": "Step by step: 1. Attacker does X. 2. Input reaches Y. 3. Result is Z."
}"""

        for finding in findings[:5]:  # Cap at 5 to control AI budget
            if ctx.cancelled:
                return

            code_context = await self.read_file(ctx, finding.file_path, max_lines=200)

            user_prompt = (
                f"## Vulnerability: {finding.title}\n"
                f"Severity: {finding.severity} | Category: {finding.category}\n"
                f"File: {finding.file_path}\n"
                f"Description: {finding.hypothesis}\n"
            )
            if finding.code_snippet:
                user_prompt += f"\nVulnerable code:\n```\n{finding.code_snippet[:500]}\n```\n"
            if finding.input_sources:
                user_prompt += f"\nInput sources: {', '.join(finding.input_sources[:3])}\n"
            if finding.sinks:
                user_prompt += f"\nSinks: {', '.join(finding.sinks[:3])}\n"

            user_prompt += f"\nFull file context:\n```\n{code_context[:2000]}\n```"

            try:
                result = await self.llm.chat_json(POC_SYSTEM, user_prompt, max_tokens=1500)
                ctx.ai_calls_made += 1

                finding.exploit_difficulty = result.get("exploit_difficulty", "")
                finding.exploit_prerequisites = result.get("prerequisites", [])
                finding.exploit_template = result.get("exploit_template", "")
                finding.attack_scenario = result.get("attack_scenario", "")

                await self.emit(
                    ctx,
                    f"PoC generated for: {finding.title} (difficulty: {finding.exploit_difficulty})",
                )

            except Exception as e:
                await self.emit(ctx, f"PoC generation failed for {finding.title}: {e}", level="warn")

    async def _correlate_cves(self, ctx: ScanContext):
        """Correlate confirmed findings with CVE database using CWE matching."""
        from app.analysis.cve_correlator import correlate_by_cwe

        correlated = 0
        for finding in ctx.candidate_findings:
            if finding.status == "dismissed" or not finding.cwe_ids:
                continue

            matches = correlate_by_cwe(
                finding.cwe_ids,
                languages=list(ctx.languages) if ctx.languages else None,
                max_results=3,
            )

            if matches:
                finding.related_cves = [
                    {
                        "cve_id": m["cve_id"],
                        "package": m["package"],
                        "severity": m["severity"],
                        "summary": m["summary"],
                        "fixed_version": m.get("fixed_version"),
                    }
                    for m in matches
                ]
                correlated += 1

        if correlated:
            await self.emit(ctx, f"CVE correlation: {correlated} findings matched with known CVEs")
        else:
            await self.emit(ctx, "CVE correlation: no matches found in advisory database")

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
                    # Safely coerce fields
                    attack_text = None
                    if candidate.attack_scenario:
                        if isinstance(candidate.attack_scenario, list):
                            attack_text = "\n".join(str(s) for s in candidate.attack_scenario)
                        else:
                            attack_text = str(candidate.attack_scenario)

                    desc = candidate.hypothesis or candidate.title or "No description"
                    if isinstance(desc, list):
                        desc = "\n".join(str(s) for s in desc)

                    conf = candidate.confidence
                    if isinstance(conf, str):
                        try:
                            conf = float(conf)
                        except (ValueError, TypeError):
                            conf = 0.5

                    finding = Finding(
                        scan_id=ctx.scan_id,
                        title=str(candidate.title or "Untitled")[:500],
                        severity=str(candidate.severity or "medium")[:20],
                        confidence=conf,
                        category=str(candidate.category or "general")[:100] if candidate.category else None,
                        description=desc,
                        code_snippet=str(candidate.code_snippet) if candidate.code_snippet else None,
                        status=str(candidate.status or "confirmed")[:20],
                        cwe_ids=candidate.cwe_ids if isinstance(candidate.cwe_ids, list) else None,
                        related_cves=candidate.related_cves if isinstance(candidate.related_cves, list) else None,
                        exploit_difficulty=str(candidate.exploit_difficulty)[:20] if candidate.exploit_difficulty else None,
                        exploit_prerequisites=candidate.exploit_prerequisites if isinstance(candidate.exploit_prerequisites, list) else None,
                        exploit_template=str(candidate.exploit_template) if candidate.exploit_template else None,
                        attack_scenario=attack_text,
                    )
                    session.add(finding)
                    await session.flush()
                    persisted += 1

                    # Link finding to its source file
                    if candidate.file_path:
                        fp = candidate.file_path.replace("\\", "/")
                        file_id = path_to_file_id.get(fp)
                        if not file_id and fp.startswith("/"):
                            file_id = path_to_file_id.get(fp.lstrip("/"))
                        if not file_id:
                            for db_path, fid in path_to_file_id.items():
                                if db_path.endswith(fp) or fp.endswith(db_path):
                                    file_id = fid
                                    break
                        if file_id:
                            session.add(FindingFile(
                                finding_id=finding.id,
                                file_id=file_id,
                            ))

                    for ev_text in (candidate.supporting_evidence or []):
                        if ev_text:
                            session.add(Evidence(
                                finding_id=finding.id,
                                type="supporting",
                                description=str(ev_text),
                                source="ai_inspection",
                            ))

                    for ev_text in (candidate.opposing_evidence or []):
                        if ev_text:
                            session.add(Evidence(
                                finding_id=finding.id,
                                type="opposing",
                                description=str(ev_text),
                                source="ai_inspection",
                            ))

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
                    attack_text = None
                    if candidate.attack_scenario:
                        attack_text = (
                            "\n".join(str(s) for s in candidate.attack_scenario)
                            if isinstance(candidate.attack_scenario, list)
                            else str(candidate.attack_scenario)
                        )
                    desc = candidate.hypothesis or candidate.title or "No description"
                    if isinstance(desc, list):
                        desc = "\n".join(str(s) for s in desc)
                    conf = candidate.confidence
                    if isinstance(conf, str):
                        try:
                            conf = float(conf)
                        except (ValueError, TypeError):
                            conf = 0.5

                    finding = Finding(
                        scan_id=ctx.scan_id,
                        title=str(candidate.title or "Untitled")[:500],
                        severity=str(candidate.severity or "medium")[:20],
                        confidence=conf,
                        category=str(candidate.category or "general")[:100] if candidate.category else None,
                        description=desc,
                        code_snippet=str(candidate.code_snippet) if candidate.code_snippet else None,
                        status=str(candidate.status or "confirmed")[:20],
                        cwe_ids=candidate.cwe_ids if isinstance(candidate.cwe_ids, list) else None,
                        related_cves=candidate.related_cves if isinstance(candidate.related_cves, list) else None,
                        exploit_difficulty=str(candidate.exploit_difficulty)[:20] if candidate.exploit_difficulty else None,
                        exploit_prerequisites=candidate.exploit_prerequisites if isinstance(candidate.exploit_prerequisites, list) else None,
                        exploit_template=str(candidate.exploit_template) if candidate.exploit_template else None,
                        attack_scenario=attack_text,
                    )
                    session.add(finding)
                    await session.flush()

                    if candidate.file_path:
                        fp = candidate.file_path.replace("\\", "/")
                        file_id = path_to_file_id.get(fp)
                        if not file_id and fp.startswith("/"):
                            file_id = path_to_file_id.get(fp.lstrip("/"))
                        if not file_id:
                            for db_path, fid in path_to_file_id.items():
                                if db_path.endswith(fp) or fp.endswith(db_path):
                                    file_id = fid
                                    break
                        if file_id:
                            session.add(FindingFile(finding_id=finding.id, file_id=file_id))

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
