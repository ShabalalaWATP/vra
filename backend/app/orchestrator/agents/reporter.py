"""Reporter Agent — generate final report and narratives."""

import json
import logging
import re
from collections import Counter

from app.config import settings
from app.database import async_session
from app.analysis.dependency_inventory import dependency_identity_key
from app.models.report import Report
from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security report writer. Generate a professional vulnerability assessment report section.

Given the application understanding and findings, produce:
1. A clear, professional executive summary of the application
2. A methodology section explaining the analysis approach
3. A limitations section noting blind spots and caveats
4. For each finding, a narrative explanation suitable for a technical audience

Write in clear, professional English. Be specific and evidence-based.
Do not use marketing language or hyperbole.

Respond with JSON:
{
  "executive_summary": "...",
  "methodology": "...",
  "limitations": "...",
  "finding_narratives": [
    {
      "title": "...",
      "explanation": "detailed explanation of the vulnerability",
      "impact": "what could happen if exploited",
      "remediation": "specific fix recommendations"
    }
  ]
}"""


class ReporterAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "reporter"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_phase = "reporting"
        ctx.current_task = "Generating report"
        await self.emit(ctx, "Generating final report...")

        # Build report prompt (executive summary + methodology + limitations)
        dep_findings = await self._load_dependency_findings(ctx)
        dependency_summary = self._build_dependency_report_context(dep_findings)
        user_content = self._build_report_prompt(ctx, dependency_summary)

        try:
            result = await self.llm.chat_json(SYSTEM_PROMPT, user_content, max_tokens=4096)
            ctx.ai_calls_made += 1
        except Exception as e:
            await self.emit(ctx, f"Report narrative generation failed: {e}. Using fallback.", level="error")
            await self.emit_progress(ctx, task="Report narrative generation failed — using fallback")
            confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
            scanners_used = ", ".join(ctx.scanner_hit_counts.keys()) or "offline scanners"
            degraded_note = (
                " Scanner coverage was degraded for at least one tool; incomplete scanner coverage should be assumed."
                if ctx.degraded_coverage
                else ""
            )
            result = {
                "executive_summary": ctx.app_summary or "Report generation encountered an error.",
                "methodology": (
                    f"This security assessment was conducted using VRAgent's multi-stage analysis pipeline. "
                    f"The scan operated in '{ctx.mode}' mode with a {len(ctx.files_inspected)}-file inspection scope.\n\n"
                    f"Phase 1 — Repository Triage: Source files were indexed and fingerprinted for language detection, "
                    f"framework identification, and obfuscation analysis. Documentation files (README, SECURITY.md) "
                    f"were read to understand the application's purpose and security posture.\n\n"
                    f"Phase 2 — Static Scanners: Multiple SAST tools ran in parallel: {scanners_used}. "
                    f"Total scanner hits: {sum(ctx.scanner_hit_counts.values())}.\n\n"
                    f"Phase 3 — Architecture Analysis: AI built an application model identifying components, "
                    f"entry points, trust boundaries, and attack surface.\n\n"
                    f"Phase 4 — AI Investigation: The AI investigator inspected source files, tracing data flows "
                    f"from user-controlled input sources to dangerous sinks (SQL queries, command execution, "
                    f"template rendering, file I/O). Each file was analysed with full application context "
                    f"including call graph edges, scanner signals, and prior findings.\n\n"
                    f"Phase 5 — Verification: Candidate findings were verified through adversarial analysis, "
                    f"checking for sanitisation, framework protection, and reachability.\n\n"
                    f"Phase 6 — Report Generation: Findings were scored, deduplicated, and mapped to CWE/OWASP."
                    f"{degraded_note}"
                ),
                "limitations": (
                    "This assessment is based on static analysis of source code only. No runtime testing, "
                    "dynamic analysis, or network-level scanning was performed. The analysis may miss "
                    "vulnerabilities that only manifest at runtime (e.g., race conditions, configuration-dependent "
                    "issues, or environment-specific bugs). AI-generated findings carry confidence scores — "
                    "lower-confidence findings may be false positives and should be manually verified. "
                    "The scan does not cover third-party library internals, compiled binaries, or obfuscated code. "
                    "Test files and non-production code paths were excluded from investigation."
                    f"{degraded_note}"
                ),
                "finding_narratives": [],
            }

        architecture_payload = self._build_architecture_payload(ctx, dep_findings)
        ctx.architecture_notes = json.dumps(architecture_payload)
        diagrams = architecture_payload.get("diagrams") or []
        if diagrams:
            ctx.diagram_spec = diagrams[0].get("mermaid", "") or ctx.diagram_spec

        # Compute enrichment data
        risk_score, risk_grade = self._compute_risk_score(ctx)
        owasp = self._build_owasp_mapping(ctx)
        comp_scores = self._build_component_scores(ctx)
        sbom = await self._build_sbom(ctx)
        coverage = self._build_scan_coverage(ctx)

        # Persist the report
        async with async_session() as session:
            report = Report(
                scan_id=ctx.scan_id,
                app_summary=result.get("executive_summary", ctx.app_summary),
                narrative=result.get("executive_summary", ctx.app_summary),
                architecture=ctx.architecture_notes,
                diagram_spec=ctx.diagram_spec,
                methodology=result.get("methodology", ""),
                limitations=result.get("limitations", ""),
                tech_stack={
                    "languages": ctx.languages,
                    "frameworks": ctx.frameworks,
                    "fingerprint": ctx.fingerprint,
                },
                scanner_hits=dict(ctx.scanner_hit_counts),
                attack_surface=self._build_attack_surface(ctx),
                risk_score=risk_score,
                risk_grade=risk_grade,
                owasp_mapping=owasp,
                component_scores=comp_scores,
                sbom=sbom,
                scan_coverage=coverage,
            )
            session.add(report)
            await session.commit()

        # Generate finding narratives in batches (avoids single-shot quality degradation)
        narratives = result.get("finding_narratives", [])
        if narratives:
            await self._update_finding_narratives(ctx, narratives)

        # Batch remaining findings that weren't covered in the first call
        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
        narrated_titles = {n.get("title", "").lower() for n in narratives}
        unnarrated = [f for f in confirmed if f.title.lower() not in narrated_titles]

        if unnarrated:
            batch_size = 6
            for i in range(0, len(unnarrated), batch_size):
                if ctx.cancelled:
                    break
                batch = unnarrated[i:i + batch_size]
                batch_num = i // batch_size + 1
                total_batches = (len(unnarrated) + batch_size - 1) // batch_size
                ctx.current_task = f"Generating finding narratives (batch {batch_num}/{total_batches})"
                await self.emit_progress(ctx, task=ctx.current_task)
                await self._generate_batch_narratives(ctx, batch)

        await self.emit(ctx, "Report generated successfully")
        await self.log_decision(ctx, action="report_generated")

    async def _generate_batch_narratives(self, ctx: ScanContext, findings: list):
        """Generate narratives for a batch of findings in a separate LLM call."""
        batch_prompt = "Generate detailed narratives for these security findings:\n\n"
        for i, f in enumerate(findings, 1):
            batch_prompt += (
                f"### {i}. {f.title}\n"
                f"Severity: {f.severity}, Confidence: {f.confidence}\n"
                f"File: {f.file_path}\n"
                f"Hypothesis: {f.hypothesis}\n"
                f"Evidence: {'; '.join(f.supporting_evidence[:3])}\n\n"
            )
        batch_prompt += (
            "\nRespond with JSON: {\"finding_narratives\": [{\"title\": \"...\", "
            "\"explanation\": \"...\", \"impact\": \"...\", \"remediation\": \"...\"}]}"
        )

        try:
            result = await self.llm.chat_json(SYSTEM_PROMPT, batch_prompt, max_tokens=3000)
            ctx.ai_calls_made += 1
            narratives = result.get("finding_narratives", [])
            if narratives:
                await self._update_finding_narratives(ctx, narratives)
        except Exception as e:
            await self.emit(ctx, f"Batch narrative generation failed: {e}", level="warn")

    async def _update_finding_narratives(self, ctx: ScanContext, narratives: list[dict]):
        """Update findings with generated narratives using fuzzy title matching."""
        from difflib import SequenceMatcher

        from sqlalchemy import select

        from app.models.finding import Finding

        async with async_session() as session:
            result = await session.execute(
                select(Finding).where(Finding.scan_id == ctx.scan_id)
            )
            findings = result.scalars().all()

            matched = 0
            for narrative in narratives:
                title = narrative.get("title", "")
                if not title:
                    continue

                # Try exact match first
                best_finding = None
                best_ratio = 0.0
                for finding in findings:
                    if finding.title == title:
                        best_finding = finding
                        best_ratio = 1.0
                        break
                    # Fuzzy match
                    ratio = SequenceMatcher(None, finding.title.lower(), title.lower()).ratio()
                    if ratio > best_ratio:
                        best_ratio = ratio
                        best_finding = finding

                # Accept match if >75% similar
                if best_finding and best_ratio >= 0.75:
                    best_finding.explanation = narrative.get("explanation", "")
                    best_finding.impact = narrative.get("impact", "")
                    best_finding.remediation = narrative.get("remediation", "")
                    matched += 1

            await session.commit()

        if matched < len(narratives):
            unmatched = len(narratives) - matched
            await self.emit(ctx, f"{unmatched} finding narratives could not be matched to findings", level="warn")

    def _build_attack_surface(self, ctx: ScanContext) -> dict:
        """Build attack surface metrics from scan context for radar chart."""
        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]

        # Count findings per attack surface category
        surface: dict[str, int] = {}

        # From file scoring signals
        category_map = {
            "auth": "Authentication",
            "crypto": "Cryptography",
            "injection": "Injection",
            "xss": "Cross-Site Scripting",
            "file_handling": "File Handling",
            "command_exec": "Command Execution",
            "deserialization": "Deserialization",
            "ssrf": "Server-Side Request",
            "secrets": "Secrets Exposure",
            "dependency": "Dependencies",
            "config": "Configuration",
            "api": "API Endpoints",
        }

        for finding in confirmed:
            cat = finding.category or "other"
            # Map to display name
            display = category_map.get(cat, cat.replace("_", " ").title())
            surface[display] = surface.get(display, 0) + 1

        # Add scanner-derived counts if no findings in those categories
        secrets_count = ctx.scanner_hit_counts.get("secrets", 0)
        if secrets_count > 0 and "Secrets Exposure" not in surface:
            surface["Secrets Exposure"] = secrets_count

        dep_count = ctx.scanner_hit_counts.get("dep_audit", 0)
        if dep_count > 0 and "Dependencies" not in surface:
            surface["Dependencies"] = dep_count

        return surface

    # ── Risk Score ────────────────────────────────────────────────
    def _compute_risk_score(self, ctx: ScanContext) -> tuple[float, str]:
        """Compute an overall risk score (0-100) and letter grade (A-F)."""
        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
        if not confirmed:
            return 0.0, "A"

        # Weighted severity scores
        sev_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}
        raw = 0.0
        for f in confirmed:
            weight = sev_weights.get(f.severity, 3)
            # Scale by confidence — a low-confidence critical is less alarming
            raw += weight * f.confidence

        # Exploitability bonus: easy-to-exploit findings are worse
        for f in confirmed:
            if f.exploit_difficulty == "easy":
                raw += 10 * f.confidence
            elif f.exploit_difficulty == "moderate":
                raw += 5 * f.confidence

        # Cap at 100
        score = min(100.0, raw)

        # Grade thresholds (higher score = worse)
        if score <= 5:
            grade = "A"
        elif score <= 15:
            grade = "B"
        elif score <= 35:
            grade = "C"
        elif score <= 60:
            grade = "D"
        else:
            grade = "F"

        return round(score, 1), grade

    # ── OWASP Top 10 Mapping ─────────────────────────────────────
    def _build_owasp_mapping(self, ctx: ScanContext) -> dict:
        """Map findings to OWASP Top 10 (2021) categories."""
        # CWE → OWASP mapping (covers most common CWEs)
        CWE_TO_OWASP: dict[str, str] = {
            # A01: Broken Access Control
            "CWE-22": "A01", "CWE-23": "A01", "CWE-35": "A01",
            "CWE-59": "A01", "CWE-200": "A01", "CWE-201": "A01",
            "CWE-219": "A01", "CWE-264": "A01", "CWE-275": "A01",
            "CWE-276": "A01", "CWE-284": "A01", "CWE-285": "A01",
            "CWE-352": "A01", "CWE-359": "A01", "CWE-377": "A01",
            "CWE-402": "A01", "CWE-425": "A01", "CWE-441": "A01",
            "CWE-497": "A01", "CWE-538": "A01", "CWE-540": "A01",
            "CWE-548": "A01", "CWE-552": "A01", "CWE-566": "A01",
            "CWE-601": "A01", "CWE-639": "A01", "CWE-651": "A01",
            "CWE-668": "A01", "CWE-706": "A01", "CWE-862": "A01",
            "CWE-863": "A01", "CWE-913": "A01", "CWE-922": "A01",
            "CWE-1275": "A01",
            # A02: Cryptographic Failures
            "CWE-261": "A02", "CWE-296": "A02", "CWE-310": "A02",
            "CWE-319": "A02", "CWE-321": "A02", "CWE-322": "A02",
            "CWE-323": "A02", "CWE-324": "A02", "CWE-325": "A02",
            "CWE-326": "A02", "CWE-327": "A02", "CWE-328": "A02",
            "CWE-329": "A02", "CWE-330": "A02", "CWE-331": "A02",
            "CWE-335": "A02", "CWE-336": "A02", "CWE-337": "A02",
            "CWE-338": "A02", "CWE-340": "A02", "CWE-347": "A02",
            "CWE-523": "A02", "CWE-720": "A02", "CWE-757": "A02",
            "CWE-759": "A02", "CWE-760": "A02", "CWE-780": "A02",
            "CWE-818": "A02", "CWE-916": "A02",
            # A03: Injection
            "CWE-20": "A03", "CWE-74": "A03", "CWE-75": "A03",
            "CWE-77": "A03", "CWE-78": "A03", "CWE-79": "A03",
            "CWE-80": "A03", "CWE-83": "A03", "CWE-87": "A03",
            "CWE-88": "A03", "CWE-89": "A03", "CWE-90": "A03",
            "CWE-91": "A03", "CWE-93": "A03", "CWE-94": "A03",
            "CWE-95": "A03", "CWE-96": "A03", "CWE-97": "A03",
            "CWE-98": "A03", "CWE-99": "A03", "CWE-100": "A03",
            "CWE-113": "A03", "CWE-116": "A03", "CWE-138": "A03",
            "CWE-184": "A03", "CWE-470": "A03", "CWE-471": "A03",
            "CWE-564": "A03", "CWE-610": "A03", "CWE-643": "A03",
            "CWE-644": "A03", "CWE-652": "A03", "CWE-917": "A03",
            # A04: Insecure Design
            "CWE-73": "A04", "CWE-183": "A04", "CWE-209": "A04",
            "CWE-213": "A04", "CWE-235": "A04", "CWE-256": "A04",
            "CWE-257": "A04", "CWE-266": "A04", "CWE-269": "A04",
            "CWE-280": "A04", "CWE-311": "A04", "CWE-312": "A04",
            "CWE-313": "A04", "CWE-316": "A04", "CWE-419": "A04",
            "CWE-430": "A04", "CWE-434": "A04", "CWE-444": "A04",
            "CWE-451": "A04", "CWE-472": "A04", "CWE-501": "A04",
            "CWE-522": "A04", "CWE-525": "A04", "CWE-539": "A04",
            "CWE-579": "A04", "CWE-598": "A04", "CWE-602": "A04",
            "CWE-642": "A04", "CWE-646": "A04", "CWE-650": "A04",
            "CWE-653": "A04", "CWE-656": "A04", "CWE-657": "A04",
            "CWE-799": "A04", "CWE-807": "A04", "CWE-840": "A04",
            "CWE-841": "A04", "CWE-927": "A04", "CWE-1021": "A04",
            "CWE-1173": "A04",
            # A05: Security Misconfiguration
            "CWE-2": "A05", "CWE-11": "A05", "CWE-13": "A05",
            "CWE-15": "A05", "CWE-16": "A05", "CWE-260": "A05",
            "CWE-315": "A05", "CWE-520": "A05", "CWE-526": "A05",
            "CWE-537": "A05", "CWE-541": "A05", "CWE-547": "A05",
            "CWE-611": "A05", "CWE-614": "A05", "CWE-756": "A05",
            "CWE-776": "A05", "CWE-942": "A05", "CWE-1004": "A05",
            "CWE-1032": "A05", "CWE-1174": "A05",
            # A06: Vulnerable and Outdated Components
            "CWE-937": "A06", "CWE-1035": "A06", "CWE-1104": "A06",
            # A07: Identification and Authentication Failures
            "CWE-255": "A07", "CWE-259": "A07", "CWE-287": "A07",
            "CWE-288": "A07", "CWE-290": "A07", "CWE-294": "A07",
            "CWE-295": "A07", "CWE-297": "A07", "CWE-300": "A07",
            "CWE-302": "A07", "CWE-304": "A07", "CWE-306": "A07",
            "CWE-307": "A07", "CWE-346": "A07", "CWE-384": "A07",
            "CWE-521": "A07", "CWE-613": "A07", "CWE-620": "A07",
            "CWE-640": "A07", "CWE-798": "A07", "CWE-940": "A07",
            "CWE-1216": "A07",
            # A08: Software and Data Integrity Failures
            "CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08",
            "CWE-494": "A08", "CWE-502": "A08", "CWE-565": "A08",
            "CWE-784": "A08", "CWE-829": "A08", "CWE-830": "A08",
            "CWE-915": "A08",
            # A09: Security Logging and Monitoring Failures
            "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09",
            "CWE-778": "A09",
            # A10: Server-Side Request Forgery
            "CWE-918": "A10",
        }

        # Category-based fallback when CWEs aren't available
        CATEGORY_TO_OWASP: dict[str, str] = {
            "injection": "A03", "sql_injection": "A03", "xss": "A03",
            "command_exec": "A03", "code_injection": "A03", "xpath_injection": "A03",
            "ldap_injection": "A03", "template_injection": "A03",
            "auth": "A07", "authentication": "A07", "session": "A07",
            "credentials": "A07", "password": "A07",
            "crypto": "A02", "cryptography": "A02", "tls": "A02", "ssl": "A02",
            "access_control": "A01", "authorization": "A01", "idor": "A01",
            "path_traversal": "A01", "file_disclosure": "A01",
            "ssrf": "A10", "server_side_request": "A10",
            "deserialization": "A08", "insecure_deserialization": "A08",
            "dependency": "A06", "outdated_component": "A06",
            "config": "A05", "misconfiguration": "A05", "debug": "A05",
            "cors": "A05", "xxe": "A05",
            "secrets": "A07", "hardcoded_secret": "A07",
            "logging": "A09", "information_disclosure": "A04",
            "file_handling": "A04", "upload": "A04",
        }

        OWASP_NAMES = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery (SSRF)",
        }

        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
        mapping: dict[str, dict] = {}

        for code, name in OWASP_NAMES.items():
            mapping[code] = {"name": name, "count": 0, "findings": [], "max_severity": "info"}

        sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

        for f in confirmed:
            owasp_code = None

            # Try CWE-based mapping first
            for cwe in (f.cwe_ids or []):
                if cwe in CWE_TO_OWASP:
                    owasp_code = CWE_TO_OWASP[cwe]
                    break

            # Fall back to category-based mapping
            if not owasp_code and f.category:
                owasp_code = CATEGORY_TO_OWASP.get(f.category)

            if not owasp_code:
                owasp_code = "A04"  # Default: Insecure Design

            entry = mapping[owasp_code]
            entry["count"] += 1
            entry["findings"].append(f.title)
            if sev_rank.get(f.severity, 0) > sev_rank.get(entry["max_severity"], 0):
                entry["max_severity"] = f.severity

        # Only return categories that have findings
        return {k: v for k, v in mapping.items() if v["count"] > 0}

    # ── Component Security Scorecard ──────────────────────────────
    def _build_component_scores(self, ctx: ScanContext) -> dict:
        """Score each architectural component based on findings within it."""
        if not ctx.components:
            return {}

        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
        sev_penalty = {"critical": 30, "high": 15, "medium": 5, "low": 1, "info": 0}

        scores: dict[str, dict] = {}
        for comp in ctx.components:
            name = comp.get("name", "Unknown")
            comp_files = comp.get("files", [])
            criticality = comp.get("criticality", "medium")

            # Find findings in this component
            comp_findings = []
            for f in confirmed:
                for cp in comp_files:
                    if f.file_path.startswith(cp) or f.file_path == cp:
                        comp_findings.append(f)
                        break

            # Calculate penalty
            penalty = sum(
                sev_penalty.get(f.severity, 3) * f.confidence
                for f in comp_findings
            )

            # Score starts at 100, subtract penalties
            raw_score = max(0, 100 - penalty)

            # Grade
            if raw_score >= 90:
                grade = "A"
            elif raw_score >= 75:
                grade = "B"
            elif raw_score >= 55:
                grade = "C"
            elif raw_score >= 35:
                grade = "D"
            else:
                grade = "F"

            scores[name] = {
                "score": round(raw_score, 1),
                "grade": grade,
                "criticality": criticality,
                "finding_count": len(comp_findings),
                "severities": {},
                "in_attack_surface": comp.get("in_attack_surface", False),
            }

            # Count severities within component
            for f in comp_findings:
                sev = f.severity
                scores[name]["severities"][sev] = scores[name]["severities"].get(sev, 0) + 1

        return scores

    # ── SBOM (Software Bill of Materials) ─────────────────────────
    async def _build_sbom(self, ctx: ScanContext) -> dict:
        """Build a CycloneDX-style SBOM from parsed dependencies."""
        from sqlalchemy import select

        from app.models.dependency import Dependency, DependencyFinding

        async with async_session() as session:
            # Get all dependencies for this scan
            deps_result = await session.execute(
                select(Dependency).where(Dependency.scan_id == ctx.scan_id)
            )
            deps = deps_result.scalars().all()

            # Get all vulnerability findings
            vuln_result = await session.execute(
                select(DependencyFinding).where(DependencyFinding.scan_id == ctx.scan_id)
            )
            vulns = vuln_result.scalars().all()

        return self._build_sbom_payload(deps, vulns)

    @staticmethod
    def _build_sbom_payload(deps: list, vulns: list) -> dict:
        """Build SBOM output while collapsing duplicate dependency rows by package identity."""
        grouped_components: dict[tuple[str, str, str, str, bool], dict] = {}
        dep_id_to_key: dict[str, tuple[str, str, str, str, bool]] = {}

        for dep in deps:
            dep_key = dependency_identity_key(
                ecosystem=dep.ecosystem,
                name=dep.name,
                version=dep.version,
                source_file=dep.source_file,
                is_dev=dep.is_dev,
            )
            dep_id_to_key[str(dep.id)] = dep_key
            component = grouped_components.setdefault(
                dep_key,
                {
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "source_file": dep.source_file,
                    "is_dev": dep.is_dev,
                    "vulnerabilities": [],
                },
            )
            # Prefer richer display values if the first row was sparse.
            if dep.name and not component["name"]:
                component["name"] = dep.name
            if dep.version and not component["version"]:
                component["version"] = dep.version

        seen_vulns: set[tuple[tuple[str, str, str, str, bool], str, str, str, str]] = set()
        for vuln in vulns:
            dep_key = dep_id_to_key.get(str(vuln.dependency_id))
            if dep_key is None:
                continue
            component = grouped_components.get(dep_key)
            if component is None:
                continue
            vuln_key = (
                dep_key,
                vuln.advisory_id or "",
                vuln.cve_id or "",
                vuln.summary or "",
                vuln.fixed_version or "",
            )
            if vuln_key in seen_vulns:
                continue
            seen_vulns.add(vuln_key)
            component["vulnerabilities"].append({
                "advisory_id": vuln.advisory_id,
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "summary": vuln.summary,
                "fixed_version": vuln.fixed_version,
            })

        # Build component list
        components = []
        ecosystems: dict[str, int] = {}
        vulnerable_count = 0

        for component in grouped_components.values():
            dep_vulns = component["vulnerabilities"]
            if dep_vulns:
                vulnerable_count += 1

            ecosystem = component["ecosystem"] or "unknown"
            ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1

            components.append({
                "name": component["name"],
                "version": component["version"],
                "ecosystem": ecosystem,
                "source_file": component["source_file"],
                "is_dev": component["is_dev"],
                "vulnerable": len(dep_vulns) > 0,
                "vulnerability_count": len(dep_vulns),
                "vulnerabilities": dep_vulns[:3],  # Cap to avoid huge payloads
            })

        return {
            "total_components": len(components),
            "vulnerable_components": vulnerable_count,
            "ecosystems": ecosystems,
            "components": sorted(components, key=lambda c: (-c["vulnerability_count"], c["name"])),
        }

    # ── Scan Coverage Map ─────────────────────────────────────────
    def _build_scan_coverage(self, ctx: ScanContext) -> dict:
        """Build scan coverage statistics."""
        return {
            "total_files": ctx.files_total,
            "files_indexed": ctx.files_total - getattr(ctx, "files_skipped_cap", 0),
            "files_inspected_by_ai": len(ctx.files_inspected),
            "files_skipped_size": getattr(ctx, "files_skipped_size", 0),
            "files_skipped_cap": getattr(ctx, "files_skipped_cap", 0),
            "scanners_used": list(ctx.scanner_runs.keys()) or list(ctx.scanner_hit_counts.keys()),
            "scanner_runs": dict(ctx.scanner_runs),
            "scanner_availability": dict(ctx.scanner_availability),
            "degraded_coverage": ctx.degraded_coverage,
            "ai_calls_made": ctx.ai_calls_made,
            "scan_mode": ctx.mode,
            "obfuscated_files": len(ctx.obfuscated_files),
            "is_monorepo": ctx.is_monorepo,
            "is_apk": ctx.source_type in ("apk", "aab", "dex", "jar"),
            "doc_files_read": len(ctx.doc_files_found),
            "has_doc_intelligence": bool(ctx.doc_intelligence),
            "ignored_file_count": ctx.ignored_file_count,
            "ignored_paths": list(ctx.ignored_paths),
            "managed_paths_ignored": list(ctx.managed_paths_ignored),
            "repo_ignore_file": ctx.repo_ignore_file,
        }

    @staticmethod
    def _truncate_dependency_text(value: str | None, max_chars: int = 220) -> str:
        if not value:
            return ""
        text = value.strip()
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 3].rstrip() + "..."

    @staticmethod
    def _summarise_dependency_usage(usage_evidence: list[dict] | None, limit: int = 2) -> str:
        if not usage_evidence:
            return ""

        kind_labels = {
            "import": "import",
            "reference": "reference",
            "vulnerable_function": "vulnerable function",
        }
        parts: list[str] = []
        for hit in usage_evidence[:limit]:
            if not isinstance(hit, dict):
                continue
            label = kind_labels.get(str(hit.get("kind", "")), str(hit.get("kind", "usage")).replace("_", " "))
            symbol = str(hit.get("symbol", "")).strip()
            location = str(hit.get("file", "")).strip()
            line = hit.get("line")
            if location and isinstance(line, int):
                location = f"{location}:{line}"
            summary = label
            if symbol:
                summary += f" {symbol}"
            if location:
                summary += f" in {location}"
            parts.append(summary)
        return "; ".join(part for part in parts if part)

    @staticmethod
    def _summarise_dependency_risk_factors(risk_factors: dict | None, limit: int = 3) -> str:
        if not isinstance(risk_factors, dict):
            return ""

        labels = {
            "reachability": "reachability",
            "relevance": "package usage",
            "vulnerable_function_match": "function match",
            "dev_dependency": "dev-only scope",
            "fix_available": "fix available",
            "hot_file_usage": "hot-file usage",
        }
        items = [
            (key, value)
            for key, value in risk_factors.items()
            if key not in {"base", "final"} and isinstance(value, (int, float)) and value != 0
        ]
        items.sort(key=lambda item: abs(float(item[1])), reverse=True)
        return ", ".join(
            f"{labels.get(key, key.replace('_', ' '))} {'+' if value > 0 else ''}{round(float(value))}"
            for key, value in items[:limit]
        )

    async def _load_dependency_findings(self, ctx: ScanContext) -> list[tuple]:
        from sqlalchemy import case, select

        from app.models.dependency import Dependency, DependencyFinding

        async with async_session() as session:
            result = await session.execute(
                select(DependencyFinding, Dependency)
                .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                .where(DependencyFinding.scan_id == ctx.scan_id)
                .order_by(
                    case((DependencyFinding.risk_score.is_(None), 1), else_=0),
                    DependencyFinding.risk_score.desc(),
                    DependencyFinding.severity.desc(),
                )
            )
            return result.all()

    def _build_dependency_report_context(self, dep_findings: list[tuple]) -> str:

        if not dep_findings:
            return ""

        reachable = sum(1 for df, _ in dep_findings if df.reachability_status == "reachable")
        active = sum(1 for df, _ in dep_findings if df.relevance in {"used", "likely_used"})
        transitive = sum(1 for df, _ in dep_findings if df.relevance == "transitive_only")
        function_matches = sum(1 for df, _ in dep_findings if df.vulnerable_functions)

        parts = [
            "\n## Dependency Risk Summary",
            f"Total dependency findings: {len(dep_findings)}",
            f"Reachable: {reachable}",
            f"Imported or likely used: {active}",
            f"Transitive only: {transitive}",
            f"Vulnerable function matches: {function_matches}",
            "Dependency discussion must distinguish manifest-only or transitive issues from imported or reachable issues.",
            "Do not describe a dependency as directly exposed unless usage or reachability evidence supports it.",
            "",
            "Top dependency risks:",
        ]

        for df, dep in dep_findings[:8]:
            risk_score = f"{round(df.risk_score)}/1000" if df.risk_score is not None else "n/a"
            advisory_id = df.cve_id or df.advisory_id or "offline advisory"
            reachability = df.reachability_status
            if df.reachability_confidence is not None:
                reachability += f" ({round(df.reachability_confidence * 100)}%)"
            parts.append(
                f"- {dep.name} {dep.version or 'unknown'} [{df.severity or 'unknown'}] "
                f"{advisory_id} risk={risk_score} relevance={df.relevance} "
                f"reachability={reachability} evidence={df.evidence_type}"
            )

            assessment = self._truncate_dependency_text(df.ai_assessment or df.summary)
            if assessment:
                parts.append(f"  Assessment: {assessment}")

            usage = self._summarise_dependency_usage(df.usage_evidence)
            if usage:
                parts.append(f"  Usage: {usage}")

            if df.vulnerable_functions:
                parts.append(f"  Functions: {', '.join(df.vulnerable_functions[:3])}")

            factors = self._summarise_dependency_risk_factors(df.risk_factors)
            if factors:
                parts.append(f"  Risk factors: {factors}")

        return "\n".join(parts)

    def _build_architecture_payload(self, ctx: ScanContext, dep_findings: list[tuple]) -> dict:
        payload = self._parse_architecture_payload(ctx.architecture_notes)
        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
        severity_counts = Counter(str(f.severity).lower() for f in confirmed)

        components = payload.get("components")
        if not isinstance(components, list) or not components:
            components = ctx.components or []
            payload["components"] = components

        component_hotspots = self._build_component_hotspots(components, confirmed)
        dependency_summary = self._summarise_dependency_findings(dep_findings)
        result_summary = {
            "finding_count": len(confirmed),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "advisory_correlated_count": sum(1 for f in confirmed if f.related_cves),
            "reachable_dependency_count": dependency_summary["reachable"],
            "active_dependency_count": dependency_summary["active"],
            "function_matched_dependency_count": dependency_summary["function_matches"],
            "high_risk_dependency_count": dependency_summary["high_risk"],
        }

        security_observations = []
        for value in payload.get("security_observations") or []:
            text = str(value).strip()
            if text and text not in security_observations:
                security_observations.append(text)
        for finding in sorted(
            confirmed,
            key=lambda item: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(item.severity).lower(), 9),
                -float(item.confidence or 0.0),
            ),
        )[:5]:
            note = f"{finding.title} in {finding.file_path}"
            if note not in security_observations:
                security_observations.append(note)
        for note in ctx.key_observations[:6]:
            text = str(note).strip()
            if text and text not in security_observations:
                security_observations.append(text)

        payload["result_summary"] = result_summary
        payload["trust_boundaries"] = payload.get("trust_boundaries") or ctx.trust_boundaries or []
        payload["entry_points"] = payload.get("entry_points") or ctx.entry_points or []
        payload["security_observations"] = security_observations[:12]
        payload["component_hotspots"] = component_hotspots
        payload["dependency_summary"] = dependency_summary
        payload["diagrams"] = self._merge_diagrams(
            self._build_result_aware_diagrams(
                payload,
                confirmed,
                component_hotspots,
                dependency_summary,
            ),
            payload.get("diagrams") or [],
        )
        return payload

    @staticmethod
    def _parse_architecture_payload(raw: str | None) -> dict:
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"analysis_markdown": str(raw)}
        except Exception:
            return {"analysis_markdown": str(raw)}

    @staticmethod
    def _merge_diagrams(primary: list[dict], existing: list[dict], max_diagrams: int = 5) -> list[dict]:
        merged: list[dict] = []
        seen_titles: set[str] = set()
        for candidate in [*primary, *existing]:
            if not isinstance(candidate, dict):
                continue
            title = str(candidate.get("title") or "").strip()
            mermaid = str(candidate.get("mermaid") or "").strip()
            if not title or not mermaid:
                continue
            key = title.lower()
            if key in seen_titles:
                continue
            seen_titles.add(key)
            merged.append(candidate)
            if len(merged) >= max_diagrams:
                break
        return merged

    @staticmethod
    def _build_component_hotspots(components: list[dict], findings: list) -> list[dict]:
        hotspots: list[dict] = []
        for component in components or []:
            if not isinstance(component, dict):
                continue
            paths = [str(path) for path in component.get("files", []) if path]
            matched = []
            for finding in findings:
                if any(finding.file_path == path or finding.file_path.startswith(f"{path}/") for path in paths):
                    matched.append(finding)
            severity_counts = Counter(str(item.severity).lower() for item in matched)
            hotspots.append(
                {
                    "name": str(component.get("name") or "Component"),
                    "criticality": str(component.get("criticality") or "medium"),
                    "finding_count": len(matched),
                    "critical_count": severity_counts.get("critical", 0),
                    "high_count": severity_counts.get("high", 0),
                    "medium_count": severity_counts.get("medium", 0),
                    "in_attack_surface": bool(component.get("in_attack_surface")),
                }
            )
        hotspots.sort(
            key=lambda item: (
                -item["critical_count"],
                -item["high_count"],
                -item["finding_count"],
                item["name"].lower(),
            )
        )
        return hotspots[:8]

    def _summarise_dependency_findings(self, dep_findings: list[tuple]) -> dict:
        summary = {
            "total": len(dep_findings),
            "reachable": 0,
            "active": 0,
            "function_matches": 0,
            "high_risk": 0,
            "top_packages": [],
            "hot_files": [],
        }
        if not dep_findings:
            return summary

        package_rows: list[dict] = []
        hot_files: Counter = Counter()
        for df, dep in dep_findings:
            if df.reachability_status == "reachable":
                summary["reachable"] += 1
            if df.relevance in {"used", "likely_used"}:
                summary["active"] += 1
            if df.vulnerable_functions:
                summary["function_matches"] += 1
            if (df.risk_score or 0) >= 700:
                summary["high_risk"] += 1
            package_rows.append(
                {
                    "package": dep.name,
                    "ecosystem": dep.ecosystem,
                    "severity": df.severity or "unknown",
                    "risk_score": float(df.risk_score or 0.0),
                    "reachability_status": df.reachability_status,
                    "evidence_type": df.evidence_type,
                    "fixed_version": df.fixed_version,
                }
            )
            for hit in df.usage_evidence or []:
                if isinstance(hit, dict) and hit.get("file"):
                    hot_files[str(hit.get("file"))] += 1

        package_rows.sort(
            key=lambda item: (
                -item["risk_score"],
                {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(item["severity"], 0),
                item["package"].lower(),
            )
        )
        summary["top_packages"] = package_rows[:5]
        summary["hot_files"] = [
            {"file": path, "hits": count}
            for path, count in hot_files.most_common(4)
        ]
        return summary

    def _build_result_aware_diagrams(
        self,
        payload: dict,
        findings: list,
        component_hotspots: list[dict],
        dependency_summary: dict,
    ) -> list[dict]:
        diagrams = [self._build_overview_diagram(payload, findings, component_hotspots, dependency_summary)]
        trust_diagram = self._build_trust_boundary_diagram(payload, findings, component_hotspots, dependency_summary)
        if trust_diagram:
            diagrams.append(trust_diagram)
        dependency_diagram = self._build_dependency_diagram(dependency_summary)
        if dependency_diagram:
            diagrams.append(dependency_diagram)
        return diagrams

    def _build_overview_diagram(
        self,
        payload: dict,
        findings: list,
        component_hotspots: list[dict],
        dependency_summary: dict,
    ) -> dict:
        summary = payload.get("result_summary") or {}
        components = component_hotspots[:3] or [{"name": "Application", "criticality": "high", "finding_count": len(findings)}]
        component_ids = []
        lines = [
            "flowchart TD",
            "    U((fa:user External Users))",
            f"    EP([fa:globe Entry Points {len(payload.get('entry_points') or []) or 1}])",
            f"    TB{{fa:shield Trust Boundaries {len(payload.get('trust_boundaries') or []) or 1}}}",
            f"    FIND{{fa:bug Verified Findings {summary.get('critical_count', 0)} critical {summary.get('high_count', 0)} high}}",
            f"    DEP[(fa:database Dependency Risks {dependency_summary.get('reachable', 0)} reachable)]",
            f"    STORE[(fa:database Data Stores {len(payload.get('external_integrations') or []) or 1})]",
        ]
        for index, component in enumerate(components, start=1):
            node_id = f"C{index}"
            component_ids.append(node_id)
            label = self._mermaid_label(component.get("name"), fallback=f"Component {index}", limit=28)
            icon = "fa:lock" if str(component.get("criticality")) == "critical" else "fa:server"
            lines.append(f"    {node_id}[{icon} {label}]")

        lines.extend([
            "    U --> EP",
            "    EP --> TB",
            f"    TB --> {component_ids[0]}",
        ])
        for left, right in zip(component_ids, component_ids[1:]):
            lines.append(f"    {left} --> {right}")
        lines.append(f"    {component_ids[-1]} --> STORE")
        for node_id in component_ids[:2]:
            lines.append(f"    FIND -.-> {node_id}")
        lines.append(f"    DEP -.-> {component_ids[min(1, len(component_ids) - 1)]}")
        lines.extend(self._mermaid_class_defs())
        lines.append("    class FIND danger")
        lines.append("    class DEP,STORE store")
        lines.append("    class TB safe")
        lines.append(f"    class {','.join(component_ids)} warn")

        highlights = [
            f"{summary.get('finding_count', len(findings))} verified findings across {len(component_hotspots) or len(components)} mapped components",
            f"{dependency_summary.get('reachable', 0)} reachable dependency risks and {dependency_summary.get('function_matches', 0)} vulnerable function matches",
        ]
        if component_hotspots:
            top = component_hotspots[0]
            highlights.append(
                f"{top.get('name')} is the hottest component with {top.get('finding_count', 0)} linked findings"
            )

        return {
            "title": "Verified Security Overview",
            "description": "Result-aware overview combining verified findings, trust boundaries, hotspots, and dependency risk.",
            "kind": "result_overview",
            "highlights": highlights,
            "mermaid": "\n".join(lines),
        }

    def _build_trust_boundary_diagram(
        self,
        payload: dict,
        findings: list,
        component_hotspots: list[dict],
        dependency_summary: dict,
    ) -> dict | None:
        entry_points = payload.get("entry_points") or []
        trust_boundaries = payload.get("trust_boundaries") or []
        auth_mechanisms = payload.get("auth_mechanisms") or []
        if not entry_points and not trust_boundaries and not findings:
            return None

        hotspot_names = [self._mermaid_label(item.get("name"), fallback="Component", limit=26) for item in component_hotspots[:2]]
        entry_labels = [
            self._mermaid_label(
                ep.get("path") or ep.get("function") or ep.get("file") or f"Entry {index + 1}",
                fallback=f"Entry {index + 1}",
                limit=24,
            )
            for index, ep in enumerate(entry_points[:3])
        ] or ["Primary Entry"]
        boundary_label = self._mermaid_label(trust_boundaries[0], fallback="Trust Boundary", limit=28) if trust_boundaries else "Trust Boundary"
        auth_label = self._mermaid_label(
            (auth_mechanisms[0] or {}).get("type") if auth_mechanisms else "Access Control",
            fallback="Access Control",
            limit=22,
        )

        lines = [
            "flowchart LR",
            "    USER((fa:user Browser Or Client))",
            "    ATT((fa:bug Attack Paths))",
            f"    BOUND{{fa:shield {boundary_label}}}",
            f"    AUTH{{fa:lock {auth_label}}}",
            f"    HOT1[fa:fire {hotspot_names[0] if hotspot_names else 'Hot Component'}]",
            f"    DEP[(fa:database Reachable Dependencies {dependency_summary.get('reachable', 0)})]",
        ]
        for index, label in enumerate(entry_labels, start=1):
            lines.append(f"    EP{index}([fa:globe {label}])")
        if len(hotspot_names) > 1:
            lines.append(f"    HOT2[fa:fire {hotspot_names[1]}]")

        lines.append("    USER --> EP1")
        for index in range(1, len(entry_labels) + 1):
            lines.append(f"    EP{index} --> BOUND")
            lines.append(f"    ATT -.-> EP{index}")
        lines.append("    BOUND --> AUTH")
        lines.append("    AUTH --> HOT1")
        if len(hotspot_names) > 1:
            lines.append("    HOT1 --> HOT2")
            lines.append("    DEP -.-> HOT2")
        else:
            lines.append("    DEP -.-> HOT1")
        lines.extend(self._mermaid_class_defs())
        lines.append("    class ATT danger")
        lines.append("    class BOUND,AUTH safe")
        hotspot_class_targets = ["HOT1"] + (["HOT2"] if len(hotspot_names) > 1 else [])
        lines.append(f"    class {','.join(hotspot_class_targets)} warn")
        lines.append("    class DEP store")

        highlights = [
            f"{len(entry_points)} mapped entry points and {len(trust_boundaries)} trust boundaries carried into final reporting",
            f"{dependency_summary.get('reachable', 0)} reachable dependency issues remain attached to the same hot paths",
        ]
        if auth_mechanisms:
            highlights.append(f"Primary auth mechanism observed: {auth_mechanisms[0].get('type', 'unknown')}")

        return {
            "title": "Trust Boundaries And Hotspots",
            "description": "Routes user entry paths through trust boundaries, access controls, and the hottest verified components.",
            "kind": "trust_boundaries",
            "highlights": highlights,
            "mermaid": "\n".join(lines),
        }

    def _build_dependency_diagram(self, dependency_summary: dict) -> dict | None:
        if dependency_summary.get("total", 0) <= 0:
            return None

        hot_files = dependency_summary.get("hot_files") or []
        top_packages = dependency_summary.get("top_packages") or []
        lines = [
            "flowchart LR",
            f"    MAN[fa:folder Dependency Manifests {dependency_summary.get('total', 0)} findings]",
            f"    IMP[fa:code Imported Packages {dependency_summary.get('active', 0)}]",
            f"    REACH{{fa:bug Reachable Packages {dependency_summary.get('reachable', 0)}}}",
            f"    FUNC([fa:fire Function Hits {dependency_summary.get('function_matches', 0)}])",
        ]

        package_nodes = []
        for index, pkg in enumerate(top_packages[:2], start=1):
            node_id = f"P{index}"
            package_nodes.append(node_id)
            label = self._mermaid_label(pkg.get("package"), fallback=f"Package {index}", limit=20)
            lines.append(f"    {node_id}[(fa:database {label})]")
        file_nodes = []
        for index, item in enumerate(hot_files[:2], start=1):
            node_id = f"F{index}"
            file_nodes.append(node_id)
            label = self._mermaid_label(item.get("file"), fallback=f"File {index}", limit=24)
            lines.append(f"    {node_id}[fa:file {label}]")

        lines.append("    MAN --> IMP")
        lines.append("    IMP --> REACH")
        lines.append("    REACH --> FUNC")
        for node_id in package_nodes:
            lines.append(f"    IMP --> {node_id}")
            lines.append(f"    {node_id} --> REACH")
        for node_id in file_nodes:
            lines.append(f"    FUNC -.-> {node_id}")
        lines.extend(self._mermaid_class_defs())
        lines.append("    class REACH,FUNC danger")
        if package_nodes:
            lines.append(f"    class {','.join(package_nodes)} store")
        if file_nodes:
            lines.append(f"    class {','.join(file_nodes)} warn")

        highlights = [
            f"{dependency_summary.get('active', 0)} imported or likely-used vulnerable packages",
            f"{dependency_summary.get('reachable', 0)} reachable packages and {dependency_summary.get('function_matches', 0)} vulnerable function matches",
        ]
        if top_packages:
            highlights.append(
                "Top package risks: " + ", ".join(self._mermaid_label(pkg.get("package"), fallback="package", limit=18) for pkg in top_packages[:3])
            )

        return {
            "title": "Dependency Exposure And Reachability",
            "description": "Shows how manifest findings collapse into imported, reachable, and function-level dependency risk.",
            "kind": "dependency_risk",
            "highlights": highlights,
            "mermaid": "\n".join(lines),
        }

    @staticmethod
    def _mermaid_class_defs() -> list[str]:
        return [
            "    classDef danger fill:#7f1d1d,stroke:#f87171,color:#fecaca",
            "    classDef warn fill:#7c2d12,stroke:#fb923c,color:#fed7aa",
            "    classDef safe fill:#14532d,stroke:#4ade80,color:#bbf7d0",
            "    classDef store fill:#1e3a5f,stroke:#60a5fa,color:#bfdbfe",
        ]

    @staticmethod
    def _mermaid_label(value: str | None, *, fallback: str, limit: int = 28) -> str:
        text = re.sub(r"[^A-Za-z0-9 /:-]+", " ", str(value or fallback))
        text = re.sub(r"\s+", " ", text).strip(" -:/")
        text = text or fallback
        return text[:limit].rstrip()

    def _build_report_prompt(self, ctx: ScanContext, dependency_summary: str = "") -> str:
        parts = [
            "## Application",
            ctx.app_summary or "No application summary available.",
            "",
            f"Languages: {', '.join(ctx.languages)}",
            f"Frameworks: {', '.join(ctx.frameworks)}",
            f"Total files: {ctx.files_total}",
            f"Files inspected by AI: {len(ctx.files_inspected)}",
            f"Scan mode: {ctx.mode}",
            f"Documentation files analysed: {len(ctx.doc_files_found)}",
        ]

        if ctx.scanner_runs:
            parts.append("\n## Scanner Run Health")
            for scanner_name, summary in ctx.scanner_runs.items():
                parts.append(
                    f"- {scanner_name}: status={summary.get('status')} "
                    f"hits={summary.get('hit_count', 0)} duration_ms={summary.get('duration_ms', 0)} "
                        f"errors={len(summary.get('errors', []))}"
                )
        if ctx.scanner_availability:
            parts.append("\n## Scanner Availability")
            for scanner_name, status in sorted(ctx.scanner_availability.items()):
                parts.append(f"- {scanner_name}: {status}")
        if ctx.degraded_coverage:
            parts.append(
                "\nNOTE: One or more scanners completed in a degraded state or failed. "
                "The methodology and limitations sections must state that scanner coverage was incomplete."
            )
        if ctx.ignored_file_count > 0:
            parts.append(
                f"\nIgnored repo paths/files: {ctx.ignored_file_count}. "
                f"Managed exclusions: {', '.join(ctx.managed_paths_ignored[:5]) or 'none'}."
            )
            if ctx.repo_ignore_file:
                parts.append(f"Repo ignore file: {ctx.repo_ignore_file}")

        # ── Documentation intelligence ─────────────────────────────
        if ctx.doc_intelligence:
            parts.append(f"\n## Developer Documentation Intelligence")
            parts.append(
                "The following was extracted from the project's documentation files "
                "(README, API docs, setup guides). Incorporate relevant context into "
                "the executive summary and methodology. If documentation mentions security "
                "considerations, note whether the code actually implements them."
            )
            parts.append(ctx.doc_intelligence[:2000])
            if ctx.doc_files_found:
                parts.append(f"\nDocumentation files read: {', '.join(ctx.doc_files_found[:10])}")

        # ── APK decompilation context ─────────────────────────────
        if ctx.source_type in ("apk", "aab", "dex", "jar"):
            parts.append(f"\n## Decompiled Android Application")
            parts.append(
                f"This application was decompiled from an {ctx.source_type.upper()} file using jadx. "
                "The methodology section MUST note that:\n"
                "- Analysis was performed on decompiled code, not original source\n"
                "- ProGuard/R8 obfuscation may hide some vulnerabilities\n"
                "- Confidence levels may be lower than for original source analysis\n"
                "- Android-specific security controls (ProGuard, network security config, etc.) were evaluated\n"
                "The report should describe the app as an Android application and include "
                "Android-specific security context in the architecture section."
            )

        # ── Monorepo context ─────────────────────────────────────
        if ctx.is_monorepo:
            parts.append(f"\n## Monorepo Structure")
            parts.append(f"This is a monorepo with {len(ctx.workspaces)} workspaces:")
            for ws in ctx.workspaces[:10]:
                parts.append(f"- **{ws['name']}** ({ws['type']}) at {ws['path']}")
            parts.append("NOTE: Findings may span multiple independent applications within this monorepo.")

        # ── Obfuscation context ───────────────────────────────────
        obs_summary = ctx.obfuscation_summary
        if obs_summary.get("obfuscated_count", 0) > 0:
            parts.append(f"\n## Obfuscation / Minification")
            parts.append(
                f"- {obs_summary.get('heavily_obfuscated', 0)} files are heavily obfuscated/minified (not analysable)"
            )
            parts.append(
                f"- {obs_summary.get('moderately_obfuscated', 0)} files are moderately obfuscated"
            )
            parts.append(
                f"- {obs_summary.get('obfuscated_percentage', 0):.1f}% of the codebase is obfuscated"
            )
            parts.append(
                "NOTE: AI analysis of obfuscated code is unreliable. "
                "Findings in obfuscated files have lower confidence. "
                "The report methodology section MUST mention this as a limitation."
            )

        # ── Scan coverage warnings ────────────────────────────────
        coverage_notes = []
        if ctx.files_skipped_size > 0:
            coverage_notes.append(f"{ctx.files_skipped_size} files exceeded the 1MB size limit and were not analysed")
        if ctx.files_skipped_cap > 0:
            coverage_notes.append(f"{ctx.files_skipped_cap} files were not indexed due to the {settings.max_files_per_scan}-file scan cap")
        if coverage_notes:
            parts.append(f"\n## Incomplete Coverage")
            for note in coverage_notes:
                parts.append(f"- {note}")
            parts.append("NOTE: The methodology section MUST note that analysis may be incomplete.")

        # ── Findings ──────────────────────────────────────────────
        parts.append("\n## Findings")

        confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
        for i, finding in enumerate(confirmed, 1):
            parts.append(f"\n### {i}. {finding.title}")
            parts.append(f"Severity: {finding.severity}")
            parts.append(f"Confidence: {finding.confidence}")
            parts.append(f"Category: {finding.category}")
            parts.append(f"File: {finding.file_path}")

            # Flag if finding is in an obfuscated file
            if finding.file_path in ctx.obfuscated_files:
                parts.append("**WARNING: This finding is in an obfuscated/minified file. Confidence may be lower than reported.**")

            # Component membership
            for comp in ctx.components:
                for cp in comp.get("files", []):
                    if finding.file_path.startswith(cp) or finding.file_path == cp:
                        parts.append(f"Component: {comp.get('name', '?')} ({comp.get('criticality', '?')} criticality)")
                        break

            parts.append(f"Hypothesis: {finding.hypothesis}")
            if finding.code_snippet:
                parts.append(f"Code:\n```\n{finding.code_snippet[:500]}\n```")
            if finding.supporting_evidence:
                parts.append(f"Supporting: {'; '.join(finding.supporting_evidence[:3])}")
            if finding.opposing_evidence:
                parts.append(f"Mitigations considered: {'; '.join(finding.opposing_evidence[:3])}")

            # Exploit evidence
            if finding.exploit_difficulty:
                parts.append(f"Exploit difficulty: {finding.exploit_difficulty.upper()}")
            if finding.exploit_prerequisites:
                parts.append(f"Prerequisites: {', '.join(finding.exploit_prerequisites)}")
            if finding.exploit_template:
                parts.append(f"Proof of Concept:\n```\n{finding.exploit_template[:500]}\n```")
            if finding.attack_scenario:
                parts.append(f"Attack scenario: {finding.attack_scenario[:300]}")

        if not confirmed:
            parts.append("No confirmed security findings.")

        # ── Component Security Summary ────────────────────────────
        if ctx.components:
            parts.append(f"\n## Component Security Summary")
            parts.append("Include this table in the report:")
            parts.append("| Component | Criticality | Attack Surface | Findings |")
            parts.append("|-----------|------------|----------------|----------|")
            for comp in ctx.components:
                comp_name = comp.get("name", "?")
                crit = comp.get("criticality", "?")
                attack = "Yes" if comp.get("in_attack_surface") else "No"
                # Count findings in this component
                comp_findings = sum(
                    1 for f in confirmed
                    if any(f.file_path.startswith(p) or f.file_path == p for p in comp.get("files", []))
                )
                parts.append(f"| {comp_name} | {crit} | {attack} | {comp_findings} |")

        # ── Exploit Chains ────────────────────────────────────────
        chains = [f for f in confirmed if f.category == "exploit_chain"]
        if chains:
            parts.append(f"\n## Exploit Chains ({len(chains)})")
            parts.append("Include these multi-step attack paths in the report:")
            for chain in chains:
                parts.append(f"\n### {chain.title}")
                parts.append(f"Severity: {chain.severity}")
                parts.append(f"Impact: {chain.hypothesis}")
                if chain.supporting_evidence:
                    parts.append("Steps:")
                    for step in chain.supporting_evidence:
                        parts.append(f"  {step}")

        # ── Taint flows ───────────────────────────────────────────
        if ctx.taint_flows:
            unsanitised = [tf for tf in ctx.taint_flows if not tf.sanitised]
            verified = [tf for tf in ctx.taint_flows if tf.graph_verified]
            if unsanitised:
                parts.append(f"\n## Unsanitised Data Flows ({len(unsanitised)}, {len(verified)} verified by call graph)")
                for tf in unsanitised[:10]:
                    verified_tag = " [CALL GRAPH VERIFIED]" if tf.graph_verified else ""
                    parts.append(
                        f"- {tf.source_type} @ {tf.source_file}:{tf.source_line} "
                        f"→ {tf.sink_type} @ {tf.sink_file}:{tf.sink_line}{verified_tag}"
                    )
                    if tf.call_chain:
                        chain_str = " → ".join(
                            f"{e['caller']}→{e['callee']}" if isinstance(e, dict)
                            else str(e)
                            for e in tf.call_chain[:5]
                        )
                        parts.append(f"  Chain: {chain_str}")

        # ── Call graph summary ────────────────────────────────────
        if ctx.call_graph and hasattr(ctx.call_graph, 'edges'):
            parts.append(f"\n## Static Analysis Summary")
            parts.append(f"- Call graph: {len(ctx.call_graph.edges)} inter-procedural edges resolved")
            parts.append(f"- Import resolution: {sum(len(v) for v in ctx.import_graph.values())} imports resolved")
            parts.append("NOTE: Include call graph statistics in the methodology section.")

        parts.append(f"\n## Key Observations")
        for obs in ctx.key_observations[:10]:
            parts.append(f"- {obs}")

        parts.append(f"\n## Scanner Results")
        for scanner, count in ctx.scanner_hit_counts.items():
            parts.append(f"- {scanner}: {count} hits")

        if dependency_summary:
            parts.append(dependency_summary)

        return "\n".join(parts)
