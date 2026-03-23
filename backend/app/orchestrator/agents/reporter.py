"""Reporter Agent — generate final report and narratives."""

import logging

from app.config import settings
from app.database import async_session
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
        user_content = self._build_report_prompt(ctx)

        try:
            result = await self.llm.chat_json(SYSTEM_PROMPT, user_content, max_tokens=4096)
            ctx.ai_calls_made += 1
        except Exception as e:
            await self.emit(ctx, f"Report narrative generation failed: {e}. Using fallback.", level="error")
            await self.emit_progress(ctx, task="Report narrative generation failed — using fallback")
            confirmed = [f for f in ctx.candidate_findings if f.status != "dismissed"]
            scanners_used = ", ".join(ctx.scanner_hit_counts.keys()) or "offline scanners"
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
                ),
                "limitations": (
                    "This assessment is based on static analysis of source code only. No runtime testing, "
                    "dynamic analysis, or network-level scanning was performed. The analysis may miss "
                    "vulnerabilities that only manifest at runtime (e.g., race conditions, configuration-dependent "
                    "issues, or environment-specific bugs). AI-generated findings carry confidence scores — "
                    "lower-confidence findings may be false positives and should be manually verified. "
                    "The scan does not cover third-party library internals, compiled binaries, or obfuscated code. "
                    "Test files and non-production code paths were excluded from investigation."
                ),
                "finding_narratives": [],
            }

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

        # Index vulns by dependency_id
        vuln_by_dep: dict[str, list] = {}
        for v in vulns:
            dep_id = str(v.dependency_id)
            if dep_id not in vuln_by_dep:
                vuln_by_dep[dep_id] = []
            vuln_by_dep[dep_id].append({
                "advisory_id": v.advisory_id,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "summary": v.summary,
                "fixed_version": v.fixed_version,
            })

        # Build component list
        components = []
        ecosystems: dict[str, int] = {}
        vulnerable_count = 0

        for dep in deps:
            dep_id = str(dep.id)
            dep_vulns = vuln_by_dep.get(dep_id, [])
            if dep_vulns:
                vulnerable_count += 1

            ecosystems[dep.ecosystem] = ecosystems.get(dep.ecosystem, 0) + 1

            components.append({
                "name": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "source_file": dep.source_file,
                "is_dev": dep.is_dev,
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
            "scanners_used": list(ctx.scanner_hit_counts.keys()),
            "ai_calls_made": ctx.ai_calls_made,
            "scan_mode": ctx.mode,
            "obfuscated_files": len(ctx.obfuscated_files),
            "is_monorepo": ctx.is_monorepo,
            "is_apk": ctx.source_type in ("apk", "aab", "dex", "jar"),
            "doc_files_read": len(ctx.doc_files_found),
            "has_doc_intelligence": bool(ctx.doc_intelligence),
        }

    def _build_report_prompt(self, ctx: ScanContext) -> str:
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

        return "\n".join(parts)
