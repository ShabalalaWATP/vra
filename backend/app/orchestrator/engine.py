"""Scan orchestrator — runs the full pipeline with feedback loops and real-time progress.

Pipeline (8 stages, mapped to 7 frontend phases):
  1. triage          — fingerprint, scanners, scoring, obfuscation detection
  2. understanding   — AI reads top files, builds app model
  3. dependencies    — assess dependency vulnerability exploitability
  4. investigation   — multi-pass adaptive vulnerability hunting
  5. targeted_scan   — AI-selected follow-up scanner rules, results fed back
  6. verification    — challenge findings, detect exploit chains, verify taint flows
  7. reporting       — generate report narratives + render diagram

Feedback loops:
  - Dependency findings boost file scores before investigation
  - Rule selector output triggers a mini-investigation pass on new hits
  - If verification confirms <30% of findings, triggers a deeper re-investigation
  - Compaction runs adaptively between phases based on model context window
"""

import asyncio
import logging
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import case, select
from sqlalchemy.orm import selectinload

from app.analysis.diagram import render_diagram_for_report
from app.database import async_session
from app.events.bus import event_bus
from app.models.llm_profile import LLMProfile
from app.models.project import Project
from app.models.report import Report
from app.models.scan import Scan
from app.api.scans import DEFAULT_SCANNERS, normalise_scanner_config
from app.scanners.registry import get_available_scanners
from app.orchestrator.agents.architecture import ArchitectureAgent
from app.orchestrator.agents.dependency import DependencyRiskAgent
from app.orchestrator.agents.investigator import InvestigatorAgent
from app.orchestrator.agents.reporter import ReporterAgent
from app.orchestrator.agents.rule_selector import RuleSelectorAgent
from app.orchestrator.agents.triage import TriageAgent
from app.orchestrator.agents.verifier import VerifierAgent
from app.orchestrator.compaction import compact_context, should_compact
from app.orchestrator.llm_client import LLMClient
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)


# ── Unified progress emitter ─────────────────────────────────────

async def _emit_progress(
    ctx: ScanContext,
    *,
    phase: str | None = None,
    task: str | None = None,
    status: str = "running",
):
    """
    Emit a progress update to BOTH the database AND the WebSocket simultaneously.
    This is the single source of truth for scan progress — no more dual-source inconsistency.
    """
    if phase:
        ctx.current_phase = phase
    if task:
        ctx.current_task = task

    # Update database
    async with async_session() as session:
        scan = await session.get(Scan, ctx.scan_id)
        if scan:
            scan.current_phase = ctx.current_phase
            scan.current_task = ctx.current_task
            scan.status = status
            await session.commit()

    # Emit WebSocket progress event
    await event_bus.publish(ctx.scan_id, {
        "type": "progress",
        "status": status,
        "phase": ctx.current_phase,
        "task": ctx.current_task,
        "findings_count": ctx.findings_count,
        "files_processed": ctx.files_processed,
        "files_total": ctx.files_total,
        "ai_calls_made": ctx.ai_calls_made,
    })


async def run_scan(scan_id: uuid.UUID) -> None:
    """Main scan entry point. Called as a background task."""
    llm = None

    # ── Pre-scan validation ───────────────────────────────────────
    async with async_session() as session:
        scan = (
            await session.execute(
                select(Scan)
                .where(Scan.id == scan_id)
                .options(selectinload(Scan.config))
            )
        ).scalar_one_or_none()
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        llm_profile = None
        if scan.llm_profile_id:
            llm_profile = await session.get(LLMProfile, scan.llm_profile_id)

        project = await session.get(Project, scan.project_id)

    # Validate repo path
    repo_path = Path(project.repo_path)
    if not repo_path.exists():
        await _finish_scan(scan_id, "failed", error=f"Repository path does not exist: {project.repo_path}")
        await event_bus.publish(scan_id, {
            "type": "progress", "status": "failed",
            "error": f"Path not found: {project.repo_path}",
        })
        await event_bus.complete(scan_id)
        return

    if not repo_path.is_dir():
        await _finish_scan(scan_id, "failed", error=f"Repository path is not a directory: {project.repo_path}")
        await event_bus.publish(scan_id, {
            "type": "progress", "status": "failed",
            "error": f"Not a directory: {project.repo_path}",
        })
        await event_bus.complete(scan_id)
        return

    # Create LLM client
    if llm_profile:
        llm = LLMClient(
            base_url=llm_profile.base_url,
            model_name=llm_profile.model_name,
            api_key=llm_profile.api_key,
            cert_path=llm_profile.cert_path,
            timeout=llm_profile.timeout_seconds,
            context_window=llm_profile.context_window,
            max_output_tokens=llm_profile.max_output_tokens,
            use_max_completion_tokens=llm_profile.use_max_completion_tokens,
        )

    ctx = ScanContext(
        scan_id=scan_id,
        project_id=scan.project_id,
        repo_path=project.repo_path,
        mode=scan.mode,
        source_type=getattr(project, "source_type", "codebase"),
    )

    # Create scanner instances once for the entire scan lifecycle, honouring scan config.
    ctx.scanner_config = normalise_scanner_config(
        getattr(scan.config, "scanners", None) or DEFAULT_SCANNERS
    )
    available_scanners = await get_available_scanners()
    ctx.scanners = {
        name: scanner
        for name, scanner in available_scanners.items()
        if ctx.scanner_config.get(name, False)
    }
    for scanner_name, enabled in ctx.scanner_config.items():
        if not enabled:
            ctx.scanner_availability[scanner_name] = "disabled"
        elif scanner_name in available_scanners:
            ctx.scanner_availability[scanner_name] = "enabled"
        else:
            ctx.scanner_availability[scanner_name] = "unavailable"

    phase_errors: list[str] = []

    try:
        # ══════════════════════════════════════════════════════════
        # STAGE 1: TRIAGE
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="triage", task="Starting repository triage")
        success = await _run_agent(ctx, TriageAgent(llm), phase_errors)
        if ctx.cancelled:
            await _finish_scan(scan_id, "cancelled")
            return
        if not success:
            await _finish_scan(scan_id, "failed", error="Triage failed: " + "; ".join(phase_errors))
            return

        if not llm:
            # Scanner-only mode
            await _emit_progress(ctx, phase="reporting", task="Generating scanner-only report")
            await event_bus.publish(scan_id, {
                "type": "event", "level": "warn",
                "message": "No LLM configured. Scanner-only mode.",
            })
            await _create_minimal_report(ctx)
            await _finish_scan(scan_id, "completed")
            await _emit_progress(ctx, phase="done", status="completed")
            return

        # ══════════════════════════════════════════════════════════
        # STAGE 2: APPLICATION UNDERSTANDING
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="understanding", task="Analysing application architecture")
        await _run_agent(ctx, ArchitectureAgent(llm), phase_errors)
        if ctx.cancelled:
            await _finish_scan(scan_id, "cancelled")
            return

        # Compact if needed
        if await should_compact(ctx, llm):
            await _emit_progress(ctx, task="Compacting context")
            await compact_context(ctx, llm)

        # ══════════════════════════════════════════════════════════
        # STAGE 3: DEPENDENCY RISK ASSESSMENT
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="dependencies", task="Assessing dependency risks")
        await _run_agent(ctx, DependencyRiskAgent(llm), phase_errors)

        # FEEDBACK: Boost files that import vulnerable dependencies
        await _boost_vulnerable_dependency_files(ctx)

        if ctx.cancelled:
            await _finish_scan(scan_id, "cancelled")
            return

        # ══════════════════════════════════════════════════════════
        # STAGE 4: VULNERABILITY INVESTIGATION (multi-pass)
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="investigation", task="Starting vulnerability investigation")
        await _run_agent(ctx, InvestigatorAgent(llm), phase_errors)
        if ctx.cancelled:
            await _finish_scan(scan_id, "cancelled")
            return

        # Compact after investigation
        if await should_compact(ctx, llm):
            await _emit_progress(ctx, task="Compacting context")
            await compact_context(ctx, llm)

        # ══════════════════════════════════════════════════════════
        # STAGE 5: TARGETED SCANNER FOLLOW-UP
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="targeted_scan", task="Selecting targeted scanner rules")
        await _run_agent(ctx, RuleSelectorAgent(llm), phase_errors)

        # FEEDBACK: If rule selector found new hits, run a mini-investigation
        new_hits = sum(
            v for k, v in ctx.scanner_hit_counts.items()
            if k.endswith("_targeted")
        )
        if new_hits > 0 and ctx.mode in ("regular", "heavy"):
            await _emit_progress(ctx, task=f"Investigating {new_hits} new scanner findings")
            await event_bus.publish(ctx.scan_id, {
                "type": "event", "level": "info",
                "message": f"Running follow-up investigation on {new_hits} new scanner hits",
            })
            # Mini-investigation on files boosted by targeted scanner hits
            mini_investigator = InvestigatorAgent(llm)
            await _run_agent(ctx, mini_investigator, phase_errors)

        if ctx.cancelled:
            await _finish_scan(scan_id, "cancelled")
            return

        # ══════════════════════════════════════════════════════════
        # STAGE 6: VERIFICATION
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="verification", task="Verifying findings")
        pre_verify_count = len([f for f in ctx.candidate_findings if f.status == "investigating"])
        await _run_agent(ctx, VerifierAgent(llm), phase_errors)

        # FEEDBACK: If verification dismissed >70% of findings AND we're in heavy mode,
        # trigger a second investigation pass to find what we might have missed
        if ctx.mode == "heavy" and pre_verify_count > 3:
            confirmed = len([f for f in ctx.candidate_findings if f.status == "confirmed"])
            confirmation_rate = confirmed / pre_verify_count if pre_verify_count > 0 else 1.0

            if confirmation_rate < 0.30:
                await _emit_progress(ctx, task="Low confirmation rate — running deeper investigation")
                await event_bus.publish(ctx.scan_id, {
                    "type": "event", "level": "info",
                    "message": f"Only {confirmation_rate:.0%} confirmed. Running additional investigation pass.",
                })
                # Re-prioritise and run one more investigation pass
                ctx.reprioritise_queue()
                await _run_agent(ctx, InvestigatorAgent(llm), phase_errors)

                # Re-verify new findings only
                new_investigating = [f for f in ctx.candidate_findings if f.status == "investigating"]
                if new_investigating:
                    await _emit_progress(ctx, task="Verifying additional findings")
                    await _run_agent(ctx, VerifierAgent(llm), phase_errors)

        if ctx.cancelled:
            await _finish_scan(scan_id, "cancelled")
            return

        # ══════════════════════════════════════════════════════════
        # STAGE 7: REPORTING + DIAGRAM
        # ══════════════════════════════════════════════════════════
        await _emit_progress(ctx, phase="reporting", task="Generating report")
        await _run_agent(ctx, ReporterAgent(llm), phase_errors)

        # Render diagram
        if ctx.diagram_spec:
            await _emit_progress(ctx, task="Rendering architecture diagram")
            try:
                diagram_bytes = await render_diagram_for_report(
                    ctx.diagram_spec,
                    llm_client=llm,
                    techs=ctx.languages + ctx.frameworks,
                )
                async with async_session() as session:
                    report = (await session.execute(
                        select(Report).where(Report.scan_id == scan_id)
                    )).scalar_one_or_none()
                    if report:
                        report.diagram_image = diagram_bytes
                        await session.commit()
            except Exception as e:
                logger.warning("Diagram rendering failed: %s", e)
                phase_errors.append(f"Diagram rendering failed: {e}")

        # ══════════════════════════════════════════════════════════
        # FINALISE
        # ══════════════════════════════════════════════════════════
        final_status = "completed"
        error_msg = None
        if phase_errors:
            error_msg = f"Completed with warnings: {'; '.join(phase_errors)}"

        await _finish_scan(scan_id, final_status, error=error_msg)
        await _emit_progress(ctx, phase="done", status="completed")

    except Exception as e:
        logger.exception("Scan %s failed with unrecoverable error", scan_id)
        await _finish_scan(scan_id, "failed", error=str(e))
        await event_bus.publish(scan_id, {
            "type": "progress",
            "status": "failed",
            "error": str(e),
        })
    finally:
        if llm:
            try:
                await llm.close()
            except Exception:
                pass
        # Clean up scanner resources (e.g., CodeQL temp directories)
        for scanner in ctx.scanners.values():
            try:
                if hasattr(scanner, 'cleanup'):
                    scanner.cleanup()
            except Exception:
                pass
        await event_bus.complete(scan_id)


# ── Agent runner with unified progress ────────────────────────────

async def _run_agent(ctx: ScanContext, agent, errors: list[str]) -> bool:
    """Run a single agent with error recovery and progress tracking."""
    try:
        await event_bus.publish(ctx.scan_id, {
            "type": "event",
            "phase": ctx.current_phase,
            "level": "info",
            "message": f"Starting {agent.name}...",
        })
        await agent.execute(ctx)

        # Emit progress after agent completes (so counters are up to date)
        await event_bus.publish(ctx.scan_id, {
            "type": "progress",
            "status": "running",
            "phase": ctx.current_phase,
            "task": ctx.current_task,
            "findings_count": ctx.findings_count,
            "files_processed": ctx.files_processed,
            "files_total": ctx.files_total,
            "ai_calls_made": ctx.ai_calls_made,
        })
        return True

    except Exception as e:
        error_msg = f"{agent.name} failed: {e}"
        logger.warning("Agent %s failed: %s", agent.name, e)
        logger.debug(traceback.format_exc())
        errors.append(error_msg)

        await event_bus.publish(ctx.scan_id, {
            "type": "event",
            "phase": ctx.current_phase,
            "level": "error",
            "message": error_msg,
        })
        return False


# ── Feedback helpers ──────────────────────────────────────────────

async def _boost_vulnerable_dependency_files(ctx: ScanContext):
    """
    After dependency assessment, boost files that import vulnerable packages.
    This ensures the investigator prioritises code that uses vulnerable deps.
    """
    from app.models.dependency import Dependency, DependencyFinding
    from app.orchestrator.agents.dependency import ACTIVE_DEPENDENCY_RELEVANCE

    try:
        async with async_session() as session:
            result = await session.execute(
                select(DependencyFinding, Dependency)
                .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                .where(
                    DependencyFinding.scan_id == ctx.scan_id,
                    DependencyFinding.relevance.in_(ACTIVE_DEPENDENCY_RELEVANCE),
                )
                .order_by(
                    case((DependencyFinding.risk_score.is_(None), 1), else_=0),
                    DependencyFinding.risk_score.desc(),
                )
            )
            for df, dep in result.all():
                usage_evidence = df.usage_evidence or []
                if usage_evidence:
                    for hit in usage_evidence:
                        file_path = hit.get("file")
                        if not file_path or file_path in ctx.files_inspected:
                            continue
                        boost = 6.0 if hit.get("kind") == "vulnerable_function" else 4.0
                        ctx.boost_file(file_path, boost, f"dependency risk: {dep.name}")
                    continue

                # Fallback heuristic when reachability evidence is unavailable.
                for file_path in ctx.file_queue:
                    if file_path in ctx.files_inspected:
                        continue
                    if dep.ecosystem == "npm" and file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
                        ctx.boost_file(file_path, 3.0, f"uses vulnerable {dep.name}")
                    elif dep.ecosystem == "pypi" and file_path.endswith(".py"):
                        ctx.boost_file(file_path, 3.0, f"uses vulnerable {dep.name}")

            # Reprioritise after boosting
            ctx.reprioritise_queue()

    except Exception as e:
        logger.warning("Failed to boost dependency files: %s", e)


# ── Scan lifecycle helpers ────────────────────────────────────────

async def _finish_scan(scan_id: uuid.UUID, status: str, *, error: str | None = None):
    """Update the scan record with final status."""
    async with async_session() as session:
        scan = await session.get(Scan, scan_id)
        if scan:
            scan.status = status
            scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
            scan.current_phase = "done" if status == "completed" else status
            scan.current_task = None
            if error:
                scan.error_message = error
            await session.commit()


async def _create_minimal_report(ctx: ScanContext):
    """Create a minimal report when no LLM is available."""
    degraded_note = (
        " Scanner coverage was degraded for at least one tool; treat clean results as partial coverage."
        if ctx.degraded_coverage
        else ""
    )
    async with async_session() as session:
        report = Report(
            scan_id=ctx.scan_id,
            app_summary=(
                f"Scanner-only analysis of repository at {ctx.repo_path}. "
                f"Detected languages: {', '.join(ctx.languages)}. "
                f"Detected frameworks: {', '.join(ctx.frameworks)}. "
                f"No AI analysis was performed (no LLM profile configured)."
            ),
            methodology=(
                "This scan was performed in scanner-only mode without AI analysis. "
                f"The following scanners were used: {', '.join(ctx.scanner_runs.keys() or ctx.scanner_hit_counts.keys())}."
                f"{degraded_note}"
            ),
            limitations=(
                "No AI-driven code inspection, architecture understanding, "
                "false positive reduction, or finding verification was performed. "
                "All results are raw scanner output."
                f"{degraded_note}"
            ),
            tech_stack={
                "languages": ctx.languages,
                "frameworks": ctx.frameworks,
                "fingerprint": ctx.fingerprint,
            },
            scanner_hits=dict(ctx.scanner_hit_counts),
            scan_coverage={
                "total_files": ctx.files_total,
                "files_indexed": ctx.files_total - getattr(ctx, "files_skipped_cap", 0),
                "files_inspected_by_ai": len(ctx.files_inspected),
                "files_skipped_size": getattr(ctx, "files_skipped_size", 0),
                "files_skipped_cap": getattr(ctx, "files_skipped_cap", 0),
                "scanners_used": list(ctx.scanner_runs.keys()) or list(ctx.scanner_hit_counts.keys()),
                "scanner_runs": dict(ctx.scanner_runs),
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
            },
        )
        session.add(report)
        await session.commit()
