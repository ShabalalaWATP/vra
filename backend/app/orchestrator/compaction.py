"""Context compaction — manage the AI's working memory relative to the model's context window.

The compaction system is driven by the actual context window of the configured model:
- Compaction triggers when accumulated context exceeds a fraction of the window
- If one round of compaction isn't enough, it runs again (recursive)
- The compaction budget (how much to keep) scales with the model's capacity
- Small-context models (4K-8K) get aggressive compaction
- Large-context models (128K+) get gentler compaction, keeping more detail
"""

import logging

from app.database import async_session
from app.models.agent_decision import CompactionSummary
from app.orchestrator.llm_client import LLMClient, estimate_tokens
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)

COMPACTION_SYSTEM_PROMPT = """You are a security research assistant. Your job is to compact
a set of observations, findings, and analysis into a concise summary that preserves
all security-relevant information while reducing token count.

Rules:
1. Preserve ALL confirmed or suspected vulnerabilities with their evidence
2. Preserve the application's architecture understanding
3. Preserve trust boundary and data flow information
4. Preserve key file names and their security relevance
5. Preserve all taint flows (source → sink mappings)
6. Drop redundant observations and verbose explanations
7. Use bullet points for density
8. Keep code snippets only for confirmed vulnerabilities
9. Summarise "checked and found safe" items in one line

Output a structured summary in plain text (not JSON)."""


def _estimate_context_size(ctx: ScanContext) -> int:
    """Estimate how many tokens the current scan context occupies."""
    total = 0
    total += estimate_tokens(ctx.app_summary or "")
    total += estimate_tokens(ctx.architecture_notes or "")
    total += sum(estimate_tokens(obs) for obs in ctx.key_observations)
    total += sum(estimate_tokens(cs) for cs in ctx.compaction_summaries)

    for finding in ctx.candidate_findings:
        total += estimate_tokens(finding.title + " " + finding.hypothesis)
        total += sum(estimate_tokens(ev) for ev in finding.supporting_evidence)
        total += sum(estimate_tokens(ev) for ev in finding.opposing_evidence)
        total += estimate_tokens(finding.code_snippet or "")

    for flow in ctx.taint_flows:
        total += estimate_tokens(
            f"{flow.source_file}:{flow.source_line} -> {flow.sink_file}:{flow.sink_line}"
        )

    return total


def compaction_threshold(context_window: int) -> int:
    """
    Determine when compaction should trigger, relative to the model's context window.

    We want to keep the accumulated context at roughly 30-40% of the window,
    leaving the rest for the current prompt + output.

    Small models:  trigger at ~2K tokens (for a 4K window, that's 50%)
    Medium models: trigger at ~15K tokens (for a 32K window, ~47%)
    Large models:  trigger at ~40K tokens (for a 128K window, ~31%)
    Huge models:   trigger at ~80K tokens (for a 400K window, ~20%)
    """
    return max(2000, int(context_window * 0.30))


def compaction_target(context_window: int) -> int:
    """
    Target size after compaction. We want to compress down to roughly
    15-20% of the window, leaving plenty of room.
    """
    return max(1000, int(context_window * 0.15))


async def should_compact(ctx: ScanContext, llm: LLMClient) -> bool:
    """Check if the current context size warrants compaction."""
    context_size = _estimate_context_size(ctx)
    threshold = compaction_threshold(llm.context_window)
    return context_size > threshold


async def compact_context(
    ctx: ScanContext,
    llm: LLMClient,
    *,
    max_rounds: int = 3,
) -> None:
    """
    Compact the scan context, potentially recursively, until it's under budget.

    The summary output token limit scales with the model:
    - Small models (4K-8K): 500-800 token summaries
    - Medium models (32K): ~2000 token summaries
    - Large models (128K+): ~3000 token summaries
    """
    threshold = compaction_threshold(llm.context_window)
    target = compaction_target(llm.context_window)

    for round_num in range(max_rounds):
        context_size = _estimate_context_size(ctx)
        if context_size <= threshold:
            break

        logger.info(
            "Compaction round %d for scan %s (context: %d tokens, threshold: %d, target: %d, window: %d)",
            round_num + 1, ctx.scan_id, context_size, threshold, target, llm.context_window,
        )

        # Scale summary output budget with model capacity
        summary_budget = min(3000, max(500, int(llm.context_window * 0.02)))

        input_text = _build_compaction_input(ctx)

        # Ensure the compaction prompt itself fits
        input_text = llm.truncate_to_fit(input_text, output_tokens=summary_budget)

        try:
            summary = await llm.chat_text(
                system=COMPACTION_SYSTEM_PROMPT,
                user=f"Compact the following security research context to under {summary_budget} tokens:\n\n{input_text}",
                max_tokens=summary_budget,
                temperature=0.1,
            )

            # Replace verbose data with compacted summary
            ctx.compaction_summaries = [summary]  # Replace, don't append (prevents unbounded growth)

            # Keep only recent observations (number scales with model capacity)
            keep_observations = min(8, max(2, llm.context_window // 30000))
            ctx.key_observations = ctx.key_observations[-keep_observations:]

            # Persist
            async with async_session() as session:
                cs = CompactionSummary(
                    scan_id=ctx.scan_id,
                    phase=ctx.current_phase,
                    summary=summary,
                    key_facts={
                        "round": round_num + 1,
                        "context_before": context_size,
                        "context_after": _estimate_context_size(ctx),
                        "threshold": threshold,
                        "window": llm.context_window,
                    },
                )
                session.add(cs)
                await session.commit()

            new_size = _estimate_context_size(ctx)
            logger.info(
                "Compaction round %d complete: %d -> %d tokens",
                round_num + 1, context_size, new_size,
            )

            if new_size <= target:
                break

        except Exception as e:
            logger.warning("Compaction round %d failed: %s", round_num + 1, e)
            # Emergency compaction: trim observations but keep more than just 2
            kept = max(3, len(ctx.key_observations) // 3)
            ctx.key_observations = ctx.key_observations[-kept:]
            ctx.compaction_summaries = ctx.compaction_summaries[-2:]
            # Notify the user via event bus
            from app.events.bus import event_bus
            import asyncio
            try:
                asyncio.get_event_loop().create_task(event_bus.publish(ctx.scan_id, {
                    "type": "event",
                    "level": "warn",
                    "message": f"Context compaction failed (round {round_num + 1}): {e}. "
                               f"Using emergency fallback — analysis quality may be reduced.",
                }))
            except Exception:
                pass  # Don't let notification failure cascade
            break


def _build_compaction_input(ctx: ScanContext) -> str:
    """Build the text to send for compaction."""
    parts = []

    if ctx.app_summary:
        parts.append(f"## Application Understanding\n{ctx.app_summary}")

    if ctx.key_observations:
        parts.append("## Key Observations")
        for obs in ctx.key_observations:
            parts.append(f"- {obs}")

    if ctx.candidate_findings:
        parts.append("## Candidate Findings")
        for f in ctx.candidate_findings:
            parts.append(
                f"- [{f.status}] {f.title} ({f.severity}, {f.confidence:.0%}) "
                f"in {f.file_path}: {f.hypothesis}"
            )
            if f.supporting_evidence:
                for ev in f.supporting_evidence[:2]:
                    parts.append(f"  + {ev}")
            if f.opposing_evidence:
                for ev in f.opposing_evidence[:2]:
                    parts.append(f"  - {ev}")

    if ctx.taint_flows:
        parts.append("## Taint Flows")
        for tf in ctx.taint_flows:
            san = " [SANITISED]" if tf.sanitised else ""
            parts.append(
                f"- {tf.source_type} @ {tf.source_file}:{tf.source_line} → "
                f"{tf.sink_type} @ {tf.sink_file}:{tf.sink_line}{san}"
            )

    if ctx.compaction_summaries:
        parts.append("## Previous Compaction Summaries")
        for summary in ctx.compaction_summaries:
            parts.append(summary)

    parts.append(f"\n## Files Inspected ({len(ctx.files_inspected)})")
    for fp in sorted(ctx.files_inspected)[:30]:
        parts.append(f"- {fp}")
    if len(ctx.files_inspected) > 30:
        parts.append(f"  ... and {len(ctx.files_inspected) - 30} more")

    return "\n".join(parts)


async def get_compacted_context(ctx: ScanContext) -> str:
    """Get the current working memory as a single text block for prompts."""
    parts = []

    if ctx.compaction_summaries:
        parts.append("## Research Context (Compacted)")
        for summary in ctx.compaction_summaries:
            parts.append(summary)

    if ctx.key_observations:
        parts.append("\n## Recent Observations")
        for obs in ctx.key_observations:
            parts.append(f"- {obs}")

    return "\n".join(parts)
