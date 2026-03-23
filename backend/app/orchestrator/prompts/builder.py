"""Prompt builder — assembles prompts sized to the model's context window.

All token budgets are derived from the LLM client's context_window and
max_output_tokens. Nothing is hardcoded to a specific model size.
"""

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.orchestrator.llm_client import CHARS_PER_TOKEN, estimate_tokens

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=False,
)


def render_prompt(template_name: str, **kwargs) -> str:
    """Render a Jinja2 prompt template with the given context."""
    template = _env.get_template(template_name)
    return template.render(**kwargs)


def truncate_to_budget(text: str, max_tokens: int) -> str:
    """Truncate text to fit within a token budget."""
    estimated = estimate_tokens(text)
    if estimated <= max_tokens:
        return text
    max_chars = int(max_tokens * CHARS_PER_TOKEN)
    truncated = text[:max_chars]
    last_newline = truncated.rfind("\n")
    if last_newline > max_chars * 0.8:
        truncated = truncated[:last_newline]
    tokens_dropped = estimated - max_tokens
    return truncated + f"\n\n[... truncated: ~{tokens_dropped} tokens omitted ...]"


def input_budget(llm_client) -> int:
    """Get the available input token budget from the LLM client."""
    if llm_client:
        return llm_client.available_input_tokens()
    return 8000  # Fallback for no-LLM mode


def build_file_context(
    files: list[dict],
    max_tokens: int,
) -> list[dict]:
    """
    Build file context entries that fit within a token budget.
    Allocates budget proportionally: larger files get more space but
    every file gets at least a minimum slice.
    """
    if not files:
        return []

    # Give each file at least 200 tokens for headers/summary
    min_per_file = 200
    total_content_tokens = sum(estimate_tokens(f.get("content", "")) for f in files)
    available = max_tokens - (min_per_file * len(files))

    result = []
    for f in files:
        content = f.get("content", "")
        content_tokens = estimate_tokens(content)

        # Proportional allocation: larger files get proportionally more budget
        if total_content_tokens > 0:
            share = max(min_per_file, int(available * (content_tokens / total_content_tokens)))
        else:
            share = available // len(files)

        if content_tokens > share:
            content = truncate_to_budget(content, share)

        result.append({**f, "content": content})

    return result


def build_investigation_prompt(
    files: list[dict],
    scan_context,
    llm_client=None,
    scanner_results: list[dict] | None = None,
) -> str:
    """Build a complete investigation prompt sized to the model's context window."""
    budget = input_budget(llm_client)

    # Reserve: ~1K for system prompt, ~30% for context, rest for files
    system_reserve = 1000
    context_share = 0.30
    context_budget = int((budget - system_reserve) * context_share)
    file_budget = budget - system_reserve - context_budget

    file_entries = build_file_context(files, max_tokens=file_budget)

    prompt = render_prompt(
        "investigate.j2",
        app_type=getattr(scan_context, "app_type", None),
        languages=scan_context.languages,
        frameworks=scan_context.frameworks,
        app_summary=truncate_to_budget(scan_context.app_summary or "", int(context_budget * 0.4)),
        attack_surface=scan_context.attack_surface,
        trust_boundaries=scan_context.trust_boundaries,
        prior_findings=[
            {
                "title": f.title,
                "severity": f.severity,
                "confidence": int(f.confidence * 100),
                "file_path": f.file_path,
            }
            for f in (scan_context.candidate_findings or [])[:8]
        ],
        scanner_context=scanner_results or [],
        key_observations=scan_context.key_observations,
        files=file_entries,
    )

    # Final safety check
    if llm_client and not llm_client.check_fits(prompt):
        prompt = llm_client.truncate_to_fit(prompt)

    return prompt


def build_verification_prompt(
    findings: list,
    files: list[dict],
    scan_context,
    llm_client=None,
) -> str:
    """Build a verification prompt sized to the model's context window."""
    budget = input_budget(llm_client)
    file_budget = int((budget - 1000) * 0.50)
    file_entries = build_file_context(files, max_tokens=file_budget)

    prompt = render_prompt(
        "verify.j2",
        app_type=getattr(scan_context, "app_type", None),
        languages=scan_context.languages,
        frameworks=scan_context.frameworks,
        app_summary=truncate_to_budget(scan_context.app_summary or "", 1500),
        findings=findings,
        files=file_entries,
    )

    if llm_client and not llm_client.check_fits(prompt):
        prompt = llm_client.truncate_to_fit(prompt)

    return prompt


def build_report_prompt(scan_context, llm_client=None) -> str:
    """Build the report generation prompt sized to the model's context window."""
    confirmed = [f for f in scan_context.candidate_findings if f.status != "dismissed"]

    prompt = render_prompt(
        "report.j2",
        app_summary=scan_context.app_summary,
        languages=scan_context.languages,
        frameworks=scan_context.frameworks,
        file_count=scan_context.files_total,
        files_inspected=len(scan_context.files_inspected),
        scan_mode=scan_context.mode,
        findings=confirmed,
        observations=scan_context.key_observations,
        scanner_hits=scan_context.scanner_hit_counts,
    )

    if llm_client and not llm_client.check_fits(prompt):
        prompt = llm_client.truncate_to_fit(prompt)

    return prompt
