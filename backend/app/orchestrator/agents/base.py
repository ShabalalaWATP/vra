"""Base agent interface for orchestrator agents."""

import json
import logging
import time
import uuid
from abc import ABC, abstractmethod

from app.database import async_session
from app.events.bus import event_bus
from app.models.agent_decision import AgentDecision
from app.models.scan import Scan, ScanEvent
from app.orchestrator.llm_client import LLMClient
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)
READ_PREVIEW_BYTES = 200_000


class BaseAgent(ABC):
    """Abstract base for all orchestrator agents.

    Every agent has access to:
    - self.llm: the LLM client for AI calls
    - self.tools: the AgentToolkit (initialised on first execute call)
    - self.emit(): log events to WebSocket
    - self.emit_progress(): update counters to both DB and WebSocket
    - self.read_file() / self.read_file_range(): shortcuts for file reading
    """

    def __init__(self, llm: LLMClient):
        self.llm = llm
        self._toolkit = None  # Lazy-initialised per scan context

    def get_tools(self, ctx: ScanContext):
        """Get the shared toolkit, creating it if needed."""
        if self._toolkit is None or self._toolkit.ctx is not ctx:
            from app.orchestrator.tools import AgentToolkit
            self._toolkit = AgentToolkit(ctx)
        return self._toolkit

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    async def execute(self, ctx: ScanContext) -> None:
        """Run this agent's logic, modifying the scan context."""
        ...

    async def emit(self, ctx: ScanContext, message: str, *, level: str = "info", detail: dict | None = None):
        """Emit a log event to both WebSocket and database."""
        await event_bus.publish(ctx.scan_id, {
            "type": "event",
            "phase": ctx.current_phase,
            "level": level,
            "message": message,
            "detail": detail,
        })
        # Persist to scan_events table
        try:
            async with async_session() as session:
                event = ScanEvent(
                    scan_id=ctx.scan_id,
                    phase=ctx.current_phase,
                    level=level,
                    message=message[:2000],
                    detail=detail,
                )
                session.add(event)
                await session.commit()
        except Exception:
            pass  # Don't let event persistence failures break the scan

    async def emit_progress(self, ctx: ScanContext, task: str | None = None):
        """
        Emit a progress update with current counters to BOTH WebSocket AND database.
        Call this periodically during long-running agent loops so the frontend
        gets real-time counter updates (files processed, findings count, etc).
        """
        if task:
            ctx.current_task = task

        # Update database
        async with async_session() as session:
            scan = await session.get(Scan, ctx.scan_id)
            if scan:
                scan.current_phase = ctx.current_phase
                scan.current_task = ctx.current_task
                scan.files_processed = ctx.files_processed
                scan.files_total = ctx.files_total
                scan.findings_count = len([f for f in ctx.candidate_findings if f.confidence >= 0.5])
                scan.ai_calls_made = ctx.ai_calls_made
                await session.commit()

        # Emit WebSocket progress event with counters
        await event_bus.publish(ctx.scan_id, {
            "type": "progress",
            "status": "running",
            "phase": ctx.current_phase,
            "task": ctx.current_task,
            "findings_count": len([f for f in ctx.candidate_findings if f.confidence >= 0.5]),
            "files_processed": ctx.files_processed,
            "files_total": ctx.files_total,
        })

    async def log_decision(
        self,
        ctx: ScanContext,
        action: str,
        *,
        reasoning: str = "",
        input_summary: str = "",
        output_summary: str = "",
        files_inspected: list[str] | None = None,
        tokens_used: int = 0,
        duration_ms: int = 0,
    ):
        """Persist an agent decision to the database."""
        async with async_session() as session:
            decision = AgentDecision(
                scan_id=ctx.scan_id,
                agent=self.name,
                phase=ctx.current_phase,
                action=action,
                reasoning=reasoning,
                input_summary=input_summary,
                output_summary=output_summary,
                files_inspected=files_inspected,
                tokens_used=tokens_used,
                duration_ms=duration_ms,
            )
            session.add(decision)
            await session.commit()

    @staticmethod
    def _read_text_preview(full_path, *, max_bytes: int = READ_PREVIEW_BYTES) -> tuple[str, bool]:
        """Read a bounded preview of a text file, avoiding full-file reads for huge files."""
        size = full_path.stat().st_size
        if size <= max_bytes:
            return full_path.read_text(encoding="utf-8", errors="replace"), False

        with full_path.open("rb") as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="replace"), True

    async def read_file(self, ctx: ScanContext, file_path: str, *, max_lines: int = 500) -> str:
        """Read a source file from the repo, truncating if needed."""
        from pathlib import Path
        from app.analysis.paths import is_safe_path

        if not file_path or not is_safe_path(file_path, Path(ctx.repo_path)):
            return f"[Path traversal blocked: {file_path}]"
        full_path = Path(ctx.repo_path) / file_path
        if not full_path.exists():
            return f"[File not found: {file_path}]"
        if not full_path.is_file():
            return f"[Not a file: {file_path}]"

        try:
            content, preview_truncated = self._read_text_preview(full_path)
            lines = content.splitlines()
            if len(lines) > max_lines:
                content = "\n".join(lines[:max_lines])
                content += f"\n\n[... truncated at {max_lines} preview lines, {len(lines)} shown ...]"
            elif preview_truncated:
                content += (
                    f"\n\n[... truncated at {READ_PREVIEW_BYTES:,} bytes; "
                    f"file is {full_path.stat().st_size:,} bytes ...]"
                )
            return content
        except Exception as e:
            return f"[Error reading {file_path}: {e}]"

    async def read_file_range(
        self, ctx: ScanContext, file_path: str, start_line: int, end_line: int
    ) -> str:
        """Read a specific line range from a source file."""
        from pathlib import Path
        from app.analysis.paths import is_safe_path

        if not file_path or not is_safe_path(file_path, Path(ctx.repo_path)):
            return f"[Path traversal blocked: {file_path}]"
        full_path = Path(ctx.repo_path) / file_path
        if not full_path.exists():
            return f"[File not found: {file_path}]"

        try:
            start_line = max(1, int(start_line))
            end_line = max(start_line, int(end_line))
            content, preview_truncated = self._read_text_preview(full_path)
            lines = content.splitlines()
            selected = lines[max(0, start_line - 1):end_line]
            numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(selected, start=max(1, start_line)))
            if preview_truncated:
                numbered += (
                    f"\n[preview truncated at {READ_PREVIEW_BYTES:,} bytes; "
                    "requested line range may be incomplete]"
                )
            return numbered
        except Exception as e:
            return f"[Error reading {file_path}: {e}]"

    async def ask_json(
        self,
        ctx: ScanContext,
        system: str,
        user: str,
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        allow_tools: bool = False,
        tool_names: list[str] | None = None,
        max_tool_rounds: int = 3,
    ) -> dict:
        """Request structured JSON, optionally allowing scan-time tool calls."""
        if allow_tools:
            toolkit = self.get_tools(ctx)
            tools = toolkit.get_openai_tools(source_type=ctx.source_type, tool_names=tool_names)
            if tools:
                try:
                    result = await self.llm.chat_with_tools(
                        [
                            {
                                "role": "system",
                                "content": (
                                    system
                                    + "\n\nYou may call tools when needed to inspect code, "
                                    "query scan state, or trace call paths. Return JSON in the final answer."
                                ),
                            },
                            {"role": "user", "content": user},
                        ],
                        tools=tools,
                        tool_executor=toolkit.execute_tool_call,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        max_tool_rounds=max_tool_rounds,
                    )
                    ctx.ai_calls_made += result.get("requests_made", 1)
                    return self._parse_json_response(result.get("content", ""))
                except Exception:
                    pass

        result = await self.llm.chat_json(
            system,
            user,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        ctx.ai_calls_made += 1
        return result

    @staticmethod
    def _parse_json_response(content: str) -> dict:
        content = (content or "").strip()
        if content.startswith("```"):
            lines = [line for line in content.splitlines() if not line.strip().startswith("```")]
            content = "\n".join(lines).strip()
        if not content:
            return {}
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {}
