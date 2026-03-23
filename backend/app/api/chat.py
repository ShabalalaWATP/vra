"""AI Chat endpoint — streaming chat with report context."""

import json
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.llm_profile import LLMProfile
from app.models.report import Report
from app.models.scan import Scan

router = APIRouter(prefix="/scans/{scan_id}", tags=["chat"])


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    currently_viewing_file: str | None = None
    file_content: str | None = None


def _build_system_prompt(
    report: Report, scan: Scan, file_context: str = "", file_index: str = "",
) -> str:
    """Build a system prompt with report context for the chat."""
    parts = [
        "You are a senior security researcher assistant. You have full access to the "
        "vulnerability scan report AND the complete source code of the scanned application. "
        "Answer questions about findings, architecture, code, and security posture. "
        "Be specific — reference actual file paths, line numbers, and code when relevant.\n\n"
        "When the user asks about a file or code, look for it in the file index below "
        "and reference the code content provided. If they ask to 'search' for something, "
        "scan through the provided file contents.",
        "",
        f"## Application Summary",
        report.app_summary or "Not available.",
        "",
    ]

    if report.risk_score is not None:
        parts.append(f"## Risk Assessment")
        parts.append(f"Risk Score: {report.risk_score}/100 (Grade: {report.risk_grade or '?'})")
        parts.append("")

    if report.tech_stack:
        try:
            ts = json.loads(report.tech_stack) if isinstance(report.tech_stack, str) else report.tech_stack
            fp = ts.get("fingerprint", {})
            langs = fp.get("languages", [])
            if langs:
                lang_str = ", ".join(f"{l['name']} ({l['file_count']} files)" for l in langs[:5])
                parts.append(f"Languages: {lang_str}")
        except Exception:
            pass

    if report.methodology:
        parts.append(f"\n## Methodology\n{report.methodology[:500]}")

    # Add architecture notes (truncated)
    if report.architecture:
        try:
            arch = json.loads(report.architecture) if isinstance(report.architecture, str) else report.architecture
            components = arch.get("components", [])
            if components:
                parts.append("\n## Components")
                for c in components[:8]:
                    crit = c.get("criticality", "?")
                    parts.append(f"- **{c.get('name', '?')}** ({crit}): {c.get('purpose', '')[:80]}")
        except Exception:
            pass

    # File index — list of all source files so the AI knows what's available
    if file_index:
        parts.append(f"\n## Source File Index")
        parts.append(file_index)

    # Currently viewed file
    if file_context:
        parts.append(f"\n## Currently Viewing File")
        parts.append(file_context[:8000])

    return "\n".join(parts)


@router.post("/chat")
async def stream_chat(
    scan_id: uuid.UUID,
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
):
    """Stream a chat response with report context."""
    # Get scan and report
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    # Get the active LLM profile
    result = await db.execute(
        select(LLMProfile).where(LLMProfile.is_default == True)
    )
    profile = result.scalar_one_or_none()
    if not profile:
        # Fall back to scan's profile
        if scan.llm_profile_id:
            profile = await db.get(LLMProfile, scan.llm_profile_id)
        if not profile:
            raise HTTPException(400, "No LLM profile configured. Add one in Settings.")

    # Get report
    report_result = await db.execute(
        select(Report).where(Report.scan_id == scan_id)
    )
    report = report_result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "No report found for this scan")

    # Load findings for this scan
    from app.models.finding import Finding
    from app.models.file import File
    from app.models.project import Project
    from pathlib import Path as _Path

    from sqlalchemy.orm import selectinload as _selectinload
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(_selectinload(Finding.files), _selectinload(Finding.evidence))
        .order_by(Finding.severity)
    )
    findings = findings_result.scalars().all()

    # Build file context — currently viewed file
    file_context = ""
    if body.currently_viewing_file and body.file_content:
        file_context = f"File: {body.currently_viewing_file}\n```\n{body.file_content[:6000]}\n```"

    file_index = ""
    file_results = await db.execute(
        select(File).where(File.scan_id == scan_id).order_by(File.path)
    )
    all_files = file_results.scalars().all()

    # Build compact index: path | language | size
    if all_files:
        index_lines = [f"{f.path} ({f.language or '?'}, {f.size_bytes or 0}B)" for f in all_files]
        file_index = "\n".join(index_lines[:200])  # Cap at 200 files for context

    # Smart file search — if the user's latest message mentions a filename, include its content
    project = await db.get(Project, scan.project_id)
    last_user_msg = ""
    for msg in reversed(body.messages):
        if msg.role == "user":
            last_user_msg = msg.content.lower()
            break

    searched_files_context = ""
    if project and project.repo_path and last_user_msg:
        # Find files that match keywords in the user's message
        matched = []
        for f in all_files:
            fname = f.path.split("/")[-1].lower()
            # Match if user mentions the filename or a significant part of the path
            if fname in last_user_msg or any(
                part in last_user_msg
                for part in f.path.lower().replace("\\", "/").split("/")
                if len(part) > 3 and part not in ("source", "src", "app", "index", "the", "this", "that", "file")
            ):
                matched.append(f)

        # Load content of matched files (up to 3, 4K each)
        for mf in matched[:3]:
            try:
                fpath = _Path(project.repo_path) / mf.path
                if fpath.exists() and fpath.stat().st_size < 100000:
                    content = fpath.read_text(encoding="utf-8", errors="replace")[:4000]
                    searched_files_context += f"\n\n## File: {mf.path}\n```\n{content}\n```"
            except Exception:
                pass

    if searched_files_context:
        file_context = (file_context + searched_files_context) if file_context else searched_files_context

    # Build findings summary for the AI
    findings_context = ""
    if findings:
        lines = [f"\n## Security Findings ({len(findings)} total)"]
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        lines.append(f"Severity breakdown: {', '.join(f'{s}: {c}' for s, c in sorted(sev_counts.items()))}")
        lines.append("")
        for i, f in enumerate(findings[:30], 1):  # Cap at 30 for context window
            cwe = f", CWE: {', '.join(f.cwe_ids)}" if f.cwe_ids else ""
            cves = ""
            if f.related_cves:
                cve_ids = [c.get("cve_id", "") for c in f.related_cves[:2]]
                cves = f", Related CVEs: {', '.join(cve_ids)}"
            exploit = f", Exploit: {f.exploit_difficulty}" if f.exploit_difficulty else ""
            lines.append(
                f"{i}. **[{f.severity.upper()}]** {f.title} "
                f"(confidence: {f.confidence:.0%}{cwe}{cves}{exploit})"
            )
            if f.description:
                lines.append(f"   {f.description[:150]}")
            if f.code_snippet:
                lines.append(f"   Code: `{f.code_snippet[:100]}...`")
        if len(findings) > 30:
            lines.append(f"\n... and {len(findings) - 30} more findings")
        findings_context = "\n".join(lines)

    # Add methodology and limitations from report
    report_extras = ""
    if report.methodology:
        report_extras += f"\n## Methodology\n{report.methodology[:800]}"
    if report.limitations:
        report_extras += f"\n## Limitations\n{report.limitations[:400]}"

    system_prompt = _build_system_prompt(
        report, scan, file_context + findings_context + report_extras, file_index
    )

    # ── Tool definitions for function calling ──────────────────────
    tools = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read the full content of a source file from the scanned codebase. Use this when the user asks about a specific file or you need to see code.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "The file path relative to the project root (e.g., 'vulnerabilities/sqli/source/low.php')"
                        }
                    },
                    "required": ["file_path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_code",
                "description": "Search for a text pattern across all source files in the codebase. Returns matching lines with file paths and line numbers. Use for finding where a function is called, where a variable is used, etc.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The text or pattern to search for (case-insensitive)"
                        },
                        "file_extension": {
                            "type": "string",
                            "description": "Optional: filter by file extension (e.g., 'php', 'js')"
                        }
                    },
                    "required": ["query"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_finding_details",
                "description": "Get full details of a specific security finding including description, code snippet, evidence, exploit info, and related CVEs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_title": {
                            "type": "string",
                            "description": "The title or partial title of the finding to look up"
                        }
                    },
                    "required": ["finding_title"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_findings_by_file",
                "description": "List all security findings that affect a specific file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "The file path to check for findings"
                        }
                    },
                    "required": ["file_path"]
                }
            }
        },
    ]

    # ── Tool execution functions ──────────────────────────────────
    def _exec_read_file(args: dict) -> str:
        fp = args.get("file_path", "")
        if not project or not project.repo_path:
            return "Error: project source not available"
        full = _Path(project.repo_path) / fp
        if not full.exists():
            # Try fuzzy match
            for f in all_files:
                if f.path.endswith(fp) or fp in f.path:
                    full = _Path(project.repo_path) / f.path
                    break
        if not full.exists():
            return f"File not found: {fp}"
        try:
            content = full.read_text(encoding="utf-8", errors="replace")
            if len(content) > 8000:
                return content[:8000] + f"\n\n[... truncated at 8000 chars, file is {len(content)} chars total]"
            return content
        except Exception as e:
            return f"Error reading file: {e}"

    def _exec_search_code(args: dict) -> str:
        query = args.get("query", "").lower()
        ext_filter = args.get("file_extension", "")
        if not project or not project.repo_path or not query:
            return "Error: no query or project not available"
        results = []
        for f in all_files:
            if ext_filter and not f.path.endswith(f".{ext_filter}"):
                continue
            try:
                fp = _Path(project.repo_path) / f.path
                if not fp.exists() or fp.stat().st_size > 200000:
                    continue
                content = fp.read_text(encoding="utf-8", errors="replace")
                for i, line in enumerate(content.splitlines(), 1):
                    if query in line.lower():
                        results.append(f"{f.path}:{i}: {line.strip()[:120]}")
                        if len(results) >= 30:
                            return "\n".join(results) + "\n\n[... more results truncated]"
            except Exception:
                continue
        return "\n".join(results) if results else f"No matches found for '{query}'"

    def _exec_get_finding_details(args: dict) -> str:
        title_query = args.get("finding_title", "").lower()
        for f in findings:
            if title_query in f.title.lower():
                parts = [
                    f"**{f.title}**",
                    f"Severity: {f.severity} | Confidence: {f.confidence:.0%} | Category: {f.category}",
                    f"CWE: {', '.join(f.cwe_ids or [])}",
                ]
                if f.description:
                    parts.append(f"\nDescription: {f.description}")
                if f.code_snippet:
                    parts.append(f"\nCode:\n```\n{f.code_snippet[:500]}\n```")
                if f.exploit_difficulty:
                    parts.append(f"\nExploit Difficulty: {f.exploit_difficulty}")
                if f.exploit_template:
                    parts.append(f"\nPoC:\n```\n{f.exploit_template[:500]}\n```")
                if f.attack_scenario:
                    parts.append(f"\nAttack Scenario: {f.attack_scenario[:300]}")
                if f.related_cves:
                    cve_strs = [f"{c['cve_id']}: {c['summary'][:80]}" for c in f.related_cves[:3]]
                    parts.append(f"\nRelated CVEs:\n" + "\n".join(cve_strs))
                if f.evidence:
                    sup = [e for e in f.evidence if e.type == "supporting"]
                    opp = [e for e in f.evidence if e.type == "opposing"]
                    if sup:
                        parts.append(f"\nSupporting evidence: {'; '.join(e.description[:80] for e in sup[:3])}")
                    if opp:
                        parts.append(f"\nOpposing evidence: {'; '.join(e.description[:80] for e in opp[:3])}")
                return "\n".join(parts)
        return f"No finding matching '{title_query}' found"

    def _exec_list_findings_by_file(args: dict) -> str:
        fp = args.get("file_path", "").lower().replace("\\", "/")
        fname = fp.split("/")[-1]

        # 1. Check the finding_files join table (most accurate)
        matched_from_db = set()
        for f in findings:
            if not hasattr(f, 'files'):
                continue
            for ff in f.files:
                linked_file = next((af for af in all_files if af.id == ff.file_id), None)
                if linked_file:
                    linked_path = linked_file.path.lower().replace("\\", "/")
                    if fp == linked_path or linked_path.endswith(fp) or fp.endswith(linked_path):
                        matched_from_db.add(f.id)

        # 2. Also search description/code_snippet/title for the filename
        matched_from_text = set()
        for f in findings:
            if (fp in (f.description or "").lower() or
                (f.code_snippet and fp in f.code_snippet.lower()) or
                fname in f.title.lower() or
                fname in (f.description or "").lower()):
                matched_from_text.add(f.id)

        all_matched_ids = matched_from_db | matched_from_text
        if not all_matched_ids:
            return f"No findings found for file '{fp}'"

        matched = [f for f in findings if f.id in all_matched_ids]
        lines = [f"Findings affecting {fp} ({len(matched)} total):"]
        for f in matched:
            cwe = f", CWE: {', '.join(f.cwe_ids)}" if f.cwe_ids else ""
            lines.append(f"- [{f.severity.upper()}] {f.title} ({f.confidence:.0%}{cwe})")
            if f.description:
                lines.append(f"  {f.description[:120]}")
        return "\n".join(lines)

    tool_executors = {
        "read_file": _exec_read_file,
        "search_code": _exec_search_code,
        "get_finding_details": _exec_get_finding_details,
        "list_findings_by_file": _exec_list_findings_by_file,
    }

    # Build messages for the LLM
    messages = [{"role": "system", "content": system_prompt}]
    for msg in body.messages:
        messages.append({"role": msg.role, "content": msg.content})

    # Resolve chat path
    chat_paths = [
        "/v1/chat/completions",
        "/chat/completions",
        "/api/v1/chat/completions",
    ]

    headers = {}
    if profile.api_key:
        headers["Authorization"] = f"Bearer {profile.api_key}"

    token_field = "max_completion_tokens" if profile.use_max_completion_tokens else "max_tokens"

    def _make_payload(msgs, stream=True):
        p = {
            "model": profile.model_name,
            "messages": msgs,
            "temperature": 0.3,
            token_field: min(profile.max_output_tokens, 4096),
            "stream": stream,
            "tools": tools,
        }
        return p

    ssl_context = None
    if profile.cert_path:
        import ssl
        ssl_context = ssl.create_default_context(cafile=profile.cert_path)

    async def generate():
        async with httpx.AsyncClient(
            base_url=profile.base_url,
            timeout=120,
            verify=ssl_context or True,
        ) as client:
            current_messages = list(messages)
            max_tool_rounds = 3  # Prevent infinite tool call loops

            for tool_round in range(max_tool_rounds + 1):
                # First, try a non-streaming call to check for tool calls
                # (streaming + tool calls is complex, so do tool resolution non-streaming)
                if tool_round < max_tool_rounds:
                    last_error = None
                    for path in chat_paths:
                        try:
                            resp = await client.post(
                                path, headers=headers,
                                json=_make_payload(current_messages, stream=False),
                            )
                            if resp.status_code == 404:
                                continue
                            if resp.status_code != 200:
                                yield f"data: {json.dumps({'error': f'LLM error {resp.status_code}: {resp.text[:200]}'})}\n\n"
                                return

                            data = resp.json()
                            choice = data.get("choices", [{}])[0]
                            msg = choice.get("message", {})
                            tool_calls = msg.get("tool_calls")

                            if tool_calls:
                                # Execute tool calls and add results to messages
                                current_messages.append(msg)  # Add assistant's tool call message
                                yield f"data: {json.dumps({'content': '*Searching codebase...*\\n\\n', 'done': False})}\n\n"

                                for tc in tool_calls:
                                    func_name = tc["function"]["name"]
                                    try:
                                        func_args = json.loads(tc["function"]["arguments"])
                                    except Exception:
                                        func_args = {}

                                    executor = tool_executors.get(func_name)
                                    if executor:
                                        result = executor(func_args)
                                    else:
                                        result = f"Unknown tool: {func_name}"

                                    current_messages.append({
                                        "role": "tool",
                                        "tool_call_id": tc["id"],
                                        "content": result[:6000],
                                    })
                                # Continue loop — will call LLM again with tool results
                                break
                            else:
                                # No tool calls — model wants to respond directly
                                # Stream this response
                                content = msg.get("content", "")
                                if content:
                                    # Send in chunks for smooth streaming feel
                                    chunk_size = 20
                                    for i in range(0, len(content), chunk_size):
                                        yield f"data: {json.dumps({'content': content[i:i+chunk_size], 'done': False})}\n\n"
                                yield f"data: {json.dumps({'content': '', 'done': True})}\n\n"
                                return
                        except httpx.HTTPStatusError as e:
                            if e.response.status_code == 404:
                                continue
                            last_error = str(e)
                            break
                        except Exception as e:
                            last_error = str(e)
                            break
                    else:
                        # All paths failed
                        yield f"data: {json.dumps({'error': last_error or 'No chat endpoint found'})}\n\n"
                        return
                    if not tool_calls:
                        break
                else:
                    # Max tool rounds reached — do final streaming call without tools
                    for path in chat_paths:
                        try:
                            final_payload = _make_payload(current_messages, stream=True)
                            del final_payload["tools"]  # No more tools
                            async with client.stream(
                                "POST", path, headers=headers, json=final_payload
                            ) as resp:
                                if resp.status_code == 404:
                                    continue
                                if resp.status_code != 200:
                                    yield f"data: {json.dumps({'error': f'LLM error {resp.status_code}'})}\n\n"
                                    return
                                async for line in resp.aiter_lines():
                                    if not line.startswith("data: "):
                                        continue
                                    data_str = line[6:].strip()
                                    if data_str == "[DONE]":
                                        yield f"data: {json.dumps({'content': '', 'done': True})}\n\n"
                                        return
                                    try:
                                        chunk_data = json.loads(data_str)
                                        delta = chunk_data.get("choices", [{}])[0].get("delta", {})
                                        c = delta.get("content", "")
                                        if c:
                                            yield f"data: {json.dumps({'content': c, 'done': False})}\n\n"
                                    except json.JSONDecodeError:
                                        continue
                                yield f"data: {json.dumps({'content': '', 'done': True})}\n\n"
                                return
                        except Exception as e:
                            yield f"data: {json.dumps({'error': str(e)})}\n\n"
                            return

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
