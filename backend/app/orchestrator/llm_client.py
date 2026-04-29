"""Context-aware OpenAI-compatible LLM client.

Key design decisions:
- Tracks the model's context window size (input + output combined)
- Validates that prompt + requested output fits before sending
- Supports both max_tokens and max_completion_tokens fields
- Auto-truncates prompts when they exceed the input budget
- Returns actual token usage from API response for tracking
- Provides helpers to check available budget before building prompts
"""

import asyncio
import logging
import re
import ssl
import time

import httpx

logger = logging.getLogger(__name__)

# Token estimation: ~3.5 chars per token for code-heavy content,
# ~4 chars per token for English prose. We use 3.2 as a conservative
# estimate (slightly over-estimates token count = safer).
CHARS_PER_TOKEN = 3.2

# Reserve some tokens as safety margin (prompt overhead, special tokens, etc.)
SAFETY_MARGIN_TOKENS = 200


def estimate_tokens(text: str) -> int:
    """Estimate the number of tokens in a text string.

    Uses a conservative ratio of ~3.2 chars per token. This slightly
    over-estimates, which is safer than under-estimating (avoids
    context overflow). For more accuracy, install tiktoken.
    """
    if not text:
        return 0
    return int(len(text) / CHARS_PER_TOKEN) + 1


class LLMClient:
    """Async client for OpenAI-compatible chat completion endpoints.

    Context-window-aware: knows the model's total capacity and ensures
    requests don't exceed it.
    """

    def __init__(
        self,
        base_url: str,
        model_name: str,
        *,
        api_key: str | None = None,
        cert_path: str | None = None,
        timeout: int = 500,
        context_window: int = 131072,
        max_output_tokens: int = 4096,
        use_max_completion_tokens: bool = False,
        concurrency: int = 2,
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.api_key = api_key
        self.timeout = timeout
        self.context_window = context_window
        self.max_output_tokens = max_output_tokens
        self.use_max_completion_tokens = use_max_completion_tokens
        self.concurrency = max(1, int(concurrency))

        verify: bool | ssl.SSLContext = True
        if cert_path:
            ctx = ssl.create_default_context(cafile=cert_path)
            verify = ctx

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            verify=verify,
        )

        # Chat completions path — auto-detected on first call
        self._chat_path: str | None = None
        self._response_format_supported: bool | None = None

        # Running token counters
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_requests = 0

        # Rate limit management: track last request time for proactive pacing
        self._last_request_time: float = 0
        self._min_request_interval: float = 0.5  # seconds between requests (adjustable)
        self._request_semaphore = asyncio.Semaphore(self.concurrency)

    @property
    def max_input_tokens(self) -> int:
        """Maximum tokens available for prompt input."""
        return self.context_window - self.max_output_tokens - SAFETY_MARGIN_TOKENS

    async def close(self):
        await self._client.aclose()

    def check_fits(self, text: str, output_tokens: int | None = None) -> bool:
        """Check whether a prompt text fits within the input budget."""
        out = output_tokens or self.max_output_tokens
        budget = self.context_window - out - SAFETY_MARGIN_TOKENS
        return estimate_tokens(text) <= budget

    def available_input_tokens(self, output_tokens: int | None = None) -> int:
        """How many input tokens are available given the output reservation."""
        out = output_tokens or self.max_output_tokens
        return max(0, self.context_window - out - SAFETY_MARGIN_TOKENS)

    async def _resolve_chat_path(self, headers: dict) -> str:
        """Auto-detect the chat completions path on first call, then cache it.

        Tries /v1/chat/completions, /chat/completions, /api/v1/chat/completions,
        and /api/chat/completions. Sends a minimal OPTIONS or HEAD to check which
        path doesn't 404, falling back to /v1/chat/completions if all fail.
        """
        if self._chat_path is not None:
            return self._chat_path

        candidates = [
            "/v1/chat/completions",
            "/chat/completions",
            "/api/v1/chat/completions",
            "/api/chat/completions",
        ]

        # Quick probe: send a minimal request to find which path works.
        # We use a tiny chat request rather than OPTIONS since many LLM
        # servers don't support OPTIONS/HEAD properly.
        token_field = "max_completion_tokens" if self.use_max_completion_tokens else "max_tokens"
        probe_body = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": "hi"}],
            token_field: 1,
        }

        for path in candidates:
            try:
                resp = await self._client.post(
                    path, headers=headers, json=probe_body
                )
                if resp.status_code == 404:
                    continue
                # Any non-404 response means this path exists
                self._chat_path = path
                logger.info("Auto-detected chat path: %s", path)
                return path
            except Exception:
                continue

        # Fallback to the standard path
        self._chat_path = "/v1/chat/completions"
        logger.warning(
            "Could not auto-detect chat path, falling back to %s",
            self._chat_path,
        )
        return self._chat_path

    def truncate_to_fit(self, text: str, output_tokens: int | None = None) -> str:
        """Truncate text to fit within the available input budget."""
        budget = self.available_input_tokens(output_tokens)
        estimated = estimate_tokens(text)
        if estimated <= budget:
            return text

        max_chars = int(budget * CHARS_PER_TOKEN)
        truncated = text[:max_chars]
        last_newline = truncated.rfind("\n")
        if last_newline > max_chars * 0.8:
            truncated = truncated[:last_newline]

        tokens_dropped = estimated - budget
        truncated += f"\n\n[... truncated: ~{tokens_dropped} tokens omitted to fit context window ...]"
        return truncated

    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        json_mode: bool = False,
        tools: list[dict] | None = None,
    ) -> dict:
        """
        Send a chat completion request with context-window validation.

        Returns {content, tokens_used, prompt_tokens, completion_tokens,
                 duration_ms, model, truncated}.
        """
        output_budget = max_tokens or self.max_output_tokens

        # ── Pre-send validation ───────────────────────────────────
        total_input = sum(estimate_tokens(m.get("content", "")) for m in messages)
        total_needed = total_input + output_budget + SAFETY_MARGIN_TOKENS
        truncated = False

        if total_needed > self.context_window:
            logger.warning(
                "Prompt too large (%d est. tokens, window=%d). Auto-truncating.",
                total_needed, self.context_window,
            )
            messages = self._truncate_messages(messages, output_budget)
            truncated = True

        # ── Build request body ────────────────────────────────────
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body: dict = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
        }

        if self.use_max_completion_tokens:
            body["max_completion_tokens"] = output_budget
        else:
            body["max_tokens"] = output_budget

        if json_mode and self._response_format_supported is not False:
            body["response_format"] = {"type": "json_object"}
        if tools:
            body["tools"] = tools

        # ── Proactive pacing to avoid rate limits ──────────────────────
        import asyncio as _aio
        import random as _random

        elapsed_since_last = time.monotonic() - self._last_request_time
        if elapsed_since_last < self._min_request_interval:
            await _aio.sleep(self._min_request_interval - elapsed_since_last)

        # ── Send request with exponential backoff on 429 ─────────────
        async with self._request_semaphore:
            chat_path = await self._resolve_chat_path(headers)
            start = time.monotonic()
            max_retries = 3
            resp = None

            for attempt in range(max_retries + 1):
                try:
                    resp = await self._client.post(
                        chat_path,
                        headers=headers,
                        json=body,
                    )
                except httpx.RequestError as exc:
                    if attempt >= max_retries:
                        logger.error(
                            "LLM transport error after %d attempts: %s (path=%s, model=%s)",
                            attempt + 1, exc, chat_path, self.model_name,
                        )
                        raise
                    base_delay = min(2 ** attempt, 30)
                    jitter = _random.uniform(0, base_delay)
                    wait = base_delay + jitter
                    logger.warning(
                        "LLM transport error (%s). Retrying in %.1fs (attempt %d/%d)...",
                        exc, wait, attempt + 1, max_retries,
                    )
                    await _aio.sleep(wait)
                    continue

                if resp.status_code in {429, 502, 503, 504} and attempt < max_retries:
                    # Exponential backoff with jitter for transient provider overload/outage.
                    base_delay = min(2 ** attempt, 60)
                    jitter = _random.uniform(0, base_delay)
                    wait = base_delay + jitter
                    logger.warning(
                        "LLM request got HTTP %d. Retrying in %.1fs (attempt %d/%d)...",
                        resp.status_code, wait, attempt + 1, max_retries,
                    )
                    await _aio.sleep(wait)
                    continue
                if (
                    json_mode
                    and "response_format" in body
                    and self._is_response_format_unsupported(resp)
                ):
                    logger.warning(
                        "LLM endpoint does not support response_format; "
                        "retrying JSON request without provider-enforced JSON mode."
                    )
                    self._response_format_supported = False
                    body = dict(body)
                    body.pop("response_format", None)
                    continue
                break

            duration_ms = int((time.monotonic() - start) * 1000)

        if resp.status_code != 200:
            body_text = resp.text[:500]
            logger.error(
                "LLM request failed: HTTP %d — %s (path=%s, model=%s)",
                resp.status_code, body_text, chat_path, self.model_name,
            )
            resp.raise_for_status()

        data = resp.json()
        if not data.get("choices"):
            logger.error("LLM response missing 'choices': %s", str(data)[:500])
            raise ValueError("LLM response missing 'choices' field")
        choice = data["choices"][0]
        message = choice.get("message", {})
        usage = data.get("usage", {})

        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)

        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_requests += 1
        self._last_request_time = time.monotonic()

        finish_reason = choice.get("finish_reason", "unknown")
        content = message.get("content") or ""
        tool_calls = message.get("tool_calls") or []

        if not content and finish_reason != "stop":
            logger.warning(
                "LLM returned empty content. finish_reason=%s, "
                "prompt_tokens=%d, completion_tokens=%d, model=%s",
                finish_reason, prompt_tokens, completion_tokens, self.model_name,
            )
        elif finish_reason == "length":
            logger.warning(
                "LLM output truncated (finish_reason=length). "
                "Got %d completion tokens (budget=%d). Response may be incomplete JSON.",
                completion_tokens, output_budget,
            )

        return {
            "content": content,
            "tool_calls": tool_calls,
            "message": message,
            "tokens_used": prompt_tokens + completion_tokens,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "duration_ms": duration_ms,
            "model": data.get("model", self.model_name),
            "truncated": truncated,
            "finish_reason": finish_reason,
        }

    async def chat_with_tools(
        self,
        messages: list[dict],
        *,
        tools: list[dict],
        tool_executor,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        max_tool_rounds: int = 3,
    ) -> dict:
        """Run a tool-using chat loop until the model returns a final answer."""
        import json

        current_messages = list(messages)
        total_tokens = 0
        requests_made = 0

        for _ in range(max_tool_rounds + 1):
            result = await self.chat(
                current_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
            )
            total_tokens += result.get("tokens_used", 0)
            requests_made += 1

            tool_calls = result.get("tool_calls") or []
            if not tool_calls:
                result["tokens_used"] = total_tokens
                result["requests_made"] = requests_made
                return result

            assistant_message = {
                "role": "assistant",
                "content": result.get("content", ""),
                "tool_calls": tool_calls,
            }
            current_messages.append(assistant_message)

            for tool_call in tool_calls:
                func = tool_call.get("function", {})
                func_name = func.get("name", "")
                try:
                    func_args = json.loads(func.get("arguments") or "{}")
                except json.JSONDecodeError:
                    func_args = {}

                tool_result = await tool_executor(func_name, func_args)
                if hasattr(tool_result, "success"):
                    payload = {
                        "success": tool_result.success,
                        "data": tool_result.data,
                        "error": tool_result.error,
                    }
                else:
                    payload = tool_result

                current_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.get("id", func_name),
                        "content": json.dumps(payload),
                    }
                )

        result = await self.chat(
            current_messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        total_tokens += result.get("tokens_used", 0)
        requests_made += 1
        result["tokens_used"] = total_tokens
        result["requests_made"] = requests_made
        return result

    async def chat_text(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> str:
        """Convenience: send system+user messages, return content string."""
        result = await self.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return result["content"]

    async def chat_json(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> dict:
        """Convenience: send messages expecting JSON response, return parsed dict."""

        result = await self.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
        )
        content = (result.get("content") or "").strip()
        if not content:
            logger.warning(
                "LLM returned empty content for JSON request. "
                "finish_reason=%s, tokens: %d prompt + %d completion",
                result.get("finish_reason", "?"),
                result.get("prompt_tokens", 0),
                result.get("completion_tokens", 0),
            )
            return {}

        parsed = self._parse_json_response(
            content,
            allow_repair=result.get("finish_reason") == "length",
        )
        if parsed is not None:
            return parsed

        logger.error("LLM JSON parse error — content preview: %.300s", content)
        return {}

    @classmethod
    def _parse_json_response(cls, content: str, *, allow_repair: bool = False) -> dict | None:
        """Parse JSON from model output, tolerating visible reasoning wrappers.

        Some OpenAI-compatible servers expose chain-of-thought in the content
        stream before the actual JSON. We intentionally discard everything
        outside the first parseable JSON value.
        """
        import json as _json

        for candidate in cls._json_candidates(content):
            try:
                parsed = _json.loads(candidate)
            except _json.JSONDecodeError:
                if allow_repair:
                    repaired = cls._repair_truncated_json(candidate)
                    if repaired is not None:
                        return repaired
                continue
            if isinstance(parsed, dict):
                return parsed
            logger.warning("LLM JSON response parsed to %s, expected object", type(parsed).__name__)
            return {}

        if allow_repair:
            cleaned = cls._strip_visible_reasoning(content)
            repaired = cls._repair_truncated_json(cleaned)
            if repaired is not None:
                return repaired
        return None

    @classmethod
    def _json_candidates(cls, content: str) -> list[str]:
        """Return likely JSON substrings, most precise first."""
        cleaned = cls._strip_visible_reasoning(content)
        candidates: list[str] = []

        for source in (cleaned, content):
            for match in re.finditer(r"```(?:json)?\s*(.*?)```", source, re.DOTALL | re.IGNORECASE):
                cls._append_unique(candidates, match.group(1).strip())

        for source in (cleaned, content):
            cls._append_unique(candidates, source.strip())
            first_partial: str | None = None
            for start, char in enumerate(source):
                if char not in "{[":
                    continue
                balanced = cls._balanced_json_from(source, start)
                if balanced:
                    cls._append_unique(candidates, balanced)
                    continue
                if first_partial is None:
                    first_partial = source[start:].strip()
            if first_partial is not None:
                cls._append_unique(candidates, first_partial)

        return candidates

    @staticmethod
    def _strip_visible_reasoning(content: str) -> str:
        """Remove common visible-reasoning blocks without touching JSON strings."""
        text = content.strip()
        if not text:
            return text

        text = re.sub(r"(?is)<think\b[^>]*>.*?</think>", "", text).strip()
        text = re.sub(r"(?is)<thinking\b[^>]*>.*?</thinking>", "", text).strip()

        # If a server emits an unterminated thinking tag, salvage from the first
        # JSON opener after that tag.
        if re.match(r"(?is)^\s*<think(?:ing)?\b", text):
            starts = [idx for idx in (text.find("{"), text.find("[")) if idx >= 0]
            if starts:
                text = text[min(starts):].strip()

        return text

    @staticmethod
    def _balanced_json_from(text: str, start: int) -> str | None:
        stack: list[str] = []
        in_string = False
        escape = False

        for idx in range(start, len(text)):
            char = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char in "{[":
                stack.append(char)
            elif char in "}]":
                if not stack:
                    return None
                opener = stack.pop()
                if (opener, char) not in (("{", "}"), ("[", "]")):
                    return None
                if not stack:
                    return text[start: idx + 1].strip()

        return None

    @staticmethod
    def _append_unique(candidates: list[str], value: str) -> None:
        if value and value not in candidates:
            candidates.append(value)

    @staticmethod
    def _is_response_format_unsupported(resp: httpx.Response) -> bool:
        if resp.status_code not in {400, 404, 422}:
            return False
        text = resp.text.lower()
        if "response_format" not in text and "response format" not in text:
            return False
        unsupported_markers = (
            "unsupported",
            "not support",
            "unknown",
            "unrecognized",
            "not permitted",
            "forbidden",
            "extra inputs are not permitted",
            "invalid parameter",
        )
        return any(marker in text for marker in unsupported_markers)

    @staticmethod
    def _repair_truncated_json(content: str) -> dict | None:
        """Try to repair truncated JSON by closing open brackets/braces."""
        import json as _json

        # Count open brackets
        open_braces = content.count("{") - content.count("}")
        open_brackets = content.count("[") - content.count("]")

        # Strip trailing incomplete values (partial strings, dangling commas)
        trimmed = content.rstrip()
        # Remove trailing comma if present
        if trimmed.endswith(","):
            trimmed = trimmed[:-1]

        # Close open structures
        trimmed += "]" * max(0, open_brackets)
        trimmed += "}" * max(0, open_braces)

        try:
            return _json.loads(trimmed)
        except _json.JSONDecodeError:
            return None

    def _truncate_messages(
        self,
        messages: list[dict[str, str]],
        output_budget: int,
    ) -> list[dict[str, str]]:
        """Truncate multiple oversized messages while preserving both head and tail context."""
        available = self.context_window - output_budget - SAFETY_MARGIN_TOKENS
        result = [dict(message) for message in messages]

        def total_tokens() -> int:
            return sum(estimate_tokens(message.get("content", "")) for message in result)

        def truncatable_indices(include_system: bool) -> list[int]:
            indices = []
            for index, message in enumerate(result):
                role = message.get("role", "")
                content = message.get("content", "")
                if not content:
                    continue
                if not include_system and role == "system":
                    continue
                if estimate_tokens(content) <= 150:
                    continue
                indices.append(index)
            indices.sort(key=lambda idx: estimate_tokens(result[idx].get("content", "")), reverse=True)
            return indices

        overage = total_tokens() - available
        if overage <= 0:
            return result

        marker = f"\n\n[... content truncated to fit {self.context_window}-token context window ...]\n\n"

        for include_system in (False, True):
            for idx in truncatable_indices(include_system):
                if overage <= 0:
                    break

                content = result[idx].get("content", "")
                current_tokens = estimate_tokens(content)
                min_tokens = 220 if result[idx].get("role") == "system" else 120
                removable_tokens = max(0, current_tokens - min_tokens)
                if removable_tokens <= 0:
                    continue

                tokens_to_trim = min(removable_tokens, max(overage, 80))
                target_tokens = max(min_tokens, current_tokens - tokens_to_trim)
                max_chars = max(80, int(target_tokens * CHARS_PER_TOKEN))

                if len(content) <= max_chars:
                    continue

                keep_chars = max(0, max_chars - len(marker))
                head_chars = max(40, keep_chars // 2)
                tail_chars = max(40, keep_chars - head_chars)
                if head_chars + tail_chars >= len(content):
                    continue

                truncated = content[:head_chars].rstrip() + marker + content[-tail_chars:].lstrip()
                result[idx]["content"] = truncated
                overage = total_tokens() - available

            if overage <= 0:
                break

        return result
