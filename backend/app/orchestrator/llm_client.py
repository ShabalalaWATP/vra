"""Context-aware OpenAI-compatible LLM client.

Key design decisions:
- Tracks the model's context window size (input + output combined)
- Validates that prompt + requested output fits before sending
- Supports both max_tokens and max_completion_tokens fields
- Auto-truncates prompts when they exceed the input budget
- Returns actual token usage from API response for tracking
- Provides helpers to check available budget before building prompts
"""

import logging
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
        timeout: int = 120,
        context_window: int = 131072,
        max_output_tokens: int = 4096,
        use_max_completion_tokens: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.api_key = api_key
        self.timeout = timeout
        self.context_window = context_window
        self.max_output_tokens = max_output_tokens
        self.use_max_completion_tokens = use_max_completion_tokens

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

        # Running token counters
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_requests = 0

        # Rate limit management: track last request time for proactive pacing
        self._last_request_time: float = 0
        self._min_request_interval: float = 0.5  # seconds between requests (adjustable)

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

        if json_mode:
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
        chat_path = await self._resolve_chat_path(headers)
        start = time.monotonic()
        max_retries = 5
        resp = None

        for attempt in range(max_retries + 1):
            resp = await self._client.post(
                chat_path,
                headers=headers,
                json=body,
            )
            if resp.status_code == 429 and attempt < max_retries:
                # Exponential backoff with jitter (OpenAI recommended)
                base_delay = min(2 ** attempt, 60)  # 1, 2, 4, 8, 16... capped at 60
                jitter = _random.uniform(0, base_delay)
                wait = base_delay + jitter
                logger.warning(
                    "Rate limited (429). Retrying in %.1fs (attempt %d/%d)...",
                    wait, attempt + 1, max_retries,
                )
                await _aio.sleep(wait)
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
        import json

        result = await self.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
        )
        content = result.get("content") or ""
        # Strip markdown code fences if the model wraps JSON in ```json ... ```
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            # Remove first line (```json) and last line (```)
            lines = [l for l in lines if not l.strip().startswith("```")]
            content = "\n".join(lines).strip()
        if not content:
            logger.warning(
                "LLM returned empty content for JSON request. "
                "finish_reason=%s, tokens: %d prompt + %d completion",
                result.get("finish_reason", "?"),
                result.get("prompt_tokens", 0),
                result.get("completion_tokens", 0),
            )
            return {}
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            # If truncated (finish_reason=length), try to repair by closing brackets
            if result.get("finish_reason") == "length":
                logger.warning("JSON truncated (finish_reason=length). Attempting repair...")
                repaired = self._repair_truncated_json(content)
                if repaired is not None:
                    return repaired
            logger.error("LLM JSON parse error: %s — content preview: %.300s", e, content)
            return {}

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
        """Truncate the largest message to fit within context window."""
        available = self.context_window - output_budget - SAFETY_MARGIN_TOKENS

        msg_sizes = [(i, estimate_tokens(m.get("content", ""))) for i, m in enumerate(messages)]
        msg_sizes.sort(key=lambda x: x[1], reverse=True)

        total = sum(s for _, s in msg_sizes)
        overage = total - available

        if overage <= 0:
            return messages

        result = list(messages)
        idx, size = msg_sizes[0]
        target_size = max(500, size - overage)
        max_chars = int(target_size * CHARS_PER_TOKEN)
        content = result[idx]["content"]

        if len(content) > max_chars:
            truncated_text = content[:max_chars]
            last_nl = truncated_text.rfind("\n")
            if last_nl > max_chars * 0.8:
                truncated_text = truncated_text[:last_nl]
            truncated_text += f"\n\n[... content truncated to fit {self.context_window}-token context window ...]"
            result[idx] = {**result[idx], "content": truncated_text}

        return result
