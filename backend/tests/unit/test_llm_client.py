import asyncio

import httpx

from app.orchestrator.llm_client import LLMClient, estimate_tokens


def test_truncate_messages_trims_multiple_large_messages_and_preserves_system():
    client = LLMClient(
        base_url="http://localhost:1234",
        model_name="test-model",
        context_window=1200,
        max_output_tokens=200,
    )
    messages = [
        {"role": "system", "content": "system guardrails " * 40},
        {"role": "user", "content": ("alpha " * 1200) + "TAIL_A"},
        {"role": "tool", "content": ("beta " * 1200) + "TAIL_B"},
    ]

    truncated = client._truncate_messages(messages, output_budget=200)

    assert truncated[0]["content"] == messages[0]["content"]
    assert "content truncated" in truncated[1]["content"]
    assert "content truncated" in truncated[2]["content"]
    assert "TAIL_A" in truncated[1]["content"]
    assert "TAIL_B" in truncated[2]["content"]
    assert sum(estimate_tokens(message.get("content", "")) for message in truncated) <= (
        client.context_window - 200 - 200
    )

    asyncio.run(client.close())


def test_chat_retries_transient_transport_errors(monkeypatch):
    client = LLMClient(
        base_url="http://localhost:1234",
        model_name="test-model",
        context_window=4096,
        max_output_tokens=256,
    )
    calls = {"count": 0}

    async def fake_resolve_chat_path(_headers):
        return "/v1/chat/completions"

    async def fake_post(path, *, headers=None, json=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ConnectError("getaddrinfo failed", request=httpx.Request("POST", f"http://localhost:1234{path}"))
        return httpx.Response(
            200,
            request=httpx.Request("POST", f"http://localhost:1234{path}"),
            json={
                "choices": [
                    {
                        "message": {"content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
                "model": "test-model",
            },
        )

    monkeypatch.setattr(client, "_resolve_chat_path", fake_resolve_chat_path)
    monkeypatch.setattr(client._client, "post", fake_post)

    result = asyncio.run(
        client.chat(
            [{"role": "user", "content": "hello"}],
            max_tokens=64,
        )
    )

    assert result["content"] == "ok"
    assert calls["count"] == 2

    asyncio.run(client.close())


def test_chat_json_retries_without_response_format_when_unsupported(monkeypatch):
    client = LLMClient(
        base_url="http://localhost:1234",
        model_name="test-model",
        context_window=4096,
        max_output_tokens=256,
    )
    bodies = []

    async def fake_resolve_chat_path(_headers):
        return "/v1/chat/completions"

    async def fake_post(path, *, headers=None, json=None):
        bodies.append(dict(json or {}))
        request = httpx.Request("POST", f"http://localhost:1234{path}")
        if len(bodies) == 1:
            return httpx.Response(
                400,
                request=request,
                json={"error": {"message": "response_format is not supported by this model"}},
            )
        return httpx.Response(
            200,
            request=request,
            json={
                "choices": [
                    {
                        "message": {"content": '{"ok": true}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
                "model": "test-model",
            },
        )

    monkeypatch.setattr(client, "_resolve_chat_path", fake_resolve_chat_path)
    monkeypatch.setattr(client._client, "post", fake_post)

    result = asyncio.run(client.chat_json("Return JSON.", "hello", max_tokens=64))

    assert result == {"ok": True}
    assert "response_format" in bodies[0]
    assert "response_format" not in bodies[1]
    assert client._response_format_supported is False

    asyncio.run(client.close())


def test_chat_retries_with_alternate_token_parameter(monkeypatch):
    client = LLMClient(
        base_url="http://localhost:1234",
        model_name="test-model",
        context_window=4096,
        max_output_tokens=256,
        use_max_completion_tokens=False,
    )
    bodies = []

    async def fake_resolve_chat_path(_headers):
        return "/v1/chat/completions"

    async def fake_post(path, *, headers=None, json=None):
        bodies.append(dict(json or {}))
        request = httpx.Request("POST", f"http://localhost:1234{path}")
        if len(bodies) == 1:
            return httpx.Response(
                400,
                request=request,
                json={"error": {"message": "max_tokens is not supported by this endpoint"}},
            )
        return httpx.Response(
            200,
            request=request,
            json={
                "choices": [
                    {
                        "message": {"content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
                "model": "test-model",
            },
        )

    monkeypatch.setattr(client, "_resolve_chat_path", fake_resolve_chat_path)
    monkeypatch.setattr(client._client, "post", fake_post)

    result = asyncio.run(client.chat([{"role": "user", "content": "hello"}], max_tokens=64))

    assert result["content"] == "ok"
    assert "max_tokens" in bodies[0]
    assert "max_completion_tokens" in bodies[1]
    assert client._token_param == "max_completion_tokens"

    asyncio.run(client.close())


def test_chat_json_retries_after_malformed_structured_output(monkeypatch):
    client = LLMClient(
        base_url="http://localhost:1234",
        model_name="test-model",
        context_window=4096,
        max_output_tokens=256,
    )
    bodies = []

    async def fake_resolve_chat_path(_headers):
        return "/v1/chat/completions"

    async def fake_post(path, *, headers=None, json=None):
        bodies.append(dict(json or {}))
        request = httpx.Request("POST", f"http://localhost:1234{path}")
        if len(bodies) == 1:
            return httpx.Response(
                200,
                request=request,
                json={
                    "choices": [
                        {
                            "message": {"content": "I think the answer is ok."},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 8},
                    "model": "test-model",
                },
            )
        return httpx.Response(
            200,
            request=request,
            json={
                "choices": [
                    {
                        "message": {"content": '{"ok": true}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
                "model": "test-model",
            },
        )

    monkeypatch.setattr(client, "_resolve_chat_path", fake_resolve_chat_path)
    monkeypatch.setattr(client._client, "post", fake_post)

    result = asyncio.run(client.chat_json("Return JSON.", "hello", max_tokens=64))

    assert result == {"ok": True}
    assert len(bodies) == 2
    assert "Structured output contract" in bodies[0]["messages"][0]["content"]
    assert "previous response was not accepted" in bodies[1]["messages"][1]["content"]

    asyncio.run(client.close())


def test_chat_normalises_provider_content_parts(monkeypatch):
    client = LLMClient(
        base_url="http://localhost:1234",
        model_name="test-model",
        context_window=4096,
        max_output_tokens=256,
    )

    async def fake_resolve_chat_path(_headers):
        return "/v1/chat/completions"

    async def fake_post(path, *, headers=None, json=None):
        return httpx.Response(
            200,
            request=httpx.Request("POST", f"http://localhost:1234{path}"),
            json={
                "choices": [
                    {
                        "message": {
                            "content": [
                                {"type": "text", "text": "hello"},
                                {"type": "text", "text": "world"},
                            ]
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
                "model": "test-model",
            },
        )

    monkeypatch.setattr(client, "_resolve_chat_path", fake_resolve_chat_path)
    monkeypatch.setattr(client._client, "post", fake_post)

    result = asyncio.run(client.chat([{"role": "user", "content": "hello"}]))

    assert result["content"] == "hello\nworld"

    asyncio.run(client.close())


def test_full_chat_completions_url_is_normalised_to_provider_root():
    client = LLMClient(
        base_url="https://example.internal/api/v1/chat/completions/",
        model_name="test-model",
    )

    assert client.base_url == "https://example.internal/api"
    assert client._chat_path is None

    asyncio.run(client.close())


def test_v1_base_url_is_normalised_to_provider_root():
    client = LLMClient(
        base_url="https://example.internal/v1/",
        model_name="test-model",
    )

    assert client.base_url == "https://example.internal"

    asyncio.run(client.close())


def test_subpath_v1_base_url_preserves_gateway_prefix():
    client = LLMClient(
        base_url="https://example.internal/api/v1/",
        model_name="test-model",
    )

    assert client.base_url == "https://example.internal/api"

    asyncio.run(client.close())


def test_chat_path_candidates_include_openai_prefixed_gateways():
    assert "/openai/v1/chat/completions" in LLMClient.chat_path_candidates()


def test_parse_json_response_ignores_visible_thinking_tokens():
    content = """
<think>
I should inspect the architecture and then emit the requested JSON.
</think>
{
  "app_summary": "A service",
  "components": [{"name": "API"}]
}
"""

    parsed = LLMClient._parse_json_response(content)

    assert parsed == {
        "app_summary": "A service",
        "components": [{"name": "API"}],
    }


def test_parse_json_response_extracts_json_after_explanatory_text():
    content = """Here is the JSON you requested:
```json
{"app_summary": "A service", "components": []}
```
Extra text from the model.
"""

    parsed = LLMClient._parse_json_response(content)

    assert parsed == {"app_summary": "A service", "components": []}


def test_parse_json_response_skips_non_json_braces_before_payload():
    content = """
The model thought about a pseudo object like {not json}
and then finally answered:
{"app_summary": "A service", "components": []}
"""

    parsed = LLMClient._parse_json_response(content)

    assert parsed == {"app_summary": "A service", "components": []}


def test_parse_json_response_prefers_final_object_after_visible_reasoning():
    content = """
Reasoning: an example object would be {"app_summary": "example", "components": []}.
Final answer:
{"app_summary": "Actual service", "components": [{"name": "API"}]}
"""

    parsed = LLMClient._parse_json_response(content)

    assert parsed == {"app_summary": "Actual service", "components": [{"name": "API"}]}
