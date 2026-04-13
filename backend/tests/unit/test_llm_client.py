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
