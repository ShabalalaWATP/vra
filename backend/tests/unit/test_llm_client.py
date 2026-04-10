import asyncio

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
