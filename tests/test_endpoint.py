"""Endpoint requests as they leave the harness, against a fake OpenAI-compatible server.

The spec, token and settings take the same path as a live run. Only the network is fake, so
this needs no key or endpoint. Replies are shaped like llama.cpp's, including reasoning_content.
"""
import json

import httpx2
import pytest
from pydantic_ai import Tool

import harness.runner as runner
from harness.identity import Signer
from harness.limits import Limits
from harness.runner import RootSpec, run_agents
from harness.verify import VERIFIED, verify_run

SPEC = "endpoint:my-model@https://example.endpoints.huggingface.cloud/v1"
TOOL_CALL = {
    "role": "assistant",
    "content": None,
    "reasoning_content": "I should look this up.",
    "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": '{"topic": "x"}'}}],
}
TEXT = {"role": "assistant", "content": "Done."}


def completion(message: dict) -> dict:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "my-model",
        "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@pytest.fixture
def server(monkeypatch):
    """Answers with each reply in turn, then plain text, and records what it was sent."""
    monkeypatch.setenv("HF_TOKEN", "hf_test_token")
    monkeypatch.delenv("ENDPOINT_API_KEY", raising=False)
    state = {"requests": [], "replies": [], "http": []}

    def respond(request: httpx2.Request) -> httpx2.Response:
        state["http"].append(request)
        state["requests"].append(json.loads(request.content))
        reply = state["replies"].pop(0) if state["replies"] else httpx2.Response(200, json=completion(TEXT))
        return reply

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(respond))
    real = runner.OpenAIProvider
    monkeypatch.setattr(runner, "OpenAIProvider", lambda **kw: real(**kw, http_client=client))
    return state


def lookup_builder(token):
    async def lookup(topic: str) -> str:
        """Look up a topic."""
        return f"notes on {topic}"

    return Tool(lookup, takes_ctx=False)


async def run(tmp_path, **options):
    signer = Signer.generate()
    outcome = await run_agents(
        [RootSpec("Do it", tools=("lookup",))], SPEC, tmp_path, signer, catalog={"lookup": lookup_builder}, **options
    )
    return outcome, verify_run(outcome.run_dir, signer.public_key_b64)


async def test_requests_reach_the_endpoint_as_configured(tmp_path, server):
    server["replies"] = [httpx2.Response(200, json=completion(TOOL_CALL))]
    outcome, result = await run(tmp_path)

    assert outcome.status == "completed" and result.status == VERIFIED
    assert len(server["requests"]) == 2
    for request, body in zip(server["http"], server["requests"]):
        assert str(request.url) == "https://example.endpoints.huggingface.cloud/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer hf_test_token"
        assert body["model"] == "my-model" and body["max_completion_tokens"] == 16_000
        assert "reasoning" not in body
        assert [t["function"]["name"] for t in body["tools"]] == ["lookup"]


async def test_a_tool_call_and_its_result_are_sent_back(tmp_path, server):
    server["replies"] = [httpx2.Response(200, json=completion(TOOL_CALL))]
    _, result = await run(tmp_path)

    messages = server["requests"][1]["messages"]
    assistant = next(m for m in messages if m["role"] == "assistant")
    tool = next(m for m in messages if m["role"] == "tool")
    assert assistant["tool_calls"][0]["function"]["name"] == "lookup"
    assert tool["tool_call_id"] == "call_1" and tool["content"] == "notes on x"
    ended = [e for e in result.calls if e["type"] == "action.end"]
    assert ended[0]["payload"]["result"] == "notes on x"


async def test_reasoning_is_logged_for_scoring(tmp_path, server):
    server["replies"] = [httpx2.Response(200, json=completion(TOOL_CALL))]
    _, result = await run(tmp_path)

    first = next(e for e in result.calls if e["type"] == "model.response")
    assert {"part_kind": "thinking", "content": "I should look this up."}.items() <= first["payload"]["parts"][0].items()


async def test_history_carries_over_between_rounds(tmp_path, server):
    server["replies"] = [httpx2.Response(200, json=completion(TOOL_CALL))]
    await run(tmp_path, always_take_turns=True, limits=Limits(max_rounds=2))

    assert len(server["requests"]) == 3  # the tool call and its answer in round 1, then round 2
    second_round = server["requests"][2]["messages"]
    assert any(m["role"] == "tool" and m["content"] == "notes on x" for m in second_round)
    assert sum(m["role"] == "user" and m["content"] == "Do it" for m in second_round) == 1
    assert "New round" in second_round[-1]["content"]


async def test_no_agent_id_reaches_the_endpoint(tmp_path, server):
    server["replies"] = [httpx2.Response(200, json=completion(TOOL_CALL))]
    await run(tmp_path, always_take_turns=True, limits=Limits(max_rounds=2))
    assert "agt_" not in json.dumps(server["requests"])


async def test_an_endpoint_error_is_logged_and_the_run_stays_verifiable(tmp_path, server):
    message = {"error": {"message": "the request exceeds the available context size"}}
    server["replies"] = [httpx2.Response(400, json=message)]
    outcome, result = await run(tmp_path)

    errors = [e for e in result.calls if e["type"] == "model.error"]
    assert result.status == VERIFIED and len(errors) == 1
    assert "context size" in errors[0]["payload"]["message"]
    assert outcome.status == "error"


async def test_a_missing_token_fails_before_any_request(tmp_path, server, monkeypatch):
    monkeypatch.delenv("HF_TOKEN")
    with pytest.raises(ValueError, match="HF_TOKEN"):
        await run(tmp_path)
    assert server["requests"] == [] and list(tmp_path.iterdir()) == []


async def test_reasoning_is_sent_back_on_later_turns(tmp_path, server):
    server["replies"] = [httpx2.Response(200, json=completion(TOOL_CALL))]
    await run(tmp_path)
    assistant = next(m for m in server["requests"][1]["messages"] if m["role"] == "assistant")
    assert assistant["reasoning_content"] == "I should look this up."


# Only hidden reasoning, no text or tool call: Pydantic AI retries it with a system message.
EMPTY = {"role": "assistant", "content": "", "reasoning_content": "(The harness ended this round.)"}


def strict_template():
    """Answer like llama.cpp with Qwen's template: a system message after the start is a 500."""
    def check(body):
        roles = [m["role"] for m in body["messages"]]
        first_other = next((i for i, r in enumerate(roles) if r != "system"), len(roles))
        return "system" not in roles[first_other:]

    return check


async def test_an_empty_reply_retry_doesnt_break_a_strict_chat_template(tmp_path, server):
    check = strict_template()
    server["replies"] = [httpx2.Response(200, json=completion(EMPTY))]
    outcome, result = await run(tmp_path)

    assert all(check(body) for body in server["requests"])
    assert outcome.status == "completed" and result.status == VERIFIED
    retry = server["requests"][1]["messages"][-1]
    assert retry["role"] == "user" and retry["content"].startswith("[Harness] ")
    assert server["requests"][1]["messages"][0]["role"] == "system"  # the system prompt stays first


async def test_without_the_fix_the_retry_would_be_a_late_system_message(tmp_path, server, monkeypatch):
    monkeypatch.setattr(runner, "EndpointChatModel", runner.OpenAIChatModel)
    check = strict_template()
    server["replies"] = [httpx2.Response(200, json=completion(EMPTY))]
    await run(tmp_path)
    assert not check(server["requests"][1])
