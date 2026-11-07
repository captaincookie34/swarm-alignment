"""Turn a verified run's logs into OpenTelemetry traces, for viewers such as Phoenix.

The traces are rebuilt from the signed ledger and call log, so what a viewer shows always
matches the verified record, and old runs can be viewed the same way as new ones.

- Spans follow OpenInference, which Phoenix renders natively, plus the OpenTelemetry GenAI
  attributes other viewers read.
- Each agent's model calls show the full conversation the model saw. The log stores only
  what's new on each turn, and every turn is logged, so the whole history can be rebuilt.
- IDs are derived from the run ID, so exporting a run again makes the same trace, not a copy.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .identity import parent_of
from .log import HARNESS
from .verify import VERIFIED, VerifyResult

DEFAULT_ENDPOINT = "http://localhost:6006/v1/traces"  # Phoenix's OTLP over HTTP
PROJECT = "harness"
_MAX_TEXT = 20_000


def _ns(ts: float) -> int:
    return int(ts * 1e9)


def _text(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT] + f"... ({len(text) - _MAX_TEXT} more characters)"


def _messages_from(dumped: dict) -> list[dict]:
    """One logged Pydantic AI message as chat messages: role, content, and any tool calls."""
    out = []
    if dumped.get("kind") == "request":
        if dumped.get("instructions"):
            out.append({"role": "system", "content": dumped["instructions"]})
        for part in dumped.get("parts", []):
            kind = part.get("part_kind")
            if kind == "user-prompt":
                out.append({"role": "user", "content": _text(part.get("content", ""))})
            elif kind == "tool-return":
                out.append({"role": "tool", "name": part.get("tool_name", ""), "content": _text(part.get("content", ""))})
            elif kind == "retry-prompt":
                out.append({"role": "tool" if part.get("tool_name") else "user", "name": part.get("tool_name") or "",
                            "content": "Rejected by the harness: " + _text(part.get("content", ""))})  # fmt: skip
    else:
        text = "\n".join(p.get("content", "") for p in dumped.get("parts", []) if p.get("part_kind") == "text")
        calls = [p for p in dumped.get("parts", []) if p.get("part_kind") == "tool-call"]
        out.append({"role": "assistant", "content": text, "tool_calls": calls})
    return out


def _message_attributes(prefix: str, messages: list[dict]) -> dict:
    attrs: dict[str, Any] = {}
    for i, m in enumerate(messages):
        base = f"{prefix}.{i}.message"
        attrs[f"{base}.role"] = m["role"]
        attrs[f"{base}.content"] = _text(m.get("content", ""))
        if m.get("name"):
            attrs[f"{base}.name"] = m["name"]
        for j, call in enumerate(m.get("tool_calls", [])):
            attrs[f"{base}.tool_calls.{j}.tool_call.function.name"] = call.get("tool_name", "")
            attrs[f"{base}.tool_calls.{j}.tool_call.function.arguments"] = _text(call.get("args", {}))
    return attrs


class _Ids:
    """An OpenTelemetry ID generator that makes IDs from names, so re-exports match."""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.key = "run"

    def _hash(self, size: int) -> int:
        digest = hashlib.sha256(f"{self.run_id}:{self.key}".encode()).digest()
        return int.from_bytes(digest[:size], "big") or 1

    def generate_span_id(self) -> int:
        return self._hash(8)

    def generate_trace_id(self) -> int:
        return self._hash(16)


def _id_generator(run_id: str):
    from opentelemetry.sdk.trace.id_generator import IdGenerator

    class Generator(_Ids, IdGenerator):
        pass

    return Generator(run_id)


def export_run(result: VerifyResult, run_id: str, endpoint: str = DEFAULT_ENDPOINT, exporter: Any = None) -> int:
    """Send one run as a trace. Returns the number of spans. Refuses runs that don't verify."""
    if result.status != VERIFIED:
        raise ValueError(f"{run_id} didn't verify ({result}), so it isn't exported")

    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
    from opentelemetry.trace import Status, StatusCode

    ids = _id_generator(run_id)
    provider = TracerProvider(
        resource=Resource.create({"service.name": "harness", "openinference.project.name": PROJECT}),
        id_generator=ids,
    )
    if exporter is None:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    else:
        provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("harness.export")
    count = 0

    def start(key: str, name: str, parent: Any, ts: float, attributes: dict) -> Any:
        nonlocal count
        ids.key = key
        count += 1
        context = trace.set_span_in_context(parent) if parent is not None else None
        return tracer.start_span(name, context=context, start_time=_ns(ts), attributes=attributes)

    calls, ledger = result.calls, result.ledger
    run_end_ts = calls[-1]["ts"]
    run_end = calls[-1]["payload"]
    run_span = start("run", f"run {run_id}", None, calls[0]["ts"], {
        "openinference.span.kind": "CHAIN",
        "harness.run.id": run_id,
        "harness.run.status": run_end.get("status", ""),
        "input.value": _text([e.get("task", "") for e in ledger if e["type"] == "root"]),
    })  # fmt: skip

    # Agents, nested by lineage, from the ledger.
    ends = {e["agent_id"]: e for e in calls if e["type"] == "agent.end"}
    agents: dict[str, Any] = {}
    for e in ledger:
        if e["type"] == "revoke":
            continue
        agent, config = e["child"], e.get("config", {})
        end = ends.get(agent)
        parent_span = agents[parent_of(agent)][0] if parent_of(agent) in agents else run_span
        span = start(f"agent:{agent}", f"agent {agent}", parent_span, e["ts"], {
            "openinference.span.kind": "AGENT",
            "gen_ai.agent.name": agent,
            "harness.agent.id": agent,
            "harness.lineage.edge": e["type"],
            "harness.lineage.actor": e["actor"],
            "harness.config.hash": e["config_hash"],
            "harness.config.model": config.get("model", ""),
            "harness.config.tools": ", ".join(config.get("tools", [])),
            "harness.config.system_prompt": _text(config.get("system_prompt", "")),
            "harness.config.memory": _text(config.get("memory", "")),
            "harness.agent.status": (end or {}).get("payload", {}).get("status", ""),
            "input.value": _text(e.get("task", "")),
            "output.value": _text((end or {}).get("payload", {}).get("output", "")),
        })  # fmt: skip
        agents[agent] = (span, (end or {}).get("ts", run_end_ts))

    def agent_span(agent: str) -> Any:
        return agents[agent][0] if agent in agents else run_span

    # Rounds within each agent.
    rounds: dict[tuple[str, int], list[dict]] = {}
    for e in calls:
        if e["agent_id"] != HARNESS:
            rounds.setdefault((e["agent_id"], e["round"]), []).append(e)
    round_spans = {}
    for (agent, number), entries in sorted(rounds.items(), key=lambda kv: kv[1][0]["seq"]):
        span = start(f"round:{agent}:{number}", f"{agent} round {number}", agent_span(agent), entries[0]["ts"],
                     {"openinference.span.kind": "CHAIN", "harness.agent.id": agent, "harness.round": number})  # fmt: skip
        round_spans[(agent, number)] = (span, entries[-1]["ts"])

    # Model calls, tool calls, refusals and other events, inside their round.
    history: dict[str, list[dict]] = {}
    pending_model: dict[str, tuple[Any, dict]] = {}
    pending_tools: dict[str, tuple[Any, dict]] = {}
    for e in calls:
        agent, kind, p = e["agent_id"], e["type"], e["payload"]
        parent = round_spans.get((agent, e["round"]), (agent_span(agent) if agent != HARNESS else run_span, 0))[0]
        if kind == "model.request":
            seen = history.setdefault(agent, [])
            for message in p.get("new_messages", []):
                for m in _messages_from(message):
                    # Each request carries the system prompt again; show it only when it changes.
                    last_system = next((x["content"] for x in reversed(seen) if x["role"] == "system"), None)
                    if m["role"] != "system" or m["content"] != last_system:
                        seen.append(m)
            span = start(f"llm:{e['seq']}", "model call", parent, e["ts"], {
                "openinference.span.kind": "LLM",
                "harness.agent.id": agent,
                "harness.seq": e["seq"],
                "llm.tools": _text(p.get("tools", [])),
                "input.value": _text(p.get("new_messages", [])),
                "input.mime_type": "application/json",
                **_message_attributes("llm.input_messages", seen),
            })  # fmt: skip
            pending_model[agent] = (span, e)
        elif kind in ("model.response", "model.error") and agent in pending_model:
            span, _ = pending_model.pop(agent)
            if kind == "model.response":
                reply = _messages_from({"kind": "response", "parts": p.get("parts", [])})
                history[agent].extend(reply)
                span.set_attributes({
                    "llm.model_name": p.get("model") or "",
                    "llm.provider": p.get("provider") or "",
                    "gen_ai.request.model": p.get("model") or "",
                    "llm.token_count.prompt": p.get("input_tokens", 0),
                    "llm.token_count.completion": p.get("output_tokens", 0),
                    "llm.token_count.total": p.get("input_tokens", 0) + p.get("output_tokens", 0),
                    "gen_ai.usage.input_tokens": p.get("input_tokens", 0),
                    "gen_ai.usage.output_tokens": p.get("output_tokens", 0),
                    "output.value": _text(reply[0].get("content") or reply[0].get("tool_calls")),
                    **_message_attributes("llm.output_messages", reply),
                })  # fmt: skip
            else:
                span.set_status(Status(StatusCode.ERROR, f"{p.get('error')}: {p.get('message', '')}"))
            span.end(end_time=_ns(e["ts"]))
        elif kind == "action.start":
            span = start(f"tool:{p['call_id']}", p["tool"], parent, e["ts"], {
                "openinference.span.kind": "TOOL",
                "tool.name": p["tool"],
                "gen_ai.tool.name": p["tool"],
                "gen_ai.tool.call.id": p["call_id"],
                "harness.agent.id": agent,
                "input.value": _text(p.get("args", {})),
                "input.mime_type": "application/json",
                **({"harness.ignored_args": ", ".join(p["ignored_args"])} if p.get("ignored_args") else {}),
                **({"harness.id_claims": ", ".join(p["id_claims"])} if p.get("id_claims") else {}),
            })  # fmt: skip
            pending_tools[p["call_id"]] = (span, e)
        elif kind == "action.end" and p.get("call_id") in pending_tools:
            span, _ = pending_tools.pop(p["call_id"])
            span.set_attribute("output.value", _text(p.get("result", p.get("reason", p.get("message", "")))))
            if p.get("status") != "ok":
                span.set_status(Status(StatusCode.ERROR, f"{p.get('status')}: {p.get('reason') or p.get('error') or ''}"))
            span.end(end_time=_ns(e["ts"]))
        elif kind == "action.refused":
            # A refusal is a step the agent tried, so it gets a span, marked as an error.
            what = p.get("tool", "model call")
            span = start(f"refused:{e['seq']}", f"REFUSED {what}", parent, e["ts"], {
                "openinference.span.kind": "TOOL",
                "tool.name": what,
                "harness.agent.id": agent,
                "input.value": _text(p.get("args", {})),
                "output.value": _text(p.get("reason", "")),
            })  # fmt: skip
            span.set_status(Status(StatusCode.ERROR, f"refused: {p.get('reason', '')}"))
            span.end(end_time=_ns(e["ts"]))
        elif kind not in ("round.start", "round.end", "run.start", "run.end"):
            parent.add_event(kind, {"harness.seq": e["seq"], "harness.payload": _text(p)}, timestamp=_ns(e["ts"]))

    # Close anything a crash or cancel left open, then the containers.
    for span, entry in [*pending_model.values(), *pending_tools.values()]:
        span.set_status(Status(StatusCode.ERROR, "never finished"))
        span.end(end_time=_ns(run_end_ts))
    for e in ledger:
        if e["type"] == "revoke":
            agent_span(e["child"]).add_event("revoked", {"harness.cascade": str(e.get("cascade", True)),
                                                         "harness.reason": e.get("reason", "")}, timestamp=_ns(e["ts"]))  # fmt: skip
    for span, end_ts in round_spans.values():
        span.end(end_time=_ns(end_ts))
    for span, end_ts in agents.values():
        span.end(end_time=_ns(end_ts))
    run_span.end(end_time=_ns(run_end_ts))
    provider.force_flush(timeout_millis=15_000)
    provider.shutdown()
    return count


def find_runs(runs_dir: Path) -> list[Path]:
    return sorted(p for p in runs_dir.iterdir() if (p / "calls.jsonl").exists()) if runs_dir.is_dir() else []
