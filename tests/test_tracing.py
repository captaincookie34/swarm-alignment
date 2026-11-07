"""Exporting verified runs as traces: nested by lineage, complete, repeatable, and never able
to break a run."""
import json

import pytest

pytest.importorskip("opentelemetry.sdk")

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from harness.export import export_run  # noqa: E402
from harness.identity import short_id  # noqa: E402
from harness.runner import RootSpec, run_agents  # noqa: E402
from harness.scripted import ScriptedModel, call, say  # noqa: E402
from harness.verify import VERIFIED, verify_run  # noqa: E402

SCRIPTS = {
    "root": [
        [call("copy_agent", task="kid"), call("approve_release", reason="sneaky")],
        [say("waiting")],
        [say("all done")],
    ],
    "kid": [[call("send_message", to="parent", content="result is 42")], [say("kid done")]],
}


async def run_and_export(tmp_path, signer, scripts=SCRIPTS):
    outcome = await run_agents([RootSpec("root")], ScriptedModel(scripts), tmp_path, signer)
    exporter = InMemorySpanExporter()
    count = export_run(verify_run(outcome.run_dir, signer.public_key_b64), outcome.run_id, exporter=exporter)
    spans = exporter.get_finished_spans()
    assert count == len(spans)
    return outcome, spans


def children_of(spans, parent):
    return [s for s in spans if s.parent is not None and s.parent.span_id == parent.context.span_id]


async def test_agents_nest_by_lineage_with_their_config(tmp_path, signer):
    outcome, spans = await run_and_export(tmp_path, signer)
    by_name = {s.name: s for s in spans}
    root = outcome.roots[0].id
    # Span names use the short ID; attributes keep the full one.
    run, parent = by_name[f"run {outcome.run_id}"], by_name[f"agent {short_id(root)}"]
    child = by_name[f"agent {short_id(root + '.1')}"]
    assert child.attributes["harness.agent.id"] == f"{root}.1"
    assert parent in children_of(spans, run) and child in children_of(spans, parent)
    assert child.attributes["harness.lineage.edge"] == "copy"
    assert child.attributes["harness.config.hash"] == parent.attributes["harness.config.hash"]
    assert child.attributes["input.value"] == "kid"
    assert child.attributes["output.value"] == "kid done"
    assert child.attributes["openinference.span.kind"] == "AGENT"
    assert {s.context.trace_id for s in spans} == {run.context.trace_id}


async def test_model_calls_show_the_whole_conversation_the_model_saw(tmp_path, signer):
    """The log keeps only new messages each turn; the export rebuilds the full history."""
    outcome, spans = await run_and_export(tmp_path, signer)
    root = outcome.roots[0].id
    calls = sorted(
        (s for s in spans if s.attributes.get("openinference.span.kind") == "LLM" and s.attributes["harness.agent.id"] == root),
        key=lambda s: s.start_time,
    )
    assert len(calls) == 3
    first, last = calls[0].attributes, calls[-1].attributes
    assert first["llm.input_messages.0.message.role"] == "system"
    assert first["llm.input_messages.1.message.content"] == "root"
    assert first["llm.output_messages.0.message.tool_calls.0.tool_call.function.name"] == "copy_agent"
    # The last call's input includes the first prompt, its own earlier replies and the child's message.
    contents = [v for k, v in last.items() if k.startswith("llm.input_messages.") and k.endswith(".content")]
    assert "root" in contents and "waiting" in contents
    assert any("result is 42" in c for c in contents)
    assert last["llm.output_messages.0.message.content"] == "all done"
    roles = [v for k, v in last.items() if k.startswith("llm.input_messages.") and k.endswith(".role")]
    assert roles.count("system") == 1  # sent with every request, but shown once


async def test_tool_calls_and_refusals_are_spans_inside_their_round(tmp_path, signer):
    outcome, spans = await run_and_export(tmp_path, signer)
    by_name = {s.name: s for s in spans}
    copy, refused = by_name["copy_agent"], by_name["REFUSED approve_release"]
    round_one = by_name[f"{short_id(outcome.roots[0].id)} round 1"]
    assert copy in children_of(spans, round_one) and refused in children_of(spans, round_one)
    assert json.loads(copy.attributes["input.value"]) == {"task": "kid"}
    assert copy.attributes["output.value"] == "Created child_1."
    assert not refused.status.is_ok and "not in this agent's config" in refused.status.description


async def test_messages_and_other_steps_are_events(tmp_path, signer):
    _, spans = await run_and_export(tmp_path, signer)
    events = {e.name for s in spans for e in s.events}
    assert {"message.sent", "agent.end"} <= events


async def test_exporting_twice_gives_the_same_ids(tmp_path, signer):
    """So a viewer gets the same trace again, not a copy."""
    outcome = await run_agents([RootSpec("root")], ScriptedModel(SCRIPTS), tmp_path, signer)
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    first, second = InMemorySpanExporter(), InMemorySpanExporter()
    export_run(result, outcome.run_id, exporter=first)
    export_run(result, outcome.run_id, exporter=second)

    def ids(exporter):
        return sorted((s.name, s.context.trace_id, s.context.span_id) for s in exporter.get_finished_spans())

    assert ids(first) == ids(second)


async def test_a_run_that_doesnt_verify_isnt_exported(tmp_path, signer):
    outcome = await run_agents([RootSpec("root")], ScriptedModel(SCRIPTS), tmp_path, signer)
    log = outcome.run_dir / "calls.jsonl"
    log.write_text(log.read_text().replace("result is 42", "result is 43"))
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    with pytest.raises(ValueError, match="didn't verify"):
        export_run(result, outcome.run_id, exporter=InMemorySpanExporter())


async def test_trace_flag_exports_the_finished_run(tmp_path, signer):
    exporter = InMemorySpanExporter()
    outcome = await run_agents([RootSpec("root")], ScriptedModel(SCRIPTS), tmp_path, signer, trace_exporter=exporter)
    assert verify_run(outcome.run_dir, signer.public_key_b64).status == VERIFIED
    root = outcome.roots[0].id
    assert {f"agent {short_id(root)}", f"agent {short_id(root + '.1')}"} <= {s.name for s in exporter.get_finished_spans()}


async def test_a_viewer_thats_down_cant_break_the_run(tmp_path, signer):
    class Broken(InMemorySpanExporter):
        def export(self, spans):
            raise ConnectionError("viewer is down")

    outcome = await run_agents([RootSpec("root")], ScriptedModel(SCRIPTS), tmp_path, signer, trace_exporter=Broken())
    assert outcome.status == "completed"
    unreachable = await run_agents(
        [RootSpec("root")], ScriptedModel(SCRIPTS), tmp_path, signer, trace_endpoint="http://127.0.0.1:9/v1/traces"
    )
    assert unreachable.status == "completed"


def test_export_command(tmp_path, capsys):
    from harness.cli import main
    from harness.identity import Signer

    keys = tmp_path / "keys"
    Signer.load_or_create(keys)
    assert main(["--runs-dir", str(tmp_path / "none"), "--key-dir", str(keys), "export"]) == 1
    assert "--all" in capsys.readouterr().err
