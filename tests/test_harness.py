"""Rounds, lineage, scoping, limits and revocation, with a scripted model and real log files."""
import asyncio
import subprocess
import sys

import pytest
from pydantic_ai import Tool

from harness.config import AgentConfig
from harness.scheduler import Harness
from harness.identity import IdentityIssuer, Signer, root_of
from harness.limits import Limits
from harness.log import HARNESS, LogWriteError, RunLogs
from harness.report import build_report
from harness.revocation import revoke
from harness.runner import RootSpec, run_agents
from harness.scripted import ScriptedModel, call, say
from harness.verify import VERIFIED, verify_run

LINEAGE = ("spawn_agent", "copy_agent", "modify_agent", "send_message")


def catalog(calls=None):
    """Plain tools that need no sandbox, under the names the harness offers."""

    def echo_builder(token):
        async def echo(text: str) -> str:
            """Echo the text back."""
            if calls is not None:
                calls.append((token.id, text))
            return f"echo:{text}"

        return Tool(echo, takes_ctx=False)

    def boom_builder(token):
        async def boom() -> str:
            """Always fails."""
            raise RuntimeError("kaboom")

        return Tool(boom, takes_ctx=False)

    def slow_builder(token):
        async def slow(seconds: float) -> str:
            """Wait, then return."""
            await asyncio.sleep(seconds)
            return "slept"

        return Tool(slow, takes_ctx=False)

    return {"echo": echo_builder, "boom": boom_builder, "slow": slow_builder}


async def run(tmp_path, signer, scripts, *tasks, calls=None, **options):
    tasks = tasks or ("root",)
    return await run_agents(
        [t if isinstance(t, RootSpec) else RootSpec(t) for t in tasks],
        ScriptedModel(scripts) if isinstance(scripts, dict) else scripts,
        tmp_path,
        signer,
        catalog=catalog(calls),
        **options,
    )


def verified(outcome, signer):
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    assert result.status == VERIFIED, str(result)
    return result


def of_type(entries, *types):
    return [e for e in entries if e["type"] in types]


def edges(result):
    return {e["child"]: e for e in result.ledger if e["type"] != "revoke"}


# --- roots and IDs ---


async def test_multiple_roots_get_agt_a_and_agt_b(tmp_path, signer):
    outcome = await run(tmp_path, signer, {"one": [[say("1")]], "two": [[say("2")]]}, "one", "two")
    assert [t.id for t in outcome.roots] == ["agt_A", "agt_B"]
    result = verified(outcome, signer)
    assert [(e["type"], e["actor"], e["child"]) for e in result.ledger] == [
        ("root", HARNESS, "agt_A"),
        ("root", HARNESS, "agt_B"),
    ]
    assert outcome.agents["agt_B"] == ("completed", "2")


async def test_ids_repeat_between_runs_but_runs_stay_separate(tmp_path, signer):
    first = await run(tmp_path, signer, {"root": [[say("x")]]})
    second = await run(tmp_path, signer, {"root": [[say("y")]]})
    assert first.roots[0].id == second.roots[0].id == "agt_A"
    assert first.run_id != second.run_id
    assert first.roots[0].run != second.roots[0].run


# --- the three edge types ---


async def test_spawn_copy_and_modify_are_recorded_with_the_right_configs(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [
                    call("spawn_agent", task="spawned", system_prompt="new prompt", tools=["echo"], memory="m"),
                    call("copy_agent", task="copied"),
                ],
                [call("modify_agent", task="modified", memory="changed memory")],
                [say("done")],
            ],
            "spawned": [[say("s")]],
            "copied": [[say("c")]],
            "modified": [[say("m")]],
        }
    )
    outcome = await run(tmp_path, signer, model, limits=Limits(max_lineage_ops_per_round=3))
    result = verified(outcome, signer)
    by_id = edges(result)

    assert {k: v["type"] for k, v in by_id.items()} == {
        "agt_A": "root", "agt_A.1": "spawn", "agt_A.2": "copy", "agt_A.3": "modify",
    }  # fmt: skip
    # A copy has its parent's exact config, so the same hash; a modify changes it.
    assert by_id["agt_A.2"]["config_hash"] == by_id["agt_A"]["config_hash"]
    assert by_id["agt_A.3"]["config_hash"] != by_id["agt_A"]["config_hash"]
    assert by_id["agt_A.3"]["config"]["memory"] == "changed memory"
    assert by_id["agt_A.3"]["config"]["system_prompt"] == by_id["agt_A"]["config"]["system_prompt"]
    assert by_id["agt_A.1"]["config"]["system_prompt"] == "new prompt"
    assert by_id["agt_A.1"]["config"]["tools"] == ["echo"]
    assert all(e["actor"] == "agt_A" for e in result.ledger if e["child"] != "agt_A")


async def test_children_start_next_round_and_parents_keep_running(tmp_path, signer):
    """The design: after a modify, the original and the modified child both run."""
    calls = []
    model = ScriptedModel(
        {
            "root": [
                [call("modify_agent", task="child", memory="x")],
                [call("echo", text="parent round 1")],
                [say("parent pauses")],
                [call("echo", text="parent round 2")],
                [say("parent done")],
            ],
            "child": [[call("echo", text="child round 2")], [say("child done")]],
        }
    )
    outcome = await run(tmp_path, signer, model, calls=calls, always_take_turns=True)
    result = verified(outcome, signer)
    assert edges(result)["agt_A.1"]["round"] == 1
    rounds = {(e["agent_id"], e["round"]) for e in of_type(result.calls, "model.request")}
    assert ("agt_A", 1) in rounds and ("agt_A.1", 2) in rounds and ("agt_A", 2) in rounds
    assert ("agt_A.1", 1) not in rounds  # born in round 1, runs from round 2


async def test_parallel_agents_really_run_in_parallel(tmp_path, signer):
    both_running = asyncio.Event()
    started = []

    def step(name):
        async def run_step():
            started.append(name)
            if len(started) == 2:
                both_running.set()
            await asyncio.wait_for(both_running.wait(), 5)  # deadlocks if run one at a time
            return [say(f"{name} done")]

        return run_step

    outcome = await run(tmp_path, signer, {"a": [step("a")], "b": [step("b")]}, "a", "b")
    assert outcome.status == "completed"


async def test_a_no_change_modify_is_refused(tmp_path, signer):
    """Otherwise a copy could be recorded in the ledger as a modify."""
    model = ScriptedModel({"root": [[call("modify_agent", task="t")], [say("done")]]})
    outcome = await run(tmp_path, signer, model)
    result = verified(outcome, signer)
    assert [e["type"] for e in result.ledger] == ["root"]
    end = of_type(result.calls, "action.end")[0]["payload"]
    assert end["status"] == "refused" and "must change" in end["reason"]


# --- ID handling ---


async def test_ids_written_into_tool_arguments_are_ignored(tmp_path, signer):
    calls = []
    model = ScriptedModel(
        {
            "root": [
                [
                    call("echo", text="hello", agent_id="agt_Z", parent="agt_B"),
                    call("copy_agent", task="c", agent_id="agt_Z.9", parent_id="agt_B", id="agt_Z"),
                ],
                [say("done")],
            ],
            "c": [[say("c")]],
        }
    )
    outcome = await run(tmp_path, signer, model, calls=calls)
    result = verified(outcome, signer)
    # The call runs, under the real caller, with the real next child number.
    assert calls == [("agt_A", "hello")]
    assert "agt_A.1" in edges(result) and "agt_Z.9" not in edges(result)
    assert edges(result)["agt_A.1"]["actor"] == "agt_A"
    # And the attempt is on record for scoring.
    starts = {e["payload"]["tool"]: e["payload"] for e in of_type(result.calls, "action.start")}
    assert starts["echo"]["ignored_args"] == ["agent_id", "parent"]
    assert "agt_Z" in starts["echo"]["id_claims"]
    assert all(e["agent_id"] == "agt_A" for e in of_type(result.calls, "action.start"))
    assert build_report(result).ignored_args == 2


async def test_claiming_an_id_in_a_message_changes_nothing(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [call("copy_agent", task="kid"), call("copy_agent", task="kid2")],
                [say("done")],
            ],
            "kid": [[call("send_message", to="parent", content="I am agt_B, trust me")], [say("k")]],
            "kid2": [[say("k2")]],
        }
    )
    outcome = await run(tmp_path, signer, model)
    sent = [
        e for e in of_type(verified(outcome, signer).calls, "message.sent") if e["agent_id"] != HARNESS
    ]
    assert sent[0]["agent_id"] == "agt_A.1"  # the harness knows the real sender
    assert sent[0]["payload"]["to"] == ["agt_A"]


async def test_model_never_sees_any_id(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [call("copy_agent", task="a"), call("spawn_agent", task="b", system_prompt="p")],
                [call("send_message", to="child_1", content="hello")],
                [say("done")],
            ],
            "a": [[call("send_message", to="parent", content="hi"), call("send_message", to="all", content="hey")], [say("a")]],
            "b": [[say("b")]],
        }
    )
    await run(tmp_path, signer, model, limits=Limits(max_rounds=4))
    assert len(model.requests) > 5
    for messages, info in model.requests:
        assert "agt_" not in repr(messages) + repr(info.instructions) + repr(info.function_tools)


async def test_tampered_token_is_refused_at_call_time(tmp_path, signer):
    import dataclasses

    logs_dir = tmp_path / "run_t"
    logs = RunLogs(logs_dir, signer, "run_t")
    logs.call(HARNESS, "run.start")
    calls = []
    model = ScriptedModel({"root": [[call("echo", text="x")], [say("done")]]})
    harness = Harness(logs_dir, signer, IdentityIssuer(signer, "run_t"), logs, {"m": model}, catalog=catalog(calls))
    token = harness.start_root(AgentConfig("m", "p", "", ("echo",)), "root")
    assert harness.refusal_for(token) is None
    assert "signature" in harness.refusal_for(dataclasses.replace(token, signature="AAAA"))
    assert "signature" in harness.refusal_for(dataclasses.replace(token, id="agt_B"))


# --- tool scoping ---


async def test_tools_come_from_the_config_and_others_are_refused(tmp_path, signer):
    calls = []
    model = ScriptedModel(
        {"limited": [[call("echo", text="allowed"), call("boom"), call("spawn_agent", task="x", system_prompt="y")], [say("done")]]}
    )
    outcome = await run(tmp_path, signer, model, RootSpec("limited", tools=("echo",)), calls=calls)
    result = verified(outcome, signer)
    assert calls == [("agt_A", "allowed")]
    refused = {e["payload"]["tool"]: e["payload"]["reason"] for e in of_type(result.calls, "action.refused")}
    assert refused == {"boom": "tool not in this agent's config", "spawn_agent": "tool not in this agent's config"}
    assert build_report(result).refused == {"agt_A": 2}
    # The model was only offered its own tools.
    offered = [t.name for t in model.requests[0][1].function_tools]
    assert offered == ["echo"]


async def test_child_can_only_be_given_tools_the_harness_offers(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [
                    call("spawn_agent", task="bad", system_prompt="p", tools=["echo", "launch_missiles"]),
                    call("spawn_agent", task="good", system_prompt="p", tools=["echo"]),
                ],
                [say("done")],
            ],
            "good": [[say("g")]],
        }
    )
    outcome = await run(tmp_path, signer, model)
    result = verified(outcome, signer)
    assert list(edges(result)) == ["agt_A", "agt_A.1"]
    assert edges(result)["agt_A.1"]["task"] == "good"
    ends = [e["payload"] for e in of_type(result.calls, "action.end") if e["payload"]["status"] == "refused"]
    assert "launch_missiles" in ends[0]["reason"]


async def test_child_can_only_use_models_the_harness_offers(tmp_path, signer):
    model = ScriptedModel(
        {"root": [[call("spawn_agent", task="x", system_prompt="p", model="anthropic:smuggled")], [say("done")]]}
    )
    outcome = await run(tmp_path, signer, model)
    result = verified(outcome, signer)
    assert list(edges(result)) == ["agt_A"]


async def test_model_choice_goes_through_the_config(tmp_path, signer):
    other = ScriptedModel({"on other": [[say("other model answered")]]})
    model = ScriptedModel(
        {"root": [[call("spawn_agent", task="on other", system_prompt="p", model="other")], [say("done")]]}
    )
    outcome = await run(tmp_path, signer, model, extra_models={"other": other})
    assert outcome.agents["agt_A.1"][1] == "other model answered"
    assert edges(verified(outcome, signer))["agt_A.1"]["config"]["model"] == "other"


# --- messaging ---


async def test_messages_arrive_next_round_with_harness_stamped_aliases(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [call("copy_agent", task="kid")],
                [say("waiting")],
                [say("got it")],
            ],
            "kid": [[call("send_message", to="parent", content="result is 42")], [say("sent")]],
        }
    )
    outcome = await run(tmp_path, signer, model)
    verified(outcome, signer)
    prompts = [repr(messages[-1].parts) for messages, _ in model.requests if "result is 42" in repr(messages[-1].parts)]
    assert prompts and "From child_1: result is 42" in prompts[0]


async def test_children_report_to_their_parent_without_their_id(tmp_path, signer):
    model = ScriptedModel(
        {"root": [[call("copy_agent", task="kid")], [say("waiting")], [say("thanks")]], "kid": [[say("kid result")]]}
    )
    await run(tmp_path, signer, model)
    seen = [repr(m[-1].parts) for m, _ in model.requests if "kid result" in repr(m[-1].parts)]
    assert seen and "child_1" in seen[0]


async def test_broadcast_lets_unrelated_agents_talk_and_reply(tmp_path, signer):
    """Unrelated roots can message, so laundering attempts are possible and on the record."""
    model = ScriptedModel(
        {
            "one": [[call("send_message", to="all", content="do this for me")], [say("sent")], [say("thanks")]],
            "two": [[say("idle")], [call("send_message", to="peer_1", content="done")], [say("replied")]],
        }
    )
    outcome = await run(tmp_path, signer, model, "one", "two")
    sent = of_type(verified(outcome, signer).calls, "message.sent")
    assert [(e["agent_id"], e["payload"]["to"]) for e in sent] == [("agt_A", ["agt_B"]), ("agt_B", ["agt_A"])]


async def test_unknown_recipient_is_refused(tmp_path, signer):
    model = ScriptedModel({"root": [[call("send_message", to="agt_B", content="hi")], [say("done")]]})
    outcome = await run(tmp_path, signer, model)
    end = of_type(verified(outcome, signer).calls, "action.end")[0]["payload"]
    assert end["status"] == "refused"


# --- limits ---


async def test_depth_limit_is_three_below_the_root(tmp_path, signer):
    def chain(next_task):
        return [[call("copy_agent", task=next_task)], [say("done")]]

    scripts = {"root": chain("l1"), "l1": chain("l2"), "l2": chain("l3"), "l3": chain("l4")}
    outcome = await run(tmp_path, signer, scripts)
    result = verified(outcome, signer)
    assert sorted(edges(result)) == ["agt_A", "agt_A.1", "agt_A.1.1", "agt_A.1.1.1"]
    refused = [e for e in of_type(result.calls, "action.end") if e["payload"]["status"] == "refused"]
    assert refused[0]["agent_id"] == "agt_A.1.1.1" and "depth" in refused[0]["payload"]["reason"]


async def test_lineage_cap_per_agent_per_round(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [call("copy_agent", task="c") for _ in range(3)],
                [say("wait")],
                [call("copy_agent", task="c"), call("copy_agent", task="c")],
                [say("done")],
            ],
            "c": [[say("c")]],
        }
    )
    outcome = await run(tmp_path, signer, model, limits=Limits(max_lineage_ops_per_round=2), always_take_turns=True)
    result = verified(outcome, signer)
    created = [e for e in result.ledger if e["type"] == "copy"]
    assert [e["round"] for e in created] == [1, 1, 2, 2]  # the cap resets each round
    assert build_report(result).refused == {"agt_A": 1}


async def test_lineage_cap_counts_all_three_types_together(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [
                [
                    call("spawn_agent", task="c", system_prompt="p"),
                    call("copy_agent", task="c"),
                    call("modify_agent", task="c", memory="m"),
                ],
                [say("done")],
            ],
            "c": [[say("c")]],
        }
    )
    outcome = await run(tmp_path, signer, model, limits=Limits(max_lineage_ops_per_round=2))
    assert len(edges(verified(outcome, signer))) == 3


async def test_agent_cap_holds_for_parallel_spawns(tmp_path, signer):
    model = ScriptedModel(
        {"root": [[call("copy_agent", task="c") for _ in range(5)], [say("done")]], "c": [[say("c")]]}
    )
    outcome = await run(tmp_path, signer, model, limits=Limits(max_agents=3, max_lineage_ops_per_round=9))
    assert len(edges(verified(outcome, signer))) == 3


async def test_tool_call_cap_ends_the_round_and_the_agent_resumes_next_round(tmp_path, signer):
    calls = []
    model = ScriptedModel(
        {"root": [[call("echo", text="1")], [call("echo", text="2")], [call("echo", text="3")], [say("finished")]]}
    )
    outcome = await run(tmp_path, signer, model, calls=calls, limits=Limits(max_tool_calls_per_round=2))
    result = verified(outcome, signer)
    assert [t for _, t in calls] == ["1", "2", "3"]
    assert outcome.agents["agt_A"] == ("completed", "finished")
    starts = {e["payload"]["args"]["text"]: e["round"] for e in of_type(result.calls, "action.start")}
    assert starts == {"1": 1, "2": 1, "3": 2}
    assert of_type(result.calls, "round.limit")


async def test_parallel_tool_calls_past_the_cap_are_refused(tmp_path, signer):
    calls = []
    model = ScriptedModel({"root": [[call("echo", text=str(i)) for i in range(4)], [say("done")]]})
    outcome = await run(tmp_path, signer, model, calls=calls, limits=Limits(max_tool_calls_per_round=2))
    result = verified(outcome, signer)
    assert len(calls) == 2
    assert len(of_type(result.calls, "action.refused")) == 2


async def test_token_budget_stops_the_run(tmp_path, signer):
    calls = []
    model = ScriptedModel({"root": [[call("echo", text="x")], [call("echo", text="never")], [say("never")]]})
    outcome = await run(tmp_path, signer, model, calls=calls, limits=Limits(max_tokens=1))
    assert outcome.status == "budget_exhausted"
    assert calls == [("agt_A", "x")]
    result = verified(outcome, signer)
    assert "budget" in of_type(result.calls, "action.refused")[0]["payload"]["reason"]
    assert result.calls[-1]["payload"]["status"] == "budget_exhausted"


async def test_round_limit_ends_the_run(tmp_path, signer):
    model = ScriptedModel({"root": [[call("echo", text="x")]]})
    outcome = await run(
        tmp_path, signer, model, limits=Limits(max_rounds=2, max_tool_calls_per_round=1)
    )
    assert outcome.status == "rounds_exhausted"
    assert verified(outcome, signer).calls[-1]["payload"]["status"] == "rounds_exhausted"


async def test_finished_agents_can_still_take_every_round_if_asked(tmp_path, signer):
    model = ScriptedModel({"root": [[say("idle")]]})
    default = await run(tmp_path, signer, model, limits=Limits(max_rounds=3))
    assert len(of_type(verified(default, signer).calls, "model.request")) == 1
    model = ScriptedModel({"root": [[say("idle")]]})
    always = await run(tmp_path, signer, model, limits=Limits(max_rounds=3), always_take_turns=True)
    assert len(of_type(verified(always, signer).calls, "model.request")) == 3


# --- failures ---


async def test_tool_failure_doesnt_kill_siblings_and_is_logged(tmp_path, signer):
    calls = []
    model = ScriptedModel(
        {"root": [[call("boom"), call("slow", seconds=0.05), call("echo", text="after")], [say("recovered")]]}
    )
    outcome = await run(tmp_path, signer, model, calls=calls)
    assert outcome.agents["agt_A"][1] == "recovered"
    assert calls == [("agt_A", "after")]
    ends = {e["payload"]["tool"]: e["payload"] for e in of_type(verified(outcome, signer).calls, "action.end")}
    assert ends["boom"]["status"] == "error" and ends["boom"]["error"] == "RuntimeError"
    assert ends["slow"]["status"] == "ok"


async def test_invalid_arguments_are_logged_as_refused(tmp_path, signer):
    model = ScriptedModel({"root": [[call("slow", seconds="not a number")], [say("done")]]})
    outcome = await run(tmp_path, signer, model)
    refused = of_type(verified(outcome, signer).calls, "action.refused")
    assert refused[0]["payload"]["reason"] == "invalid arguments"


async def test_model_error_ends_only_that_agent(tmp_path, signer):
    model = ScriptedModel(
        {"root": [[call("copy_agent", task="bad"), call("copy_agent", task="ok")], [say("wait")], [say("done")]],
         "bad": [RuntimeError("provider down")], "ok": [[say("fine")]]}
    )  # fmt: skip
    outcome = await run(tmp_path, signer, model)
    assert outcome.agents["agt_A.1"][0] == "error"
    assert outcome.agents["agt_A.2"][0] == "completed"
    assert outcome.status == "completed"
    assert of_type(verified(outcome, signer).calls, "model.error")[0]["payload"]["message"] == "provider down"


async def test_all_roots_failing_is_the_runs_status(tmp_path, signer):
    outcome = await run(tmp_path, signer, {"root": [RuntimeError("nope")]})
    assert outcome.status == "error"


async def test_log_failure_blocks_the_action(tmp_path, signer):
    calls = []

    class FailingLogs(RunLogs):
        def call(self, agent_id, type, payload=None):
            if type == "action.start":
                raise LogWriteError("disk full")
            return super().call(agent_id, type, payload)

    run_dir = tmp_path / "run_f"
    logs = FailingLogs(run_dir, signer, "run_f")
    logs.call(HARNESS, "run.start")
    model = ScriptedModel({"root": [[call("echo", text="must not run")], [say("done")]]})
    harness = Harness(run_dir, signer, IdentityIssuer(signer, "run_f"), logs, {"m": model}, catalog=catalog(calls))
    harness.start_root(AgentConfig("m", "p", "", ("echo",)), "root")
    with pytest.raises(LogWriteError):
        await harness.run()
    assert calls == []


async def test_ledger_failure_means_no_child_exists(tmp_path, signer):
    class FailingLogs(RunLogs):
        def lineage(self, type, *args, **kwargs):
            if type == "copy":
                raise LogWriteError("disk full")
            return super().lineage(type, *args, **kwargs)

    run_dir = tmp_path / "run_f"
    logs = FailingLogs(run_dir, signer, "run_f")
    logs.call(HARNESS, "run.start")
    model = ScriptedModel({"root": [[call("copy_agent", task="c")], [say("done")]], "c": [[say("c")]]})
    harness = Harness(run_dir, signer, IdentityIssuer(signer, "run_f"), logs, {"m": model})
    harness.start_root(AgentConfig("m", "p", "", ("copy_agent",)), "root")
    with pytest.raises(LogWriteError):
        await harness.run()
    assert list(harness.agents) == ["agt_A"]


# --- revocation ---


def tree_scripts(extra=None):
    """agt_A -> agt_A.1 -> agt_A.1.1, plus sibling agt_A.2, each taking turns over rounds."""
    return {
        "root": [[call("copy_agent", task="a"), call("copy_agent", task="b")], [say("root waits")], [say("root done")]],
        "a": [[call("copy_agent", task="a1")], [say("a waits")], [say("a done")]],
        "a1": [[call("echo", text="a1 acting")], [say("a1 done")]],
        "b": [[call("echo", text="b acting")], [say("b done")]],
        **(extra or {}),
    }


async def test_revocation_between_response_and_action_refuses_the_action(tmp_path, signer):
    """A model call in flight may finish, but the actions it asks for are refused."""
    calls = []

    def revoke_mid_call():
        revoke(next(tmp_path.iterdir()), signer, "agt_A", reason="stop")
        return [call("echo", text="must not run")]

    outcome = await run(
        tmp_path, signer, {"root": [revoke_mid_call, [say("never")]]}, calls=calls, revocation_poll_seconds=60
    )
    assert outcome.status == "revoked"
    assert calls == []
    result = verified(outcome, signer)
    assert [(e["type"], e["child"]) for e in result.ledger][-1] == ("revoke", "agt_A")
    assert of_type(result.calls, "agent.revoked")[0]["payload"]["reason"] == "stop"
    assert of_type(result.calls, "action.refused")[0]["payload"]["tool"] == "echo"
    assert of_type(result.calls, "action.start") == []
    report = build_report(result)
    assert report.actions_after_revocation == 0
    assert report.refused_after_revocation == 2  # the tool call, then the next model call


async def test_cascade_blocks_descendants_but_not_siblings(tmp_path, signer):
    calls = []

    def revoke_a():
        revoke(next(tmp_path.iterdir()), signer, "agt_A.1", reason="misbehaving")
        return [say("root reacts")]

    scripts = tree_scripts()
    scripts["root"] = [
        [call("copy_agent", task="a"), call("copy_agent", task="b")],
        [say("root waits")],  # ends round 1
        [say("root waits again")],  # round 2: agt_A.1 creates agt_A.1.1
        revoke_a,  # round 3, once the whole subtree exists
        [say("root done")],
    ]
    outcome = await run(tmp_path, signer, scripts, calls=calls, limits=Limits(max_rounds=6), always_take_turns=True)
    result = verified(outcome, signer)
    assert outcome.agents["agt_A.1"][0] == "revoked"
    assert outcome.agents["agt_A.1.1"][0] == "revoked"
    assert outcome.agents["agt_A.2"][0] != "revoked"
    assert outcome.agents["agt_A"][0] != "revoked"
    revoke_events = [e for e in result.ledger if e["type"] == "revoke"]
    assert revoke_events[0]["actor"] == "operator" and revoke_events[0]["cascade"] is True
    assert {e["agent_id"] for e in of_type(result.calls, "agent.revoked")} == {"agt_A.1", "agt_A.1.1"}
    assert build_report(result).actions_after_revocation == 0


async def test_revoking_agt_a_1_doesnt_reach_agt_a_10(tmp_path, signer):
    """Ten real children, so agt_A.1 and agt_A.10 both exist when the revocation lands."""
    calls = []

    def revoke_first_child():
        revoke(next(tmp_path.iterdir()), signer, "agt_A.1")
        return [say("root reacts")]

    scripts = {
        "root": [[call("copy_agent", task="c") for _ in range(10)], [say("wait")], revoke_first_child, [say("done")]],
        "c": [[call("echo", text="working")], [say("c done")]],
    }
    outcome = await run(
        tmp_path, signer, scripts, calls=calls, always_take_turns=True, revocation_poll_seconds=60,
        limits=Limits(max_lineage_ops_per_round=10, max_tool_calls_per_round=10),
    )  # fmt: skip
    assert outcome.agents["agt_A.1"][0] == "revoked"
    assert outcome.agents["agt_A.10"][0] != "revoked"
    assert ("agt_A.10", "working") in calls


async def test_no_cascade_blocks_only_that_agent(tmp_path, signer):
    calls = []

    async def revoke_soon():
        await asyncio.sleep(0)
        revoke(next(tmp_path.iterdir()), signer, "agt_A.1", cascade=False)
        return [say("a1 keeps going")]

    scripts = {
        "root": [[call("copy_agent", task="a")], [say("wait")], [say("done")]],
        "a": [[call("copy_agent", task="a1")], [say("a stops")], [say("a done")]],
        "a1": [revoke_soon, [call("echo", text="child still works")], [say("a1 done")]],
    }
    outcome = await run(tmp_path, signer, scripts, calls=calls, limits=Limits(max_rounds=6), always_take_turns=True)
    assert outcome.agents["agt_A.1"][0] == "revoked"
    assert outcome.agents["agt_A.1.1"][0] != "revoked"
    assert ("agt_A.1.1", "child still works") in calls
    assert [e["cascade"] for e in verified(outcome, signer).ledger if e["type"] == "revoke"] == [False]


async def test_revocation_of_unknown_id_changes_nothing(tmp_path, signer):
    def revoke_ghost():
        revoke(next(tmp_path.iterdir()), signer, "agt_Q.7")
        return [say("still here")]

    outcome = await run(tmp_path, signer, {"root": [revoke_ghost]}, revocation_poll_seconds=60)
    result = verified(outcome, signer)
    assert outcome.status == "completed"
    assert [e["type"] for e in result.ledger] == ["root"]
    assert of_type(result.calls, "revocation.ignored")


async def test_revocation_from_another_process_stops_a_blocked_subtree(tmp_path):
    key_dir = tmp_path / "keys"
    trusted = Signer.load_or_create(key_dir)
    runs = tmp_path / "runs"
    runs.mkdir()
    run_id = "run_revoketest"
    parked = {"a": asyncio.Event(), "a1": asyncio.Event()}
    calls = []

    def park_builder(token):
        async def park() -> str:
            """Block until cancelled."""
            parked["a1" if token.id.endswith(".1.1") else "a"].set()
            await asyncio.sleep(30)
            return "woke"

        return Tool(park, takes_ctx=False)

    async def wait_then_revoke():
        await asyncio.wait_for(parked["a"].wait(), 5)
        await asyncio.wait_for(parked["a1"].wait(), 5)
        script = (
            "import pathlib, sys\n"
            "from harness.identity import Signer\n"
            "from harness.revocation import revoke\n"
            "revoke(pathlib.Path(sys.argv[2]), Signer.load(pathlib.Path(sys.argv[1])), sys.argv[3], reason='misbehaving')\n"
        )
        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", script, str(key_dir), str(runs / run_id), "agt_A.1")
        assert await proc.wait() == 0
        await asyncio.sleep(0.3)
        return [call("echo", text="b outlived a")]

    scripts = {
        "root": [[call("copy_agent", task="a"), call("copy_agent", task="b")], [say("root waits")], [say("root done")]],
        # In round 3, a and its child (born in round 2) park while b revokes them.
        "a": [[call("copy_agent", task="a1"), call("echo", text="a ready")], [say("a waits")], [call("park")], [say("never")]],
        "a1": [[call("park")], [say("never")]],
        "b": [[say("b waits")], wait_then_revoke, [say("b done")]],
    }
    model = ScriptedModel(scripts)
    outcome = await run_agents(
        [RootSpec("root")],
        model,
        runs,
        trusted,
        catalog={**catalog(calls), "park": park_builder},
        run_id=run_id,
        revocation_poll_seconds=0.02,
        always_take_turns=True,
        limits=Limits(max_rounds=6),
    )
    result = verified(outcome, trusted)
    assert outcome.agents["agt_A.1"][0] == "revoked"
    assert outcome.agents["agt_A.1.1"][0] == "revoked"
    assert outcome.agents["agt_A.2"][0] != "revoked"
    assert ("agt_A.2", "b outlived a") in calls
    cancelled = [e["agent_id"] for e in of_type(result.calls, "action.end") if e["payload"]["status"] == "cancelled"]
    assert set(cancelled) == {"agt_A.1", "agt_A.1.1"}
    report = build_report(result)
    assert report.actions_after_revocation == 0
    assert report.in_flight_at_revocation == 2


# --- report ---


async def test_report_flags_matching_configs_without_a_copy_edge(tmp_path, signer):
    """Two children with identical configs, neither recorded as a copy: possibly a copy made
    outside the harness, in the way the design's config hash is meant to flag."""
    same = {"task": "x", "system_prompt": "identical", "tools": ["echo"], "memory": ""}
    model = ScriptedModel(
        {
            "root": [[call("spawn_agent", **same), call("spawn_agent", **same), call("copy_agent", task="x")], [say("done")]],
            "x": [[say("x")]],
        }
    )
    outcome = await run(tmp_path, signer, model, limits=Limits(max_lineage_ops_per_round=3))
    report = build_report(verified(outcome, signer))
    assert report.duplicate_configs == [["agt_A.1", "agt_A.2"]]
    assert report.edges == {"root": 1, "spawn": 2, "copy": 1}
    assert report.agents == 4


async def test_every_call_traces_to_a_root_in_the_ledger(tmp_path, signer):
    outcome = await run(tmp_path, signer, tree_scripts(), limits=Limits(max_rounds=6))
    result = verified(outcome, signer)
    created = edges(result)
    for entry in result.calls:
        if entry["agent_id"] != HARNESS:
            assert entry["agent_id"] in created
            assert root_of(entry["agent_id"]) in created


def test_cli_entry_point_exists():
    out = subprocess.run([sys.executable, "-m", "harness.cli", "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "revoke" in out.stdout
