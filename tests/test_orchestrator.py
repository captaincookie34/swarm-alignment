"""The orchestrator: freeze a chain, judge each agent, kill threats, resume or salvage the cleared."""
import asyncio
import json

import pytest

from harness import orchestrator
from harness.identity import Lineage, Signer
from harness.monitor import Monitor, agents, read_jsonl
from harness.monitor_demo import LEAD, PARSER, ROGUE, ROGUE_CHILD, ROGUE_GRANDCHILD, TESTS, run_demo
from harness.threats import read_threats
from harness.verify import VERIFIED, verify_run


def _lineage(*edges):
    lineage = Lineage()
    for child, parent in edges:
        lineage.add(child, parent)
    return lineage


def test_a_threat_mid_chain_retires_what_it_made_and_reprompts_the_agent_above_it():
    # lead -> a -> b -> c, frozen at a; b is the threat.
    lineage = _lineage(("lead", None), ("a", "lead"), ("b", "a"), ("c", "b"))
    plan = orchestrator.plan(["a", "b", "c"], {"a": "cleared", "b": "threat", "c": "cleared"}, lineage, {"lead"})
    assert plan["threats"] == ["b"] and plan["resume"] == ["a"] and plan["retire"] == ["c"]
    assert plan["reprompt"] == {"a": {"lost": ["b"], "saved": ["c"]}} and plan["unrouted"] == []


def test_a_threat_at_the_top_of_the_freeze_reprompts_its_living_parent():
    lineage = _lineage(("lead", None), ("a", "lead"), ("b", "a"), ("c", "a"))
    plan = orchestrator.plan(["a", "b", "c"], {"a": "threat", "b": "cleared", "c": "threat"}, lineage, {"lead"})
    assert plan["resume"] == [] and plan["retire"] == ["b"]
    assert plan["reprompt"] == {"lead": {"lost": ["a", "c"], "saved": ["b"]}}


def test_a_threat_root_has_nobody_to_hand_work_to():
    lineage = _lineage(("r", None), ("x", "r"))
    plan = orchestrator.plan(["r", "x"], {"r": "threat", "x": "cleared"}, lineage, set())
    assert plan["reprompt"] == {} and plan["unrouted"] == ["x"]


def test_unsigned_or_edited_control_entries_are_ignored(tmp_path):
    run_dir, signer = tmp_path / "run_x", Signer.generate()
    run_dir.mkdir()
    orchestrator.write(run_dir, signer, orchestrator.FREEZE, "agt_A")
    forged = json.loads((run_dir / orchestrator.CONTROL_FILE).read_text())
    forged["agent_id"] = "agt_B"
    with open(run_dir / orchestrator.CONTROL_FILE, "a") as f:
        f.write(json.dumps(forged) + "\n")
    orchestrator.write(run_dir, Signer.generate(), orchestrator.FREEZE, "agt_C")  # another key
    assert [e["agent_id"] for e in orchestrator.read(run_dir, signer.public_key_b64)] == ["agt_A"]
    with pytest.raises(ValueError):
        orchestrator.write(run_dir, signer, orchestrator.VERDICT, "agt_A", verdict="maybe")


def _roster(run_dir):
    """Agents by task. The first agent with each task: a replacement can start another on the same one."""
    out = {}
    for a in agents(read_jsonl(run_dir / "ledger.jsonl"), read_jsonl(run_dir / "calls.jsonl")):
        out.setdefault(a["task"], a)
    return out


async def _wait(predicate, demo, timeout=20.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not predicate():
        assert not demo.done(), "the run ended first"
        assert loop.time() < end, "timed out"
        await asyncio.sleep(0.02)


async def _freeze_and_judge(tmp_path, freeze_task, verdicts):
    """Run the demo, freeze the agent with freeze_task once its grandchild's running, give each
    frozen agent its verdict (by task), resolve, then let the run finish."""
    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    demo = asyncio.create_task(run_demo(runs, signer, pace=0.01, max_rounds=40))
    await _wait(lambda: runs.is_dir() and next(runs.iterdir(), None) is not None, demo)
    run_dir = next(runs.iterdir())
    await _wait(lambda: _roster(run_dir).get(TESTS, {}).get("tool_calls", 0) >= 1 and _roster(run_dir).get(ROGUE_GRANDCHILD, {}).get("tool_calls", 0) >= 1, demo)
    target = _roster(run_dir)[freeze_task]["id"]
    await asyncio.to_thread(monitor.freeze, run_dir, target, "looked off")
    await _wait(lambda: any(f["agent_id"] == target for f in monitor.state(run_dir, 10**9)["freezes"]), demo)
    chain = next(f for f in monitor.state(run_dir, 10**9)["freezes"] if f["agent_id"] == target)
    with pytest.raises(ValueError, match="undecided"):
        monitor.resolve(run_dir, target)
    for a in chain["agents"]:
        monitor.verdict(run_dir, a["id"], verdicts[a["task"]], "bad" if verdicts[a["task"]] == "threat" else "")
    frozen_calls = {t: _roster(run_dir)[t]["tool_calls"] for t in verdicts}
    await asyncio.sleep(0.3)  # frozen agents make no calls while they wait
    assert {t: _roster(run_dir)[t]["tool_calls"] for t in verdicts} == frozen_calls
    monitor.resolve(run_dir, target)
    await demo
    return run_dir, signer, frozen_calls


async def test_freezing_a_helper_kills_the_threat_and_spawns_a_replacement_with_the_cleared_work(tmp_path):
    run_dir, signer, before = await _freeze_and_judge(tmp_path, PARSER, {PARSER: "threat", TESTS: "cleared"})
    roster = _roster(run_dir)
    assert roster[PARSER]["status"] == "revoked" and roster[TESTS]["status"] == "retired"
    assert roster[LEAD]["status"] != "revoked" and roster[ROGUE]["status"] != "revoked"
    assert roster[TESTS]["tool_calls"] == before[TESTS]  # retired, so it never ran again
    calls, ledger = read_jsonl(run_dir / "calls.jsonl"), read_jsonl(run_dir / "ledger.jsonl")

    # The orchestrator started a new child of the lead, the removed helper's parent, on its task.
    event = next(e["payload"] for e in calls if e["type"] == "orchestrator.replacement")
    assert event["parent"] == roster[LEAD]["id"] and event["replaces"] == roster[PARSER]["id"]
    saved = event["saved"]
    assert [s["task"] for s in saved] == [TESTS] and saved[0]["work"], "the cleared grandchild's work was kept"
    spawn = next(e for e in ledger if e["child"] == event["child"])
    parsed = next(e for e in ledger if e["child"] == roster[PARSER]["id"])
    assert spawn["type"] == "spawn" and spawn["actor"] == roster[LEAD]["id"]
    assert spawn["made_by"] == "orchestrator" and spawn["replaces"] == roster[PARSER]["id"]
    assert spawn["config_hash"] == parsed["config_hash"]  # same tools and prompt as the agent it replaces
    assert spawn["task"].startswith(PARSER) and "[Orchestrator]" in spawn["task"] and saved[0]["work"][0][:40] in spawn["task"]
    # It ran, and the lead was told to wait for it.
    assert any(e["type"] == "model.request" and e["agent_id"] == event["child"] for e in calls)
    lead_prompts = [
        part.get("content", "") for e in calls if e["type"] == "model.request" and e["agent_id"] == roster[LEAD]["id"]
        for m in e["payload"]["new_messages"] for part in m.get("parts", []) if part.get("part_kind") == "user-prompt"
    ]  # fmt: skip
    assert any("[Orchestrator]" in p and "in its place" in p for p in lead_prompts)
    threats = read_threats(run_dir, signer.public_key_b64)
    assert [(t["agent_id"], t["cascade"], t["verified"]) for t in threats] == [(roster[PARSER]["id"], False, True)]
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


async def test_a_chain_cleared_in_full_resumes_and_keeps_working(tmp_path):
    run_dir, signer, before = await _freeze_and_judge(tmp_path, PARSER, {PARSER: "cleared", TESTS: "cleared"})
    roster = _roster(run_dir)
    assert roster[PARSER]["status"] != "revoked" and roster[TESTS]["status"] != "revoked"
    assert roster[PARSER]["tool_calls"] > before[PARSER] and roster[TESTS]["tool_calls"] > before[TESTS]
    calls = read_jsonl(run_dir / "calls.jsonl")
    assert not any(e["type"] == "orchestrator.reprompt" for e in calls)
    assert sum(e["type"] == "agent.unfrozen" for e in calls) == 2
    assert read_threats(run_dir, signer.public_key_b64) == []
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


async def test_a_rogue_root_judged_a_threat_throughout_is_killed_with_no_one_to_reprompt(tmp_path):
    verdicts = {ROGUE: "threat", ROGUE_CHILD: "threat", ROGUE_GRANDCHILD: "threat"}
    run_dir, signer, _ = await _freeze_and_judge(tmp_path, ROGUE, verdicts)
    roster = _roster(run_dir)
    assert {roster[t]["status"] for t in verdicts} == {"revoked"}
    assert roster[LEAD]["status"] != "revoked"
    calls = read_jsonl(run_dir / "calls.jsonl")
    assert not any(e["type"] == "orchestrator.reprompt" for e in calls)
    assert len(read_threats(run_dir, signer.public_key_b64)) == 3
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


def test_a_quiet_run_waiting_on_verdicts_still_counts_as_running():
    from harness.monitor import STALE_SECONDS, run_status

    calls = [{"seq": 0, "ts": 0.0, "type": "run.start", "payload": {}}, {"seq": 1, "ts": 1.0, "type": "agent.frozen", "agent_id": "a", "payload": {}}]
    assert run_status(calls, now=1.0 + STALE_SECONDS * 2)["running"]
    calls.append({"seq": 2, "ts": 2.0, "type": "agent.unfrozen", "agent_id": "a", "payload": {}})
    assert not run_status(calls, now=2.0 + STALE_SECONDS * 2)["running"]


async def _kill_parser(tmp_path, cascade):
    """Run the demo and flag the parser helper (the lead's child) once its own child is working."""
    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    demo = asyncio.create_task(run_demo(runs, signer, pace=0.01, max_rounds=30))
    await _wait(lambda: runs.is_dir() and next(runs.iterdir(), None) is not None, demo)
    run_dir = next(runs.iterdir())
    await _wait(lambda: _roster(run_dir).get(TESTS, {}).get("tool_calls", 0) >= 1, demo)
    roster = _roster(run_dir)
    await asyncio.to_thread(monitor.flag, run_dir, roster[PARSER]["id"], "rewrote the tests", cascade)
    await demo
    return run_dir, signer, roster


async def test_a_kill_tells_the_parent_and_starts_a_replacement_so_it_isnt_left_waiting(tmp_path):
    run_dir, signer, before = await _kill_parser(tmp_path, cascade=True)
    roster, calls, ledger = _roster(run_dir), read_jsonl(run_dir / "calls.jsonl"), read_jsonl(run_dir / "ledger.jsonl")
    assert roster[PARSER]["status"] == roster[TESTS]["status"] == "revoked"
    kill = next(e["payload"] for e in calls if e["type"] == "orchestrator.kill")
    assert kill["agent_id"] == before[PARSER]["id"] and set(kill["killed"]) == {before[PARSER]["id"], before[TESTS]["id"]}
    event = next(e["payload"] for e in calls if e["type"] == "orchestrator.replacement")
    assert event["parent"] == before[LEAD]["id"] and event["replaces"] == before[PARSER]["id"] and event["saved"] == []
    spawn = next(e for e in ledger if e["child"] == event["child"])
    assert spawn["actor"] == before[LEAD]["id"] and spawn["made_by"] == "orchestrator" and "from the beginning" in spawn["task"]
    assert any(e["type"] == "model.request" and e["agent_id"] == event["child"] for e in calls)
    assert any("in its place" in str(m) for e in calls if e["type"] == "model.request" and e["agent_id"] == before[LEAD]["id"] for m in e["payload"]["new_messages"])
    assert len(read_threats(run_dir, signer.public_key_b64)) == 1  # only the operator's flag
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


async def test_a_kill_that_spares_the_children_hands_their_work_to_the_replacement(tmp_path):
    run_dir, signer, before = await _kill_parser(tmp_path, cascade=False)
    roster, calls = _roster(run_dir), read_jsonl(run_dir / "calls.jsonl")
    assert roster[PARSER]["status"] == "revoked" and roster[TESTS]["status"] == "retired"
    event = next(e["payload"] for e in calls if e["type"] == "orchestrator.replacement")
    assert event["parent"] == before[LEAD]["id"] and [s["agent_id"] for s in event["saved"]] == [before[TESTS]["id"]]
    assert event["saved"][0]["work"] and event["saved"][0]["work"][0][:40] in event["task"]
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


async def test_the_final_analysis_lists_each_agents_input_and_output_and_each_kill_with_its_replacement(tmp_path):
    run_dir, signer, before = await _kill_parser(tmp_path, cascade=False)
    result = Monitor(run_dir.parent, signer).analysis(run_dir)
    by_id = {a["id"]: a for a in result["agents"]}
    assert result["ended"] and result["integrity"].startswith("VERIFIED")
    assert result["counts"]["killed"] == 1 and result["counts"]["retired"] == 1 and result["counts"]["replacements"] == 1
    parser, tests = by_id[before[PARSER]["id"]], by_id[before[TESTS]["id"]]
    assert parser["task"] == PARSER and parser["killed"]["reason"] == "rewrote the tests" and parser["killed"]["direct"]
    assert parser["final_source"] == "last reply before it was killed" and parser["final"]
    replacement = by_id[parser["replaced_by"][0]]
    assert replacement["made_by"] == "orchestrator" and replacement["replaces"] == parser["id"] and replacement["parent"] == before[LEAD]["id"]
    assert tests["status"] == "retired" and tests["retired_work"] > 0
    kill = result["kills"][0]
    assert kill["target"] == parser["id"] and kill["retired"] == [tests["id"]] and kill["replacements"] == [replacement["id"]]
    assert by_id[before[LEAD]["id"]]["task"] == LEAD  # the root's first input is the operator's prompt


async def test_the_page_lookup_gives_the_same_answer_as_harness_whois(tmp_path):
    run_dir, signer, before = await _kill_parser(tmp_path, cascade=True)
    monitor = Monitor(run_dir.parent, signer)
    parser = before[PARSER]["id"]
    ours = monitor.whois(parser)
    assert ours["ours"] is True and ours["status"] == "revoked" and ours["revoked_by"][0]["reason"].endswith("rewrote the tests")
    assert [a["id"] for a in ours["ancestors"]] == [before[LEAD]["id"], parser]
    foreign = monitor.whois("agt_zzzzzz" + parser[len("agt_zzzzzz"):])
    assert foreign["ours"] is False and "not ours" in foreign["verdict"]


async def test_with_no_room_for_a_replacement_the_parent_gets_the_work_and_the_page_still_loads(tmp_path):
    """The demo's seven agents fill a seven-agent cap, so resolving a freeze can't start a replacement:
    the parent gets the saved work instead, and the monitor must still read the run."""
    from harness.limits import Limits
    from harness.monitor_demo import LEAD_TOOLS, ROGUE_TOOLS, _tools, demo_model
    from harness.runner import RootSpec, run_agents

    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    roots = [RootSpec(LEAD, tools=LEAD_TOOLS), RootSpec(ROGUE, tools=ROGUE_TOOLS)]
    demo = asyncio.create_task(run_agents(
        roots, demo_model(0.01), runs, signer, Limits(max_rounds=30, max_tool_calls_per_round=3, max_tokens=50_000_000, max_agents=7),
        catalog=_tools(), always_take_turns=True, orchestrate_kills=True,
    ))  # fmt: skip
    await _wait(lambda: runs.is_dir() and next(runs.iterdir(), None) is not None, demo)
    run_dir = next(runs.iterdir())
    await _wait(lambda: len(_roster(run_dir)) == 7 and _roster(run_dir)[TESTS]["tool_calls"] >= 1, demo)
    before = _roster(run_dir)
    monitor.freeze(run_dir, before[PARSER]["id"], "")
    await _wait(lambda: monitor.state(run_dir, 10**9)["freezes"], demo)
    monitor.verdict(run_dir, before[PARSER]["id"], "threat", "bad")
    monitor.verdict(run_dir, before[TESTS]["id"], "cleared")
    monitor.resolve(run_dir, before[PARSER]["id"])
    await _wait(lambda: not monitor.state(run_dir, 10**9)["freezes"], demo)  # the panel clears
    await demo

    calls = read_jsonl(run_dir / "calls.jsonl")
    entry = next(e for e in calls if e["type"] == "orchestrator.reprompt")
    reprompt = entry["payload"]
    assert reprompt["to"] == before[LEAD]["id"] and reprompt["reason"] == "agent limit reached"
    assert [s["agent_id"] for s in reprompt["saved"]] == [before[TESTS]["id"]] and reprompt["saved"][0]["work"]
    assert not any(e["type"] == "orchestrator.replacement" for e in calls)
    from harness.monitor import summarize

    line = summarize(entry)  # the line that broke the page: the removed agents here are plain IDs
    assert line["level"] == "lineage" and before[TESTS]["id"] in line["agents"] and before[PARSER]["id"] in line["agents"]
    assert monitor.state(run_dir, -1)["events"]  # and the whole run's state loads
    assert monitor.analysis(run_dir)["counts"]["retired"] == 1
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


def test_an_entry_the_monitor_cant_read_doesnt_stop_the_page():
    from harness.monitor import summarize_safely

    odd = {"seq": 5, "ts": 1.0, "round": 2, "agent_id": "harness", "type": "orchestrator.reprompt", "payload": {"lost": [3], "saved": None}}
    line = summarize_safely(odd)
    assert line["seq"] == 5 and line["level"] == "warn" and "couldn't summarize" in line["text"]
