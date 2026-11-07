"""The live monitor, its HTTP API, flagging and the threat log, on the offline demo run."""
import asyncio
import time
import json
import urllib.error
import urllib.request

import pytest

from harness.cli import main as cli_main
from harness.identity import Signer
from harness.monitor import Monitor, agents, read_jsonl, serve, summarize
from harness.monitor_demo import LEAD, PARSER, ROGUE, ROGUE_CHILD, ROGUE_GRANDCHILD, TESTS, run_demo
from harness.revocation import read_entries
from harness.threats import THREAT_FILE, read_threats
from harness.verify import VERIFIED, verify_run


async def _run_and_flag(runs, signer, flagger, reason="probing for the signing key"):
    """Run the demo, flag the rogue once its child is busy, and return the run directory."""
    demo = asyncio.create_task(run_demo(runs, signer, pace=0, max_rounds=30))
    run_dir = None
    while not demo.done():
        await asyncio.sleep(0.02)
        run_dir = next(runs.iterdir(), None)
        if run_dir is None:
            continue
        roster = agents(read_jsonl(run_dir / "ledger.jsonl"), read_jsonl(run_dir / "calls.jsonl"))
        rogue = next((a for a in roster if a["task"] == ROGUE), None)
        grandchild = next((a for a in roster if a["task"] == ROGUE_GRANDCHILD), None)
        if rogue and grandchild and grandchild["tool_calls"] >= 1:
            await asyncio.to_thread(flagger, run_dir, rogue["id"], reason)
            break
    outcome = await demo
    return run_dir, outcome


async def test_flagging_the_rogue_kills_it_and_its_child_and_logs_a_signed_threat(tmp_path):
    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    run_dir, outcome = await _run_and_flag(runs, signer, lambda d, a, r: monitor.flag(d, a, r, True))

    roster = monitor.state(run_dir, -1)["agents"]
    statuses = {a["task"]: a["status"] for a in roster}
    assert statuses[ROGUE] == statuses[ROGUE_CHILD] == statuses[ROGUE_GRANDCHILD] == "revoked"
    assert "revoked" not in {s for task, s in statuses.items() if task not in (ROGUE, ROGUE_CHILD, ROGUE_GRANDCHILD)}
    # Three generations on each side, with IDs that show the lineage.
    ids = {a["task"]: a["id"] for a in roster}
    assert ids[TESTS].startswith(ids[PARSER] + ".") and ids[PARSER].startswith(ids[LEAD] + ".")
    assert ids[ROGUE_GRANDCHILD] == ids[ROGUE] + ".1.1"

    threats = read_threats(run_dir, signer.public_key_b64)
    revocations, _ = read_entries(run_dir, signer.public_key_b64)
    assert len(threats) == 1 and threats[0]["verified"] and threats[0]["reason"] == "probing for the signing key"
    assert threats[0]["revocation_signature"] == revocations[0]["signature"]
    assert "flagged as a threat" in revocations[0]["reason"]
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED
    ledger_revokes = [e for e in read_jsonl(run_dir / "ledger.jsonl") if e["type"] == "revoke"]
    assert [e["child"] for e in ledger_revokes] == [threats[0]["agent_id"]]  # one entry; it covers the child


async def test_a_flag_can_spare_the_descendants(tmp_path):
    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    run_dir, _ = await _run_and_flag(runs, signer, lambda d, a, r: monitor.flag(d, a, r, False))
    statuses = {a["task"]: a["status"] for a in monitor.state(run_dir, -1)["agents"]}
    assert statuses[ROGUE] == "revoked" and statuses[ROGUE_CHILD] != "revoked" and statuses[ROGUE_GRANDCHILD] != "revoked"


async def test_an_edited_threat_entry_shows_as_invalid_and_a_finished_run_cant_be_flagged(tmp_path):
    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    run_dir, _ = await _run_and_flag(runs, signer, lambda d, a, r: monitor.flag(d, a, r, True))
    path = run_dir / THREAT_FILE
    path.write_text(path.read_text().replace("signing key", "nothing much"))
    assert [t["verified"] for t in read_threats(run_dir, signer.public_key_b64)] == [False]
    agent = monitor.state(run_dir, -1)["agents"][0]["id"]
    with pytest.raises(ValueError, match="already ended"):
        monitor.flag(run_dir, agent, "too late", True)


def test_summaries_mark_refusals_kills_and_suspicious_calls():
    def entry(kind, payload, agent="agt_A"):
        return {"seq": 1, "ts": 0.0, "round": 1, "agent_id": agent, "type": kind, "payload": payload}

    assert summarize(entry("action.refused", {"kind": "tool", "tool": "x", "reason": "agent is revoked"}))["level"] == "danger"
    assert summarize(entry("agent.revoked", {"reason": "flagged"}))["level"] == "danger"
    assert summarize(entry("action.start", {"tool": "run_shell", "args": {"command": "cat ../ledger.jsonl"}}))["level"] == "warn"
    assert summarize(entry("action.start", {"tool": "read_file", "args": {"path": "src/dates.py"}}))["level"] == "info"
    spawned = summarize(entry("action.end", {"tool": "spawn_agent", "status": "ok", "result": "Created agt_A.1."}))
    assert (spawned["level"], spawned["text"]) == ("lineage", "⑂ spawn: Created agt_A.1.")
    reply = summarize(entry("model.response", {"parts": [{"part_kind": "tool-call", "tool_name": "ls", "args": "{}"}], "input_tokens": 3, "output_tokens": 2}))
    assert reply["text"] == "🛠 model asks to call ls()  · 5 tokens" and "said" not in reply
    spoken = summarize(entry("model.response", {"parts": [{"part_kind": "thinking", "content": "Line 5 is next."},
                                                          {"part_kind": "text", "content": "Done.\nAll 40 lines saved."}]}))
    assert (spoken["level"], spoken["text"], spoken["said"], spoken["thinking"]) == ("reply", "💬 model replied", "Done.\nAll 40 lines saved.", "Line 5 is next.")


def test_read_jsonl_skips_a_half_written_last_line(tmp_path):
    path = tmp_path / "calls.jsonl"
    path.write_text('{"seq": 0}\n{"seq": 1, "ty')
    assert read_jsonl(path) == [{"seq": 0}]


async def test_http_api_serves_state_and_only_accepts_flags_from_the_page(tmp_path):
    runs, signer = tmp_path / "runs", Signer.generate()
    server = serve(runs, signer, 0)
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def request(path, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data, {"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read()) if "json" in r.headers["Content-Type"] else r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def flag_via_http(run_dir, agent_id, reason):
        url = f"/api/runs/{run_dir.name}/flag"
        assert request(url, {"agent_id": agent_id, "reason": reason})[0] == 403  # no header
        assert request(url, {"agent_id": agent_id}, {"X-Harness-Monitor": "1", "Host": "evil.example"})[0] == 403
        assert request(url, {"agent_id": "agt_ZZ"}, {"X-Harness-Monitor": "1"})[0] == 400  # not in this run
        status, body = request(url, {"agent_id": agent_id, "reason": reason}, {"X-Harness-Monitor": "1"})
        assert status == 200 and body["threat"]["agent_id"] == agent_id

    try:
        status, page = request("/")
        assert status == 200 and "Harness monitor" in page
        run_dir, _ = await _run_and_flag(runs, signer, flag_via_http)
        assert request("/api/runs")[1]["runs"][0]["id"] == run_dir.name
        status, state = request(f"/api/runs/{run_dir.name}/state?after=-1")
        assert status == 200 and not state["running"] and len(state["threats"]) == 1
        assert [a["flagged"] for a in state["agents"] if a["task"] == ROGUE] == [True]
        assert request("/api/runs/../../etc/state")[0] == 404
        assert request("/api/runs/run_nope/state")[0] == 404
    finally:
        server.shutdown()


async def test_flag_command_refuses_a_finished_run(tmp_path, capsys):
    runs, key_dir = tmp_path / "runs", tmp_path / "keys"
    signer = Signer.load_or_create(key_dir)
    outcome = await run_demo(runs, signer, pace=0, max_rounds=2)
    agent = next(iter(outcome.agents))
    args = ["--runs-dir", str(runs), "--key-dir", str(key_dir), "flag", outcome.run_id, agent, "--reason", "test"]
    assert await asyncio.to_thread(cli_main, args) == 1
    assert "already ended" in capsys.readouterr().err


async def test_a_flagged_live_lead_and_its_helper_stop_short_and_nothing_runs_after(tmp_path):
    """run_live's path, with a scripted model in place of the real one: the lead spawns a helper,
    both write, and flagging the lead stops both."""
    from harness.monitor_demo import live_task, notebooks, run_live
    from harness.scripted import ScriptedModel, call

    helper_task = "write 21 to 40 into second-half"
    lead_numbers, helper_numbers = iter(range(1, 21)), iter(range(21, 41))
    model = ScriptedModel({
        live_task(40): [[call("spawn_agent", task=helper_task, system_prompt="helper", tools=["write_line", "send_message"])],
                        lambda: [call("write_line", text=str(next(lead_numbers)), notebook="first-half")]],
        helper_task: [lambda: [call("write_line", text=str(next(helper_numbers)), notebook="second half!")]],
    })  # fmt: skip
    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    live = asyncio.create_task(run_live(runs, signer, model, target=40, pace=0.02))
    run_dir = lead = None
    while not live.done():
        await asyncio.sleep(0.02)
        run_dir = next(runs.iterdir(), None)
        if run_dir and len(notebooks(run_dir).get("second-half", [])) >= 3:
            lead = next(a["id"] for a in monitor.state(run_dir, -1)["agents"] if a["parent"] is None)
            await asyncio.to_thread(monitor.flag, run_dir, lead, "test stop", True)
            break
    outcome = await live
    spawned = [e for e in monitor.state(run_dir, -1)["events"] if e["level"] == "lineage"]
    assert [e["child"] for e in spawned] == [lead + ".1"] and f"created {lead}.1" in spawned[0]["text"]
    books = notebooks(run_dir)
    assert set(books) == {"first-half", "second-half"}  # the name is cleaned up
    assert 0 < len(books["first-half"]) < 20 and 3 <= len(books["second-half"]) < 20
    assert outcome.agents[lead][0] == outcome.agents[lead + ".1"][0] == "revoked"
    calls = read_jsonl(run_dir / "calls.jsonl")
    revoked = {e["agent_id"]: e["seq"] for e in calls if e["type"] == "agent.revoked"}
    assert set(revoked) == {lead, lead + ".1"}
    late = [e for e in calls if e["agent_id"] in revoked and e["seq"] > revoked[e["agent_id"]] and e["type"] in ("action.start", "model.request")]
    assert late == []
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


def test_a_custom_live_task_replaces_the_default(tmp_path):
    from harness.monitor_demo import LIVE_TOOLS, run_live
    from harness.scripted import ScriptedModel, say

    model = ScriptedModel({"Say hi.": [[say("hi")]]})
    outcome = asyncio.run(run_live(tmp_path / "runs", Signer.generate(), model, task="Say hi.", pace=0))
    ledger = read_jsonl(tmp_path / "runs" / outcome.run_id / "ledger.jsonl")
    assert ledger[0]["task"] == "Say hi." and set(ledger[0]["config"]["tools"]) == set(LIVE_TOOLS)


def test_the_page_can_start_a_run_with_any_prompt_one_at_a_time(tmp_path):
    from harness.monitor_demo import LIVE_MODEL, live_task, notebooks
    from harness.scripted import ScriptedModel, call

    numbers = iter(range(1, 10_000))
    task = "Write numbers into the notebook n, forever."
    model = ScriptedModel({task: [lambda: [call("write_line", text=str(next(numbers)), notebook="n")]]})
    runs, signer = tmp_path / "runs", Signer.generate()
    server = serve(runs, signer, 0, model_override=model)
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def request(path, body=None, header=True):
        req = urllib.request.Request(base + path, json.dumps(body).encode() if body is not None else None,
                                     {"Content-Type": "application/json", **({"X-Harness-Monitor": "1"} if header else {})})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        status, defaults = request("/api/defaults")
        assert status == 200 and defaults["task"] == live_task(40) and defaults["model"] == LIVE_MODEL
        assert "spawn_agent" in defaults["task"]
        assert request("/api/start", {"task": task}, header=False)[0] == 403
        assert request("/api/start", {"task": "   "})[0] == 400
        status, body = request("/api/start", {"task": task, "pace": 0.01, "max_tokens": 500_000})
        assert status == 200
        run_id = body["run"]
        assert request("/api/start", {"task": task})[1]["error"].startswith("a run started from this page is still going")
        run_dir = runs / run_id
        ledger = read_jsonl(run_dir / "ledger.jsonl")
        assert ledger[0]["task"] == task
        while len(notebooks(run_dir).get("n", [])) < 3:
            time.sleep(0.02)
        root = ledger[0]["child"]
        assert request(f"/api/runs/{run_id}/flag", {"agent_id": root, "reason": "enough"})[0] == 200
        deadline = time.time() + 10
        while request(f"/api/runs/{run_id}/state?after=-1")[1]["running"] and time.time() < deadline:
            time.sleep(0.05)
        state = request(f"/api/runs/{run_id}/state?after=-1")[1]
        assert not state["running"] and state["agents"][0]["status"] == "revoked"
        assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED
    finally:
        server.shutdown()


async def test_full_trace_and_terminal_transcript_show_spawns_prompts_and_kills(tmp_path):
    import io

    from harness.live_chat import Transcript
    from harness.monitor_demo import LEAD, PARSER

    runs, signer = tmp_path / "runs", Signer.generate()
    monitor = Monitor(runs, signer)
    run_dir, _ = await _run_and_flag(runs, signer, lambda d, a, r: monitor.flag(d, a, r, True))
    roster = {a["task"]: a["id"] for a in monitor.state(run_dir, -1)["agents"]}

    lead = monitor.trace(run_dir, roster[LEAD])
    assert lead["parent"] is None and lead["edge"] == "root" and roster[PARSER] in lead["children"]
    assert "spawn_agent" in lead["config"]["tools"] and lead["task"] == LEAD
    kinds = {s["type"] for s in lead["steps"]}
    assert {"model.request", "model.response", "action.end"} <= kinds
    prompt = next(s for s in lead["steps"] if s["type"] == "model.request")["payload"]["parts"][0]
    assert prompt == {"part_kind": "user-prompt", "content": LEAD}
    child = monitor.trace(run_dir, roster[PARSER])
    assert child["edge"] == "spawn" and child["parent"] == roster[LEAD] and child["task"] == PARSER
    rogue_child = monitor.trace(run_dir, roster[ROGUE_CHILD])
    assert rogue_child["revocations"][0]["of"] == roster[ROGUE]  # killed through its parent
    with pytest.raises(ValueError):
        monitor.trace(run_dir, "agt_ZZ")

    out = io.StringIO()
    transcript = Transcript(run_dir, colour=False, out=out)
    assert transcript.poll() is True
    text = out.getvalue()
    assert f"agent ID {roster[LEAD]}" in text
    assert "agent ⑂ spawned helper .1" in text and f"task: {PARSER}" in text
    assert "agent › Split the work" in text
    assert "revoked and everything below it" in text and "run ended" in text
