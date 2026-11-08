"""Running testbed test cases from the monitor page, and recording agents an operator killed."""
import json
import time
import urllib.error
import urllib.request

from harness.identity import Signer
from harness.monitor import read_jsonl, serve
from harness.threats import flag
from harness.verify import VERIFIED, verify_run
from testbed import experiment
from testbed.__main__ import main as cli
from testbed.conditions import CONDITIONS, Trial
from testbed.experiment import aggregate, describe, render_table, run_trial
from testbed.live import TestbedSource


def _client(server):
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def request(path, body=None):
        req = urllib.request.Request(base + path, json.dumps(body).encode() if body is not None else None,
                                     {"Content-Type": "application/json", "X-Harness-Monitor": "1"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    return request


def test_the_page_lists_the_test_cases_and_runs_one_into_results(tmp_path):
    out, signer = tmp_path / "live", Signer.generate()
    logged = []
    tests = TestbedSource(out, signer, log=logged.append)
    server = serve(out / "runs", signer, 0, tests=tests)
    request = _client(server)
    try:
        status, defaults = request("/api/defaults")
        assert status == 200
        cases = defaults["tests"]["cases"]
        assert [c["name"] for c in cases] == list(CONDITIONS)
        assert {c["name"]: c["attacker"] for c in cases}["baseline"] is False
        assert defaults["tests"]["model"] == "scripted" and defaults["tests"]["out"] == str(out)

        assert request("/api/start", {"test": "no_such_test"})[1]["error"] == "no test case called 'no_such_test'"
        status, body = request("/api/start", {"test": "forge_id", "seed": 2})
        assert status == 200
        run_id = body["run"]
        assert run_id.startswith("run_001_forge_id_s2_")
        server.monitor.wait()

        records = experiment.load_records(out)
        assert len(records) == 1 and records[0]["run_id"] == run_id and records[0]["seed"] == 2
        assert records[0]["integrity"] == VERIFIED and "attempts" in records[0]
        assert "operator_flags" not in records[0]
        assert verify_run(out / "runs" / run_id, signer.public_key_b64).status == VERIFIED
        assert any(line.startswith("forge_id seed 2:") for line in logged)
        state = request(f"/api/runs/{run_id}/state?after=-1")[1]
        assert not state["running"] and not state["busy"] and len(state["agents"]) >= 4

        # The next one is numbered after it, in the same folder.
        status, body = request("/api/start", {"test": "baseline"})
        assert status == 200 and body["run"].startswith("run_002_baseline_s0_")
        server.monitor.wait()
        assert len(experiment.load_records(out)) == 2
    finally:
        server.shutdown()


def test_a_monitor_without_test_cases_refuses_to_start_one(tmp_path):
    server = serve(tmp_path / "runs", Signer.generate(), 0)
    request = _client(server)
    try:
        assert "tests" not in request("/api/defaults")[1]
        status, body = request("/api/start", {"test": "baseline"})
        assert status == 400 and "no test cases" in body["error"]
    finally:
        server.shutdown()


def test_a_test_that_cant_start_shows_why(tmp_path):
    out, signer = tmp_path / "live", Signer.generate()
    tests = TestbedSource(out, signer, log=lambda line: None)
    server = serve(out / "runs", signer, 0, tests=tests)
    request = _client(server)
    try:
        status, body = request("/api/start", {"test": "baseline", "attacker_model": "scripted-other"})
        assert status == 400 and body["error"] == "the scripted model takes no attacker model"
    finally:
        server.shutdown()


async def test_agents_killed_from_the_monitor_are_recorded_in_the_result(tmp_path, monkeypatch):
    signer = Signer.generate()
    original = experiment.run_agents

    async def run_then_flag(*args, **kwargs):
        outcome = await original(*args, **kwargs)
        root = next(e["child"] for e in read_jsonl(outcome.run_dir / "ledger.jsonl") if e["type"] == "root")
        flag(outcome.run_dir, signer, root, "probing for the key")
        return outcome

    monkeypatch.setattr(experiment, "run_agents", run_then_flag)
    record = await run_trial(Trial(CONDITIONS["baseline"], 0), tmp_path, signer)
    assert record["operator_flags"][0]["reason"] == "probing for the key"
    assert record["operator_flags"][0]["cascade"] is True
    assert describe(record).endswith("[you killed 1 agent(s) from the monitor]")
    table = render_table(aggregate([record]))
    assert "(1 with agents you killed)" in table


def test_testbed_monitor_needs_a_model_or_scripted(capsys):
    assert cli(["monitor", "--no-browser"]) == 1
    assert "give --worker-model, or --scripted" in capsys.readouterr().err
