"""harness whois: did we create this agent, and what's its lineage."""
import asyncio
import json

import pytest

from harness.cli import main as cli_main
from harness.identity import IdentityIssuer, Lineage, Signer
from harness.lookup import lookup
from harness.monitor import read_jsonl
from harness.monitor_demo import LEAD, PARSER, TESTS, run_demo


@pytest.fixture
def demo(tmp_path):
    key_dir = tmp_path / "keys"
    signer = Signer.load_or_create(key_dir)
    runs = tmp_path / "runs"
    outcome = asyncio.run(run_demo(runs, signer, pace=0, max_rounds=8))
    ledger = read_jsonl(runs / outcome.run_id / "ledger.jsonl")
    by_task = {e["task"]: e for e in ledger if e["type"] in ("root", "spawn")}
    return signer, key_dir, runs, outcome.run_id, by_task


def test_a_grandchild_is_ours_with_its_lineage_and_descendants(demo):
    signer, _, runs, run_id, by_task = demo
    lead, parser, tests = (by_task[t]["child"] for t in (LEAD, PARSER, TESTS))
    result = lookup(tests, signer.public_key_b64, [runs])
    assert result.ours is True and result.run == run_id and result.integrity == "VERIFIED" and result.token_valid
    assert [a["id"] for a in result.ancestors] == [lead, parser, tests]
    assert result.created["created_by"] == parser and result.created["task"] == TESTS
    assert result.descendants == []
    of_lead = lookup(lead, signer.public_key_b64, [runs])
    assert of_lead.created["edge"] == "root" and tests in [d["id"] for d in of_lead.descendants]
    assert {d["id"]: d["depth"] for d in of_lead.descendants}[tests] == 2


def test_other_keys_unknown_ids_and_non_ids(demo):
    signer, _, runs, _, _ = demo
    other = Signer.generate()
    foreign = IdentityIssuer(other, "run_X").issue_root()
    assert lookup(foreign.id, signer.public_key_b64, [runs]).ours is False
    unknown = IdentityIssuer(signer, "run_X").issue_root().id  # our key's format, but never recorded
    result = lookup(unknown, signer.public_key_b64, [runs])
    assert result.ours is None and "can't tell" in result.verdict
    assert lookup("not-an-id", signer.public_key_b64, [runs]).ours is False


def test_a_token_proves_it_without_the_run_and_a_forged_one_doesnt(demo, tmp_path):
    signer, _, _, _, _ = demo
    token = IdentityIssuer(signer, "run_ELSEWHERE").issue_root()
    assert lookup(token.id, signer.public_key_b64, [tmp_path / "nowhere"], token).ours is True
    forged = IdentityIssuer(Signer.generate(), "run_X").issue_root()
    # Same ID shape as ours, signed by someone else.
    fake = type(token)(token.id, token.run, token.issued_at, token.depth, forged.signature, token.parent, token.root)
    assert lookup(token.id, signer.public_key_b64, [tmp_path / "nowhere"], fake).ours is False


def test_tampered_logs_mean_the_lineage_cant_be_confirmed(demo):
    signer, _, runs, run_id, by_task = demo
    ledger = runs / run_id / "ledger.jsonl"
    ledger.write_text(ledger.read_text().replace(TESTS, TESTS + " (edited)"))
    result = lookup(by_task[PARSER]["child"], signer.public_key_b64, [runs])
    assert result.ours is None and "TAMPERED" in result.integrity


def test_whois_command_takes_an_id_or_a_ledger_entry_and_sets_the_exit_code(demo, tmp_path, capsys):
    signer, key_dir, runs, run_id, by_task = demo
    child = by_task[PARSER]["child"]
    base = ["--key-dir", str(key_dir), "--runs-dir", str(runs), "whois"]
    assert cli_main([*base, child]) == 0
    assert "lineage, root first" in capsys.readouterr().out
    entry = tmp_path / "entry.json"
    entry.write_text(json.dumps(by_task[PARSER]))
    assert cli_main([*base, str(entry), "--json"]) == 0
    answer = json.loads(capsys.readouterr().out)
    assert answer["ours"] is True and answer["run"] == run_id
    lineage = Lineage.from_ledger(read_jsonl(runs / run_id / "ledger.jsonl"))
    assert [a["id"] for a in answer["ancestors"]] == [lineage.parent(child), child]
    assert cli_main([*base, IdentityIssuer(Signer.generate(), "r").issue_root().id]) == 1
    assert cli_main([*base, IdentityIssuer(signer, "r").issue_root().id]) == 2
