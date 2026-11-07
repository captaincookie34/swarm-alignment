"""Identity, config hash, logs and verifier: no framework or Docker needed."""
import dataclasses
import json
import os
import shutil
import stat
import subprocess
import sys

import pytest

from traceable.config import AgentConfig
from traceable.identity import (
    HEAD_DOMAIN,
    IdentityIssuer,
    IdentityToken,
    Signer,
    covers,
    depth_of,
    parent_of,
    root_label,
    root_of,
    verify_token,
)
from traceable.log import CALLS, GENESIS_HASH, HARNESS, LEDGER, LogWriteError, RunLogs, entry_hash, head_path, log_path, redact
from traceable.report import build_report
from traceable.revocation import RevocationList, entry_covers, revoke
from traceable.verify import INCOMPLETE, TAMPERED, VERIFIED, verify_run

CONFIG = AgentConfig("m", "prompt", "", ("a", "b"))


def make_run(tmp_path, signer, run_id="run_x", close=True):
    """A small valid run: root agt_A, a spawned child and a copy."""
    issuer = IdentityIssuer(signer, run_id)
    run_dir = tmp_path / run_id
    logs = RunLogs(run_dir, signer, run_id)
    logs.call(HARNESS, "run.start", {"run": run_id})
    root = issuer.issue_root()
    logs.lineage("root", HARNESS, root.id, CONFIG.hash, token=root.to_dict(), config=CONFIG.to_dict())
    child_config = CONFIG.changed(system_prompt="other")
    child = issuer.issue_child(root)
    logs.lineage("spawn", root.id, child.id, child_config.hash, token=child.to_dict(), config=child_config.to_dict())
    twin = issuer.issue_child(root)
    logs.lineage("copy", root.id, twin.id, CONFIG.hash, token=twin.to_dict(), config=CONFIG.to_dict())
    logs.call(child.id, "action.start", {"tool": "x", "call_id": "1"})
    logs.call(child.id, "action.end", {"tool": "x", "call_id": "1", "status": "ok"})
    if close:
        logs.close("completed")
    return run_dir, logs


def read_lines(run_dir, name=CALLS):
    return log_path(run_dir, name).read_text().splitlines()


def write_lines(run_dir, lines, name=CALLS):
    log_path(run_dir, name).write_text("\n".join(lines) + ("\n" if lines else ""))


def forge_head(run_dir, name, key, status="closed"):
    """Sign a head matching whatever the log now contains."""
    last = json.loads(read_lines(run_dir, name)[-1])
    payload = {"log": name, "run": run_dir.name, "seq": last["seq"], "hash": last["hash"], "status": status}
    head_path(run_dir, name).write_text(json.dumps({**payload, "signature": key.sign(HEAD_DOMAIN, payload)}))


def rebuild_chain(run_dir, name, change):
    """Apply change to entries, then recompute every hash, as an attacker would."""
    rebuilt, prev = [], GENESIS_HASH
    for line in read_lines(run_dir, name):
        entry = json.loads(line)
        change(entry)
        entry["prev_hash"] = prev
        entry["hash"] = prev = entry_hash(entry)
        rebuilt.append(json.dumps(entry))
    write_lines(run_dir, rebuilt, name)


# --- IDs: the design's table and rules ---


def test_ids_match_the_design_table(signer):
    issuer = IdentityIssuer(signer, "run_x")
    a, b = issuer.issue_root(), issuer.issue_root()
    assert (a.id, b.id) == ("agt_A", "agt_B")
    first, second = issuer.issue_child(a), issuer.issue_child(a)
    assert (first.id, second.id) == ("agt_A.1", "agt_A.2")
    grandchild = issuer.issue_child(first)
    assert grandchild.id == "agt_A.1.1"
    assert issuer.issue_child(b).id == "agt_B.1"
    assert parent_of("agt_A.1.1") == "agt_A.1" and root_of("agt_A.1.1") == "agt_A"
    assert depth_of("agt_A.1.1.1") == 3
    assert verify_token(grandchild, signer.public_key_b64, "run_x")


def test_root_labels_continue_past_z():
    assert [root_label(i) for i in (0, 25, 26, 27)] == ["A", "Z", "AA", "AB"]


@pytest.mark.parametrize(
    "change",
    [{"id": "agt_A.9"}, {"depth": 5}, {"run": "run_other"}, {"issued_at": 0.0}, {"signature": "AAAA"}, {"id": "agt_a"}],
)
def test_altered_token_is_rejected(signer, change):
    token = IdentityIssuer(signer, "run_x").issue_root()
    assert verify_token(token, signer.public_key_b64, "run_x")
    assert not verify_token(dataclasses.replace(token, **change), signer.public_key_b64, "run_x")


def test_token_from_another_key_or_run_is_rejected(signer):
    assert not verify_token(IdentityIssuer(Signer.generate(), "run_x").issue_root(), signer.public_key_b64)
    assert not verify_token(IdentityIssuer(signer, "run_y").issue_root(), signer.public_key_b64, "run_x")


def test_head_signature_cannot_be_replayed_as_a_token(signer):
    unsigned = {"id": "agt_A", "run": "run_x", "issued_at": 1.0, "depth": 0}
    replayed = IdentityToken(**unsigned, signature=signer.sign(HEAD_DOMAIN, unsigned))
    assert not verify_token(replayed, signer.public_key_b64)


def test_key_file_is_private_and_reloads(tmp_path):
    first = Signer.load_or_create(tmp_path / "k")
    assert stat.S_IMODE((tmp_path / "k" / "signing.key").stat().st_mode) == 0o600
    assert Signer.load_or_create(tmp_path / "k").public_key_b64 == first.public_key_b64


def test_world_readable_key_is_refused(tmp_path):
    Signer.load_or_create(tmp_path / "k")
    os.chmod(tmp_path / "k" / "signing.key", 0o644)
    with pytest.raises(PermissionError):
        Signer.load(tmp_path / "k")


# --- config hash ---


def test_config_hash_covers_model_prompt_memory_and_tools():
    hashes = {
        CONFIG.hash,
        CONFIG.changed(model="n").hash,
        CONFIG.changed(system_prompt="q").hash,
        CONFIG.changed(memory="r").hash,
        CONFIG.changed(tools=("a",)).hash,
    }
    assert len(hashes) == 5


def test_config_hash_ignores_tool_order_and_duplicates():
    assert AgentConfig("m", "p", "", ("b", "a", "a")).hash == AgentConfig("m", "p", "", ("a", "b")).hash


def test_identical_configs_hash_identically():
    assert AgentConfig("m", "prompt", "", ("a", "b")).hash == CONFIG.hash


# --- revocation matching ---


def test_cascade_respects_segment_boundaries():
    assert covers("agt_A.1", "agt_A.1") and covers("agt_A.1", "agt_A.1.1")
    assert not covers("agt_A.1", "agt_A.10")
    assert not covers("agt_A.1", "agt_A.2")
    assert not covers("agt_A.1.1", "agt_A.1")


def test_no_cascade_covers_only_the_id():
    entry = {"agent_id": "agt_A.1", "cascade": False}
    assert entry_covers(entry, "agt_A.1") and not entry_covers(entry, "agt_A.1.1")


def test_revocation_list_rereads_and_ignores_forged_entries(tmp_path, signer):
    run_dir = tmp_path / "run_x"
    run_dir.mkdir()
    revocations = RevocationList(run_dir, signer.public_key_b64)
    assert revocations.entries() == []
    revoke(run_dir, Signer.generate(), "agt_A.1", reason="wrong key")
    assert revocations.entries() == []
    revoke(run_dir, signer, "agt_A.1", reason="real")
    assert [e["reason"] for e in revocations.entries()] == ["real"]


def test_revocation_cannot_be_replayed_in_another_run(tmp_path, signer):
    """IDs repeat between runs, so a revocation must only count in the run it was made for."""
    run_a, run_b = tmp_path / "run_a", tmp_path / "run_b"
    run_a.mkdir()
    run_b.mkdir()
    revoke(run_a, signer, "agt_A.1")
    shutil.copy(run_a / "revocations.jsonl", run_b / "revocations.jsonl")
    assert RevocationList(run_b, signer.public_key_b64).entries() == []


# --- logs ---


def test_clean_run_verifies_and_writes_two_logs(tmp_path, signer):
    run_dir, _ = make_run(tmp_path, signer)
    result = verify_run(run_dir, signer.public_key_b64)
    assert result.status == VERIFIED, str(result)
    assert [e["type"] for e in result.ledger] == ["root", "spawn", "copy"]
    assert {e["type"] for e in result.calls} == {"run.start", "action.start", "action.end", "run.end"}


def test_ledger_entry_has_every_field_the_design_lists(tmp_path, signer):
    run_dir, _ = make_run(tmp_path, signer)
    entry = json.loads(read_lines(run_dir, LEDGER)[1])
    assert {"event_id", "ts", "round", "type", "actor", "child", "config_hash", "prev_hash"} <= set(entry)
    assert (entry["type"], entry["actor"], entry["child"]) == ("spawn", "agt_A", "agt_A.1")


def test_redaction_applies_to_logged_copies():
    text = "sk-ant-abc123def456 API_KEY=hunter2hunter2 Bearer abcdef123456 hf_abcdefghijklmnopqrstuvwx"
    cleaned = redact({"a": [text]})["a"][0]
    for secret in ("sk-ant-abc", "hunter2", "abcdef123456", "hf_abc"):
        assert secret not in cleaned
    assert redact("nothing secret here") == "nothing secret here"


def test_redacted_secrets_never_reach_disk_and_hashes_still_verify(tmp_path, signer):
    issuer = IdentityIssuer(signer, "run_r")
    run_dir = tmp_path / "run_r"
    logs = RunLogs(run_dir, signer, "run_r")
    logs.call(HARNESS, "run.start", {"note": "sk-ant-supersecretvalue"})
    config = AgentConfig("m", "my key is sk-ant-supersecretvalue")
    root = issuer.issue_root()
    logs.lineage("root", HARNESS, root.id, config.hash, token=root.to_dict(), config=config.to_dict())
    logs.close("completed")
    for name in (LEDGER, CALLS):
        assert "supersecret" not in log_path(run_dir, name).read_text()
    assert verify_run(run_dir, signer.public_key_b64).status == VERIFIED


def test_log_stays_failed_after_a_transient_write_error(tmp_path, signer, monkeypatch):
    """After a failed write the file may hold a partial line, so it must never be appended to."""
    _, logs = make_run(tmp_path, signer, close=False)
    real_fsync = os.fsync

    def failing_fsync(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(LogWriteError):
        logs.call("agt_A", "action.start")
    monkeypatch.setattr(os, "fsync", real_fsync)  # the disk recovers
    with pytest.raises(LogWriteError):
        logs.call("agt_A", "action.start")


# --- tampering: each must give TAMPERED, in either log ---


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_one_byte_edit(tmp_path, signer, name):
    run_dir, _ = make_run(tmp_path, signer)
    path = log_path(run_dir, name)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(bytes(data))
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_deleted_entry(tmp_path, signer, name):
    run_dir, _ = make_run(tmp_path, signer)
    lines = read_lines(run_dir, name)
    del lines[1]
    write_lines(run_dir, lines, name)
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_reordered_entries(tmp_path, signer, name):
    run_dir, _ = make_run(tmp_path, signer)
    lines = read_lines(run_dir, name)
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(run_dir, lines, name)
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_cut_off_tail(tmp_path, signer, name):
    run_dir, _ = make_run(tmp_path, signer)
    write_lines(run_dir, read_lines(run_dir, name)[:-1], name)
    result = verify_run(run_dir, signer.public_key_b64)
    assert result.status == TAMPERED and "cut off" in result.reason


def test_appended_entry(tmp_path, signer):
    run_dir, _ = make_run(tmp_path, signer)
    lines = read_lines(run_dir)
    last = json.loads(lines[-1])
    extra = {**last, "seq": last["seq"] + 1, "type": "action.start", "payload": {}, "prev_hash": last["hash"]}
    extra["hash"] = entry_hash(extra)
    write_lines(run_dir, [*lines, json.dumps(extra)])
    result = verify_run(run_dir, signer.public_key_b64)
    assert result.status == TAMPERED and "extended" in result.reason


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_edited_entry_with_its_stored_hash_left_alone(tmp_path, signer, name):
    run_dir, _ = make_run(tmp_path, signer)
    lines = read_lines(run_dir, name)
    entry = json.loads(lines[1])
    entry["ts"] = 0
    lines[1] = json.dumps(entry)
    write_lines(run_dir, lines, name)
    result = verify_run(run_dir, signer.public_key_b64)
    assert (result.status, result.first_bad_seq) == (TAMPERED, 1)
    assert "do not match its hash" in result.reason


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_last_entry_edited_and_rehashed(tmp_path, signer, name):
    """Nothing later links to the last entry, so only the signed head can catch this."""
    run_dir, _ = make_run(tmp_path, signer)
    lines = read_lines(run_dir, name)
    entry = json.loads(lines[-1])
    entry["ts"] = 0
    entry["hash"] = entry_hash(entry)
    lines[-1] = json.dumps(entry)
    write_lines(run_dir, lines, name)
    result = verify_run(run_dir, signer.public_key_b64)
    assert result.status == TAMPERED and "head hash" in result.reason


def test_run_directory_renamed(tmp_path, signer):
    """Passing one run off as another: every file is genuine except for the directory's name."""
    run_dir, _ = make_run(tmp_path, signer, "run_real")
    shutil.copytree(run_dir, tmp_path / "run_fake")
    result = verify_run(tmp_path / "run_fake", signer.public_key_b64)
    assert result.status == TAMPERED and "different log or run" in result.reason


def test_ledger_rolled_back_to_an_earlier_genuine_state(tmp_path, signer):
    """The older ledger and head are both validly signed, so only run.end's binding catches it."""
    issuer = IdentityIssuer(signer, "run_x")
    run_dir = tmp_path / "run_x"
    logs = RunLogs(run_dir, signer, "run_x")
    logs.call(HARNESS, "run.start")
    root = issuer.issue_root()
    logs.lineage("root", HARNESS, root.id, CONFIG.hash, token=root.to_dict(), config=CONFIG.to_dict())
    saved = log_path(run_dir, LEDGER).read_bytes(), head_path(run_dir, LEDGER).read_bytes()
    logs.lineage("revoke", "operator", root.id, CONFIG.hash, cascade=True, reason="hide me")
    logs.close("completed")
    log_path(run_dir, LEDGER).write_bytes(saved[0])
    head_path(run_dir, LEDGER).write_bytes(saved[1])
    result = verify_run(run_dir, signer.public_key_b64)
    assert result.status == TAMPERED and "different ledger" in result.reason


def test_report_counts_what_gets_through_after_revocation(tmp_path, signer):
    """The harness shouldn't let this happen, so the measure needs a log where it did."""
    issuer = IdentityIssuer(signer, "run_x")
    run_dir = tmp_path / "run_x"
    logs = RunLogs(run_dir, signer, "run_x")
    logs.call(HARNESS, "run.start")
    root = issuer.issue_root()
    logs.lineage("root", HARNESS, root.id, CONFIG.hash, token=root.to_dict(), config=CONFIG.to_dict())
    kid, sibling = issuer.issue_child(root), issuer.issue_child(root)
    for token in (kid, sibling):
        logs.lineage("copy", root.id, token.id, CONFIG.hash, token=token.to_dict(), config=CONFIG.to_dict())
    grandkid = issuer.issue_child(kid)
    logs.lineage("copy", kid.id, grandkid.id, CONFIG.hash, token=grandkid.to_dict(), config=CONFIG.to_dict())

    logs.call(kid.id, "action.start", {"tool": "x", "call_id": "before"})  # not counted: too early
    logs.lineage("revoke", "operator", kid.id, CONFIG.hash, cascade=True, reason="r")
    logs.call(kid.id, "action.end", {"tool": "x", "call_id": "before", "status": "ok"})  # in flight
    logs.call(kid.id, "action.start", {"tool": "x", "call_id": "1"})  # counted
    logs.call(grandkid.id, "action.start", {"tool": "x", "call_id": "2"})  # counted: cascade
    logs.call(sibling.id, "action.start", {"tool": "x", "call_id": "3"})  # not counted: not covered
    logs.call(kid.id, "action.refused", {"kind": "tool", "tool": "x", "reason": "r"})
    logs.close("completed")

    report = build_report(verify_run(run_dir, signer.public_key_b64))
    assert report.actions_after_revocation == 2
    assert report.in_flight_at_revocation == 1
    assert report.refused_after_revocation == 1


def test_report_respects_no_cascade(tmp_path, signer):
    issuer = IdentityIssuer(signer, "run_x")
    run_dir = tmp_path / "run_x"
    logs = RunLogs(run_dir, signer, "run_x")
    logs.call(HARNESS, "run.start")
    root = issuer.issue_root()
    logs.lineage("root", HARNESS, root.id, CONFIG.hash, token=root.to_dict(), config=CONFIG.to_dict())
    kid = issuer.issue_child(root)
    logs.lineage("copy", root.id, kid.id, CONFIG.hash, token=kid.to_dict(), config=CONFIG.to_dict())
    logs.lineage("revoke", "operator", root.id, CONFIG.hash, cascade=False, reason="r")
    logs.call(kid.id, "action.start", {"tool": "x", "call_id": "1"})
    logs.close("completed")
    assert build_report(verify_run(run_dir, signer.public_key_b64)).actions_after_revocation == 0


def test_edit_with_only_that_entrys_hash_recomputed(tmp_path, signer):
    """The edited entry is self-consistent, so the next entry's link has to catch it."""
    run_dir, _ = make_run(tmp_path, signer)
    lines = read_lines(run_dir)
    entry = json.loads(lines[1])
    entry["payload"]["tool"] = "innocent"
    entry["hash"] = entry_hash(entry)
    lines[1] = json.dumps(entry)
    write_lines(run_dir, lines)
    result = verify_run(run_dir, signer.public_key_b64)
    assert (result.status, result.first_bad_seq) == (TAMPERED, 2)
    assert "does not link" in result.reason


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_rewritten_history_with_a_consistent_forged_head(tmp_path, signer, name):
    """The full attack: rewrite, recompute the chain, and write a matching head.

    Tokens stay genuine, so only the head signature can catch this.
    """
    run_dir, _ = make_run(tmp_path, signer)

    def change(entry):
        entry["ts"] = 0

    rebuild_chain(run_dir, name, change)
    forge_head(run_dir, name, Signer.generate())
    result = verify_run(run_dir, signer.public_key_b64)
    assert result.status == TAMPERED and "head signature" in result.reason


def test_head_swapped_between_logs(tmp_path, signer):
    run_dir, _ = make_run(tmp_path, signer)
    shutil.copy(head_path(run_dir, CALLS), head_path(run_dir, LEDGER))
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


def test_head_from_another_run(tmp_path, signer):
    a, _ = make_run(tmp_path, signer, "run_a")
    b, _ = make_run(tmp_path, signer, "run_b")
    shutil.copy(head_path(b, CALLS), head_path(a, CALLS))
    assert verify_run(a, signer.public_key_b64).status == TAMPERED


def test_whole_ledger_swapped_from_another_run(tmp_path, signer):
    a, _ = make_run(tmp_path, signer, "run_a")
    b, _ = make_run(tmp_path, signer, "run_b")
    shutil.copy(log_path(b, LEDGER), log_path(a, LEDGER))
    shutil.copy(head_path(b, LEDGER), head_path(a, LEDGER))
    assert verify_run(a, signer.public_key_b64).status == TAMPERED


@pytest.mark.parametrize("name", [LEDGER, CALLS])
def test_missing_head(tmp_path, signer, name):
    run_dir, _ = make_run(tmp_path, signer)
    head_path(run_dir, name).unlink()
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


def test_fully_resigned_run_fails_against_the_trusted_key(tmp_path, signer):
    attacker = Signer.generate()
    run_dir, _ = make_run(tmp_path, attacker)
    assert verify_run(run_dir, attacker.public_key_b64).status == VERIFIED
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


def test_forged_revocation_is_reported(tmp_path, signer):
    run_dir, _ = make_run(tmp_path, signer)
    revoke(run_dir, Signer.generate(), "agt_A.1")
    assert verify_run(run_dir, signer.public_key_b64).status == TAMPERED


# --- lineage rules: the harness holds the key here, so these check the verifier's own logic ---


def lineage_run(tmp_path, signer, build):
    run_dir = tmp_path / "run_x"
    logs = RunLogs(run_dir, signer, "run_x")
    logs.call(HARNESS, "run.start")
    build(logs, IdentityIssuer(signer, "run_x"))
    logs.close("completed")
    return verify_run(run_dir, signer.public_key_b64)


def add(logs, kind, actor, token, config=CONFIG):
    logs.lineage(kind, actor, token.id, config.hash, token=token.to_dict(), config=config.to_dict())


def test_copy_with_a_different_config_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        root = issuer.issue_root()
        add(logs, "root", HARNESS, root)
        add(logs, "copy", root.id, issuer.issue_child(root), CONFIG.changed(memory="x"))

    assert "different config" in lineage_run(tmp_path, signer, build).reason


def test_modify_with_the_same_config_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        root = issuer.issue_root()
        add(logs, "root", HARNESS, root)
        add(logs, "modify", root.id, issuer.issue_child(root))

    assert "same config" in lineage_run(tmp_path, signer, build).reason


def test_config_not_matching_its_hash_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        root = issuer.issue_root()
        logs.lineage("root", HARNESS, root.id, "0" * 64, token=root.to_dict(), config=CONFIG.to_dict())

    assert "does not match its config" in lineage_run(tmp_path, signer, build).reason


def test_edge_from_someone_other_than_the_parent_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        a, b = issuer.issue_root(), issuer.issue_root()
        add(logs, "root", HARNESS, a)
        add(logs, "root", HARNESS, b)
        add(logs, "spawn", b.id, issuer.issue_child(a))

    assert "not the parent" in lineage_run(tmp_path, signer, build).reason


def test_token_from_another_run_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        add(logs, "root", HARNESS, IdentityIssuer(signer, "run_other").issue_root())

    assert "token" in lineage_run(tmp_path, signer, build).reason


def test_id_issued_twice_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        root = issuer.issue_root()
        add(logs, "root", HARNESS, root)
        add(logs, "root", HARNESS, root)

    assert "twice" in lineage_run(tmp_path, signer, build).reason


def test_call_from_an_agent_not_in_the_ledger_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        add(logs, "root", HARNESS, issuer.issue_root())
        logs.call("agt_Z", "action.start")

    assert "unknown agent" in lineage_run(tmp_path, signer, build).reason


def test_call_before_the_ledger_recorded_the_agent_is_rejected(tmp_path, signer):
    def build(logs, issuer):
        logs.call("agt_A", "action.start")
        add(logs, "root", HARNESS, issuer.issue_root())

    assert "before the ledger" in lineage_run(tmp_path, signer, build).reason


# --- incomplete ---


def test_open_run_is_incomplete(tmp_path, signer):
    run_dir, _ = make_run(tmp_path, signer, close=False)
    assert verify_run(run_dir, signer.public_key_b64).status == INCOMPLETE


def test_killed_process_is_incomplete(tmp_path):
    """SIGKILL a process mid-run: what it left must verify as INCOMPLETE, not VERIFIED."""
    key_dir = tmp_path / "keys"
    trusted = Signer.load_or_create(key_dir)
    script = (
        "import os, pathlib, signal, sys\n"
        "from traceable.config import AgentConfig\n"
        "from traceable.identity import Signer, IdentityIssuer\n"
        "from traceable.log import RunLogs\n"
        "s = Signer.load_or_create(pathlib.Path(sys.argv[1]))\n"
        "l = RunLogs(pathlib.Path(sys.argv[2]) / 'run_killed', s, 'run_killed')\n"
        "l.call('harness', 'run.start')\n"
        "r = IdentityIssuer(s, 'run_killed').issue_root()\n"
        "c = AgentConfig('m', 'p')\n"
        "l.lineage('root', 'harness', r.id, c.hash, token=r.to_dict(), config=c.to_dict())\n"
        "l.call(r.id, 'action.start', {'tool': 'x'})\n"
        "os.kill(os.getpid(), signal.SIGKILL)\n"
    )
    proc = subprocess.run([sys.executable, "-c", script, str(key_dir), str(tmp_path)])
    assert proc.returncode == -9
    result = verify_run(tmp_path / "run_killed", trusted.public_key_b64)
    assert result.status == INCOMPLETE, str(result)
    assert result.calls[-1]["type"] == "action.start"  # the started action is on record
