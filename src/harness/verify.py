"""Offline verification of a run directory.

Pass a public key obtained outside the run directory. A key read from the directory
being checked proves nothing: an attacker could replace the key, re-sign and pass.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .config import config_hash
from .identity import HEAD_DOMAIN, IdentityToken, parent_of, verify_signature, verify_token
from .log import CALLS, GENESIS_HASH, HARNESS, LEDGER, entry_hash, head_path, head_payload, log_path
from .revocation import read_entries

VERIFIED = "VERIFIED"
INCOMPLETE = "INCOMPLETE"
TAMPERED = "TAMPERED"
CHILD_EDGES = ("spawn", "copy", "modify")
_REQUIRED = {
    LEDGER: {"seq", "ts", "event_id", "round", "type", "actor", "child", "config_hash", "prev_hash", "hash"},
    CALLS: {"seq", "ts", "round", "ledger_seq", "agent_id", "type", "payload", "prev_hash", "hash"},
}


@dataclass
class VerifyResult:
    status: str
    reason: str = ""
    log: str | None = None
    first_bad_seq: int | None = None
    ledger: list[dict] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)

    def __str__(self) -> str:
        where = f" ({self.log} log, first bad seq: {self.first_bad_seq})" if self.first_bad_seq is not None else ""
        reason = f": {self.reason}" if self.reason else ""
        return f"{self.status}{where}{reason}"


class _Tampered(Exception):
    def __init__(self, reason: str, log: str | None = None, seq: int | None = None):
        self.reason, self.log, self.seq = reason, log, seq


def _read_chain(run_dir: Path, name: str, public_key: str) -> tuple[list[dict], dict]:
    """Check one log against its signed head. Returns (entries, head)."""
    try:
        head = json.loads(head_path(run_dir, name).read_text(encoding="utf-8"))
        signed = verify_signature(public_key, HEAD_DOMAIN, head_payload(head), head["signature"])
    except FileNotFoundError:
        raise _Tampered(f"{name} head is missing", name) from None
    except (ValueError, KeyError, TypeError):
        raise _Tampered(f"{name} head is malformed", name) from None
    if not signed:
        raise _Tampered(f"{name} head signature is invalid for the trusted key", name)
    if head["run"] != run_dir.name or head["log"] != name:
        raise _Tampered(f"{name} head belongs to a different log or run", name)

    try:
        lines = log_path(run_dir, name).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise _Tampered(f"{name} log is missing", name) from None
    entries, prev_hash = [], GENESIS_HASH
    for index, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            raise _Tampered("entry is not valid JSON", name, index) from None
        if not isinstance(entry, dict) or not _REQUIRED[name] <= set(entry):
            raise _Tampered("entry is missing fields", name, index)
        if entry["seq"] != index:
            raise _Tampered(f"expected seq {index}, found {entry['seq']}", name, index)
        if entry["prev_hash"] != prev_hash:
            raise _Tampered("entry does not link to the previous entry", name, index)
        if entry_hash(entry) != entry["hash"]:
            raise _Tampered("entry contents do not match its hash", name, index)
        prev_hash = entry["hash"]
        entries.append(entry)

    # Head vs chain: catches a cut-off tail, appended entries and a swapped head.
    last_seq = len(entries) - 1
    if head["seq"] != last_seq:
        kind = "cut off" if last_seq < head["seq"] else "extended"
        raise _Tampered(f"log was {kind}: head says seq {head['seq']}, log ends at {last_seq}", name, max(last_seq, 0))
    if head["hash"] != prev_hash:
        raise _Tampered("head hash does not match the end of the chain", name, last_seq)
    return entries, head


def _load_token(data: object, public_key: str, run: str) -> IdentityToken | None:
    try:
        token = IdentityToken.from_dict(data)  # type: ignore[arg-type]
    except (TypeError, KeyError, AttributeError):
        return None
    return token if verify_token(token, public_key, run) else None


def _check_ledger(ledger: list[dict], public_key: str, run: str) -> dict[str, int]:
    """Check lineage rules. Returns each agent's creation event seq."""
    created: dict[str, int] = {}
    hashes: dict[str, str] = {}
    roots: dict[str, str] = {}
    depths: dict[str, int] = {}
    if not ledger:
        raise _Tampered("ledger is empty", LEDGER)

    def fail(reason: str, seq: int):
        raise _Tampered(reason, LEDGER, seq)

    for entry in ledger:
        seq, kind, actor, child = entry["seq"], entry["type"], entry["actor"], entry["child"]
        if kind == "revoke":
            if child not in created:
                fail(f"revoke of unknown agent {child}", seq)
            continue
        if kind != "root" and kind not in CHILD_EDGES:
            fail(f"unknown ledger event type {kind!r}", seq)
        token = _load_token(entry.get("token"), public_key, run)
        if token is None or token.id != child:
            fail(f"token for {child} is invalid", seq)
        if child in created:
            fail(f"ID {child} was issued twice", seq)
        config = entry.get("config")
        if not isinstance(config, dict) or config_hash(config) != entry["config_hash"]:
            fail(f"config hash for {child} does not match its config", seq)
        if kind == "root":
            if actor != HARNESS or token.depth != 0:
                fail(f"invalid root {child}", seq)
            if token.opaque and (token.parent is not None or token.root != child):
                fail(f"invalid root {child}", seq)
            roots[child] = child
        else:
            if actor not in created:
                fail(f"lineage event from unknown agent {actor}", seq)
            if token.opaque:
                # The ID carries no lineage; the token signs its parent, root and depth, and
                # they must match the agent the ledger says created it.
                if token.parent != actor:
                    fail(f"{actor} is not the parent of {child}", seq)
                if token.root != roots[actor] or token.depth != depths[actor] + 1:
                    fail(f"token for {child} has the wrong root or depth for its parent {actor}", seq)
            elif parent_of(child) != actor:  # an older path ID names its parent
                fail(f"{actor} is not the parent of {child}", seq)
            roots[child] = roots[actor]
            if kind == "copy" and entry["config_hash"] != hashes[actor]:
                fail(f"copy {child} has a different config from its parent", seq)
            if kind == "modify" and entry["config_hash"] == hashes[actor]:
                fail(f"modify {child} has the same config as its parent", seq)
        created[child] = seq
        hashes[child] = entry["config_hash"]
        depths[child] = token.depth
    return created


def _check_calls(calls: list[dict], created: dict[str, int]) -> None:
    if not calls or calls[0]["type"] != "run.start":
        raise _Tampered("call log does not begin with run.start", CALLS, 0)
    for entry in calls:
        agent = entry["agent_id"]
        if agent == HARNESS:
            continue
        if agent not in created:
            raise _Tampered(f"entry from unknown agent {agent}", CALLS, entry["seq"])
        if entry["ledger_seq"] < created[agent]:
            raise _Tampered(f"{agent} acted before the ledger recorded it", CALLS, entry["seq"])


def verify_run(run_dir: Path, public_key_b64: str) -> VerifyResult:
    ledger: list[dict] = []
    calls: list[dict] = []
    try:
        ledger, ledger_head = _read_chain(run_dir, LEDGER, public_key_b64)
        calls, calls_head = _read_chain(run_dir, CALLS, public_key_b64)
        created = _check_ledger(ledger, public_key_b64, run_dir.name)
        _check_calls(calls, created)
        _, invalid = read_entries(run_dir, public_key_b64)
        if invalid:
            raise _Tampered(f"{invalid} revocation entries have invalid signatures")

        statuses = {ledger_head["status"], calls_head["status"]}
        if not statuses <= {"open", "closed"}:
            raise _Tampered(f"unknown head status in {statuses}")
        if calls_head["status"] == "closed":
            last = calls[-1]
            if last["type"] != "run.end":
                raise _Tampered("closed run does not end with run.end", CALLS, last["seq"])
            if last["payload"].get("ledger_head") != ledger[-1]["hash"]:
                raise _Tampered("run.end names a different ledger", CALLS, last["seq"])
            if ledger_head["status"] != "closed":
                raise _Tampered("call log is closed but the ledger is open", LEDGER)
            return VerifyResult(VERIFIED, ledger=ledger, calls=calls)
        return VerifyResult(INCOMPLETE, "run never closed (still running or crashed)", ledger=ledger, calls=calls)
    except _Tampered as exc:
        return VerifyResult(TAMPERED, exc.reason, exc.log, exc.seq, ledger, calls)
