"""Signed revocation list. By default, revoking an ID also covers all its descendants.

The list is a file so a separate process (`harness revoke`) can revoke during a run.
Entries with bad signatures are ignored at runtime, so writing to the file without the
key can't stop an agent. The verifier reports them as tampering.

The run ID is part of what's signed. IDs repeat between runs, so without it a revocation
of agt_A.1 in one run could be replayed against agt_A.1 in another.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path

from .identity import ID_PATTERN, REVOCATION_DOMAIN, Signer, covers, verify_signature

REVOCATION_FILE = "revocations.jsonl"
_SIGNED_FIELDS = ("run", "agent_id", "cascade", "actor", "reason", "revoked_at")
OPERATOR = "operator"


def revoke(
    run_dir: Path, signer: Signer, agent_id: str, cascade: bool = True, reason: str = "", actor: str = OPERATOR
) -> dict:
    if not ID_PATTERN.match(agent_id):
        raise ValueError(f"invalid agent ID: {agent_id}")
    payload = {
        "run": run_dir.name,
        "agent_id": agent_id,
        "cascade": cascade,
        "actor": actor,
        "reason": reason,
        "revoked_at": time.time(),
    }
    entry = {**payload, "signature": signer.sign(REVOCATION_DOMAIN, payload)}
    with open(run_dir / REVOCATION_FILE, "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return entry


def read_entries(run_dir: Path, public_key_b64: str) -> tuple[list[dict], int]:
    """Return (valid entries for this run, count of invalid lines)."""
    try:
        text = (run_dir / REVOCATION_FILE).read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], 0
    valid, invalid = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            payload = {k: entry[k] for k in _SIGNED_FIELDS}
            ok = entry["run"] == run_dir.name and verify_signature(
                public_key_b64, REVOCATION_DOMAIN, payload, entry["signature"]
            )
        except (ValueError, KeyError, TypeError):
            ok = False
        if ok:
            valid.append(entry)
        else:
            invalid += 1
    return valid, invalid


def entry_covers(entry: dict, agent_id: str) -> bool:
    return covers(entry["agent_id"], agent_id) if entry["cascade"] else entry["agent_id"] == agent_id


class RevocationList:
    """Runtime view of the file, re-read at every step. Unchanged files aren't re-verified."""

    def __init__(self, run_dir: Path, public_key_b64: str):
        self._run_dir = run_dir
        self._public_key = public_key_b64
        self._stamp: tuple[int, int] | None = None
        self._entries: list[dict] = []

    def entries(self) -> list[dict]:
        try:
            stat = (self._run_dir / REVOCATION_FILE).stat()
        except FileNotFoundError:
            return self._entries
        stamp = (stat.st_size, stat.st_mtime_ns)
        if stamp != self._stamp:
            self._entries, _ = read_entries(self._run_dir, self._public_key)
            self._stamp = stamp
        return self._entries
