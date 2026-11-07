"""Threat log: agents an operator flagged as threats, and the revocation that stopped each one.

Flagging revokes the agent through the signed revocation list, which the running harness
polls, so the agent and by default its descendants stop at their next step. The flag itself
goes in `threats.jsonl` beside the run's logs, signed like a revocation, so an entry can't be
added or edited without the key. Each entry carries the revocation's signature, which ties
the flag to the `revoke` entry the harness then writes to the ledger.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path

from .identity import ID_PATTERN, Signer, verify_signature
from .revocation import OPERATOR, revoke

THREAT_FILE = "threats.jsonl"
THREAT_DOMAIN = b"traceable-threat-v1\0"
_SIGNED_FIELDS = ("run", "agent_id", "reason", "cascade", "actor", "flagged_at", "revocation_signature")


def flag(
    run_dir: Path, signer: Signer, agent_id: str, reason: str = "", cascade: bool = True, actor: str = OPERATOR
) -> dict:
    """Revoke the agent, then record it in the threat log. Returns the threat entry."""
    if not ID_PATTERN.match(agent_id):
        raise ValueError(f"invalid agent ID: {agent_id}")
    revocation = revoke(run_dir, signer, agent_id, cascade, f"flagged as a threat: {reason}" if reason else "flagged as a threat", actor)
    payload = {
        "run": run_dir.name,
        "agent_id": agent_id,
        "reason": reason,
        "cascade": cascade,
        "actor": actor,
        "flagged_at": time.time(),
        "revocation_signature": revocation["signature"],
    }
    entry = {**payload, "signature": signer.sign(THREAT_DOMAIN, payload)}
    with open(run_dir / THREAT_FILE, "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return entry


def read_threats(run_dir: Path, public_key_b64: str) -> list[dict]:
    """Every entry, each with `verified` set to whether its signature checks out for this run."""
    try:
        text = (run_dir / THREAT_FILE).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            payload = {k: entry[k] for k in _SIGNED_FIELDS}
            ok = entry["run"] == run_dir.name and verify_signature(public_key_b64, THREAT_DOMAIN, payload, entry["signature"])
        except (ValueError, KeyError, TypeError):
            entry, ok = {"raw": line}, False
        entries.append({**entry, "verified": ok})
    return entries
