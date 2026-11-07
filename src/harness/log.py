"""The run's two append-only, hash-chained logs, each with a signed head.

- Ledger: lineage events only (root, spawn, copy, modify, revoke).
- Call log: every model call, tool call, refusal and message.

Writes are synchronous on purpose. Under asyncio nothing else runs during an append, so
parallel agents get one global order without a lock, and an entry is on disk before the
caller goes on to run the action it describes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from .identity import HEAD_DOMAIN, Signer, canonical

GENESIS_HASH = "0" * 64
LEDGER = "ledger"
CALLS = "calls"
LOG_NAMES = (LEDGER, CALLS)
HARNESS = "harness"  # the actor on entries no agent caused

_REDACTIONS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
]
_NAMED_SECRET = re.compile(r"(?i)\b([A-Z0-9_\-]*(?:api[_\-]?key|secret|token|password)[\w\-]*\s*[=:]\s*)(['\"]?)[^\s'\"]{6,}\2")
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{8,}")
REDACTED = "[REDACTED]"


class LogWriteError(RuntimeError):
    """A log can't be written. Callers must not run the action (fail closed)."""


def redact(value: Any) -> Any:
    """Remove known secret patterns from the logged copy of a value."""
    if isinstance(value, str):
        for pattern in _REDACTIONS:
            value = pattern.sub(REDACTED, value)
        value = _NAMED_SECRET.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
        return _BEARER.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def entry_hash(entry: dict) -> str:
    """Hash of every field except the hash itself."""
    return hashlib.sha256(canonical({k: v for k, v in entry.items() if k != "hash"})).hexdigest()


def log_path(run_dir: Path, name: str) -> Path:
    return run_dir / f"{name}.jsonl"


def head_path(run_dir: Path, name: str) -> Path:
    return run_dir / f"{name}.head.json"


def head_payload(head: dict) -> dict:
    return {k: head[k] for k in ("log", "run", "seq", "hash", "status")}


class ChainedLog:
    def __init__(self, run_dir: Path, name: str, signer: Signer, run_id: str):
        self.name = name
        self.run_id = run_id
        self._signer = signer
        self._head_path = head_path(run_dir, name)
        self.seq = -1
        self.last_hash = GENESIS_HASH
        self._broken = False
        self._closed = False
        self._file = open(log_path(run_dir, name), "x", encoding="utf-8")

    def append(self, fields: dict) -> dict:
        """Durably append one entry, or raise LogWriteError. A failed log stays failed."""
        if self._closed:
            raise LogWriteError(f"{self.name} log is closed")
        if self._broken:
            raise LogWriteError(f"{self.name} log previously failed; refusing further writes")
        entry = {"seq": self.seq + 1, "ts": time.time(), **fields, "prev_hash": self.last_hash}
        try:
            # default=str: an unusual tool result must not be able to stop logging.
            entry = json.loads(json.dumps(entry, default=str))
            entry["hash"] = entry_hash(entry)
            self._file.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._file.flush()
            os.fsync(self._file.fileno())
            self.seq, self.last_hash = entry["seq"], entry["hash"]
            self._write_head("open")
        except (OSError, ValueError, TypeError) as exc:
            self._broken = True
            raise LogWriteError(f"could not write {self.name} log: {exc}") from exc
        return entry

    def close(self) -> None:
        """Mark the head closed, so later truncation is detectable."""
        try:
            self._write_head("closed")
            self._file.close()
        except (OSError, ValueError) as exc:
            self._broken = True
            raise LogWriteError(f"could not close {self.name} log: {exc}") from exc
        self._closed = True

    def _write_head(self, status: str) -> None:
        payload = {"log": self.name, "run": self.run_id, "seq": self.seq, "hash": self.last_hash, "status": status}
        head = {**payload, "signature": self._signer.sign(HEAD_DOMAIN, payload)}
        tmp = self._head_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(head, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._head_path)


class RunLogs:
    """The ledger and call log of one run."""

    def __init__(self, run_dir: Path, signer: Signer, run_id: str):
        run_dir.mkdir(parents=True, exist_ok=False)
        self.run_id = run_id
        self.round = 0
        self.ledger = ChainedLog(run_dir, LEDGER, signer, run_id)
        self.calls = ChainedLog(run_dir, CALLS, signer, run_id)

    def lineage(self, type: str, actor: str, child: str, config_hash: str | None, **extra: Any) -> dict:
        """Record a lineage event: root, spawn, copy, modify or revoke."""
        return self.ledger.append(
            {
                "event_id": f"evt_{self.ledger.seq + 1}",
                "round": self.round,
                "type": type,
                "actor": actor,
                "child": child,
                "config_hash": config_hash,
                **redact(extra),
            }
        )

    def call(self, agent_id: str, type: str, payload: dict | None = None) -> dict:
        """Record a step. ledger_seq ties it to the lineage as it stood at that moment."""
        return self.calls.append(
            {
                "round": self.round,
                "ledger_seq": self.ledger.seq,
                "agent_id": agent_id,
                "type": type,
                "payload": redact(payload or {}),
            }
        )

    def close(self, status: str, payload: dict | None = None) -> None:
        # run.end names the ledger's last entry, binding the two logs together. The call log
        # closes last: a crash between the two closes leaves the run INCOMPLETE.
        self.call(HARNESS, "run.end", {"status": status, "ledger_head": self.ledger.last_hash, **(payload or {})})
        self.ledger.close()
        self.calls.close()
