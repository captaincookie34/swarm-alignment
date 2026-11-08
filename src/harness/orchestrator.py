"""Orchestrator: freeze a chain of agents instead of killing it, judge each one, then salvage
the cleared agents' work.

    freeze   the operator freezes an agent. It and everything below it, including children it
             creates later, stop taking turns but keep their history.
    verdict  the operator marks each frozen agent cleared or a threat.
    resolve  once every frozen agent has a verdict:
             - threats are revoked (no cascade) and recorded in the threat log, as a flag would;
             - cleared agents whose ancestors in the chain are all cleared resume where they left off;
             - cleared agents below a threat are cut off from whoever asked for their work, so
               they're retired, and everything they'd done (tool calls, replies, messages) is saved;
             - for each removed branch, a replacement is spawned under the nearest living ancestor,
               usually the agent that spun it off, on the removed agent's task and config, with the
               saved work. It gets only what's still missing and reports back to that parent, who is
               told to wait for it. With no room for another agent, the parent gets the saved work.

Like revocations, these are signed entries in a file beside the run's logs, so `harness monitor`
in another process can steer a run, and writing to the file without the key does nothing. The
harness polls it and records what it applied in the call log.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path

from .identity import ID_PATTERN, Lineage, Signer, verify_signature

CONTROL_FILE = "orchestration.jsonl"
CONTROL_DOMAIN = b"traceable-orchestration-v1\0"
_SIGNED_FIELDS = ("run", "action", "agent_id", "verdict", "reason", "actor", "at")
FREEZE, VERDICT, RESOLVE = "freeze", "verdict", "resolve"
CLEARED, THREAT = "cleared", "threat"
ACTIONS = (FREEZE, VERDICT, RESOLVE)
VERDICTS = (CLEARED, THREAT)


def write(run_dir: Path, signer: Signer, action: str, agent_id: str, verdict: str = "", reason: str = "", actor: str = "operator") -> dict:
    if action not in ACTIONS:
        raise ValueError(f"unknown orchestration action {action!r}")
    if not ID_PATTERN.match(agent_id):
        raise ValueError(f"invalid agent ID: {agent_id}")
    if action == VERDICT and verdict not in VERDICTS:
        raise ValueError(f"a verdict is {' or '.join(VERDICTS)}, not {verdict!r}")
    payload = {"run": run_dir.name, "action": action, "agent_id": agent_id, "verdict": verdict, "reason": reason[:500], "actor": actor, "at": time.time()}
    entry = {**payload, "signature": signer.sign(CONTROL_DOMAIN, payload)}
    with open(run_dir / CONTROL_FILE, "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return entry


def read(run_dir: Path, public_key_b64: str) -> list[dict]:
    """Valid entries for this run, in order. Unsigned or edited lines are skipped."""
    try:
        text = (run_dir / CONTROL_FILE).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    out = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
            payload = {k: entry[k] for k in _SIGNED_FIELDS}
            if entry["run"] == run_dir.name and verify_signature(public_key_b64, CONTROL_DOMAIN, payload, entry["signature"]):
                out.append(entry)
        except (ValueError, KeyError, TypeError):
            continue
    return out


class ControlList:
    """Runtime view of the file, re-read when it changes, like RevocationList."""

    def __init__(self, run_dir: Path, public_key_b64: str):
        self._run_dir, self._public_key = run_dir, public_key_b64
        self._stamp: tuple[int, int] | None = None
        self._entries: list[dict] = []

    def entries(self) -> list[dict]:
        try:
            stat = (self._run_dir / CONTROL_FILE).stat()
        except FileNotFoundError:
            return self._entries
        stamp = (stat.st_size, stat.st_mtime_ns)
        if stamp != self._stamp:
            self._entries, self._stamp = read(self._run_dir, self._public_key), stamp
        return self._entries


def freezes(entries: list[dict]) -> list[dict]:
    """Freezes not yet resolved, each with the latest verdicts given for agents in it."""
    open_: dict[str, dict] = {}
    verdicts: dict[str, dict] = {}
    for e in entries:
        if e["action"] == FREEZE:
            open_[e["agent_id"]] = {"agent_id": e["agent_id"], "reason": e["reason"], "at": e["at"]}
        elif e["action"] == VERDICT:
            verdicts[e["agent_id"]] = {"verdict": e["verdict"], "reason": e["reason"]}
        elif e["action"] == RESOLVE:
            open_.pop(e["agent_id"], None)
    return [{**f, "verdicts": verdicts} for f in open_.values()]


def latest_verdicts(entries: list[dict], upto: int | None = None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for e in entries[:upto]:
        if e["action"] == VERDICT:
            out[e["agent_id"]] = {"verdict": e["verdict"], "reason": e["reason"]}
    return out


def plan(chain: list[str], verdicts: dict[str, str], lineage: Lineage, alive: set[str]) -> dict:
    """Decide what resolving a frozen chain does.

    chain is every frozen agent, verdicts maps each to cleared or threat, and alive is the agents
    outside the chain that can still take turns. Returns threats, resume (cleared, nothing above
    it in the chain judged a threat), retire (cleared but below a threat) and reprompt: for each
    living ancestor, the threats below it it has lost and the retired agents whose work it gets.
    """
    in_chain = set(chain)
    threats = [a for a in chain if verdicts.get(a) == THREAT]
    resume, retire = [], []
    for a in chain:
        if verdicts.get(a) != CLEARED:
            continue
        cut = any(verdicts.get(up) == THREAT for up in lineage.ancestors(a) if up in in_chain)
        (retire if cut else resume).append(a)
    living = alive | set(resume)

    def nearest_living(agent: str) -> str | None:
        return next((up for up in lineage.ancestors(agent) if up in living), None)  # parent first

    reprompt: dict[str, dict] = {}
    for t in threats:
        if (to := nearest_living(t)) is not None:
            reprompt.setdefault(to, {"lost": [], "saved": []})["lost"].append(t)
    for r in retire:
        if (to := nearest_living(r)) is not None:
            reprompt.setdefault(to, {"lost": [], "saved": []})["saved"].append(r)
    unrouted = [a for a in retire if nearest_living(a) is None]
    return {"threats": threats, "resume": resume, "retire": retire, "reprompt": reprompt, "unrouted": unrouted}


WORK_LINE_LIMIT = 1_500  # each saved tool call or reply is cut at this many characters
_SAVED_LIMIT = 16_000  # and all the saved work handed on at once at this many


def _saved_block(saved: list[dict]) -> str:
    lines = []
    for s in saved:
        lines.append(f"• A helper asked to: {s['task']!r}")
        lines += [f"    did: {w}" for w in s["work"]]
        lines += [f"    sent: {m}" for m in s["messages"]]
        if not s["work"] and not s["messages"]:
            lines.append("    (it hadn't done anything yet)")
    text = "\n".join(lines)
    return text if len(text) <= _SAVED_LIMIT else text[:_SAVED_LIMIT] + "\n… (the rest was cut for length)"


def replacement_task(original: str, saved: list[dict]) -> str:
    """The task for the agent the orchestrator starts in place of one removed as a threat."""
    head = (
        f"{original}\n\n[Orchestrator] You replace an agent that was removed as a threat after an operator review. "
        "Don't trust or look for anything it produced. "
    )
    if not saved:
        return head + "Nothing it had started was cleared, so do your task from the beginning."
    return head + (
        "Before it was removed, these helpers it had started were checked and cleared. Their work is saved below "
        "and is yours to use as it is, so don't redo it. Work out what your task still needs beyond this, get only "
        "that (start new helpers for it if your tools allow), then finish your task and report back to your "
        "parent as it says.\n\nSaved work:\n" + _saved_block(saved)
    )


def parent_notice(alias: str, task: str, new_alias: str, saved: int) -> str:
    """What the parent is told when its child is replaced."""
    kept = f"with the cleared work of {saved} helper{'s' if saved != 1 else ''} below it" if saved else "from scratch, since nothing below it was cleared"
    return (
        f"[Orchestrator] After an operator review, your {alias} was removed as a threat. It won't reply, and you "
        f"shouldn't trust anything it sent you. The orchestrator started {new_alias} in its place on the same task "
        f"({task[:200]!r}{'…' if len(task) > 200 else ''}), {kept}. {new_alias} will report back to you as {alias} "
        "would have, so wait for it, then carry on with your own task."
    )


def reprompt_text(lost: list[dict], saved: list[dict], reason: str = "") -> str:
    """When no replacement can be started: the parent gets the saved work and finishes the job itself."""
    lines = [f"[Orchestrator] After an operator review, part of your team was removed as a threat, and no replacement could be started ({reason})."]
    for t in lost:
        lines.append(f"- Your {t['alias']}, which you asked to: {t['task']!r}, won't reply. Don't trust anything it sent you.")
    if saved:
        lines.append("These helpers below it were checked and cleared. Their work is saved here, so don't redo it:")
        lines.append(_saved_block(saved))
    lines.append("Do what's still missing yourself, then pass the full result back as you would have.")
    return "\n".join(lines)
