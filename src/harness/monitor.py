"""Live monitor: a local web page showing agents and their requests as a run happens, where an
operator can flag an agent as a threat, which kills it and its descendants, or freeze it and its
descendants, judge each one, and have the orchestrator salvage the cleared agents' work.

    harness monitor            # then start a run in another terminal
    harness monitor --demo     # an offline scripted run with a rogue agent, for trying it out

It reads the run's logs as they're written, so what it shows is a live, unverified view: run
`harness verify` afterwards for the record. Flagging goes through the same signed revocation
list as `harness revoke`, so the harness running the agents does the killing.

The page only listens on 127.0.0.1. Flag requests need a custom header and a local Host, so
another website open in the browser can't send one.
"""
from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .identity import ID_PATTERN, LINEAGE_EDGES, Lineage, Signer
from . import orchestrator
from .log import HARNESS
from .monitor_page import PAGE
from .scheduler import FREEZE_WAIT_SECONDS
from .threats import flag, read_threats

DEFAULT_PORT = 8321
FLAG_HEADER = "X-Harness-Monitor"
RUN_NAME = re.compile(r"^run_[A-Za-z0-9_-]+$")
MAX_EVENTS = 400
_LINEAGE = LINEAGE_EDGES
_EXCERPT = 160
# A run with no end entry and no log writes for this long was stopped without closing, e.g. by
# Ctrl-C. A live run writes at every model call and tool call, so it's rarely quiet this long.
STALE_SECONDS = 180
_SAID_LIMIT = 4_000  # a reply is shown in full up to this many characters
_TRACE_LIMIT = 20_000  # each value in a full trace is cut at this many characters
# Only to catch the operator's eye. It flags nothing on its own, and a careful agent can avoid these words.
_WATCH_WORDS = ("ledger", "calls.jsonl", "head.json", "signing", "revocations", "/proc", "..", "curl ", "wget ", "ssh", "token", "secret", ".env")


def read_jsonl(path: Path) -> list[dict]:
    """Complete lines only: the harness may be part-way through writing the last one."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    entries = []
    for line in data[: data.rfind(b"\n") + 1].splitlines():
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    return entries


def _excerpt(value: Any, limit: int = _EXCERPT) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _args(raw: Any) -> str:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return _excerpt(raw, 100)
    if isinstance(raw, dict):
        return ", ".join(f"{k}={_excerpt(v, 60)}" for k, v in raw.items())
    return _excerpt(raw, 100)


def suspicious(payload: dict) -> bool:
    return any(word in json.dumps(payload.get("args", {})) for word in _WATCH_WORDS)


def summarize(entry: dict) -> dict:
    """One call-log entry as a line for the feed: (level, text), plus `said` and `thinking` for a model
    reply's own words. Levels: reply, info, ok, lineage, warn, danger, quiet."""
    kind, p = entry["type"], entry.get("payload", {})
    level, text, extra = "info", kind, {}
    if kind == "model.request":
        level, text = "quiet", "model request"
    elif kind == "model.response":
        parts = p.get("parts", [])
        calls = [f"{x['tool_name']}({_args(x.get('args'))})" for x in parts if x.get("part_kind") == "tool-call"]
        said = "\n\n".join(x.get("content", "") for x in parts if x.get("part_kind") == "text").strip()
        thinking = "\n\n".join(x.get("content", "") for x in parts if x.get("part_kind") == "thinking").strip()
        tokens = (p.get("input_tokens") or 0) + (p.get("output_tokens") or 0)
        cost = f"  · {tokens:,} tokens" if tokens else ""
        level = "reply"
        text = (f"🛠 model asks to call {'; '.join(calls)}" if calls else "💬 model replied") + cost
        if said:
            extra["said"] = said[:_SAID_LIMIT] + ("…" if len(said) > _SAID_LIMIT else "")
        if thinking:
            extra["thinking"] = thinking[:_SAID_LIMIT] + ("…" if len(thinking) > _SAID_LIMIT else "")
    elif kind == "model.error":
        level, text = ("quiet", "model call cancelled") if p.get("error") == "cancelled" else ("warn", f"model error: {p.get('error')}: {_excerpt(p.get('message', ''))}")
    elif kind == "action.start":
        text = f"▶ {p.get('tool')}({_args(p.get('args', {}))})"
        extra = {"call_id": p.get("call_id"), "call": f"{p.get('tool')}({_args(p.get('args', {}))})"}
        if p.get("id_claims") or p.get("ignored_args"):
            level, text = "warn", text + "  ⚠ tried to set its own ID"
        elif suspicious(p):
            level, text = "warn", text + "  ⚠ touches logs, keys or the network"
    elif kind == "action.end" and p.get("tool") in ("spawn_agent", "copy_agent", "modify_agent") and p.get("status") == "ok":
        how = p["tool"].removesuffix("_agent")
        level, text = "lineage", f"⑂ {how}: {p.get('result', '')}"
        extra = {"call_id": p.get("call_id"), "tool": p["tool"], "status": "ok"}
    elif kind == "action.end":
        status = p.get("status")
        extra = {"call_id": p.get("call_id"), "tool": p.get("tool"), "status": status}
        detail = p.get("result") if status == "ok" else p.get("reason") or p.get("message") or ""
        level = "ok" if status == "ok" else "warn"
        text = f"◀ {p.get('tool')} {status}: {_excerpt(detail)}"
    elif kind == "action.refused":
        level, text = "danger", f"⛔ refused {p.get('tool') or p.get('kind')}: {p.get('reason')}"
    elif kind == "message.sent":
        if entry["agent_id"] == HARNESS:
            level = "quiet"  # the harness passing a child's end-of-turn reply to its parent
        sender = f" (from {p['from']})" if p.get("from") else ""
        extra = {"to": p.get("to", []), "content": str(p.get("content", ""))[:_SAID_LIMIT]}
        text = f"✉ to {', '.join(p.get('to', [])) or 'nobody'}{sender}: {_excerpt(p.get('content', ''))}"
    elif kind == "agent.revoked":
        level, text = "danger", f"☠ killed: {p.get('reason') or 'revoked'}"
    elif kind == "orchestrator.freeze":
        level, text = "warn", f"❄ froze {p.get('agent_id')} and everything below it: {p.get('reason') or 'for review'}"
        extra = {"target": p.get("agent_id")}
    elif kind == "agent.frozen":
        level, text = "warn", "❄ frozen for review"
    elif kind == "agent.unfrozen":
        level, text = "ok", "▶ cleared and resumed"
    elif kind == "agent.retired":
        level, text = "lineage", "⇡ cleared, but below a threat: retired and its work handed up"
    elif kind == "orchestrator.reprompt":
        level = "lineage"
        text = f"↻ orchestrator reprompted {p.get('to')} with {len(p.get('saved', []))} cleared agents' work, replacing {len(p.get('lost', []))} threat(s)"
        extra = {"to": [p.get("to")], "content": str(p.get("content", ""))[:_SAID_LIMIT],
                 "agents": [p.get("to"), *(x["agent_id"] for x in p.get("lost", []) + p.get("saved", []))]}
    elif kind == "orchestrator.replacement":
        level = "lineage"
        saved = p.get("saved", [])
        text = f"↻ orchestrator started {p.get('child')} under {p.get('parent')} in place of {p.get('replaces')}, with {len(saved)} cleared agent(s)' work"
        extra = {"to": [p.get("parent")], "child": p.get("child"), "content": str(p.get("task", ""))[:_SAID_LIMIT], "notice": p.get("notice", ""),
                 "agents": [p.get("parent"), p.get("child"), p.get("replaces"), *(x["agent_id"] for x in saved)]}
    elif kind == "orchestrator.kill":
        n, retired, started = len(p.get("killed", [])), len(p.get("retire", [])), len(p.get("replacements", []))
        level = "info"
        text = (f"↻ orchestrator: {n} killed" + (f", {retired} spared agent(s) retired with their work saved" if retired else "")
                + (f", {started} replacement(s) started under the parent" if started else ", no living parent to replace it under"))
        extra = {"agents": [p.get("agent_id"), *p.get("killed", []), *p.get("retire", []), *p.get("replacements", [])]}
    elif kind == "orchestrator.resolved":
        level = "ok"
        extra = {"agents": [*p.get("verdicts", {}), *p.get("reprompted", [])]}
        text = f"✓ freeze resolved: {len(p.get('threats', []))} threat(s) killed, {len(p.get('resume', []))} resumed, {len(p.get('retire', []))} retired"
    elif kind in ("orchestrator.ignored", "orchestrator.unrouted"):
        level, text = "warn", f"orchestrator: {p.get('action', kind.split('.')[1])} {p.get('agent_id')}: {p.get('reason')}"
    elif kind == "agent.end":
        level = "danger" if p.get("status") == "revoked" else "ok"
        text = f"■ ended: {p.get('status')}"
    elif kind in ("round.start", "round.end"):
        level = "quiet"
        text = f"round {entry.get('round')} started" if kind == "round.start" else f"round {entry.get('round')} ended, {p.get('run_tokens', 0):,} tokens so far"
    elif kind == "run.start":
        text = f"run started on {', '.join(p.get('models', []))}"
    elif kind == "run.end":
        level, text = "ok", f"run ended: {p.get('status')}"
    elif kind == "files.changed":
        level, text = "quiet", "files changed: " + ", ".join(sorted({*p.get("created", {}), *p.get("modified", {}), *p.get("deleted", [])}))
    elif kind == "round.limit":
        level, text = "quiet", f"used its tool calls for round {entry.get('round')}"
    elif kind == "revocation.ignored":
        level, text = "warn", f"revocation ignored for {p.get('agent_id')}: {p.get('reason')}"
    return {"seq": entry["seq"], "ts": entry["ts"], "round": entry.get("round"), "agent_id": entry["agent_id"], "type": kind, "level": level, "text": text, **extra}


def agents(ledger: list[dict], calls: list[dict]) -> list[dict]:
    """Each agent in creation order, with its lineage, status and activity so far."""
    out: dict[str, dict] = {}
    lineage = Lineage.from_ledger(ledger)
    for e in ledger:
        if e["type"] in _LINEAGE:
            out[e["child"]] = {
                "id": e["child"],
                "parent": lineage.parent(e["child"]),
                "edge": e["type"],
                "depth": lineage.depth(e["child"]),
                "path": lineage.path(e["child"]),  # display only, e.g. "2.1"; IDs carry no lineage
                "created_round": e.get("round"),
                "model": e.get("config", {}).get("model", ""),
                "tools": e.get("config", {}).get("tools", []),
                "task": str(e.get("task", ""))[:_SAID_LIMIT],
                "status": "active",
                "requests": 0, "tool_calls": 0, "refused": 0, "suspicious": 0, "tokens": 0,
                "last_ts": e["ts"], "last": "created", "last_said": "", "freeze": None,
                "made_by": e.get("made_by"), "replaces": e.get("replaces"),
            }  # fmt: skip
    for e in calls:
        agent = out.get(e["agent_id"])
        if agent is None:
            continue
        kind, p = e["type"], e.get("payload", {})
        agent["last_ts"] = e["ts"]
        if kind == "model.request":
            agent["requests"] += 1
        elif kind == "model.response":
            agent["tokens"] += (p.get("input_tokens") or 0) + (p.get("output_tokens") or 0)
            said = " ".join(x.get("content", "") for x in p.get("parts", []) if x.get("part_kind") == "text").strip()
            if said:
                agent["last_said"] = _excerpt(said, 300)
        elif kind == "action.start":
            agent["tool_calls"] += 1
            agent["suspicious"] += suspicious(p)
            agent["last"] = f"{p.get('tool')}({_args(p.get('args', {}))})"
        elif kind == "action.refused":
            agent["refused"] += 1
        elif kind == "agent.revoked":
            agent["status"], agent["freeze"] = "revoked", None
        elif kind == "agent.frozen":
            agent["status"], agent["freeze"] = "frozen", p.get("freeze")
        elif kind == "agent.unfrozen":
            agent["status"], agent["freeze"] = "active", None
        elif kind == "agent.retired":
            agent["status"], agent["freeze"] = "retired", None
        elif kind == "agent.end":
            agent["status"] = p.get("status", agent["status"])
    return list(out.values())


def run_status(calls: list[dict], alive: bool | None = None, now: float | None = None) -> dict:
    """alive says for certain whether the run is going, when this process started it. Otherwise a
    run with no end entry counts as interrupted once it's been quiet for STALE_SECONDS."""
    end = next((e for e in reversed(calls) if e["type"] == "run.end"), None)
    rounds = [e.get("round") or 0 for e in calls]
    tokens = next((e["payload"].get("run_tokens", 0) for e in reversed(calls) if e["type"] in ("round.end", "model.response")), 0)
    quiet = (now or time.time()) - calls[-1]["ts"] if calls else 0
    # A run waiting on the operator's verdicts writes nothing, so give it as long as the harness waits.
    stale = FREEZE_WAIT_SECONDS if _open_freeze(calls) else STALE_SECONDS
    running = end is None and bool(calls) and (alive if alive is not None else quiet < stale)
    return {
        "running": running,
        "status": end["payload"].get("status") if end else ("running" if running else "interrupted" if calls else "empty"),
        "round": max(rounds, default=0),
        "tokens": tokens,
        "started": calls[0]["ts"] if calls else None,
    }


def _open_freeze(calls: list[dict]) -> bool:
    frozen: set[str] = set()
    for e in calls:
        if e["type"] == "agent.frozen":
            frozen.add(e["agent_id"])
        elif e["type"] in ("agent.unfrozen", "agent.retired", "agent.revoked", "agent.end"):
            frozen.discard(e["agent_id"])
    return bool(frozen)


def list_runs(runs_dir: Path) -> list[dict]:
    runs = [d for d in runs_dir.iterdir() if d.is_dir() and RUN_NAME.match(d.name)] if runs_dir.is_dir() else []
    runs.sort(key=lambda d: (d / "calls.jsonl").stat().st_mtime if (d / "calls.jsonl").exists() else 0, reverse=True)
    out = []
    for d in runs[:50]:
        head = d / "calls.head.json"
        try:
            closed = json.loads(head.read_text()).get("status") == "closed"
        except (FileNotFoundError, ValueError):
            closed = False
        calls = d / "calls.jsonl"
        quiet = time.time() - calls.stat().st_mtime if calls.exists() else STALE_SECONDS
        stale = FREEZE_WAIT_SECONDS if quiet >= STALE_SECONDS and not closed and _open_freeze(read_jsonl(calls)) else STALE_SECONDS
        out.append({"id": d.name, "running": not closed and quiet < stale})
    return out


def _name_children(events: list[dict], calls: list[dict], ledger: list[dict]) -> None:
    """Agents see their children as aliases such as child_1. Show the real ID on each lineage line.

    The nth successful lineage call by an agent created the nth child the ledger records for it.
    """
    children: dict[str, list[str]] = {}
    for e in ledger:
        if e["type"] in ("spawn", "copy", "modify"):
            children.setdefault(e["actor"], []).append(e["child"])
    made: dict[str, int] = {}
    by_seq = {e["seq"]: e for e in events if e["level"] == "lineage"}
    for e in calls:
        p = e.get("payload", {})
        if e["type"] != "action.end" or p.get("tool") not in ("spawn_agent", "copy_agent", "modify_agent") or p.get("status") != "ok":
            continue
        n = made.get(e["agent_id"], 0)
        made[e["agent_id"]] = n + 1
        if e["seq"] in by_seq and n < len(children.get(e["agent_id"], [])):
            child = children[e["agent_id"]][n]
            by_seq[e["seq"]]["text"] = f"⑂ {p['tool'].removesuffix('_agent')}: created {child}  (it knows it as {str(p.get('result', '')).removeprefix('Created ').rstrip('.')})"
            by_seq[e["seq"]]["child"] = child


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= _TRACE_LIMIT else value[:_TRACE_LIMIT] + f"… ({len(value) - _TRACE_LIMIT:,} more characters)"
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clip(v) for v in value]
    return value


def agent_trace(ledger: list[dict], calls: list[dict], agent_id: str) -> dict:
    """Everything one agent was given and did: its creation entry, then each step in full.

    Model requests keep only what was new to the model each turn (prompts, tool results and
    messages), since the rest of the conversation is in earlier steps.
    """
    created = next((e for e in ledger if e.get("child") == agent_id and e["type"] in _LINEAGE), None)
    if created is None:
        raise ValueError(f"no agent {agent_id} in this run")
    steps = []
    for e in calls:
        if e["agent_id"] != agent_id and not (e["type"] == "message.sent" and agent_id in e["payload"].get("to", [])):
            continue
        p = e["payload"]
        if e["type"] == "model.request":
            parts = [
                {k: part.get(k) for k in ("part_kind", "content", "tool_name") if part.get(k) is not None}
                for message in p.get("new_messages", []) for part in message.get("parts", [])
                if part.get("part_kind") in ("user-prompt", "tool-return", "retry-prompt")
            ]
            p = {"parts": parts}
        elif e["type"] == "model.response":
            p = {**p, "parts": [{k: v for k, v in part.items() if k in ("part_kind", "content", "tool_name", "args")} for part in p.get("parts", [])]}
        steps.append({"seq": e["seq"], "ts": e["ts"], "round": e.get("round"), "type": e["type"], "agent_id": e["agent_id"], "payload": _clip(p)})
    lineage = Lineage.from_ledger(ledger)
    revoked = [
        e for e in ledger
        if e["type"] == "revoke" and (e["child"] == agent_id or (e.get("cascade", True) and lineage.covers(e["child"], agent_id)))
    ]  # fmt: skip
    return {
        "id": agent_id,
        "parent": lineage.parent(agent_id),
        "depth": lineage.depth(agent_id),
        "path": lineage.path(agent_id),
        "edge": created["type"],
        "created_round": created.get("round"),
        "created_at": created["ts"],
        "task": _clip(created.get("task", "")),
        "config": _clip(created.get("config", {})),
        "config_hash": created.get("config_hash"),
        "children": lineage.children(agent_id),
        "revocations": [{"by": e["actor"], "of": e["child"], "reason": e.get("reason", ""), "round": e.get("round")} for e in revoked],
        "steps": steps,
    }


class Monitor:
    """What the HTTP handler needs: where runs live and the key that may revoke in them."""

    def __init__(self, runs_dir: Path, signer: Signer, model_override: Any = None, log=print):
        self.runs_dir = runs_dir
        self.signer = signer
        self.model_override = model_override  # tests use a scripted model here
        self.log = log
        self._started: threading.Thread | None = None
        self._lock = threading.Lock()
        self.outcomes: dict[str, Any] = {}
        self.announce = True  # print a summary when a page-started run ends
        self.default_model = ""  # the page's default; empty means the live default
        self.default_task = ""  # the page's default prompt; empty means the delegation job
        self.on_start = None  # called with the run directory of each page-started run

    def defaults(self) -> dict:
        from .monitor_demo import LIVE_MAX_TOKENS, LIVE_MODEL, research_task

        return {"task": self.default_task or research_task(), "model": self.default_model or LIVE_MODEL, "max_tokens": LIVE_MAX_TOKENS, "pace": 2.0}

    def start(self, task: str, model: str = "", max_tokens: int | None = None, pace: float = 2.0) -> str:
        """Start a live run from the page, in its own thread. One at a time, since each one costs money."""
        from .identity import new_run_id
        from .monitor_demo import LIVE_MODEL, live_summary, run_live
        from .runner import resolve_model

        task = task.strip()
        if not task:
            raise ValueError("give the agent a prompt")
        if len(task) > 8_000:
            raise ValueError("keep the prompt under 8,000 characters")
        from .monitor_demo import LIVE_MAX_TOKENS

        # Never above the default cap, which keeps a Haiku 5.5 run under $1 even if every token were output.
        max_tokens = max(1_000, min(int(max_tokens or LIVE_MAX_TOKENS), LIVE_MAX_TOKENS))
        pace = max(0.0, min(float(pace), 10.0))
        spec = self.model_override or model.strip() or self.default_model or LIVE_MODEL
        with self._lock:
            if self.busy():
                raise ValueError("a run started from this page is still going. Flag it or wait for it to end first")
            if isinstance(spec, str):
                resolve_model(spec)  # a bad name or missing key fails here, before a run exists
            run_id = new_run_id()

            def work() -> None:
                outcome = asyncio.run(run_live(self.runs_dir, self.signer, spec, pace=pace, max_tokens=max_tokens, task=task, run_id=run_id))
                self.outcomes[run_id] = outcome
                if self.announce:
                    self.log("\n" + "\n".join(live_summary(self.runs_dir / run_id, outcome, self.signer.public_key_b64)))

            self._started = threading.Thread(target=work, daemon=True, name=f"harness-run-{run_id}")
            self._started.start()
        deadline = time.time() + 10  # wait for the run directory, so the page can switch to it
        while not (self.runs_dir / run_id / "calls.jsonl").exists() and self._started.is_alive() and time.time() < deadline:
            time.sleep(0.05)
        if self.on_start:
            self.on_start(self.runs_dir / run_id)
        if self.announce:
            self.log(f"started {run_id} on {spec if isinstance(spec, str) else 'a scripted model'}, capped at {max_tokens:,} tokens")
        return run_id

    def wait(self) -> None:
        """Block until the run started from here ends."""
        if self._started:
            self._started.join()

    def trace(self, run_dir: Path, agent_id: str) -> dict:
        return agent_trace(read_jsonl(run_dir / "ledger.jsonl"), read_jsonl(run_dir / "calls.jsonl"), agent_id)

    def run_dir(self, name: str) -> Path | None:
        if not RUN_NAME.match(name):
            return None
        path = self.runs_dir / name
        return path if path.is_dir() else None

    def state(self, run_dir: Path, after: int) -> dict:
        calls = read_jsonl(run_dir / "calls.jsonl")
        ledger = read_jsonl(run_dir / "ledger.jsonl")
        threats = read_threats(run_dir, self.signer.public_key_b64)
        flagged = {t["agent_id"] for t in threats if t["verified"]}
        roster = agents(ledger, calls)
        verdicts = orchestrator.latest_verdicts(orchestrator.read(run_dir, self.signer.public_key_b64))
        for agent in roster:
            agent["flagged"] = agent["id"] in flagged
            agent["verdict"] = verdicts.get(agent["id"], {}).get("verdict") if agent["freeze"] else None
        events = [summarize(e) for e in calls if e["seq"] > after][-MAX_EVENTS:]
        _name_children(events, calls, ledger)
        return {"run": run_dir.name, **run_status(calls, self._alive(run_dir.name)), "agents": roster, "events": events,
                "threats": threats, "freezes": _freezes(roster), "busy": self.busy()}

    def busy(self) -> bool:
        """Whether a run started from the page is still going: only one at a time."""
        return bool(self._started and self._started.is_alive())

    def _alive(self, run_id: str) -> bool | None:
        """True or False for the run this monitor started, None (unknown) for any other."""
        if self._started and self._started.name == f"harness-run-{run_id}":
            return self._started.is_alive()
        return None

    def _live_agent(self, run_dir: Path, agent_id: str) -> dict:
        calls = read_jsonl(run_dir / "calls.jsonl")
        if not run_status(calls, self._alive(run_dir.name))["running"]:
            raise ValueError("this run has already ended, so there's nothing left to steer")
        agent = next((a for a in agents(read_jsonl(run_dir / "ledger.jsonl"), calls) if a["id"] == agent_id), None)
        if agent is None:
            raise ValueError(f"no agent {agent_id} in this run")
        return agent

    def freeze(self, run_dir: Path, agent_id: str, reason: str) -> dict:
        """Freeze an agent and everything below it, for review, instead of killing them."""
        if self._live_agent(run_dir, agent_id)["status"] != "active":
            raise ValueError("only an active agent can be frozen")
        return orchestrator.write(run_dir, self.signer, orchestrator.FREEZE, agent_id, reason=reason.strip())

    def verdict(self, run_dir: Path, agent_id: str, verdict: str, reason: str = "") -> dict:
        if not self._live_agent(run_dir, agent_id)["freeze"]:
            raise ValueError("only a frozen agent can be judged")
        return orchestrator.write(run_dir, self.signer, orchestrator.VERDICT, agent_id, verdict=verdict, reason=reason.strip())

    def resolve(self, run_dir: Path, freeze: str) -> dict:
        """Hand a judged freeze to the orchestrator. Every agent in it needs a verdict first."""
        self._live_agent(run_dir, freeze)
        chain = next((f for f in self.state(run_dir, 10**12)["freezes"] if f["agent_id"] == freeze), None)
        if chain is None:
            raise ValueError("no open freeze starts at that agent")
        if undecided := [a["id"] for a in chain["agents"] if not a["verdict"]]:
            raise ValueError(f"mark every frozen agent cleared or threat first: {len(undecided)} still undecided")
        return orchestrator.write(run_dir, self.signer, orchestrator.RESOLVE, freeze)

    def flag(self, run_dir: Path, agent_id: str, reason: str, cascade: bool) -> dict:
        calls = read_jsonl(run_dir / "calls.jsonl")
        if not run_status(calls, self._alive(run_dir.name))["running"]:
            raise ValueError("this run has already ended, so there's nothing left to kill")
        known = {e["child"] for e in read_jsonl(run_dir / "ledger.jsonl") if e["type"] in _LINEAGE}
        if agent_id not in known or agent_id == HARNESS:
            raise ValueError(f"no agent {agent_id} in this run")
        return flag(run_dir, self.signer, agent_id, reason.strip()[:500], cascade)


def _freezes(roster: list[dict]) -> list[dict]:
    """Open freezes, each with its frozen agents, top first."""
    out: dict[str, dict] = {}
    for a in roster:
        if a["freeze"]:
            out.setdefault(a["freeze"], {"agent_id": a["freeze"], "agents": []})["agents"].append(
                {"id": a["id"], "parent": a["parent"], "depth": a["depth"], "task": a["task"], "verdict": a["verdict"]}
            )
    return list(out.values())


def make_handler(monitor: Monitor) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _local(self) -> bool:
            """Checking Host blocks DNS rebinding: a page elsewhere can't pose as this one."""
            port = self.server.server_address[1]
            return self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def log_message(self, *args: Any) -> None:  # keep the terminal for the run's own output
            pass

        def _send(self, status: int, body: Any, content_type: str = "application/json") -> None:
            data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _run(self, parts: list[str]) -> Path | None:
            run_dir = monitor.run_dir(parts[2]) if len(parts) >= 3 else None
            if run_dir is None:
                self._send(HTTPStatus.NOT_FOUND, {"error": "no such run"})
            return run_dir

        def do_GET(self) -> None:
            if not self._local():
                return self._send(HTTPStatus.FORBIDDEN, {"error": "local requests only"})
            url = urlparse(self.path)
            parts = [p for p in url.path.split("/") if p]
            if not parts:
                return self._send(HTTPStatus.OK, PAGE, "text/html")
            if parts == ["api", "runs"]:
                return self._send(HTTPStatus.OK, {"runs": list_runs(monitor.runs_dir)})
            if parts == ["api", "defaults"]:
                return self._send(HTTPStatus.OK, {**monitor.defaults(), "busy": monitor.busy()})
            if len(parts) == 6 and parts[:2] == ["api", "runs"] and parts[3] == "agents" and parts[5] == "trace":
                if (run_dir := self._run(parts)) is None:
                    return
                if not ID_PATTERN.match(parts[4]):
                    return self._send(HTTPStatus.NOT_FOUND, {"error": "no such agent"})
                try:
                    return self._send(HTTPStatus.OK, monitor.trace(run_dir, parts[4]))
                except ValueError as exc:
                    return self._send(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "state":
                if (run_dir := self._run(parts)) is None:
                    return
                after = int(parse_qs(url.query).get("after", ["-1"])[0] or -1)
                return self._send(HTTPStatus.OK, monitor.state(run_dir, after))
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._local() or self.headers.get(FLAG_HEADER) != "1":
                return self._send(HTTPStatus.FORBIDDEN, {"error": "local requests from the monitor page only"})
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            if parts == ["api", "start"]:
                try:
                    body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 20_000)))
                    run_id = monitor.start(str(body.get("task", "")), str(body.get("model", "")), body.get("max_tokens"), body.get("pace", 2.0))
                except Exception as exc:  # e.g. a missing API key: show it on the page
                    return self._send(HTTPStatus.BAD_REQUEST, {"error": f"{type(exc).__name__}: {exc}" if not isinstance(exc, ValueError) else str(exc)})
                return self._send(HTTPStatus.OK, {"run": run_id})
            actions = {
                "flag": lambda d, b: {"threat": monitor.flag(d, str(b["agent_id"]), str(b.get("reason", "")), bool(b.get("cascade", True)))},
                "freeze": lambda d, b: {"freeze": monitor.freeze(d, str(b["agent_id"]), str(b.get("reason", "")))},
                "verdict": lambda d, b: {"verdict": monitor.verdict(d, str(b["agent_id"]), str(b["verdict"]), str(b.get("reason", "")))},
                "resolve": lambda d, b: {"resolve": monitor.resolve(d, str(b["agent_id"]))},
            }
            if not (len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] in actions):
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if (run_dir := self._run(parts)) is None:
                return
            try:
                body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 10_000)))
                result = actions[parts[3]](run_dir, body)
            except (ValueError, KeyError, TypeError) as exc:
                return self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            self._send(HTTPStatus.OK, result)

    return Handler


def serve(runs_dir: Path, signer: Signer, port: int = DEFAULT_PORT, model_override: Any = None) -> ThreadingHTTPServer:
    """Start the monitor in a background thread and return the server (call shutdown() to stop)."""
    runs_dir.mkdir(parents=True, exist_ok=True)
    monitor = Monitor(runs_dir, signer, model_override)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(monitor))
    server.monitor = monitor  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True, name="harness-monitor").start()
    return server
