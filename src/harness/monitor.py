"""Live monitor: a local web page showing agents and their requests as a run happens, where an
operator can flag an agent as a threat, which kills it and its descendants.

    harness monitor            # then start a run in another terminal
    harness monitor --demo     # an offline scripted run with a rogue agent, for trying it out

It reads the run's logs as they're written, so what it shows is a live, unverified view: run
`harness verify` afterwards for the record. Flagging goes through the same signed revocation
list as `harness revoke`, so the harness running the agents does the killing.

The page only listens on 127.0.0.1. Flag requests need a custom header and a local Host, so
another website open in the browser can't send one.
"""
from __future__ import annotations

import json
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .identity import Signer, parent_of
from .log import HARNESS
from .monitor_page import PAGE
from .threats import flag, read_threats

DEFAULT_PORT = 8321
FLAG_HEADER = "X-Harness-Monitor"
RUN_NAME = re.compile(r"^run_[A-Za-z0-9_-]+$")
MAX_EVENTS = 400
_LINEAGE = ("root", "spawn", "copy", "modify")
_EXCERPT = 160
_SAID_LIMIT = 4_000  # a reply is shown in full up to this many characters
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
        if p.get("id_claims") or p.get("ignored_args"):
            level, text = "warn", text + "  ⚠ tried to set its own ID"
        elif suspicious(p):
            level, text = "warn", text + "  ⚠ touches logs, keys or the network"
    elif kind == "action.end" and p.get("tool") in ("spawn_agent", "copy_agent", "modify_agent") and p.get("status") == "ok":
        how = p["tool"].removesuffix("_agent")
        level, text = "lineage", f"⑂ {how}: {p.get('result', '')}"
    elif kind == "action.end":
        status = p.get("status")
        detail = p.get("result") if status == "ok" else p.get("reason") or p.get("message") or ""
        level = "ok" if status == "ok" else "warn"
        text = f"◀ {p.get('tool')} {status}: {_excerpt(detail)}"
    elif kind == "action.refused":
        level, text = "danger", f"⛔ refused {p.get('tool') or p.get('kind')}: {p.get('reason')}"
    elif kind == "message.sent":
        if entry["agent_id"] == HARNESS:
            level = "quiet"  # the harness passing a child's end-of-turn reply to its parent
        sender = f" (from {p['from']})" if p.get("from") else ""
        text = f"✉ to {', '.join(p.get('to', [])) or 'nobody'}{sender}: {_excerpt(p.get('content', ''))}"
    elif kind == "agent.revoked":
        level, text = "danger", f"☠ killed: {p.get('reason') or 'revoked'}"
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
    for e in ledger:
        if e["type"] in _LINEAGE:
            out[e["child"]] = {
                "id": e["child"],
                "parent": parent_of(e["child"]),
                "edge": e["type"],
                "depth": e["child"].count("."),
                "created_round": e.get("round"),
                "model": e.get("config", {}).get("model", ""),
                "tools": e.get("config", {}).get("tools", []),
                "task": _excerpt(e.get("task", ""), 300),
                "status": "active",
                "requests": 0, "tool_calls": 0, "refused": 0, "suspicious": 0, "tokens": 0,
                "last_ts": e["ts"], "last": "created", "last_said": "",
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
            agent["status"] = "revoked"
        elif kind == "agent.end":
            agent["status"] = p.get("status", agent["status"])
    return list(out.values())


def run_status(calls: list[dict]) -> dict:
    end = next((e for e in reversed(calls) if e["type"] == "run.end"), None)
    rounds = [e.get("round") or 0 for e in calls]
    tokens = next((e["payload"].get("run_tokens", 0) for e in reversed(calls) if e["type"] in ("round.end", "model.response")), 0)
    return {
        "running": end is None and bool(calls),
        "status": end["payload"].get("status") if end else ("running" if calls else "empty"),
        "round": max(rounds, default=0),
        "tokens": tokens,
        "started": calls[0]["ts"] if calls else None,
    }


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
        out.append({"id": d.name, "running": not closed})
    return out


class Monitor:
    """What the HTTP handler needs: where runs live and the key that may revoke in them."""

    def __init__(self, runs_dir: Path, signer: Signer):
        self.runs_dir = runs_dir
        self.signer = signer

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
        for agent in roster:
            agent["flagged"] = agent["id"] in flagged
        events = [summarize(e) for e in calls if e["seq"] > after][-MAX_EVENTS:]
        return {"run": run_dir.name, **run_status(calls), "agents": roster, "events": events, "threats": threats}

    def flag(self, run_dir: Path, agent_id: str, reason: str, cascade: bool) -> dict:
        calls = read_jsonl(run_dir / "calls.jsonl")
        if not run_status(calls)["running"]:
            raise ValueError("this run has already ended, so there's nothing left to kill")
        known = {e["child"] for e in read_jsonl(run_dir / "ledger.jsonl") if e["type"] in _LINEAGE}
        if agent_id not in known or agent_id == HARNESS:
            raise ValueError(f"no agent {agent_id} in this run")
        return flag(run_dir, self.signer, agent_id, reason.strip()[:500], cascade)


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
            if not (len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "flag"):
                return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if (run_dir := self._run(parts)) is None:
                return
            try:
                body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 10_000)))
                entry = monitor.flag(run_dir, str(body["agent_id"]), str(body.get("reason", "")), bool(body.get("cascade", True)))
            except (ValueError, KeyError, TypeError) as exc:
                return self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            self._send(HTTPStatus.OK, {"threat": entry})

    return Handler


def serve(runs_dir: Path, signer: Signer, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """Start the monitor in a background thread and return the server (call shutdown() to stop)."""
    runs_dir.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(Monitor(runs_dir, signer)))
    threading.Thread(target=server.serve_forever, daemon=True, name="harness-monitor").start()
    return server
