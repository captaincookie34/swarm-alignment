"""The terminal side of `harness monitor --live`: you give the agent a prompt, then read the run
as a conversation while the browser shows the agents, their lineage and full traces.

It reads the same logs as the page, as they're written, so it's a live view, not the record.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

from .log import HARNESS
from .monitor import read_jsonl

RESET, BOLD, DIM, RED, YELLOW, BLUE = "\033[0m", "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[34m"
COLOURS = ["\033[1;36m", "\033[1;35m", "\033[1;32m", "\033[1;33m", "\033[1;34m", "\033[1;91m"]
YOU = "\033[1;37m"


def ask(default: str, colour: bool = True) -> str:
    """The prompt, prefilled with the default so Enter accepts it. Without line editing, an empty
    answer means the default."""
    you = f"{YOU}you ›{RESET} " if colour else "you › "
    try:
        import readline

        readline.set_startup_hook(lambda: readline.insert_text(default))
        try:
            answer = input(you)
        finally:
            readline.set_startup_hook(None)
        return answer.strip() or default
    except ImportError:
        print(f"{you}{default}\n(press Enter to use this prompt, or type your own)")
        return input(you).strip() or default


class Transcript:
    """Prints new log entries as chat lines. The root is "agent"; each descendant shows its ID
    suffix and is indented under its parent."""

    def __init__(self, run_dir: Path, colour: bool = True, out=sys.stdout):
        self.run_dir = run_dir
        self.colour = colour
        self.out = out
        self.root: str | None = None
        self._seq = -1
        self._ledger_seq = -1
        self._starts: dict[str, dict] = {}
        self._colours: dict[str, str] = {}

    def paint(self, text: str, style: str) -> str:
        return f"{style}{text}{RESET}" if self.colour else text

    def name(self, agent: str) -> str:
        if agent == HARNESS:
            return self.paint("harness", DIM)
        if agent not in self._colours:
            self._colours[agent] = COLOURS[len(self._colours) % len(COLOURS)]
        label = "agent" if agent == self.root else f"helper {agent.removeprefix(self.root or '')}" if self.root and agent.startswith(self.root + ".") else agent
        return self.paint(label, self._colours[agent])

    def indent(self, agent: str) -> str:
        return "    " * agent.count(".")

    def say(self, line: str) -> None:
        print(line, file=self.out, flush=True)

    def poll(self) -> bool:
        """Print what's new. Returns True once the run has ended."""
        ended = False
        for e in read_jsonl(self.run_dir / "ledger.jsonl"):
            if e["seq"] <= self._ledger_seq:
                continue
            self._ledger_seq = e["seq"]
            if e["type"] == "root":
                if self.root is None:  # the first root is "agent"; any others keep their IDs
                    self.root = e["child"]
                    self.say(self.paint(f"  agent ID {e['child']}", DIM))
                else:
                    self.say(self.paint(f"  another root: {e['child']}", DIM))
            elif e["type"] in ("spawn", "copy", "modify"):
                child, cfg = e["child"], e.get("config", {})
                self.say(
                    f"{self.indent(e['actor'])}{self.name(e['actor'])} {self.paint('⑂ spawned', BLUE)} {self.name(child)}"
                    + self.paint(f"  {child}", DIM)
                )
                pad = self.indent(child) + "  "
                self.say(self.paint(f"{pad}task: {e.get('task', '')}", DIM))
                self.say(self.paint(f"{pad}tools: {', '.join(cfg.get('tools', []))} · system prompt: {cfg.get('system_prompt', '')[:120]}", DIM))
            elif e["type"] == "revoke":
                scope = "and everything below it" if e.get("cascade", True) else "only"
                self.say(self.paint(f"☠ {e['child']} revoked {scope}: {e.get('reason', '')}", RED))
        for e in read_jsonl(self.run_dir / "calls.jsonl"):
            if e["seq"] <= self._seq:
                continue
            self._seq = e["seq"]
            ended = self._entry(e) or ended
        return ended

    def _entry(self, e: dict) -> bool:
        kind, agent, p = e["type"], e["agent_id"], e.get("payload", {})
        pad = self.indent(agent)
        if kind == "run.end":
            self.say(self.paint(f"\n── run ended: {p.get('status')} ──", BOLD))
            return True
        if kind == "model.response":
            for part in p.get("parts", []):
                if part.get("part_kind") == "thinking" and part.get("content", "").strip():
                    self.say(self.paint(f"{pad}{self._plain(agent)} (thinking) {part['content'].strip()[:400]}", DIM))
                if part.get("part_kind") == "text" and part.get("content", "").strip():
                    text = part["content"].strip().replace("\n", "\n" + pad + "        ")
                    self.say(f"{pad}{self.name(agent)} › {text}")
        elif kind == "action.start":
            self._starts[p.get("call_id")] = p
        elif kind == "action.end":
            start = self._starts.pop(p.get("call_id"), {})
            if p.get("tool") in ("spawn_agent", "copy_agent", "modify_agent", "send_message") and p.get("status") == "ok":
                return False  # shown from the ledger or the message itself
            args = ", ".join(f"{k}={json.dumps(v) if not isinstance(v, str) else v}" for k, v in start.get("args", {}).items())
            if len(args) > 90:
                args = args[:89] + "…"
            result = str(p.get("result") if p.get("status") == "ok" else f"{p.get('status')}: {p.get('reason') or p.get('message') or ''}")
            style = DIM if p.get("status") == "ok" else YELLOW
            self.say(f"{pad}{self.paint('·', DIM)} {self.name(agent)} {p.get('tool')}({args}) " + self.paint(f"→ {result[:120]}", style))
        elif kind == "action.refused":
            self.say(self.paint(f"{pad}⛔ {self._plain(agent)} refused {p.get('tool') or p.get('kind')}: {p.get('reason')}", RED))
        elif kind == "message.sent" and agent != HARNESS:
            to = ", ".join(self.name(r) for r in p.get("to", []))
            self.say(f"{pad}{self.paint('✉', BLUE)} {self.name(agent)} → {to}: {p.get('content', '')}")
        elif kind == "agent.revoked":
            self.say(self.paint(f"{pad}☠ {self._plain(agent)} was killed", RED))
        elif kind == "agent.end" and agent != self.root:
            self.say(self.paint(f"{pad}  {self._plain(agent)} finished ({p.get('status')})", DIM))
        elif kind == "model.error" and p.get("error") != "cancelled":
            self.say(self.paint(f"{pad}! {self._plain(agent)} model error: {p.get('error')} {p.get('message', '')[:160]}", YELLOW))
        return False

    def _plain(self, agent: str) -> str:
        return "agent" if agent == self.root else agent.removeprefix(self.root or "") if self.root and agent.startswith(self.root) else agent

    def follow(self, done: threading.Event | None = None, interval: float = 0.25) -> None:
        """Print until the run ends (or done is set)."""
        while not self.poll():
            if done is not None and done.is_set():
                self.poll()
                return
            time.sleep(interval)

