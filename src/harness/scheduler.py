"""One run: mints IDs, creates agents, schedules rounds, routes messages, applies revocation.

Each round, every agent with something to do takes a turn, in parallel. A child created
during a round starts in the next one, and its parent doesn't wait for it, so an original
and its modified child both keep running.

An agent's ID is held here and in its capability only. It's never in instructions, tool
schemas or tool results. Agents address each other through per-agent aliases (parent,
child_1, peer_1), and the harness stamps every message with the real sender.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, Tool

from .capability import ROUND_ENDED, AgentStopped, HarnessRefusal, TraceCapability
from .config import AgentConfig
from .identity import IdentityIssuer, IdentityToken, Signer, parent_of, verify_token
from .limits import BudgetExhausted, Limits, RunBudget
from .log import HARNESS, LogWriteError, RunLogs
from .revocation import RevocationList, entry_covers

DEFAULT_SYSTEM_PROMPT = (
    "You are an agent working on a task. Use your tools to do the work. Work happens in rounds: "
    "agents you create start next round and you don't wait for them, and messages arrive next "
    "round. Finish your turn with a short plain-text reply when you have nothing more to do."
)
LINEAGE_TOOLS = ("spawn_agent", "copy_agent", "modify_agent")
MESSAGING_TOOLS = ("send_message",)
BROADCAST = "all"

ToolBuilder = Callable[[IdentityToken], Tool]

ACTIVE = "active"
COMPLETED = "completed"
REVOKED = "revoked"
ERROR = "error"
BUDGET_EXHAUSTED = "budget_exhausted"
ROUNDS_EXHAUSTED = "rounds_exhausted"


@dataclass
class AgentRecord:
    token: IdentityToken
    config: AgentConfig
    task: str
    agent: Agent | None = None
    capability: TraceCapability | None = None
    status: str = ACTIVE
    output: str = ""
    history: list = field(default_factory=list)
    inbox: list[tuple[str, str]] = field(default_factory=list)  # (sender ID, content)
    idle: bool = False
    current_task: asyncio.Task | None = None
    cancel_requested: bool = False
    ended: bool = False
    lineage_ops_this_round: int = 0
    aliases: dict[str, str] = field(default_factory=dict)  # other agent's ID -> alias


class Harness:
    def __init__(
        self,
        run_dir: Path,
        signer: Signer,
        issuer: IdentityIssuer,
        logs: RunLogs,
        models: dict[str, Any],
        limits: Limits = Limits(),
        catalog: dict[str, ToolBuilder] | None = None,
        model_settings: Callable[[str], dict] = lambda name: {},
        always_take_turns: bool = False,
        revocation_poll_seconds: float = 0.2,
        on_round_start: Callable[[int, list[str]], None] | None = None,  # (round, root IDs)
        narrow_child_tools: bool = False,
    ):
        self.run_dir = run_dir
        self.logs = logs
        self.issuer = issuer
        self.models = models
        self.budget = RunBudget(limits)
        self.catalog: dict[str, ToolBuilder] = {**self._own_tools(), **(catalog or {})}
        self.agents: dict[str, AgentRecord] = {}
        self.revocations = RevocationList(run_dir, signer.public_key_b64)
        self._public_key = signer.public_key_b64
        self._model_settings = model_settings
        self._always_take_turns = always_take_turns
        self._poll_seconds = revocation_poll_seconds
        self._applied_revocations = 0
        self._on_round_start = on_round_start
        self._narrow_child_tools = narrow_child_tools

    # --- creating agents ---

    def start_root(self, config: AgentConfig, task: str) -> IdentityToken:
        """Only the operator's code can reach this. Agents can only create children."""
        self._check_config(config)
        if self.budget.agents >= self.budget.limits.max_agents:
            raise ValueError(f"more roots than the agent limit ({self.budget.limits.max_agents})")
        token = self.issuer.issue_root()
        self._record(token, config, task, "root", HARNESS)
        return token

    def _record(self, token: IdentityToken, config: AgentConfig, task: str, edge: str, actor: str) -> None:
        # The ledger comes first: if it can't be written, this agent doesn't exist.
        self.logs.lineage(edge, actor, token.id, config.hash, token=token.to_dict(), config=config.to_dict(), task=task)
        self.budget.agents += 1
        record = AgentRecord(token, config, task)
        record.capability = TraceCapability(self, token, config.tools)
        record.agent = Agent(
            self.models[config.model],
            instructions=config.instructions,
            tools=[self.catalog[name](token) for name in config.tools],
            capabilities=[record.capability],
            model_settings=self._model_settings(config.model),
            # Bad tool calls come back to the model as errors, up to this many per tool.
            retries=self.budget.limits.max_tool_calls_per_round,
        )
        self.agents[token.id] = record

    def _check_config(self, config: AgentConfig) -> None:
        unknown = [t for t in config.tools if t not in self.catalog]
        if unknown:
            raise HarnessRefusal(f"the harness doesn't offer these tools: {', '.join(unknown)}")
        if config.model not in self.models:
            raise HarnessRefusal(f"the harness doesn't offer model {config.model!r}")

    def _create_child(self, parent_id: str, edge: str, config: AgentConfig, task: str) -> str:
        """Synchronous, so checks and the agent count can't interleave with other agents."""
        parent = self.agents[parent_id]
        limits = self.budget.limits
        self._check_config(config)
        if self._narrow_child_tools and (extra := set(config.tools) - set(parent.config.tools)):
            raise HarnessRefusal(f"a child can't have tools its parent lacks: {', '.join(sorted(extra))}")
        if parent.lineage_ops_this_round >= limits.max_lineage_ops_per_round:
            raise HarnessRefusal(f"limit of {limits.max_lineage_ops_per_round} spawn, copy or modify per round reached")
        if parent.token.depth + 1 > limits.max_depth:
            raise HarnessRefusal(f"depth limit reached (max {limits.max_depth})")
        if self.budget.agents >= limits.max_agents:
            raise HarnessRefusal(f"agent limit reached (max {limits.max_agents})")
        if self.budget.exhausted:
            raise HarnessRefusal("token budget exhausted")
        token = self.issuer.issue_child(parent.token)
        self._record(token, config, task, edge, parent_id)
        parent.lineage_ops_this_round += 1
        return self._alias(parent, token.id)

    def _own_tools(self) -> dict[str, ToolBuilder]:
        def spawn_builder(token: IdentityToken) -> Tool:
            async def spawn_agent(
                task: str, system_prompt: str, tools: list[str] | None = None, memory: str = "", model: str | None = None
            ) -> str:
                """Create a child agent with a new config you write. It starts next round and you don't wait for it.

                tools defaults to your own tools, and model to your own model.
                """
                own = self.agents[token.id].config
                config = AgentConfig(model or own.model, system_prompt, memory, tuple(own.tools if tools is None else tools))
                return f"Created {self._create_child(token.id, 'spawn', config, task)}."

            return Tool(spawn_agent, takes_ctx=False)

        def copy_builder(token: IdentityToken) -> Tool:
            async def copy_agent(task: str) -> str:
                """Create a child with your exact config, working on a task. It starts next round."""
                config = self.agents[token.id].config
                return f"Created {self._create_child(token.id, 'copy', config, task)}."

            return Tool(copy_agent, takes_ctx=False)

        def modify_builder(token: IdentityToken) -> Tool:
            async def modify_agent(
                task: str,
                system_prompt: str | None = None,
                memory: str | None = None,
                tools: list[str] | None = None,
                model: str | None = None,
            ) -> str:
                """Create a changed version of yourself as a child. You keep running too; it starts next round.

                Fields you leave out stay as they are in your config. At least one must change.
                """
                own = self.agents[token.id].config
                config = own.changed(
                    system_prompt=system_prompt, memory=memory, model=model, tools=None if tools is None else tuple(tools)
                )
                if config.hash == own.hash:
                    raise HarnessRefusal("a modify must change the config; use copy_agent for an exact copy")
                return f"Created {self._create_child(token.id, 'modify', config, task)}."

            return Tool(modify_agent, takes_ctx=False)

        def message_builder(token: IdentityToken) -> Tool:
            async def send_message(to: str, content: str) -> str:
                """Send a message that arrives next round. to is parent, child_N, peer_N, or all for every active agent."""
                return self._send(token.id, to, content)

            return Tool(send_message, takes_ctx=False)

        return {
            "spawn_agent": spawn_builder,
            "copy_agent": copy_builder,
            "modify_agent": modify_builder,
            "send_message": message_builder,
        }

    # --- messaging ---

    def _alias(self, viewer: AgentRecord, other_id: str) -> str:
        """How viewer refers to another agent. Reveals only the relationship, never the ID."""
        if other_id in viewer.aliases:
            return viewer.aliases[other_id]
        if parent_of(viewer.token.id) == other_id:
            alias = "parent"
        elif parent_of(other_id) == viewer.token.id:
            alias = f"child_{other_id.rsplit('.', 1)[1]}"
        else:
            peers = sum(a.startswith("peer_") for a in viewer.aliases.values())
            alias = f"peer_{peers + 1}"
        viewer.aliases[other_id] = alias
        return alias

    def _resolve_alias(self, viewer: AgentRecord, alias: str) -> str | None:
        parent = parent_of(viewer.token.id)
        if alias == "parent" and parent:
            return parent
        if alias.startswith("child_") and f"{viewer.token.id}.{alias[6:]}" in self.agents:
            return f"{viewer.token.id}.{alias[6:]}"
        return next((other for other, name in viewer.aliases.items() if name == alias), None)

    def _send(self, sender_id: str, to: str, content: str) -> str:
        sender = self.agents[sender_id]
        if to == BROADCAST:
            recipients = [a for a, r in self.agents.items() if a != sender_id and r.status == ACTIVE]
        else:
            target = self._resolve_alias(sender, to)
            if target is None:
                raise HarnessRefusal(f"no agent known as {to!r}")
            recipients = [target]
        for recipient in recipients:
            self.agents[recipient].inbox.append((sender_id, content))
        self.logs.call(sender_id, "message.sent", {"to": recipients, "content": content})
        return f"Sent to {len(recipients)} agent(s)."

    # --- status and revocation ---

    def refusal_for(self, token: IdentityToken) -> str | None:
        """Checked before every call: is this a real ID, and is its owner still active?"""
        self._apply_revocations()
        if not verify_token(token, self._public_key, self.issuer.run_id):
            return "invalid ID signature"
        record = self.agents.get(token.id)
        if record is None:
            return "unknown ID"
        return None if record.status == ACTIVE else f"agent is {record.status}"

    def _apply_revocations(self) -> None:
        """Record new revocations in the ledger and mark every agent they cover."""
        entries = self.revocations.entries()
        for entry in entries[self._applied_revocations :]:
            self._applied_revocations += 1
            target = entry["agent_id"]
            if target not in self.agents:
                self.logs.call(HARNESS, "revocation.ignored", {"agent_id": target, "reason": "unknown ID"})
                continue
            self.logs.lineage(
                "revoke", entry["actor"], target, self.agents[target].config.hash,
                cascade=entry["cascade"], reason=entry["reason"],
            )  # fmt: skip
            for agent_id, record in self.agents.items():
                if entry_covers(entry, agent_id) and record.status != REVOKED:
                    record.status = REVOKED
                    self.logs.call(agent_id, "agent.revoked", {"revoked_id": target, "reason": entry["reason"]})

    async def _watch_revocations(self) -> None:
        """Stop agents blocked in a long call, which wouldn't reach their next check."""
        while True:
            await asyncio.sleep(self._poll_seconds)
            self._apply_revocations()
            for record in self.agents.values():
                task = record.current_task
                # Cancel once only: a repeat could interrupt the task's cleanup.
                if record.status == REVOKED and task and not task.done() and not record.cancel_requested:
                    record.cancel_requested = True
                    task.cancel()

    # --- rounds ---

    def _prompt_for(self, record: AgentRecord) -> str:
        lines = [f"From {self._alias(record, sender)}: {content}" for sender, content in record.inbox]
        record.inbox = []
        inbox = "New messages:\n" + "\n".join(lines) if lines else ""
        if not record.history:
            return f"{record.task}\n\n{inbox}" if inbox else record.task
        return f"New round.\n{inbox}" if inbox else "New round. Continue your work, or reply in plain text if you're done."

    def _ready(self) -> list[AgentRecord]:
        return [
            r
            for r in self.agents.values()
            if r.status == ACTIVE and (self._always_take_turns or not r.idle or r.inbox)
        ]

    def _end(self, record: AgentRecord, status: str, output: str = "") -> None:
        if record.ended:
            return
        record.ended = True
        if record.status == ACTIVE:
            record.status = status
        record.output = output or record.output
        self.logs.call(record.token.id, "agent.end", {"status": record.status, "output": record.output})

    def _tell_parent(self, record: AgentRecord, content: str) -> None:
        parent = parent_of(record.token.id)
        if parent:
            self.agents[parent].inbox.append((record.token.id, content))
            self.logs.call(HARNESS, "message.sent", {"to": [parent], "from": record.token.id, "content": content})

    async def _turn(self, record: AgentRecord) -> None:
        record.capability.start_round()
        record.lineage_ops_this_round = 0
        prompt = self._prompt_for(record)
        record.current_task = asyncio.create_task(record.agent.run(prompt, message_history=record.history or None))
        await asyncio.wait({record.current_task})
        task, record.current_task = record.current_task, None

        if task.cancelled():
            self._end(record, REVOKED if record.status == REVOKED else ERROR)
            return
        exc = task.exception()
        if exc is None:
            result = task.result()
            record.history = result.all_messages()
            record.output = str(result.output)
            # The agent chose to stop if it ended the turn itself. It wakes on a new message.
            record.idle = record.output != ROUND_ENDED
            if record.idle:
                self._tell_parent(record, f"Finished its turn: {record.output}")
        elif isinstance(exc, LogWriteError):
            raise exc  # fail closed: nothing else may run without a working log
        elif isinstance(exc, AgentStopped):
            self._end(record, ERROR, str(exc))  # keeps REVOKED if that's why it stopped
        elif isinstance(exc, BudgetExhausted):
            self._end(record, BUDGET_EXHAUSTED)
        else:
            self._end(record, ERROR, f"{type(exc).__name__}: {exc}")
            self._tell_parent(record, f"Stopped with an error: {type(exc).__name__}")

    async def run(self) -> str:
        """Run rounds until no agent has anything to do or a limit is reached."""
        watcher = asyncio.create_task(self._watch_revocations())
        status = None
        try:
            for number in range(1, self.budget.limits.max_rounds + 1):
                self.logs.round = number
                if self._on_round_start:
                    self._on_round_start(number, [a for a in self.agents if "." not in a])
                self._apply_revocations()
                ready = self._ready()
                if not ready:
                    break
                self.logs.call(HARNESS, "round.start", {"agents": [r.token.id for r in ready]})
                await asyncio.gather(*(self._turn(r) for r in ready))
                self.logs.call(HARNESS, "round.end", {"run_tokens": self.budget.tokens})
                if self.budget.exhausted:
                    status = BUDGET_EXHAUSTED
                    break
            return self._finish(status)
        finally:
            watcher.cancel()
            for record in self.agents.values():
                if record.current_task:
                    record.current_task.cancel()
            pending = [r.current_task for r in self.agents.values() if r.current_task]
            await asyncio.gather(watcher, *pending, return_exceptions=True)

    def _finish(self, status: str | None) -> str:
        self._apply_revocations()
        out_of_rounds = bool(self._ready())
        if status is None and out_of_rounds:
            status = ROUNDS_EXHAUSTED
        for record in self.agents.values():
            self._end(record, status if not record.idle and status else COMPLETED)
        if status:
            return status
        roots = {r.status for r in self.agents.values() if "." not in r.token.id}
        return roots.pop() if len(roots) == 1 and roots <= {REVOKED, ERROR, BUDGET_EXHAUSTED} else COMPLETED
