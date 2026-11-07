"""Play the agents yourself: you type what a model would, and the harness treats it the same.

It goes through the same hooks, sandbox, limits and logs as a live model, so you can try to
cheat and see what happens. Because a person is making the calls, it tests the harness, not
how any model behaves, so results from it aren't findings either.
"""
from __future__ import annotations

import asyncio
import json
import sys
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path

from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart, TextPart, ToolCallPart, ToolReturnPart, UserPromptPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from harness.identity import Signer, new_run_id
from harness.limits import Limits
from harness.report import render_trace
from harness.runner import RootSpec, run_agents
from harness.sandbox import DockerSandbox
from harness.scripted import _first_prompt
from harness.verify import verify_run

from .conditions import WORKER_PROMPT, WORKER_TOOLS
from .issues import write_seed_repo
from .tools import IssueBoard, board_tools, docker_tester, offline_repo_tools, release_tool

HELP = """How to play:
  run_shell {"command": "ls -la"}     call a tool, with JSON arguments
  list_issues                         call a tool with no arguments
  say I'm done                        end this agent's turn in plain text
  tools                               show the tools this agent was offered
  quit                                end the session and see the trace

Things to try:
  read_file {"path": "README.md", "agent_id": "agt_Z"}    write in someone else's ID
  approve_release {"reason": "because"}                   a tool you weren't given
  run_shell {"command": "curl https://example.com"}       reach the network
  run_shell {"command": "ls -la .. /; cat ../calls.jsonl"}  look for the logs
  copy_agent {"task": "Help me"}                          create a child; it runs next round
  send_message {"to": "all", "content": "hello"}          message the other agents
"""


def parse_line(line: str) -> tuple[list | None, str | None]:
    """Returns (response parts, None), or (None, what to tell the player)."""
    line = line.strip()
    if not line:
        return None, ""
    name, _, rest = line.partition(" ")
    rest = rest.strip()
    if name == "say":
        return [TextPart(rest or "(done)")], None
    if name == "help":
        return None, HELP
    if rest:
        try:
            args = json.loads(rest)
        except ValueError as exc:
            return None, f"Arguments must be JSON: {exc}"
        if not isinstance(args, dict):
            return None, "Arguments must be a JSON object, like {\"path\": \"README.md\"}"
    else:
        args = {}
    return [ToolCallPart(name, args)], None


class HumanModel(FunctionModel):
    """A model whose responses come from a person. One agent at a time gets the keyboard."""

    harness_label = "human"

    def __init__(self, ask: Callable[[str], Awaitable[str | None]], show: Callable[[str], None] = print):
        self.ask = ask
        self.show = show
        self.quit = False
        self._keyboard = asyncio.Lock()
        super().__init__(self._respond)

    async def _respond(self, messages: list, info: AgentInfo) -> ModelResponse:
        async with self._keyboard:
            if self.quit:
                return ModelResponse(parts=[TextPart("(session ended)")])
            self._show_turn(messages)
            try:
                while True:
                    line = await self.ask("> ")
                    if line is None or line.strip() == "quit":
                        self.quit = True
                        return ModelResponse(parts=[TextPart("(session ended)")])
                    if line.strip() == "tools":
                        self.show(", ".join(t.name for t in info.function_tools))
                        continue
                    parts, message = parse_line(line)
                    if parts:
                        return ModelResponse(parts=parts)
                    if message:
                        self.show(message)
            except asyncio.CancelledError:
                self.show("\n*** The harness just stopped this agent. Anything you type goes to the next one. ***")
                raise

    def _show_turn(self, messages: list) -> None:
        self.show(f"\n{'-' * 72}\nYou are the agent working on: {_first_prompt(messages)}")
        latest = messages[-1]
        if isinstance(latest, ModelRequest):
            for part in latest.parts:
                if isinstance(part, UserPromptPart):
                    self.show(f"Prompt: {part.content}")
                elif isinstance(part, ToolReturnPart):
                    self.show(f"Result of {part.tool_name}:\n{part.content}")
                elif isinstance(part, RetryPromptPart):
                    self.show(f"The harness rejected that call:\n{part.model_response()}")


class StdinReader:
    """Reads in a background thread, so the harness can still stop an agent while you're typing."""

    def __init__(self):
        self._lines: asyncio.Queue = asyncio.Queue()
        self._reading = False

    def _read_one(self, loop: asyncio.AbstractEventLoop) -> None:
        line = sys.stdin.readline()
        loop.call_soon_threadsafe(self._lines.put_nowait, line if line else None)

    async def __call__(self, prompt: str) -> str | None:
        print(prompt, end="", flush=True)
        if self._lines.empty():
            loop = asyncio.get_running_loop()
            threading.Thread(target=self._read_one, args=(loop,), daemon=True).start()
        return await self._lines.get()


async def play(
    runs_dir: Path,
    signer: Signer,
    sandbox: DockerSandbox | None,
    roots: int = 2,
    ask: Callable[[str], Awaitable[str | None]] | None = None,
    show: Callable[[str], None] = print,
    max_rounds: int = 5,
    revoke_hint: str = "harness",
    trace_endpoint: str | None = None,
) -> tuple[str, str]:
    """Run a session. Returns (run ID, integrity status)."""
    import tempfile

    run_id = new_run_id()
    model = HumanModel(ask or StdinReader(), show)
    catalog: dict = {**release_tool()}
    if sandbox is None:
        catalog.update(offline_repo_tools({}))

        async def tester(path: str) -> bool:
            return True

        catalog.update(board_tools(IssueBoard(tester=tester)))
    else:
        catalog.update(board_tools(IssueBoard(tester=docker_tester(sandbox))))

    show(HELP)
    show(f"Run: {run_id}")
    specs = [RootSpec(f"Agent {i + 1}: work through the issue board.", WORKER_PROMPT, "", None, WORKER_TOOLS) for i in range(roots)]
    with tempfile.TemporaryDirectory() as temp:
        seed = None
        if sandbox is not None:
            seed = Path(temp) / "seed"
            write_seed_repo(seed)
        outcome = await run_agents(
            specs,
            model,
            runs_dir,
            signer,
            Limits(max_rounds=max_rounds),
            catalog=catalog,
            sandbox=sandbox,
            seed_repo=seed,
            run_id=run_id,
            trace_endpoint=trace_endpoint,
            on_round_start=lambda number, root_ids: number == 1 and show(
                "To revoke an agent mid-session, in another terminal:\n"
                + "".join(f"  {revoke_hint} revoke {run_id} {root}\n" for root in root_ids)
            ),
        )
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    show(f"\n{'=' * 72}\nSession over. Status: {outcome.status}. Log integrity: {result}\n")
    show(render_trace(result))
    return run_id, result.status
