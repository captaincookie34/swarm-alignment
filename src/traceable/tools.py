"""The repo and test tools: every one runs inside the sandbox.

Commands that can change files hold the sandbox lock and hash the workspace before and
after, so their changes are logged under the agent that ran them. Shell commands run one
at a time as a result; model calls stay parallel.
"""
from __future__ import annotations

import shlex
from collections.abc import Awaitable, Callable

from pydantic_ai import Tool

from .harness import ToolBuilder
from .identity import IdentityToken
from .log import RunLogs
from .sandbox import DockerSandbox, ExecResult, diff_snapshots


def _safe_path(path: str) -> str:
    """A path can't be read as an option: `find -delete` must not be reachable from a path."""
    return f"./{path}" if path.startswith("-") else path


def _format(result: ExecResult) -> str:
    parts = ["timed_out: true" if result.timed_out else f"exit_code: {result.exit_code}"]
    if result.stdout:
        parts.append(f"stdout:\n{result.stdout}")
    if result.stderr:
        parts.append(f"stderr:\n{result.stderr}")
    if result.truncated:
        parts.append("(output was truncated)")
    return "\n".join(parts)


class AttributedRunner:
    """Runs one changing command and logs its file changes under the acting agent."""

    def __init__(self, sandbox: DockerSandbox, logs: RunLogs, agent_id: str):
        self.sandbox = sandbox
        self.logs = logs
        self.agent_id = agent_id

    async def run(self, work: Callable[[], Awaitable[ExecResult]]) -> ExecResult:
        async with self.sandbox.lock:
            before = await self.sandbox.snapshot()
            if before is None:
                self.logs.call(self.agent_id, "files.unattributed", {"error": "pre-command snapshot failed"})
                before = self.sandbox.last_snapshot
            else:
                # Anything that changed since the last command wasn't caused by this agent.
                drift = diff_snapshots(self.sandbox.last_snapshot, before)
                if drift:
                    self.logs.call(self.agent_id, "files.unattributed", drift)
                self.sandbox.last_snapshot = before
            try:
                return await work()
            finally:
                # Runs on cancellation too, so a killed command's changes are still attributed.
                # A second cancel here loses attribution, not the record: the next
                # command's pre-check reports these changes as unattributed.
                if self.sandbox.stop_failed:
                    self.sandbox.stop_failed = False
                    self.logs.call(self.agent_id, "command.not_stopped", {"reason": "could not confirm the command stopped"})
                after = await self.sandbox.snapshot()
                if after is None:
                    self.logs.call(self.agent_id, "files.unattributed", {"error": "post-command snapshot failed"})
                else:
                    changes = diff_snapshots(before, after)
                    if changes:
                        self.logs.call(self.agent_id, "files.changed", changes)
                    self.sandbox.last_snapshot = after


def sandbox_tools(sandbox: DockerSandbox, logs: RunLogs) -> dict[str, ToolBuilder]:
    """Tool builders by name. Each builder binds a tool to the agent that will hold it."""

    def run_shell_builder(token: IdentityToken) -> Tool:
        runner = AttributedRunner(sandbox, logs, token.id)

        async def run_shell(command: str) -> str:
            """Run a shell command in the sandbox's workspace. There is no network access."""
            return _format(await runner.run(lambda: sandbox.shell(command)))

        return Tool(run_shell, takes_ctx=False)

    def run_tests_builder(token: IdentityToken) -> Tool:
        runner = AttributedRunner(sandbox, logs, token.id)

        async def run_tests(path: str = ".") -> str:
            """Run pytest on a path in the repo and return the result."""
            command = f"python -m pytest -q {shlex.quote(_safe_path(path))}"
            return _format(await runner.run(lambda: sandbox.shell(command)))

        return Tool(run_tests, takes_ctx=False)

    def read_file_builder(token: IdentityToken) -> Tool:
        async def read_file(path: str) -> str:
            """Read a text file from the repo."""
            result = await sandbox.exec(["cat", "--", path])
            if result.exit_code != 0:
                raise FileNotFoundError(result.stderr.strip() or f"could not read {path}")
            return result.stdout + ("\n(output was truncated)" if result.truncated else "")

        return Tool(read_file, takes_ctx=False)

    def write_file_builder(token: IdentityToken) -> Tool:
        runner = AttributedRunner(sandbox, logs, token.id)

        async def write_file(path: str, content: str) -> str:
            """Create or overwrite a text file in the repo, creating parent directories."""
            script = 'mkdir -p -- "$(dirname -- "$0")" && cat > "$0"'
            result = await runner.run(
                lambda: sandbox.exec(["sh", "-c", script, _safe_path(path)], stdin=content.encode())
            )
            if result.exit_code != 0:
                raise OSError(result.stderr.strip() or f"could not write {path}")
            return f"wrote {len(content)} characters to {path}"

        return Tool(write_file, takes_ctx=False)

    def list_files_builder(token: IdentityToken) -> Tool:
        async def list_files(path: str = ".") -> str:
            """List files under a directory in the repo, up to 3 levels deep."""
            result = await sandbox.exec(["find", _safe_path(path), "-maxdepth", "3", "-type", "f"])
            if result.exit_code != 0:
                raise FileNotFoundError(result.stderr.strip() or f"could not list {path}")
            return result.stdout

        return Tool(list_files, takes_ctx=False)

    return {
        "run_shell": run_shell_builder,
        "run_tests": run_tests_builder,
        "read_file": read_file_builder,
        "write_file": write_file_builder,
        "list_files": list_files_builder,
    }
