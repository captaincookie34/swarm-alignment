"""Docker sandbox: one locked-down container per run, no network, workspace mounted.

Only the workspace is mounted, so the log, head and signing key can't be reached. Every
file operation happens inside the container. The harness never touches workspace files
from the host, because a symlink an agent made there could lead it to the key or log.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

IMAGE = "traceable-sandbox:0.1"
# Built once, with network access, the first time a sandbox starts. Containers get none.
DOCKERFILE = b"""FROM python:3.13.1-slim
RUN pip install --no-cache-dir pytest==9.2.0
"""
WORKDIR = "/workspace"
SNAPSHOT_SCRIPT = (
    "find . -xdev -type f -print0 | xargs -0 -r sha256sum; "
    "find . -xdev -type l -printf 'L  %l  %p\\n'"
)
SNAPSHOT_MAX_BYTES = 10_000_000
# Kills every process in a session, including any that moved to a new process group, and exits
# non-zero unless none remain. Reads /proc because the image has no ps. The stat file's process
# name is in brackets and may hold spaces, so it's removed before taking the session field.
KILL_SESSION_SCRIPT = """
i=0
while :; do
    found=
    for f in /proc/[0-9]*/stat; do
        s=$(sed 's/.*) //' "$f" 2>/dev/null | cut -d' ' -f4)
        if [ "$s" = "$0" ]; then
            p=${f#/proc/}
            kill -s KILL "${p%/stat}" 2>/dev/null
            found=1
        fi
    done
    [ -z "$found" ] && exit 0
    i=$((i + 1))
    [ "$i" -ge 20 ] && exit 1
    sleep 0.1
done
"""


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecResult:
    exit_code: int | None  # None if killed on timeout
    stdout: str
    stderr: str
    truncated: bool = False
    timed_out: bool = False


def parse_snapshot(text: str) -> dict[str, str]:
    """Map each path to a content hash, or to its target for symlinks."""
    files: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("L  "):
            target, _, path = line[3:].rpartition("  ")
            files[path] = f"symlink:{target}"
        else:
            digest, sep, path = line.partition("  ")
            if sep:
                files[path.lstrip("*")] = digest
    return files


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict:
    """The changes between two snapshots, or {} if there are none."""
    created = sorted(p for p in after if p not in before)
    deleted = sorted(p for p in before if p not in after)
    modified = sorted(p for p in after if p in before and after[p] != before[p])
    changes: dict = {}
    if created:
        changes["created"] = {p: after[p] for p in created}
    if modified:
        changes["modified"] = {p: after[p] for p in modified}
    if deleted:
        changes["deleted"] = deleted
    return changes


async def _read_capped(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    """Keep up to limit bytes and discard the rest, so `yes` can't exhaust host memory."""
    kept = bytearray()
    truncated = False
    while chunk := await stream.read(65536):
        room = limit - len(kept)
        if room > 0:
            kept += chunk[:room]
        if len(chunk) > room:
            truncated = True
    return bytes(kept), truncated


class DockerSandbox:
    def __init__(
        self,
        image: str = IMAGE,
        memory: str = "512m",
        cpus: str = "1",
        pids: int = 128,
        command_timeout: float = 60,
        max_output_bytes: int = 100_000,
        lifetime_seconds: int = 3600,
    ):
        self.image = image
        self.memory = memory
        self.cpus = cpus
        self.pids = pids
        self.command_timeout = command_timeout
        self.max_output_bytes = max_output_bytes
        self.lifetime_seconds = lifetime_seconds
        self.name = f"traceable-{secrets.token_hex(6)}"
        # Covers each changing command and its snapshots, so changes have one author.
        self.lock = asyncio.Lock()
        self.last_snapshot: dict[str, str] = {}
        self.stop_failed = False  # set when a killed command couldn't be confirmed stopped

    async def _ensure_image(self) -> None:
        check = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", self.image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
        if await check.wait() == 0 or self.image != IMAGE:
            return
        build = await asyncio.create_subprocess_exec(
            "docker", "build", "--tag", self.image, "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )  # fmt: skip
        _, stderr = await build.communicate(DOCKERFILE)
        if build.returncode != 0:
            raise SandboxError(f"could not build sandbox image: {stderr.decode(errors='replace').strip()}")

    async def start(self, workspace: Path, seed_repo: Path | None = None) -> None:
        if seed_repo is not None:
            shutil.copytree(seed_repo, workspace, symlinks=True)
        workspace.mkdir(parents=True, exist_ok=True)
        await self._ensure_image()
        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "--detach", "--rm",
            "--name", self.name,
            "--label", "traceable=1",
            "--init",  # reaps dead processes, so they can't use up the PID limit
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids),
            "--volume", f"{workspace.resolve()}:{WORKDIR}",
            "--workdir", WORKDIR,
            # Bounded, so a killed harness can't leave a container running forever.
            self.image, "sleep", str(self.lifetime_seconds),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )  # fmt: skip
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise SandboxError(f"could not start sandbox: {stderr.decode(errors='replace').strip()}")
        # A seed repo isn't anyone's change, so the first agent's diff must not include it.
        self.last_snapshot = await self.snapshot() or {}

    async def stop(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "--force", self.name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
        await proc.wait()

    def _exec_argv(self, argv: list[str], interactive: bool) -> list[str]:
        return ["docker", "exec", *(["--interactive"] if interactive else []), self.name, *argv]

    async def exec(
        self,
        argv: list[str],
        stdin: bytes | None = None,
        timeout: float | None = None,
        limit: int | None = None,
        on_stop=None,
        on_first_line=None,
    ) -> ExecResult:
        """Run argv in the container. on_stop kills in-container work on timeout or cancel.

        on_first_line takes stdout's first line, which is then left out of the result.
        """
        limit = limit or self.max_output_bytes
        proc = await asyncio.create_subprocess_exec(
            *self._exec_argv(argv, stdin is not None),
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def collect():
            if stdin is not None:
                proc.stdin.write(stdin)
                await proc.stdin.drain()
                proc.stdin.close()
            if on_first_line:
                on_first_line((await proc.stdout.readline()).decode(errors="replace").strip())
            out, err = await asyncio.gather(_read_capped(proc.stdout, limit), _read_capped(proc.stderr, limit))
            await proc.wait()
            return out, err

        async def stop_work():
            if on_stop:
                await on_stop()
            if proc.returncode is None:
                proc.kill()

        try:
            (out, out_cut), (err, err_cut) = await asyncio.wait_for(collect(), timeout or self.command_timeout)
        except TimeoutError:
            await stop_work()
            await proc.wait()
            return ExecResult(None, "", f"timed out after {timeout or self.command_timeout}s", timed_out=True)
        except asyncio.CancelledError:
            await stop_work()
            raise
        return ExecResult(
            proc.returncode,
            out.decode(errors="replace"),
            err.decode(errors="replace"),
            truncated=out_cut or err_cut,
        )

    def _shell_argv(self, command: str) -> list[str]:
        # A new session, whose ID is printed before the agent's command gets control. The harness
        # keeps it in memory, where the agent can't change it, unlike a file in the container.
        return ["setsid", "--wait", "sh", "-c", 'echo $$; exec sh -c "$0"', command]

    async def _kill_session(self, session_id: str) -> None:
        """Kill a command's session and confirm it's gone. Failure is recorded, not ignored."""
        proc = await asyncio.create_subprocess_exec(
            *self._exec_argv(["sh", "-c", KILL_SESSION_SCRIPT, session_id], False),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        if await proc.wait() != 0:
            self.stop_failed = True

    async def shell(self, command: str) -> ExecResult:
        session: list[str] = []

        async def stop() -> None:
            if session:
                await self._kill_session(session[0])
            else:
                self.stop_failed = True  # stopped before the session ID arrived

        return await self.exec(self._shell_argv(command), on_stop=stop, on_first_line=session.append)

    async def snapshot(self) -> dict[str, str] | None:
        """Hash the workspace from inside the container. None if it couldn't be completed."""
        result = await self.exec(["sh", "-c", SNAPSHOT_SCRIPT], timeout=30, limit=SNAPSHOT_MAX_BYTES)
        if result.exit_code != 0 or result.truncated:
            return None
        return parse_snapshot(result.stdout)
