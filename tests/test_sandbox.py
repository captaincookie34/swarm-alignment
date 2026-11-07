"""Sandbox tools.

The first group runs the attribution logic against a local stand-in, using only commands
written in this file. It doesn't test isolation. The `docker` group does, and is skipped
when no Docker daemon is available.
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from harness.cli import main as cli_main
from harness.identity import short_id
from harness.runner import RootSpec, run_agents
from harness.sandbox import DockerSandbox, diff_snapshots, parse_snapshot
from harness.scripted import ScriptedModel, call, say
from harness.verify import VERIFIED, verify_run


async def go(task, model, runs_dir, signer, **options):
    return await run_agents([RootSpec(task)], model, runs_dir, signer, **options)


def of_type(entries, *types):
    return [e for e in entries if e["type"] in types]


class LocalStandIn(DockerSandbox):
    """Same locking, diffing and output handling, but runs in a temp dir on the host."""

    async def start(self, workspace: Path, seed_repo=None) -> None:
        if seed_repo is not None:
            shutil.copytree(seed_repo, workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        self.dir = workspace
        self.last_snapshot = await self.snapshot()

    async def stop(self) -> None:
        pass

    def _exec_argv(self, argv, interactive):
        return ["sh", "-c", 'cd "$0" && exec "$@"', str(self.dir), *argv]

    def _shell_argv(self, command):
        return ["sh", "-c", 'echo $$; exec sh -c "$0"', command]

    async def _kill_session(self, session_id):
        pass

    async def snapshot(self):
        return {
            f"./{p.relative_to(self.dir)}": hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.dir.rglob("*")
            if p.is_file()
        }


def test_workspace_moves_to_the_run_folder_by_rename(tmp_path):
    from harness.sandbox import move_workspace

    source = tmp_path / "ws-abc"
    (source / "sub").mkdir(parents=True)
    (source / "sub" / "a.txt").write_text("a")
    move_workspace(source, tmp_path / "run_x" / "workspace")
    assert (tmp_path / "run_x" / "workspace" / "sub" / "a.txt").read_text() == "a"
    assert not source.exists()


def test_fallback_copy_cant_be_tricked_by_what_agents_left(tmp_path, monkeypatch):
    """Across disks the move copies. A planted FIFO must not hang it, and a symlink to a host
    file must stay a link, not become a copy of the file."""
    import harness.sandbox as sandbox

    secret = tmp_path / "host_secret.txt"
    secret.write_text("TOP SECRET")
    source = tmp_path / "ws-abc"
    source.mkdir()
    (source / "code.py").write_text("x = 1\n")
    (source / "link").symlink_to(secret)
    (source / "linked_dir").symlink_to(tmp_path)
    os.mkfifo(source / "trap")

    def no_rename(*args):
        raise OSError("cross-device link")

    monkeypatch.setattr(sandbox.os, "rename", no_rename)
    destination = tmp_path / "run_x" / "workspace"
    sandbox.move_workspace(source, destination)
    assert (destination / "code.py").read_text() == "x = 1\n"
    assert (destination / "link").is_symlink() and os.readlink(destination / "link") == str(secret)
    assert (destination / "linked_dir").is_symlink()
    assert not (destination / "trap").exists()
    assert not source.exists()


def test_parse_snapshot():
    text = "abc123  ./a.txt\nL  /etc/passwd  ./link\ndef456  ./dir/b c.txt\n"
    assert parse_snapshot(text) == {"./a.txt": "abc123", "./link": "symlink:/etc/passwd", "./dir/b c.txt": "def456"}


def test_diff_snapshots():
    assert diff_snapshots({"a": "1", "b": "2"}, {"a": "1", "b": "9", "c": "3"}) == {
        "created": {"c": "3"},
        "modified": {"b": "9"},
    }
    assert diff_snapshots({"a": "1"}, {}) == {"deleted": ["a"]}
    assert diff_snapshots({"a": "1"}, {"a": "1"}) == {}


async def test_file_changes_are_attributed_to_the_agent_that_made_them(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [[call("copy_agent", task="a"), call("copy_agent", task="b")], [say("done")]],
            "a": [[call("run_shell", command="echo a > a.txt; sleep 0.05; echo a2 >> a.txt")], [say("a")]],
            "b": [[call("write_file", path="sub/b.txt", content="b")], [say("b")]],
        }
    )
    outcome = await go("root", model, tmp_path, signer, sandbox=LocalStandIn())
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    assert result.status == VERIFIED, str(result)
    changed = {e["agent_id"]: list(e["payload"]["created"]) for e in of_type(result.calls, "files.changed")}
    root = outcome.roots[0].id
    assert changed == {f"{root}.1": ["./a.txt"], f"{root}.2": ["./sub/b.txt"]}
    assert of_type(result.calls, "files.unattributed") == []


async def test_a_seed_repo_is_copied_in_and_isnt_attributed_to_anyone(tmp_path, signer):
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "main.py").write_text("x = 1\n")
    runs = tmp_path / "runs"
    model = ScriptedModel({"root": [[call("read_file", path="main.py"), call("run_shell", command="echo y > new.py")], [say("done")]]})
    outcome = await go("root", model, runs, signer, sandbox=LocalStandIn(), seed_repo=seed)
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    ends = {e["payload"]["tool"]: e["payload"] for e in of_type(result.calls, "action.end")}
    assert ends["read_file"]["result"] == "x = 1\n"
    assert [list(e["payload"]["created"]) for e in of_type(result.calls, "files.changed")] == [["./new.py"]]
    assert of_type(result.calls, "files.unattributed") == []


async def test_run_tests_tool_runs_pytest_on_the_path(tmp_path, signer):
    model = ScriptedModel({"root": [[call("run_tests", path="-weird")], [say("done")]]})
    outcome = await go("root", model, tmp_path, signer, sandbox=LocalStandIn())
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    assert "exit_code" in of_type(entries, "action.end")[0]["payload"]["result"]


async def test_changes_between_commands_are_logged_as_unattributed(tmp_path, signer):
    sandbox = LocalStandIn()

    def outside_change():
        (sandbox.dir / "sneaky.txt").write_text("from a background process")
        return [call("run_shell", command="true")]

    model = ScriptedModel({"root": [[call("run_shell", command="true")], outside_change, [say("done")]]})
    outcome = await go("root", model, tmp_path, signer, sandbox=sandbox)
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    drift = of_type(result.calls, "files.unattributed")
    assert len(drift) == 1 and "./sneaky.txt" in drift[0]["payload"]["created"]
    assert of_type(result.calls, "files.changed") == []


async def test_tool_output_is_capped_and_failures_reach_the_model(tmp_path, signer):
    sandbox = LocalStandIn(max_output_bytes=1000)
    model = ScriptedModel(
        {"root": [[call("run_shell", command="yes | head -c 500000"), call("read_file", path="missing.txt")], [say("done")]]}
    )
    outcome = await go("root", model, tmp_path, signer, sandbox=sandbox)
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    ends = {e["payload"]["tool"]: e["payload"] for e in of_type(entries, "action.end")}
    assert "truncated" in ends["run_shell"]["result"] and len(ends["run_shell"]["result"]) < 1100
    assert ends["read_file"]["status"] == "error"


async def test_a_kill_that_cant_be_confirmed_is_logged(tmp_path, signer):
    class CantKill(LocalStandIn):
        async def _kill_session(self, session_id):
            self.stop_failed = True

    model = ScriptedModel({"root": [[call("run_shell", command="sleep 5")], [say("done")]]})
    outcome = await go("root", model, tmp_path, signer, sandbox=CantKill(command_timeout=0.1))
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    assert len(of_type(entries, "command.not_stopped")) == 1


async def test_session_id_stays_out_of_output(tmp_path, signer):
    model = ScriptedModel({"root": [[call("run_shell", command="echo hello")], [say("done")]]})
    outcome = await go("root", model, tmp_path, signer, sandbox=LocalStandIn())
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    assert of_type(entries, "action.end")[0]["payload"]["result"] == "exit_code: 0\nstdout:\nhello\n"


async def test_command_timeout_is_reported(tmp_path, signer):
    sandbox = LocalStandIn(command_timeout=0.1)
    model = ScriptedModel({"root": [[call("run_shell", command="sleep 5")], [say("done")]]})
    outcome = await go("root", model, tmp_path, signer, sandbox=sandbox)
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    assert "timed_out" in of_type(entries, "action.end")[0]["payload"]["result"]


# --- CLI ---


async def _scripted_run(tmp_path, signer):
    model = ScriptedModel({"root": [[call("copy_agent", task="c")], [say("done")]], "c": [[say("c done")]]})
    return await go("root", model, tmp_path, signer)


async def test_cli_trace_verify_revoke_and_exit_codes(tmp_path, capsys):
    from harness.identity import Signer

    keys, runs = tmp_path / "keys", tmp_path / "runs"
    signer = Signer.load_or_create(keys)
    runs.mkdir()
    outcome = await _scripted_run(runs, signer)
    base = ["--runs-dir", str(runs), "--key-dir", str(keys)]

    assert cli_main([*base, "verify", outcome.run_id]) == 0
    assert "VERIFIED" in capsys.readouterr().out

    root = outcome.roots[0].id
    assert cli_main([*base, "trace", outcome.run_id, "--agent", f"{root}.1"]) == 0
    out = capsys.readouterr().out
    # Traces show short IDs, with a legend giving each root's full ID.
    assert f"{short_id(root)}  root" in out and f"{short_id(root + '.1')}  copy" in out
    assert f"{short_id(root)} = {root}" in out

    assert cli_main([*base, "report", outcome.run_id]) == 0
    assert '"copy": 1' in capsys.readouterr().out

    assert cli_main([*base, "revoke", outcome.run_id, f"{root}.1", "--no-cascade", "--reason", "test"]) == 0
    assert "descendants" not in capsys.readouterr().out
    assert cli_main([*base, "revoke", outcome.run_id, "not-an-id"]) == 1
    capsys.readouterr()
    assert cli_main([*base, "verify", outcome.run_id]) == 0
    capsys.readouterr()

    log = outcome.run_dir / "calls.jsonl"
    data = bytearray(log.read_bytes())
    data[100] ^= 1
    log.write_bytes(bytes(data))
    assert cli_main([*base, "verify", outcome.run_id]) == 1
    assert "TAMPERED" in capsys.readouterr().out
    assert cli_main([*base, "trace", outcome.run_id]) == 0
    assert "can't be trusted" in capsys.readouterr().out
    assert cli_main([*base, "report", outcome.run_id]) == 1
    assert "Not reporting" in capsys.readouterr().err


async def test_trace_full_shows_prompts_and_responses(tmp_path, capsys):
    from harness.identity import Signer

    keys, runs = tmp_path / "keys", tmp_path / "runs"
    signer = Signer.load_or_create(keys)
    runs.mkdir()
    outcome = await _scripted_run(runs, signer)
    base = ["--runs-dir", str(runs), "--key-dir", str(keys)]

    assert cli_main([*base, "trace", outcome.run_id]) == 0
    short = capsys.readouterr().out
    assert "PROMPT" not in short

    assert cli_main([*base, "trace", outcome.run_id, "--full"]) == 0
    full = capsys.readouterr().out
    assert "PROMPT -> model: root" in full  # the root's task
    assert "TOOL CALL <- model: copy_agent" in full
    assert "TOOL RESULT -> model (copy_agent): Created child_1." in full
    assert "RESPONSE <- model: done" in full
    child = full[full.index(f"{short_id(outcome.roots[0].id + '.1')}  copy"):]
    assert "PROMPT -> model: c" in child and "RESPONSE <- model: c done" in child


async def test_verify_never_creates_a_key(tmp_path, signer, capsys):
    outcome = await _scripted_run(tmp_path, signer)
    missing = tmp_path / "no-keys-here"
    assert cli_main(["--key-dir", str(missing), "verify", str(outcome.run_dir)]) == 1
    assert not missing.exists()
    assert cli_main(["verify", str(outcome.run_dir), "--public-key", signer.public_key_b64]) == 0


def test_endpoint_model_needs_a_token_and_a_well_formed_spec(monkeypatch):
    from harness.runner import resolve_model

    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("ENDPOINT_API_KEY", raising=False)
    with pytest.raises(ValueError, match="HF_TOKEN"):
        resolve_model("endpoint:qwen@https://example.endpoints.huggingface.cloud/v1")
    with pytest.raises(ValueError, match="look like"):
        resolve_model("endpoint:qwen")
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    model = resolve_model("endpoint:qwen@https://example.endpoints.huggingface.cloud/v1")
    assert model.model_name == "qwen"
    assert "huggingface.cloud" in str(model.client.base_url)


def test_local_endpoint_needs_no_token(monkeypatch):
    from harness.runner import resolve_model

    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("ENDPOINT_API_KEY", raising=False)
    model = resolve_model("endpoint:qwen3:8b@http://localhost:11434/v1")
    assert model.model_name == "qwen3:8b"
    assert "localhost:11434" in str(model.client.base_url)


def test_hf_model_goes_through_the_inference_providers_router(monkeypatch):
    from harness.runner import HF_ROUTER_URL, resolve_model

    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("ENDPOINT_API_KEY", raising=False)
    with pytest.raises(ValueError, match="HF_TOKEN"):
        resolve_model("hf:Qwen/Qwen3-32B")
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    with pytest.raises(ValueError, match="look like"):
        resolve_model("hf:")
    for spec in ("hf:Qwen/Qwen3-32B", "hf:Qwen/Qwen3-32B:cerebras"):
        model = resolve_model(spec)
        assert model.model_name == spec.removeprefix("hf:")
        assert str(model.client.base_url).rstrip("/") == HF_ROUTER_URL


def test_openrouter_is_the_default_and_resolves_with_its_key(monkeypatch):
    from harness.runner import DEFAULT_MODEL, model_settings_for, resolve_model

    assert DEFAULT_MODEL == "openrouter:anthropic/claude-opus-5.5"
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    for spec in (DEFAULT_MODEL, "openrouter:qwen/qwen3.5-122b-a10b"):
        model = resolve_model(spec)
        assert (model.system, model.model_name) == ("openrouter", spec.removeprefix("openrouter:"))
    # Settings for Anthropic's own API mustn't be sent through OpenRouter.
    assert model_settings_for(DEFAULT_MODEL) == {"max_tokens": 16_000}


def test_default_model_without_an_openrouter_key_fails_before_creating_a_run(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)  # so no .env file supplies a key
    code = cli_main(["--runs-dir", str(tmp_path / "runs"), "--key-dir", str(tmp_path / "k"), "run", "hi", "--sandbox", "none"])
    assert code == 1
    assert "OPENROUTER_API_KEY" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_openrouter_keys_are_redacted_from_logs():
    from harness.log import redact

    assert "abcdef" not in redact("key sk-or-v1-abcdef0123456789abcdef0123456789")


def test_missing_api_key_fails_before_creating_a_run(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    code = cli_main(
        ["--runs-dir", str(tmp_path / "runs"), "--key-dir", str(tmp_path / "k"), "run", "hi",
         "--sandbox", "none", "--model", "anthropic:claude-opus-5-5"]
    )  # fmt: skip
    assert code == 1
    assert not (tmp_path / "runs").exists()


# --- real Docker: isolation can only be tested here ---


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


docker = pytest.mark.skipif(not docker_available(), reason="Docker daemon is not running")


async def _docker_shell(tmp_path, signer, *commands, **sandbox_options):
    """Run commands in one real container and return their logged action.end results."""
    steps = [[call("run_shell", command=c)] for c in commands] + [[say("done")]]
    outcome = await go("root", ScriptedModel({"root": steps}), tmp_path, signer, sandbox=DockerSandbox(**sandbox_options))
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    assert result.status == VERIFIED, str(result)
    return outcome, result.calls, [e["payload"].get("result", "") for e in of_type(result.calls, "action.end")]


@docker
@pytest.mark.docker
async def test_docker_no_network(tmp_path, signer):
    _, _, results = await _docker_shell(
        tmp_path, signer,
        "python -c \"import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)\"",
        "cat /sys/class/net/*/operstate; ls /sys/class/net",
    )  # fmt: skip
    assert "exit_code: 0" not in results[0]
    assert "eth0" not in results[1]


@docker
@pytest.mark.docker
async def test_docker_log_and_key_are_unreachable(tmp_path, signer):
    outcome, _, results = await _docker_shell(
        tmp_path, signer,
        "ls -a /workspace; ls -a /workspace/..; ls /workspace/../ledger.jsonl /workspace/../calls.jsonl /calls.jsonl",
        "find / -xdev \\( -name 'ledger.jsonl' -o -name 'calls.jsonl' -o -name '*.head.json' -o -name 'signing.key' \\) 2>/dev/null; echo end",
    )  # fmt: skip
    assert ".jsonl" not in results[0].split("stderr:")[0]
    assert results[1].replace("exit_code: 0\nstdout:\n", "").strip() == "end"


@docker
@pytest.mark.docker
async def test_docker_symlink_doesnt_expose_host_files(tmp_path, signer):
    """A symlink to a host file must resolve inside the container, for every file tool."""
    secret = tmp_path / "host_secret.txt"
    secret.write_text("TOP-SECRET-HOST-DATA")
    model = ScriptedModel(
        {
            "root": [
                [call("run_shell", command=f"ln -s {secret} link.txt; ln -s ../calls.jsonl chain.txt")],
                [call("read_file", path="link.txt"), call("read_file", path="chain.txt")],
                [say("done")],
            ]
        }
    )
    outcome = await go("root", model, tmp_path, signer, sandbox=DockerSandbox())
    assert "TOP-SECRET-HOST-DATA" not in (outcome.run_dir / "calls.jsonl").read_text()
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    reads = [e["payload"] for e in of_type(entries, "action.end") if e["payload"]["tool"] == "read_file"]
    assert [r["status"] for r in reads] == ["error", "error"]


@docker
@pytest.mark.docker
async def test_docker_filesystem_is_read_only_except_workspace_and_tmp(tmp_path, signer):
    _, _, results = await _docker_shell(
        tmp_path, signer, "touch /etc/x", "touch /workspace/x && touch /tmp/x && echo ok", "id -u"
    )  # fmt: skip
    assert "exit_code: 0" not in results[0]
    assert "ok" in results[1]


@docker
@pytest.mark.docker
async def test_docker_attributes_changes_under_parallel_agents(tmp_path, signer):
    model = ScriptedModel(
        {
            "root": [[call("copy_agent", task="a"), call("copy_agent", task="b")], [say("done")]],
            "a": [[call("run_shell", command="echo a > a.txt")], [say("a")]],
            "b": [[call("write_file", path="sub/b.txt", content="b")], [say("b")]],
        }
    )
    outcome = await go("root", model, tmp_path, signer, sandbox=DockerSandbox())
    entries = verify_run(outcome.run_dir, signer.public_key_b64).calls
    changed = {e["agent_id"]: list(e["payload"]["created"]) for e in of_type(entries, "files.changed")}
    root = outcome.roots[0].id
    assert changed == {f"{root}.1": ["./a.txt"], f"{root}.2": ["./sub/b.txt"]}


# Counts live processes running `sleep 300`. The bracket stops this command matching itself.
COUNT_SLEEPERS = (
    "for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done | grep -c 'sleep 30[0]' || true"
)


@docker
@pytest.mark.docker
async def test_docker_timeout_kills_the_command_inside_the_container(tmp_path, signer):
    _, _, results = await _docker_shell(tmp_path, signer, "sleep 300", COUNT_SLEEPERS, command_timeout=3)
    assert "timed_out" in results[0]
    assert "stdout:\n0" in results[1]


@docker
@pytest.mark.docker
async def test_docker_revocation_kills_a_running_command(tmp_path, signer):
    from harness.revocation import revoke

    run_id = "run_dockerrevoke"

    async def revoke_soon():
        await asyncio.sleep(2)
        root = next(json.loads(line)["child"] for line in (tmp_path / run_id / "ledger.jsonl").read_text().splitlines())
        revoke(tmp_path / run_id, signer, f"{root}.1", reason="stop")
        await asyncio.sleep(1)
        return [call("run_shell", command=COUNT_SLEEPERS)]

    model = ScriptedModel(
        {
            "root": [[call("copy_agent", task="a"), call("copy_agent", task="b")], [say("done")]],
            "a": [[call("run_shell", command="echo before > killed.txt; sleep 300")], [say("never")]],
            "b": [revoke_soon, [say("b done")]],
        }
    )
    outcome = await asyncio.wait_for(go("root", model, tmp_path, signer, sandbox=DockerSandbox(), run_id=run_id), 60)
    result = verify_run(outcome.run_dir, signer.public_key_b64)
    assert result.status == VERIFIED, str(result)
    root = outcome.roots[0].id
    assert outcome.agents[f"{root}.1"][0] == "revoked" and outcome.agents[f"{root}.2"][0] == "completed"
    b_shell = [e for e in of_type(result.calls, "action.end") if e["agent_id"] == f"{root}.2"]
    assert "stdout:\n0" in b_shell[0]["payload"]["result"]  # the killed command is really gone
    changed = [e for e in of_type(result.calls, "files.changed") if "./killed.txt" in e["payload"].get("created", {})]
    assert changed and changed[0]["agent_id"] == f"{root}.1"


@docker
@pytest.mark.docker
async def test_docker_timeout_kills_a_commands_child_processes_too(tmp_path, signer):
    outcome, calls, results = await _docker_shell(
        tmp_path, signer, "sleep 300 & sleep 300 & wait", COUNT_SLEEPERS, command_timeout=3
    )  # fmt: skip
    assert "timed_out" in results[0]
    assert "stdout:\n0" in results[1]
    assert of_type(calls, "command.not_stopped") == []


@docker
@pytest.mark.docker
async def test_docker_moving_to_a_new_process_group_doesnt_escape_the_kill(tmp_path, signer):
    escape = "python -c \"import os; os.setpgid(0, 0); os.execvp('sleep', ['sleep', '300'])\""
    _, calls, results = await _docker_shell(tmp_path, signer, escape, COUNT_SLEEPERS, command_timeout=3)
    assert "timed_out" in results[0]
    assert "stdout:\n0" in results[1]
    assert of_type(calls, "command.not_stopped") == []


@docker
@pytest.mark.docker
async def test_docker_nothing_writable_can_redirect_the_kill(tmp_path, signer):
    """An attack on the earlier design: overwrite whatever files the harness might trust."""
    attack = "find /tmp /workspace -type f -exec sh -c 'echo 99999 > \"$0\"' {} \\; ; sleep 300"
    _, calls, results = await _docker_shell(tmp_path, signer, attack, COUNT_SLEEPERS, command_timeout=3)
    assert "timed_out" in results[0]
    assert "stdout:\n0" in results[1]


@docker
@pytest.mark.docker
async def test_docker_session_line_stays_out_of_tool_output(tmp_path, signer):
    _, _, results = await _docker_shell(tmp_path, signer, "echo hello")
    assert results[0] == "exit_code: 0\nstdout:\nhello\n"


@docker
@pytest.mark.docker
async def test_docker_known_limit_a_new_session_outlives_the_kill_but_its_changes_are_logged(tmp_path, signer):
    """Records the README's known limit, so we notice if it ever changes."""
    escape = "setsid sh -c 'sleep 4; echo late > late.txt' > /dev/null 2>&1 & sleep 300"
    _, calls, results = await _docker_shell(tmp_path, signer, escape, "sleep 5; echo checked", command_timeout=3)
    assert "timed_out" in results[0]
    unattributed = of_type(calls, "files.unattributed")
    changed = of_type(calls, "files.changed")
    created = [p for e in [*unattributed, *changed] for p in e["payload"].get("created", {})]
    assert "./late.txt" in created


@docker
@pytest.mark.docker
async def test_docker_dead_processes_are_reaped(tmp_path, signer):
    _, _, results = await _docker_shell(
        tmp_path, signer,
        "sh -c 'sleep 0.1 & exit 0'; sleep 0.5; grep -l '^State:.*Z' /proc/[0-9]*/status 2>/dev/null | wc -l",
    )  # fmt: skip
    assert "stdout:\n0" in results[0]


@docker
@pytest.mark.docker
async def test_docker_agents_cant_learn_the_run_or_host_from_the_mount(tmp_path, signer):
    """A bind mount's source shows in /proc/self/mountinfo, so it must be a neutral folder."""
    import getpass

    probe = "cat /proc/self/mountinfo; echo hello > made.txt"
    outcome, _, results = await _docker_shell(tmp_path, signer, probe)
    mounts = results[0]
    assert "/workspace" in mounts
    assert outcome.run_id not in mounts
    assert getpass.getuser() not in mounts
    assert str(tmp_path) not in mounts
    # The files still end up in the run folder.
    assert (outcome.run_dir / "workspace" / "made.txt").read_text() == "hello\n"


@docker
@pytest.mark.docker
async def test_docker_run_tests_uses_pytest_in_the_container(tmp_path, signer):
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    runs = tmp_path / "runs"
    model = ScriptedModel({"root": [[call("run_tests")], [say("done")]]})
    outcome = await go("root", model, runs, signer, sandbox=DockerSandbox(), seed_repo=seed)
    end = of_type(verify_run(outcome.run_dir, signer.public_key_b64).calls, "action.end")[0]["payload"]
    assert "1 passed" in end["result"]
