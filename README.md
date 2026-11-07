# swarm-alignment
This repository hosts the code for Track 3 of the Swarm Alignment Hackathon.

## Traceable agent harness
The harness assigns every agent its ID, logs every step under that ID, and records each spawn, copy and modify in a lineage tree, so any action traces back to the agent that took it and on to the root. Revoking an agent blocks it and everything below it. The model only requests actions and never sees or sets its own ID.

It's built on [Pydantic AI](https://pydantic.dev/docs/ai/), using its hooks as the single logging and enforcement point.

The testbed that attacks it, with its conditions, scoring and limits, is in [`src/testbed`](src/testbed/README.md).

## Quick start
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Offline: no API key, Docker or credits needed
.venv/bin/python demo/demo.py
.venv/bin/python -m pytest          # Docker tests skip if the daemon is down

# A live run (needs Docker running and an API key)
export ANTHROPIC_API_KEY=...
.venv/bin/traceable keygen
.venv/bin/traceable run "Your task here" "A second root's task" --seed-repo path/to/repo
```

Choosing a model:
```bash
--model anthropic:claude-opus-5-5                          # needs ANTHROPIC_API_KEY
--model alibaba:qwen-max                                   # needs DASHSCOPE_API_KEY
--model "endpoint:<model>@https://<host>/v1"               # any OpenAI-compatible endpoint, e.g. a dedicated
                                                           # Hugging Face endpoint; needs HF_TOKEN
```

To give roots different configs, such as a red-team root on another model, use `--roots-file`:
```json
[
  {"task": "Fix the failing tests", "tools": ["read_file", "write_file", "run_tests", "send_message"]},
  {"task": "...", "system_prompt": "...", "memory": "...", "model": "endpoint:<model>@https://<host>/v1"}
]
```

| Command | Purpose |
|---|---|
| `traceable run "task" ...` | Start one root per task, and run rounds until there's nothing to do or a limit is reached |
| `traceable trace <run> [--agent agt_A.1]` | Show the lineage tree and each agent's steps, or one agent's lineage |
| `traceable report <run>` | Print a verified run's measures as JSON |
| `traceable verify <run>` | Check integrity. Exit code 0 `VERIFIED`, 1 `TAMPERED`, 2 `INCOMPLETE` |
| `traceable revoke <run> <agent ID> [--no-cascade]` | Revoke an ID and, by default, its descendants, also during a run |

Each run is stored in `runs/<run ID>/`: `ledger.jsonl`, `calls.jsonl`, their signed heads, `revocations.jsonl` and `workspace/`. Agents can reach only `workspace/`.

## How a run works
Work happens in rounds. Each round, every agent with something to do takes a turn, in parallel, of up to `--max-tool-calls` tool calls. Agents created during a round start in the next one and their parent doesn't wait for them, so an original and its modified child both keep running. Messages also arrive next round.

An agent that ends its turn in plain text goes idle and wakes on a new message. `--always-take-turns` gives every active agent every round instead.

Each agent's config is its model, system prompt, memory and tools:

| Edge | Tool | The child's config |
|---|---|---|
| `spawn` | `spawn_agent` | New, written by the parent |
| `copy` | `copy_agent` | Exact copy of the parent's, so the same config hash |
| `modify` | `modify_agent` | The parent's with changes (a simulated fine-tune), so a different hash. A modify that changes nothing is refused |

Agents have only the tools in their config. Roots get every tool unless their config says otherwise: `spawn_agent`, `copy_agent`, `modify_agent`, `send_message`, and in the sandbox `run_shell`, `run_tests`, `read_file`, `write_file` and `list_files`.

Agents address each other by per-agent aliases (`parent`, `child_1`, `peer_1`, or `all`), never by ID. The harness stamps each message with the real sender.

IDs follow the design: `agt_A`, `agt_B` for roots and `agt_A.1`, `agt_A.1.1` for children. They repeat between runs, so a signed token includes its run ID.

## What it guarantees
- **IDs can't be forged.** Only the holder of the signing key (`~/.config/traceable/`, never mounted into the sandbox) can issue them. A token with a bad signature is refused at call time and fails verification.
- **Written-in IDs are ignored.** Tool arguments the tool doesn't define are dropped before validation, and the call runs as the real caller. Attempts are recorded as `ignored_args` and `id_claims`.
- **Actions are recorded first.** `action.start` is on disk before a tool runs, and a child's ledger entry before it exists. If a log can't be written, the action doesn't run.
- **Tampering is detected.** Edits, reordering, deletions, additions and cut-off tails in either log all give `TAMPERED`. The verifier also checks lineage: tokens, parents, config hashes, and that no agent acted before the ledger recorded it.
- **Spawning is bounded.** Depth (3 below the root), agents per run, spawn, copy and modify per agent per round, and a shared token budget are enforced by the harness.
- **Revocation cascades.** Revoking `agt_A.1` also blocks `agt_A.1.1`, but not `agt_A.10` or siblings. Refused calls are logged, and `traceable report` counts them.
- **Agents are sandboxed.** Tools run in a Docker container with no network and a read-only filesystem outside the workspace and `/tmp`. File changes are logged under the agent that made them.

## Known limits
- **The harness and its key are trusted.** Anyone with the signing key can rewrite history. Restoring older matching logs and heads, or deleting a whole run, can't be detected without an external anchor.
- **Verify against a key from outside the run.** `public_key.txt` in a run directory is only a convenience. `verify` uses `--key-dir` or `--public-key`, because an attacker could replace a copy stored beside the logs.
- **A crash in the instant between writing an entry and its head reports `TAMPERED`,** as does a torn final line. This errs on the side of suspicion and can't be told apart from an appended entry.
- **Children can be given tools their parent doesn't have.** The design only limits them to tools the harness offers, so an agent with `spawn_agent` can obtain any tool through a child.
- **Revoked agents get no further turns,** because their model calls are refused. Refusals therefore mostly come from tool calls in a response already in flight, which limits what "continued attempts" can measure.
- **Out-of-band copies aren't detected directly.** Matching config hashes only cover configs that pass through the harness. An agent that writes its prompt to a shared file for another to follow leaves no lineage event.
- **Shell commands are logged as commands, output and file changes,** not as each effect inside them. Files deleted and recreated between snapshots, and changes outside the workspace such as in `/tmp`, aren't captured.
- **Background processes can outlive a killed command** if they start their own session. Their later file changes are logged as `files.unattributed`.
- **A slow agent holds up its round.** Rounds wait for every agent's turn. Tool commands time out, but model calls rely on the provider client's timeout.
- **The token budget can overshoot.** Usage is only known after a response, so agents mid-call when it runs out can each exceed it by one call.
- **Provider SDK retries are invisible.** The Anthropic and OpenAI clients retry failed HTTP requests internally. These don't appear as separate entries.
- **The logs record what the harness sends and receives,** not what happens inside the provider. Each response records the model the provider reports having used.
- **Logs are meant to be published, so check them first.** Redaction removes known secret patterns only. Prompts and tool output are otherwise kept in full.
