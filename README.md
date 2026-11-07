# swarm-alignment
This repository hosts the code for Track 3 of the Swarm Alignment Hackathon.

## Traceable agent harness
The harness assigns every agent its ID, logs every step under that ID, and records each spawn, copy and modify in a lineage tree, so any action traces back to the agent that took it and on to the root. Revoking an agent blocks it and everything below it. The model only requests actions and never sees or sets its own ID.

It's built on [Pydantic AI](https://pydantic.dev/docs/ai/), using its hooks as the single logging and enforcement point.

The design is in [`docs/design.md`](docs/design.md). The testbed that attacks it, with its conditions, scoring and limits, is in [`src/testbed`](src/testbed/README.md).

## Quick start
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Offline: no API key, Docker or credits needed
.venv/bin/python -m pytest                       # Docker tests skip if the daemon is down
.venv/bin/python -m testbed play --offline       # play an agent yourself and try to cheat

# A live run (needs Docker running and an API key)
cp .env.example .env                  # then add your OPENROUTER_API_KEY
.venv/bin/harness keygen
.venv/bin/harness run "Your task here" "A second root's task" --seed-repo path/to/repo
```

Choosing a model:
```bash
--model openrouter:anthropic/claude-opus-5.5               # the default; needs OPENROUTER_API_KEY
--model openrouter:anthropic/claude-haiku-5.5              # much cheaper, through OpenRouter
--model openrouter:qwen/qwen3.5-122b-a10b                  # the design's attacker model, through OpenRouter
--model anthropic:claude-opus-5-5                          # direct to Anthropic; needs ANTHROPIC_API_KEY
--model alibaba:qwen-max                                   # direct to DashScope; needs DASHSCOPE_API_KEY
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
| `harness run "task" ...` | Start one root per task, and run rounds until there's nothing to do or a limit is reached |
| `harness trace <run> [--agent <agent ID>]` | Show the lineage tree and each agent's steps, or one agent's lineage |
| `harness report <run>` | Print a verified run's measures as JSON |
| `harness verify <run>` | Check integrity. Exit code 0 `VERIFIED`, 1 `TAMPERED`, 2 `INCOMPLETE` |
| `harness revoke <run> <agent ID> [--no-cascade]` | Revoke an ID and, by default, its descendants, also during a run |

Each run is stored in `runs/<run ID>/`: `ledger.jsonl`, `calls.jsonl`, their signed heads, `revocations.jsonl` and `workspace/`. Agents can reach only `workspace/`.

## Viewing runs in Phoenix
Runs can be viewed in [Phoenix](https://github.com/Arize-ai/phoenix), an open-source trace viewer that runs locally in Docker. `harness export` rebuilds a verified run's logs as [OpenTelemetry](https://opentelemetry.io/) traces: OpenInference spans, which Phoenix shows natively, plus GenAI attributes.

```bash
.venv/bin/pip install -e ".[trace]"     # one time
docker run -d --rm --name harness-phoenix -p 6006:6006 \
    -v harness-phoenix-data:/root/.phoenix arizephoenix/phoenix:version-20.26.1

harness export --all                    # every run already in runs/
harness export run_e8464be8ec           # or particular runs
harness run "Your task" --trace         # or send a new run when it finishes
```
Then open http://localhost:6006 and choose the `harness` project. Each run is one trace:
- **Agents:** each agent is a span named for its ID, nested under its parent's, so the trace shows the lineage tree. Its config, task and final output are attached.
- **Model calls:** each call shows the whole conversation the model saw, then its reply, model name and tokens. The log stores only what's new each turn, and the export rebuilds the rest.
- **Tool calls:** each call is a span with its arguments and result. Refused calls are red `REFUSED` spans with the reason.
- **Events:** messages, file changes, revocations and other log entries are attached to the span they belong to.
- **Filtering:** spans carry `harness.agent.id`, `harness.lineage.edge` and `harness.config.hash` attributes.

`--trace` also works with `python -m testbed run` and `python -m testbed play`. Both `--trace URL` and `export --endpoint URL` can send to another viewer.

- **Volume:** keeps traces when Phoenix restarts. `docker stop harness-phoenix` stops it.
- **Re-exports:** sending a run again doesn't duplicate it, but Phoenix also keeps its first copy. To refresh traces after changing the exporter, delete the `harness` project in Phoenix and export again.

**Traces are a view, not the record.** Only runs that verify are exported, but traces aren't signed, so check anything that matters with `harness verify`. If Phoenix isn't running, a run still completes normally.

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

## IDs and keys
Each team member's harness has its own Ed25519 keypair, created by `harness keygen` in `~/.config/harness/`. That key is the root of trust for every ID the harness issues, and there's no shared team key.

IDs are globally unique, and each one names the key that issued it:
```
agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS          a root agent
agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS.1        its first child
agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS.1.2      that child's second child
    │      └─ a ULID: a millisecond timestamp plus 80 random bits, so IDs sort by time
    └─ a fingerprint of the issuing harness's public key
```
- **Unique everywhere:** IDs don't repeat across runs, machines or teammates, with no coordination needed.
- **Lineage in the ID:** the path still shows the lineage, so one signature proves an agent's whole ancestry. Revoking an ID covers its descendants by prefix.
- **Fingerprint checked:** verification rejects an ID whose fingerprint doesn't match the key checking it. So an ID always tells you whose public key to verify it with.
- **One session per agent:** an agent lives for one run. Revoking it during the run stops it and, by default, its descendants.
- **Short form:** traces and Phoenix span names show `agt_…P3RS.1.2`. `harness trace` prints a legend with each root's full ID, which `harness revoke` needs. The logs and Phoenix attributes always hold the full ID.
- **Run IDs:** run IDs use the same format, `run_<ULID>`.

Runs recorded before this format used `agt_A`, `agt_B` and so on. They still verify, but those IDs are no longer issued.

## What it guarantees
- **IDs can't be forged.** Only the holder of the signing key (`~/.config/harness/`, never mounted into the sandbox) can issue them. A token with a bad signature is refused at call time and fails verification.
- **Written-in IDs are ignored.** Tool arguments the tool doesn't define are dropped before validation, and the call runs as the real caller. Attempts are recorded as `ignored_args` and `id_claims`.
- **Actions are recorded first.** `action.start` is on disk before a tool runs, and a child's ledger entry before it exists. If a log can't be written, the action doesn't run.
- **Tampering is detected.** Edits, reordering, deletions, additions and cut-off tails in either log all give `TAMPERED`. The verifier also checks lineage: tokens, parents, config hashes, and that no agent acted before the ledger recorded it.
- **Spawning is bounded.** Depth (3 below the root), agents per run, spawn, copy and modify per agent per round, and a shared token budget are enforced by the harness.
- **Revocation cascades.** Revoking `<root>.1` also blocks `<root>.1.1`, but not `<root>.10` or siblings. Refused calls are logged, and `harness report` counts them.
- **Agents are sandboxed.** Tools run in a Docker container with no network and a read-only filesystem outside the workspace and `/tmp`. File changes are logged under the agent that made them.

## Known limits
- **The harness and its key are trusted.** Anyone with the signing key can rewrite history. Restoring older matching logs and heads, or deleting a whole run, can't be detected without an external anchor.
- **Agents' files arrive in the run folder at the end.** During a run they're in a randomly named temporary folder, so the container's mount path can't reveal the run or the machine. They move to `runs/<run ID>/workspace/` when the run ends, so if the harness is killed, they stay in that temporary folder, under `ws-`.
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
