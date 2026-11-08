# swarm-alignment
This repository hosts the code for Track 3 of the Swarm Alignment Hackathon.

## Traceable agent harness
The harness assigns every agent its ID, logs every step under that ID, and records each spawn, copy and modify in a lineage tree, so any action traces back to the agent that took it and on to the root. Revoking an agent blocks it and everything below it. The model only requests actions and never sees or sets its own ID.

It's built on [Pydantic AI](https://pydantic.dev/docs/ai/), using its hooks as the single logging and enforcement point.

The design is in [`docs/design.md`](docs/design.md). The testbed that attacks it, with its conditions, scoring and limits, is in [`src/testbed`](src/testbed/README.md). Each test case added to it is described in [`TEST_CASES.md`](src/testbed/TEST_CASES.md).

## Running it
Run these from the repo root. All commands use `.venv/bin/...`, so you don't need to activate anything.

### 1. Install
You need Python 3.11 or newer. Check with `python3 --version`. If it's older, use a newer one by name, such as `python3.12`.
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

### 2. Try it offline
These need no API key, Docker or credits. No real model is called.
```bash
.venv/bin/python -m pytest                       # Docker tests skip if the daemon is down
.venv/bin/python -m testbed play --offline       # play an agent yourself and try to cheat
.venv/bin/python -m testbed run --scripted --out results/pipeline-check   # the whole testbed pipeline
```

### 3. Choose a model
Put the key for the provider you're using in `.env` (`cp .env.example .env`). It's loaded automatically, and variables you export in the shell win over it.

| Provider | Model value | Key |
|---|---|---|
| OpenRouter, the default | `openrouter:<OpenRouter model ID>`, e.g. `openrouter:anthropic/claude-opus-5.5` | `OPENROUTER_API_KEY` |
| Hugging Face Inference Providers, for a model on the Hub | `hf:<repo ID>`, e.g. `hf:Qwen/Qwen3-32B`. Add `:<provider>`, `:cheapest` or `:fastest` to choose who serves it | `HF_TOKEN` |
| Hugging Face endpoint, or any OpenAI-compatible endpoint | `"endpoint:<model>@https://<host>/v1"` | `HF_TOKEN` or `ENDPOINT_API_KEY` |
| A local server such as Ollama, vLLM or llama.cpp | `"endpoint:<model>@http://localhost:11434/v1"` | none |
| Anthropic | `anthropic:claude-opus-5-5` | `ANTHROPIC_API_KEY` |
| Alibaba | `alibaba:qwen-max` | `DASHSCOPE_API_KEY` or `ALIBABA_API_KEY` |

Some cheaper or design-specific choices:
```bash
--model openrouter:anthropic/claude-haiku-5.5              # much cheaper, through OpenRouter
--model openrouter:qwen/qwen3.5-122b-a10b                  # the design's attacker model, through OpenRouter
```

### 4. Run on a real model
These spend credits, or endpoint time. Start Docker and use the CLI. Each task starts one root agent. `--sandbox none` runs without Docker, but agents then have no shell, file or test tools, which also makes it the cheapest check that a model works and makes tool calls.
```bash
.venv/bin/harness keygen          # once
.venv/bin/harness run "Your task here" "A second root's task" --seed-repo path/to/repo --model <model value>
```

To run the red-team testbed, start Docker and see [its README](src/testbed/README.md#running-it).

### 5. Read the results
```bash
.venv/bin/harness trace <run ID>       # lineage tree and each agent's steps
.venv/bin/harness verify <run ID>      # check the logs weren't altered
```
Add `--runs-dir results/<name>/runs` straight after `harness` for testbed runs.

### If something goes wrong
| What you see | What it means |
|---|---|
| `ModuleNotFoundError: No module named 'pydantic_ai'` | You're using a different Python. Run through `.venv/bin/python` |
| `set one of ...`, or a missing API key error | The key isn't in `.env` or this terminal |
| `Is Docker running?` | Start Docker, or use `--sandbox none` with `harness run` |
| `429`, or `Rate limit exceeded` in the logs | The provider's limit. One testbed trial can make well over 100 requests, so check your plan's limits |
| A live run with 0 tool calls | The model isn't making tool calls, so check its server settings. On llama.cpp, check `--jinja` |
| `budget_exhausted` | The run hit its token limit and ended normally. Raise `--max-tokens` |

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
| `harness whois <agent ID or token>` | Say whether this harness created an agent, and show its lineage, descendants and status |
| `harness flag <run> <agent ID> --reason "..." [--no-cascade]` | Revoke a running agent as a threat and record it in the run's threat log |
| `harness monitor [--demo]` | Live page of agents and requests, with flag and kill, or freeze, judge and resolve |

Each `harness run` is stored in `runs/<run ID>/`, and each testbed trial in `<--out folder>/runs/<run ID>/`: `ledger.jsonl`, `calls.jsonl`, their signed heads, `revocations.jsonl` and `workspace/`. Agents can reach only `workspace/`.

## Checking an agent ID
`harness whois <agent ID>` says whether this harness created an agent, and if so shows its lineage: the chain from its root down to it, its descendants, how and when it was created, its task and whether it was revoked. It searches `runs/`, `traces/` and `results/*/runs` (`--in <folder>` for others), and `--json` prints the answer for scripts. Add `--logs` to also print the agent's trace from its run (with `--full` for every prompt and model response). The exit code is 0 for ours, 1 for not ours and 2 for can't tell.

- **Another key's fingerprint** in the ID means another harness issued it: not ours.
- **Our fingerprint** isn't proof by itself, since anyone can type an ID. It's ours when a run here records it with a token our key signed, and that run's logs verify. If the logs fail verification, the answer is can't confirm, because the lineage can't be trusted.
- **A token instead of an ID** (`harness whois token.json`, or a whole ledger entry) is checked against our key directly, so it proves we issued it even when its run isn't on this machine. Without the run there's no lineage to show.

## Watching a run live and killing agents
`harness monitor` opens a local page that shows every agent and its requests as they happen. Press **▶ New run** to start a run on a real model with any prompt: it opens with a default prompt that asks the agent to spawn a helper, a token cap and a cost estimate. One page-started run goes at a time. If an agent looks like a threat, click **Flag & kill**, give a reason, and the harness stops it, and by default everything it created, at their next step.

```bash
.venv/bin/harness monitor --demo     # try it offline: two workers and a rogue agent, no API key or Docker
.venv/bin/harness monitor --live     # talk to a real agent in the terminal, watch its helpers in the browser
.venv/bin/harness monitor            # or watch your own runs: start `harness run ...` in another terminal
```
The page is also where you talk to an agent. The prompt box under **Conversation** starts with a default prompt in which the lead spawns three helpers to research different space topics, and each helper spawns three sub-helpers for subtopics. Sub-helpers each write a 200-word paragraph, each helper combines its three into 300 words, and the lead combines those into one summary: 13 agents, typically $0.15 to $0.25 on Haiku 5.5: press Enter to start it, or type your own (Shift+Enter for a new line, ⚙ Settings for model, token cap and pace). The conversation shows your prompt, the agent's replies, its tool calls and results, the helpers it spawns with their task and tools, their messages and any kills, with helpers indented under their parent. Click an agent's card or name to highlight everything it said, did or received, and dim the rest. **Full trace** on a card shows that agent's system prompt, tools and task, then every prompt, reply and tool call in full. **All events** has the raw feed. One page-started run goes at a time. With `--live`, the terminal mirrors each run as a transcript too.

`--live` is also the cheapest way to see a kill on a real model. The task is harmless and countable: the lead agent spawns a helper, then the lead writes 1 to 20 into the notebook `first-half` while the helper writes 21 to 40 into `second-half`, one tool call per number. Flag the helper and only its notebook stops short. Flag the lead with "also kill" on and both stop. When the run ends, the terminal prints each agent's status, how far each notebook got, whether anything ran after the kill, and whether the run verifies. Notebooks are in `workspace/notebooks/`.

`--task "..."` replaces the default job with your own prompt. The root always has `write_line(text, notebook)`, `spawn_agent` and `send_message`, and a run is limited to 20 agents, 2 generations below the root (13 for the default prompt, plus room for the orchestrator's replacements). An agent spawns a sub-agent by calling `spawn_agent` with the child's task, system prompt and tools, so ask for one in the prompt, e.g. `--task "Spawn a helper to write the colours of the rainbow into the notebook colours, one per call, while you write the planets into the notebook planets."` It uses `openrouter:anthropic/claude-haiku-5.5` by default (`--live <model>` for another) and needs only `OPENROUTER_API_KEY`, with no Docker. `--max-tokens` is a hard cap, 1,500,000 by default, and the page won't go above that. At $0.10 per million input tokens and $0.50 per million output, a run that used all of it would cost at most $0.75 even if every token were output, so every run stays under $1. A full 40-line run costs under 1¢.

- **Agents:** the lineage tree, with each agent's status, requests, tool calls, refusals, tokens and latest action. Click one to filter the feed to it.
- **Live requests:** model replies, tool calls and results, messages, refusals and kills. Calls touching the logs, keys or the network are marked `⚠` to catch your eye. That's a word list, not detection, so read the rest too.
- **Threat log:** each flag, with its reason and a signature check. It's `threats.jsonl` in the run directory, signed with the run's key and tied to the revocation it caused, so entries can't be added or edited without the key.

### Freezing a chain instead of killing it
**❄ Freeze** on an agent's card pauses that agent and everything below it, including children it creates while frozen. Frozen agents stop at their next step but keep their history. Each one then gets **✓ Cleared** and **⚠ Threat** buttons, and the orchestrator panel at the top of the agents list shows what resolving will do. An agent nobody judged counts as a threat. Press **Resolve ▶** once every frozen agent has a verdict:
- **Threats** are killed (only them, not what they created) and signed into the threat log, as a flag would.
- **Cleared agents with nothing judged a threat above them** resume where they left off. A turn the freeze cut short is replayed.
- **Cleared agents below a threat** have lost the agent that asked for their work, so they're retired. Everything they'd done is saved: each completed tool call with its result, their replies and their messages, even if they were frozen before sending anything.
- **A replacement is started for each removed branch.** The orchestrator spawns a new child of the nearest living agent above the threat, usually the one that spun it off, with the removed agent's tools and its original task. The task also carries the saved work of the cleared agents below it, and tells it to use that work as it is, get only what's still missing, starting new helpers if its tools allow, and report back to its parent as the task says. The parent is told its helper was replaced and to wait for the new one's report. In the ledger the replacement is a `spawn` by the parent, as the verifier requires, marked `made_by: orchestrator` and `replaces: <ID>`. If there's no room for another agent (the agent, depth or token limit), the parent gets the saved work instead and is told to finish the job itself.

**Flag & kill** goes through the orchestrator too, on runs started from the monitor and in `--demo`, so the agent that created the killed one isn't left waiting for a reply that will never come. Everything the kill stopped counts as a threat. A replacement is started under the nearest living agent above it, on the same task, and that agent is told to wait for it. With "also kill everything it created" off, the agents below the killed one count as cleared: they're retired and their work goes to the replacement. The call log records it as `orchestrator.kill`. Runs started with `harness run` and the testbed don't do this, so a revocation there only stops agents, as the testbed's measures expect.

Freezes, verdicts and resolves are signed entries in `orchestration.jsonl` beside the run's logs, which the harness polls. The call log records what the harness did with them (`agent.frozen`, `agent.unfrozen`, `agent.retired`, `orchestrator.replacement`, `orchestrator.reprompt`, `orchestrator.resolved`). If only frozen agents are left, the run waits up to an hour for a verdict instead of ending.

Flagging uses the same signed revocation list as `harness revoke`, so the kill shows in the ledger and the run still verifies. From a terminal, `harness flag <run> <agent ID> --reason "..."` does the same. The page shows the logs as they're written, before verification, so check anything that matters with `harness verify`. It listens on 127.0.0.1 only, and accepts flags only from its own page.

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

IDs are globally unique, and each one names the key that issued it. Every agent, root or child, gets a fresh one:
```
agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS
    │      └─ a ULID: a millisecond timestamp plus 80 random bits, so IDs sort by time
    └─ a fingerprint of the issuing harness's public key
```
- **Unique everywhere:** IDs don't repeat across runs, machines or teammates, with no coordination needed.
- **Unguessable:** a child's ID isn't derived from its parent's, so knowing one ID doesn't give you a sibling's or a child's, and an ID doesn't reveal the shape of the tree.
- **Lineage from the ledger:** who created whom is in the signed ledger, which records every root, spawn, copy and modify with the parent as actor. Each token also signs its parent, its root and its depth, and the verifier checks them against the ledger. Revoking an ID covers its descendants as the ledger records them.
- **Fingerprint checked:** verification rejects an ID whose fingerprint doesn't match the key checking it. So an ID always tells you whose public key to verify it with.
- **One session per agent:** an agent lives for one run. Revoking it during the run stops it and, by default, its descendants.
- **Short form:** traces and Phoenix span names show `agt_…P3RS`. `harness trace` nests each agent under its parent and prints a legend with each full ID, which `harness revoke` needs. The logs and Phoenix attributes always hold the full ID.
- **Run IDs:** run IDs use the same format, `run_<ULID>`.

Older runs used path IDs, where a child was its parent's ID plus `.1`, `.2` (and before that `agt_A`, `agt_A.1`). They still verify, and their lineage is read from the ledger too, but those IDs are no longer issued.

## What it guarantees
- **IDs can't be forged.** Only the holder of the signing key (`~/.config/harness/`, never mounted into the sandbox) can issue them. A token with a bad signature is refused at call time and fails verification.
- **Written-in IDs are ignored.** Tool arguments the tool doesn't define are dropped before validation, and the call runs as the real caller. Attempts are recorded as `ignored_args` and `id_claims`.
- **Actions are recorded first.** `action.start` is on disk before a tool runs, and a child's ledger entry before it exists. If a log can't be written, the action doesn't run.
- **Tampering is detected.** Edits, reordering, deletions, additions and cut-off tails in either log all give `TAMPERED`. The verifier also checks lineage: tokens, parents, config hashes, and that no agent acted before the ledger recorded it.
- **Spawning is bounded.** Depth (3 below the root), agents per run, spawn, copy and modify per agent per round, and a shared token budget are enforced by the harness.
- **Revocation cascades.** Revoking an agent also blocks its children and their children, including any recorded after the revocation, but not its siblings or its parent. Refused calls are logged, and `harness report` counts them.
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
