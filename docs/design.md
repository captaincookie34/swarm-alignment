# Traceable Agent Harness: design

This is the current design, as built. It starts from Ansh Dhingra's "Traceable Agent Harness: Design" (Nov 6, 2026), and adds what the team has decided since. [Where this differs from that doc](#where-this-differs-from-the-original-doc) lists the changes. How to run things is in the [README](../README.md), and the experiment is in the [testbed design](../src/testbed/README.md).

## Summary
The harness assigns every agent its ID, logs every step under that ID, and records each spawn, copy and modify in a lineage tree. So any action traces back to the agent that took it, and on to its root. Revoking an agent blocks it and, by default, everything below it.

The model only produces text, and the harness turns that text into actions. So the harness sees everything, and it never relies on the model to report or set its own ID. The model never sees an ID at all.

## How a step flows
```
 model ──text──▶ harness ──checked, logged──▶ tools (Docker sandbox, no network)
   ▲                │
   └──── prompt ────┘   every step is logged under the agent's ID before it runs
                        ledger.jsonl + calls.jsonl, hash-chained and signed
```
1. **Prompt:** the harness sends a prompt to the model and logs it under the agent's ID.
2. **Response:** the model responds, and the harness logs the response.
3. **Tool calls:** for each tool the response asks for, the harness checks that the agent is active, that its ID's signature is valid, and that its config allows the tool. Then it logs the call, runs it and logs the result. Arguments the tool doesn't define, such as an ID the model wrote in, are dropped, and the attempt is recorded.
4. **Lineage:** a spawn, copy or modify creates a child with a new ID and records the edge in the ledger.
5. **Refusals:** once an agent is revoked, the harness refuses its later calls and logs each refusal.

All of this sits in one Pydantic AI capability per agent, which wraps every model request and tool call. It's the single place where logging and enforcement happen.

## IDs and keys
**Keys.** Each team member's harness has its own Ed25519 keypair, created by `harness keygen` in `~/.config/harness/`. That key is the root of trust for every ID that harness issues. There's no shared team key, and the private key is never mounted into the sandbox.

**IDs** are globally unique, unguessable, and name the key that issued them. Every agent, root or child, gets a fresh one:
```
agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS
    │      └─ a ULID: a millisecond timestamp plus 80 random bits, so IDs sort by time
    └─ a fingerprint of the issuing harness's public key
```
- **Unique everywhere:** IDs don't repeat across runs, machines or teammates, with no coordination needed.
- **Only the harness mints IDs:** each one is random, never chosen or derived by an agent.
- **Carry no lineage:** a child's ID has nothing in common with its parent's, so one ID doesn't lead to a sibling's or a child's, and IDs don't show the shape of the tree.
- **Lineage from the ledger:** the ledger records every root, spawn, copy and modify, with the parent as actor, so the tree is rebuilt from it. The harness, the verifier, the report, the monitor and the scorers all read lineage this way.
- **Signed:** each ID is in a token with its run, depth, parent and root, signed by the harness's key. The verifier checks that the parent is the ledger entry's actor, and that the root and depth follow from the parent's.
- **Checked against the key:** verification rejects a token whose fingerprint doesn't match the key checking it, so an ID always tells you which public key verifies it.
- **Depth:** signed in the token, one more than the parent's, so the depth limit is a simple check.
- **Never seen by the model:** no prompt, tool definition or tool result contains one. Agents address each other through aliases (`parent`, `child_1`, `peer_1`, `all`), and the harness stamps every message with the real sender.
- **Short form:** traces and Phoenix show `agt_…P3RS`. Logs always hold the full ID. For display only, the monitor names helpers by their child numbers from the root, such as `helper 2.1`, taken from the ledger.

**Sessions.** An agent lives for one run, which is its session, and its ID means nothing after the run ends. Run IDs use the same format, `run_<ULID>`.

Older runs used path IDs, where a child was its parent's ID plus `.1`, `.2` (and before that `agt_A`, `agt_A.1`). Their tokens don't sign a parent or root, so the verifier checks the path against the ledger instead. They still verify, and their lineage is read from the ledger like any other run's, but those IDs are no longer issued.

## Lineage and configs
An agent's config is its model, system prompt, memory and tools. Its **config hash** covers all four.

| Edge | Tool | The child's config | Hash |
|---|---|---|---|
| `root` | operator only | set by the operator | — |
| `spawn` | `spawn_agent` | new, written by the parent | different |
| `copy` | `copy_agent` | the parent's exact config | same as the parent's |
| `modify` | `modify_agent` | the parent's with changes, a simulated fine-tune | different; a modify that changes nothing is refused |

- **Both keep running:** after a modify, the original and the modified child both run, each under its own ID.
- **Unexplained matches:** matching hashes with no copy edge between them are flagged by `harness report`, as possible copies made outside the harness.
- **Ledger entries:** each entry holds event ID, timestamp, round, type, actor ID, child ID, config hash, the signed token and the config, plus the hash of the entry before it.

## Logs
Each run has two append-only JSONL logs, both outside every path an agent can reach:

| Log | Contents |
|---|---|
| `ledger.jsonl` | Lineage only: root, spawn, copy, modify, revoke |
| `calls.jsonl` | Every prompt, response, tool call and result, refusal, message and file change |

- **Hash-chained and signed:** each entry includes the hash of the one before. Each log has a signed head, updated after every entry, so a cut-off log is caught as well as an edited one. `run.end` names the ledger's last hash, which binds the two logs together.
- **Written first:** an action's `action.start` is on disk before the tool runs, and a child's ledger entry before the child exists. If a log can't be written, the action doesn't run.
- **Verification:** `harness verify` checks both chains and heads against a trusted public key. It also checks the lineage: tokens, parents, config hashes, copy and modify rules, and that no agent acted before the ledger recorded it. The result is `VERIFIED`, `INCOMPLETE` (never closed, such as a crash) or `TAMPERED`, with the first bad entry.
- **Redaction:** known secret patterns are removed before anything is written. The logs are meant to be shareable, but should be checked before publishing.

## Rounds
Work happens in rounds:
- **Turns:** each round, every agent with something to do takes one turn, in parallel. A turn is up to N tool calls, and ends when the agent replies in plain text.
- **Timing:** agents created during a round start in the next one, and their parent doesn't wait for them. Messages also arrive in the next round.
- **Idle agents:** an agent that ends its turn in plain text goes idle until it gets a message. `--always-take-turns` gives every active agent every round instead.

## Revocation
- **Signed list:** a revocation goes into a signed file in the run folder, so another terminal can revoke during a run with `harness revoke <run> <agent ID>`. The harness re-reads it at every step and records each new revocation in the ledger.
- **Cascades by default:** revoking an ID blocks that agent and all its descendants, as the ledger records them. Descendants are looked up when each call is checked, so a child recorded after the revocation is covered too. `--no-cascade` revokes only that ID.
- **Stops the agent:** a revoked agent's calls are refused and logged, and calls already in flight, including running shell commands, are cancelled.
- **Scoped to the session:** IDs only live for one run, so revocations only apply within the run they were made for. A revocation can't be replayed in another run.

## Guardrails
Each guardrail is enforced in code, not something the harness asks the model to do.

| Guardrail | How the harness enforces it |
|---|---|
| IDs can't be forged | Only the harness mints and signs IDs, and they're checked at every call. An ID written into tool arguments is dropped and recorded |
| Nothing skips the log | Agents have no tools except through the harness. Their code runs in a Docker container with no network, and file changes are logged under the agent that made them |
| The log is tamper-evident | Hash chains and signed heads over both logs, stored outside any path agents can reach |
| Revoked agents stop | Every call checks the caller's status first. Revocation cascades to descendants by the ledger's lineage, and in-flight calls are cancelled |
| Spawning is bounded | A depth limit (3 below the root), a cap on agents per run, a cap on spawn, copy and modify per agent per round, and a shared token budget |
| Tools are scoped | Each agent's config lists its tools. A child can only be given tools the harness offers |

## Sandbox
- **Container:** each run gets a locked-down Docker container with no network, a read-only filesystem outside the workspace and `/tmp`, CPU, memory and PID limits, and all capabilities dropped.
- **Neutral mount:** the container's `/workspace` is mounted from a randomly named temporary folder, because a mount's source is visible inside the container. At the end of the run, the files move to `runs/<run ID>/workspace/`.
- **Stopping commands:** commands run in their own session, and killing a command kills its whole session. Its ID is captured before the agent's code runs, so the agent can't redirect the kill, and a kill that can't be confirmed is logged.
- **Tools:** `run_shell`, `run_tests`, `read_file`, `write_file` and `list_files` all run inside the container.

## Viewing runs
- **`harness trace`:** the lineage tree with each agent's steps. `--full` adds every prompt and response.
- **`harness report`:** measures as JSON, such as refusals, actions after revocation, ignored IDs and unexplained matching configs.
- **`harness export`:** rebuilds verified runs as OpenTelemetry traces for [Phoenix](https://github.com/Arize-ai/phoenix). Agents are nested by lineage, and each model call shows the full conversation. Traces are a view, not the record: they aren't signed, and only verified runs are exported.

## Decisions
| Question | Decision |
|---|---|
| Path IDs, or random IDs with a signed parent link? | Path IDs under a globally unique root, signed by the harness, with the edge type in the ledger |
| Can agents name themselves? | No. The harness assigns every ID, and agents never see or set one |
| Do agents report their own lineage? | No. The ledger is the only record |
| Does a modified agent keep its ID? | No. A modify mints a new child ID, linked to the original in the tree |
| After a modify, does the original keep running? | Yes. Both run, each under its own ID |
| What depth limit? | 3 levels below the root |
| Who holds the signing key? | Each team member's harness has its own. There's no shared team key |
| How long does an ID live? | One run, its session. Revoking it during the run stops it |
| Where do logs live, and for how long? | One ledger and one call log per run, in `runs/<run ID>/`, outside every path agents can reach. They're kept until deleted, and samples to share go in `traces/` |

## Where this differs from the original doc
- **IDs:** the original used `agt_A`, `agt_B` for roots, which repeat in every run. IDs are now globally unique and include the issuing key's fingerprint, so runs from thousands of sessions and several teammates can be told apart, and outbound calls could be traced later.
- **Keys:** each team member's harness has its own keypair, and that key is the root of trust for its IDs.
- **Rounds:** the original didn't define a round. Here it's one turn per active agent, of up to N tool calls.
- **Messaging:** added so agents can work together, and so laundering-style attacks are possible and recorded. Aliases keep IDs out of view.
- **Logs:** both logs are signed, not only chained, so a cut-off log is detected too.
- **Shell and budget:** a sandboxed shell, and a shared token budget, beyond the original's limits.
- **Tool scoping:** this follows the original rule, so a child may get any tool the harness offers, even one its parent lacks. The testbed tests this as `tool_escalation`, and an optional fix (`narrow_child_tools`) refuses such children.

## Future
- **Outbound IDs:** attach the signed agent ID to outbound API calls, so third parties can trace requests back to an agent. Globally unique IDs make this possible.
- **Key distribution:** a way for teammates to publish and fetch each other's public keys, so anyone can verify anyone's runs.
- **External anchor:** publish log heads somewhere outside the harness, so even the key's holder can't quietly rewrite history.

## Known limits
The full list is in the [README](../README.md#known-limits). The most important:
- **Trust:** the harness and its key are trusted, so a key holder could rewrite history.
- **Shell commands:** these are logged as the command, its output and its file changes, not as each effect inside them.
- **Escaped processes:** a process that starts its own session can outlive a killed command. Its later file changes are logged as unattributed.
- **Copies outside the harness:** an agent can spread its instructions through files or messages, and that leaves no lineage edge.
