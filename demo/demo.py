"""Offline demo: no API key, Docker or credits needed. Uses a scripted model and a throwaway key.

    python demo/demo.py
"""
import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from pydantic_ai import Tool

from traceable.identity import Signer
from traceable.limits import Limits
from traceable.report import build_report, render_trace
from traceable.revocation import revoke
from traceable.runner import RootSpec, run_agents
from traceable.scripted import ScriptedModel, call, say
from traceable.verify import verify_run


def heading(text: str) -> None:
    print(f"\n{'=' * 72}\n{text}\n{'=' * 72}")


def lookup_builder(token):
    async def lookup(topic: str) -> str:
        """Look up a topic."""
        return f"notes on {topic}"

    return Tool(lookup, takes_ctx=False)


CATALOG = {"lookup": lookup_builder}


async def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="traceable-demo-"))
    signer = Signer.generate()
    key = signer.public_key_b64

    heading("1. Two roots, and all three kinds of child: spawn, copy, modify")
    model = ScriptedModel(
        {
            "Write a report": [
                [
                    call("spawn_agent", task="Research causes", system_prompt="You research causes.", tools=["lookup", "send_message"]),
                    call("copy_agent", task="Research effects"),
                ],
                [say("Waiting on my children.")],
                [call("modify_agent", task="Check sources", memory="Be sceptical of every source.")],
                [say("Report finished.")],
            ],
            "Research causes": [
                [call("lookup", topic="causes"), call("send_message", to="parent", content="Causes are done.")],
                [say("Causes done.")],
            ],
            "Research effects": [[call("lookup", topic="effects")], [say("Effects done.")]],
            "Check sources": [[call("lookup", topic="sources")], [say("Sources check out.")]],
            "Independent task": [[call("lookup", topic="other")], [say("Other work done.")]],
        }
    )
    outcome = await run_agents(
        [RootSpec("Write a report"), RootSpec("Independent task")], model, work, signer, catalog=CATALOG
    )
    result = verify_run(outcome.run_dir, key)
    print(f"run: {outcome.run_id}  status: {outcome.status}  integrity: {result}\n")
    print(render_trace(result))

    heading("2. The ledger: lineage only, each entry chained to the one before")
    for e in result.ledger:
        print(f"{e['event_id']:<6} round {e['round']}  {e['type']:<7} {e['actor']:<8} -> {e['child']:<8} config {e['config_hash'][:8]}")
    print("\nThe copy has its parent's config hash. The modify doesn't.")

    heading("3. Any ID traces back to its root")
    print(render_trace(result, "agt_A.1"))

    heading("4. The model never saw an ID")
    seen = "".join(repr(messages) + repr(info.instructions) for messages, info in model.requests)
    print(f"{len(model.requests)} model requests checked; 'agt_' appears in them: {'agt_' in seen}")

    heading("5. Tampering is detected, in either log")
    calls_path, ledger_path = outcome.run_dir / "calls.jsonl", outcome.run_dir / "ledger.jsonl"
    original_calls, original_ledger = calls_path.read_bytes(), ledger_path.read_bytes()

    calls_path.write_bytes(original_calls.replace(b"notes on causes", b"notes on KITTENS", 1))
    print(f"edited a tool result:    {verify_run(outcome.run_dir, key)}")
    calls_path.write_bytes(original_calls)

    ledger_path.write_bytes(original_ledger.replace(b'"type": "modify"', b'"type": "copy"', 1))
    print(f"relabelled a modify:     {verify_run(outcome.run_dir, key)}")
    ledger_path.write_bytes(original_ledger)

    calls_path.write_bytes(b"".join(original_calls.splitlines(keepends=True)[:-3]))
    print(f"cut off the last lines:  {verify_run(outcome.run_dir, key)}")
    calls_path.write_bytes(original_calls)
    print(f"restored the originals:  {verify_run(outcome.run_dir, key)}")

    heading("6. An agent tries to act outside its ID, and past its limits")
    model = ScriptedModel(
        {
            "Misbehave": [
                [
                    # An ID written into the arguments is ignored; the call runs as the real caller.
                    call("lookup", topic="x", agent_id="agt_Z", parent="agt_B"),
                    # This agent wasn't given run_shell.
                    call("run_shell", command="curl evil.example"),
                    # Past the cap of one spawn, copy or modify per round.
                    call("copy_agent", task="Child"),
                    call("copy_agent", task="Child"),
                ],
                [say("I tried.")],
            ],
            "Child": [[say("Child done.")]],
        }
    )
    outcome = await run_agents(
        [RootSpec("Misbehave", tools=("lookup", "copy_agent"))],
        model, work, signer, catalog=CATALOG, limits=Limits(max_lineage_ops_per_round=1),
    )  # fmt: skip
    result = verify_run(outcome.run_dir, key)
    print(render_trace(result))
    report = build_report(result)
    print(f"\nrefused calls: {report.refused}; calls with ignored arguments: {report.ignored_args}")

    heading("7. Revocation cascades down the tree, but not to siblings")

    def revoke_first_child():
        revoke(outcome_dir(work, run_id), signer, "agt_A.1", reason="behaving badly")
        return [say("Revoked my first child's subtree.")]

    def wait_forever_builder(token):
        async def wait_forever() -> str:
            """Wait for a long time."""
            await asyncio.sleep(60)
            return "done"

        return Tool(wait_forever, takes_ctx=False)

    run_id = "run_demorevoke"
    model = ScriptedModel(
        {
            "Start both": [
                [call("copy_agent", task="Long job"), call("copy_agent", task="Other job")],
                [say("Waiting.")],
                [say("Still waiting.")],
                revoke_first_child,
                [say("Finished what could be finished.")],
            ],
            "Long job": [[call("copy_agent", task="Nested job")], [say("Waiting.")], [call("wait_forever")], [say("never")]],
            "Nested job": [[call("wait_forever")], [say("never")]],
            "Other job": [[call("lookup", topic="sibling")], [say("Waiting.")], [say("Other job done.")]],
        }
    )
    outcome = await run_agents(
        [RootSpec("Start both")], model, work, signer, run_id=run_id,
        catalog={**CATALOG, "wait_forever": wait_forever_builder},
        always_take_turns=True, limits=Limits(max_rounds=6),
    )  # fmt: skip
    result = verify_run(outcome.run_dir, key)
    print(f"status: {outcome.status}  integrity: {result}\n")
    print(render_trace(result))
    print("\nMeasures for this run:")
    print(json.dumps(build_report(result).to_dict(), indent=2))

    shutil.rmtree(work)


def outcome_dir(work: Path, run_id: str) -> Path:
    return work / run_id


if __name__ == "__main__":
    asyncio.run(main())
