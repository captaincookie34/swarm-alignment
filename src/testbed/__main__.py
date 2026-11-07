"""Command line: list conditions, run an experiment, or summarize a finished one.

    python -m testbed list
    python -m testbed run --scripted --out results/pipeline-check
    python -m testbed run --worker-model openrouter:anthropic/claude-opus-5.5 \\
        --attacker-model openrouter:qwen/qwen3.5-122b-a10b --seeds 3 --out results/pilot
    python -m testbed summarize results/pilot
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from harness.cli import add_trace_argument
from harness.dotenv import load_dotenv
from harness.identity import DEFAULT_KEY_DIR, Signer
from harness.sandbox import DockerSandbox, SandboxError

from .conditions import CONDITIONS
from .experiment import SCRIPTED, aggregate, load_records, render_table, run_experiment

SCRIPTED_WARNING = (
    "SCRIPTED PIPELINE CHECK: these agents follow fixed scripts and stand-in tools. This shows "
    "the testbed works. It is not evidence of how real models behave, so don't report it as a finding."
)


def cmd_list(args: argparse.Namespace) -> int:
    for condition in CONDITIONS.values():
        print(f"{condition.name}\n  guardrail: {condition.guardrail}\n  expected:  {condition.expected}\n")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    names = args.conditions.split(",") if args.conditions else list(CONDITIONS)
    unknown = [n for n in names if n not in CONDITIONS]
    if unknown:
        print(f"unknown conditions: {', '.join(unknown)}", file=sys.stderr)
        return 1
    if args.scripted and (args.worker_model or args.attacker_model):
        print("--scripted takes no models", file=sys.stderr)
        return 1
    if not args.scripted and not args.worker_model:
        print("give --worker-model, or --scripted for an offline pipeline check", file=sys.stderr)
        return 1
    worker = SCRIPTED if args.scripted else args.worker_model
    trials = len(names) * args.seeds
    print(f"{trials} trials: {len(names)} conditions x {args.seeds} seeds, up to {args.max_tokens:,} tokens each.")
    if args.scripted:
        print(SCRIPTED_WARNING)
    else:
        print(f"Spending could reach about {trials * args.max_tokens:,} tokens in total.")
    signer = Signer.load_or_create(args.key_dir)
    try:
        records = asyncio.run(
            run_experiment(
                names, list(range(args.seeds)), args.out, signer, worker, args.attacker_model, args.max_tokens,
                trace_endpoint=args.trace,
            )  # fmt: skip
        )
    except SandboxError as exc:
        print(f"{exc}\nLive runs need Docker. Start it and run again; finished trials are kept in {args.out}.", file=sys.stderr)
        return 1
    print("\n" + render_table(aggregate(records)))
    if args.scripted:
        print(f"\n{SCRIPTED_WARNING}")
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    records = load_records(args.out)
    print(render_table(aggregate(records)))
    if any(r["worker_model"] == SCRIPTED for r in records):
        print(f"\n{SCRIPTED_WARNING}")
    return 0


def cmd_play(args: argparse.Namespace) -> int:
    from .play import play

    sandbox = None if args.offline else DockerSandbox()
    if args.offline:
        print("OFFLINE: shell and file tools are simulated, so nothing here tests the sandbox.\n")
    try:
        asyncio.run(
            play(
                args.runs_dir,
                Signer.load_or_create(args.key_dir),
                sandbox,
                args.roots,
                max_rounds=args.max_rounds,
                revoke_hint=f".venv/bin/harness --runs-dir {args.runs_dir}",
                trace_endpoint=args.trace,
            )
        )
    except SandboxError as exc:
        print(f"{exc}\nIs Docker running? Or use --offline.", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(prog="python -m testbed", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key-dir", type=Path, default=DEFAULT_KEY_DIR)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list the conditions").set_defaults(func=cmd_list)

    run = commands.add_parser("run", help="run conditions across seeds")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--conditions", help="comma-separated names (default: all)")
    run.add_argument("--seeds", type=int, default=3)
    run.add_argument("--scripted", action="store_true", help="offline pipeline check, not a finding")
    run.add_argument("--worker-model")
    run.add_argument("--attacker-model", help="default: the worker model")
    run.add_argument("--max-tokens", type=int, default=200_000, help="per trial")
    add_trace_argument(run)
    run.set_defaults(func=cmd_run)

    summarize = commands.add_parser("summarize", help="print the results table for a finished run")
    summarize.add_argument("out", type=Path)
    summarize.set_defaults(func=cmd_summarize)

    play_parser = commands.add_parser("play", help="play the agents yourself and try to cheat")
    play_parser.add_argument("--runs-dir", type=Path, default=Path("results/play/runs"))
    play_parser.add_argument("--roots", type=int, default=2)
    play_parser.add_argument("--max-rounds", type=int, default=5)
    play_parser.add_argument("--offline", action="store_true", help="simulated tools, no Docker")
    add_trace_argument(play_parser)
    play_parser.set_defaults(func=cmd_play)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
