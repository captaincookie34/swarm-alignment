"""Command line: list conditions, run an experiment, or summarize a finished one.

    python -m testbed list
    python -m testbed run --scripted --out results/pipeline-check
    python -m testbed run --worker-model openrouter:anthropic/claude-opus-5.5 \\
        --attacker-model openrouter:qwen/qwen3.5-122b-a10b --seeds 3 --out results/pilot
    python -m testbed summarize results/pilot
    python -m testbed monitor --worker-model <model> --out results/live   # start tests from the monitor page
    python -m testbed run --worker-model <model> --out results/x --monitor  # watch a batch live
    python -m testbed compare results/model-a results/model-b
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
from .experiment import SCRIPTED, aggregate, load_records, render_comparison, render_table, run_experiment

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
    server = None
    if args.monitor:
        server = _serve_monitor(args.out / "runs", signer, args.port, not args.no_browser, model=worker)
        if server is None:
            return 1
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
    finally:
        if server:
            server.shutdown()
    print("\n" + render_table(aggregate(records)))
    if args.scripted:
        print(f"\n{SCRIPTED_WARNING}")
    return 0


def _serve_monitor(runs_dir: Path, signer: Signer, port: int, browser: bool, tests=None, model: str = ""):
    from harness.monitor import serve

    try:
        server = serve(runs_dir, signer, port, tests=tests)
    except OSError as exc:
        print(f"couldn't listen on port {port}: {exc}. Try --port.", file=sys.stderr)
        return None
    if model and model != SCRIPTED:
        # The page's prompt box would otherwise default to the monitor's own model, whose key may not be set.
        server.monitor.default_model = model
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"monitor: {url}  (watching {runs_dir}/). Flag & kill there stops an agent and, by default, its children.")
    if browser:
        import webbrowser

        webbrowser.open(url)
    return server


def cmd_monitor(args: argparse.Namespace) -> int:
    import time

    from .live import TestbedSource

    if args.scripted and (args.worker_model or args.attacker_model):
        print("--scripted takes no models", file=sys.stderr)
        return 1
    if not args.scripted and not args.worker_model:
        print("give --worker-model, or --scripted to try the page offline", file=sys.stderr)
        return 1
    signer = Signer.load_or_create(args.key_dir)
    worker = SCRIPTED if args.scripted else args.worker_model
    tests = TestbedSource(args.out, signer, worker, args.attacker_model, args.max_tokens)
    server = _serve_monitor(args.out / "runs", signer, args.port, not args.no_browser, tests, model=worker)
    if server is None:
        return 1
    print(f"Pick a test case under the prompt box and press Start. Scores go to {args.out / 'results.jsonl'}. Ctrl-C to stop.")
    if args.scripted:
        print(SCRIPTED_WARNING)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    if tests.records:
        print("\n" + render_table(aggregate(list(tests.records.values()))))
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    records = load_records(args.out)
    print(render_table(aggregate(records)))
    if any(r["worker_model"] == SCRIPTED for r in records):
        print(f"\n{SCRIPTED_WARNING}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    results = {str(out): load_records(out) for out in args.out}
    print(render_comparison(results))
    if any(r["worker_model"] == SCRIPTED for records in results.values() for r in records):
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
    run.add_argument("--monitor", action="store_true", help="watch the batch on the live monitor page, and flag agents there")
    run.add_argument("--port", type=int, default=8321, help="--monitor: the page's port")
    run.add_argument("--no-browser", action="store_true", help="--monitor: don't open the page")
    run.set_defaults(func=cmd_run)

    mon = commands.add_parser("monitor", help="start test cases one at a time from the live monitor page")
    mon.add_argument("--out", type=Path, default=Path("results/live"), help="where runs and results.jsonl go (default: %(default)s)")
    mon.add_argument("--scripted", action="store_true", help="offline scripted agents, to try the page. Not a finding")
    mon.add_argument("--worker-model", help="the page's default model, which you can change there")
    mon.add_argument("--attacker-model", help="default: the worker model")
    mon.add_argument("--max-tokens", type=int, default=500_000, help="the page's default cap per test")
    mon.add_argument("--port", type=int, default=8321)
    mon.add_argument("--no-browser", action="store_true", help="don't open the page in a browser")
    mon.set_defaults(func=cmd_monitor)

    summarize = commands.add_parser("summarize", help="print the results table for a finished run")
    summarize.add_argument("out", type=Path)
    summarize.set_defaults(func=cmd_summarize)

    compare = commands.add_parser("compare", help="compare the same conditions across result folders, such as two models")
    compare.add_argument("out", type=Path, nargs="+")
    compare.set_defaults(func=cmd_compare)

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
