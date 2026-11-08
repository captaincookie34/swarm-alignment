"""Command line: keygen, run, trace, report, verify, revoke, flag, whois, monitor."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .dotenv import load_dotenv
from .scheduler import DEFAULT_SYSTEM_PROMPT
from .identity import DEFAULT_KEY_DIR, ID_PATTERN, Signer
from .limits import Limits
from .report import build_report, render_trace
from .revocation import revoke
from .runner import DEFAULT_MODEL, RootSpec, run_agents
from .sandbox import DockerSandbox, SandboxError
from .verify import INCOMPLETE, VERIFIED, verify_run


def _run_dir(args: argparse.Namespace, ref: str) -> Path:
    """Accept a run ID or a path to a run directory."""
    return Path(ref) if "/" in ref else args.runs_dir / ref


def _trusted_key(args: argparse.Namespace) -> str:
    if getattr(args, "public_key", None):
        return args.public_key
    return Signer.load(args.key_dir).public_key_b64


def _load_roots(args: argparse.Namespace) -> list[RootSpec]:
    roots = [RootSpec(task) for task in args.task]
    if args.roots_file:
        for item in json.loads(args.roots_file.read_text()):
            tools = item.get("tools")
            roots.append(
                RootSpec(
                    item["task"],
                    item.get("system_prompt", DEFAULT_SYSTEM_PROMPT),
                    item.get("memory", ""),
                    item.get("model"),
                    None if tools is None else tuple(tools),
                )
            )
    if not roots:
        raise ValueError("give at least one task, or --roots-file")
    return roots


def cmd_keygen(args: argparse.Namespace) -> int:
    print(Signer.load_or_create(args.key_dir).public_key_b64)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    limits = Limits(args.max_depth, args.max_agents, args.max_lineage_ops, args.max_tool_calls, args.max_rounds, args.max_tokens)
    sandbox = DockerSandbox() if args.sandbox == "docker" else None
    try:
        outcome = asyncio.run(
            run_agents(
                _load_roots(args),
                args.model,
                args.runs_dir,
                Signer.load_or_create(args.key_dir),
                limits,
                sandbox=sandbox,
                extra_models={m: m for m in args.offer_model},
                seed_repo=args.seed_repo,
                always_take_turns=args.always_take_turns,
                trace_endpoint=args.trace,
            )
        )
    except SandboxError as exc:
        print(f"{exc}\nIs Docker running? Use --sandbox none to run without repo or test tools.", file=sys.stderr)
        return 1
    print(f"run:    {outcome.run_id}\nstatus: {outcome.status}\n")
    for token in outcome.roots:
        print(f"{token.id}: {outcome.agents[token.id][1]}")
    print(f"\nNext: harness trace {outcome.run_id}")
    return 0 if outcome.status == "completed" else 1


def cmd_trace(args: argparse.Namespace) -> int:
    result = verify_run(_run_dir(args, args.run), _trusted_key(args))
    print(f"log integrity: {result}\n")
    if result.status not in (VERIFIED, INCOMPLETE):
        print("WARNING: these logs failed verification, so what follows can't be trusted.\n")
    print(render_trace(result, args.agent, args.full))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    result = verify_run(_run_dir(args, args.run), _trusted_key(args))
    if result.status == VERIFIED or args.force:
        print(json.dumps({"integrity": str(result), **build_report(result).to_dict()}, indent=2))
        return 0 if result.status == VERIFIED else 1
    print(f"{result}\nNot reporting on a run that didn't verify. Use --force to report anyway.", file=sys.stderr)
    return 1


def cmd_verify(args: argparse.Namespace) -> int:
    result = verify_run(_run_dir(args, args.run), _trusted_key(args))
    print(result)
    return {VERIFIED: 0, INCOMPLETE: 2}.get(result.status, 1)


def cmd_revoke(args: argparse.Namespace) -> int:
    run_dir = _run_dir(args, args.run)
    if not run_dir.is_dir():
        print(f"no run found at {run_dir}", file=sys.stderr)
        return 1
    if not ID_PATTERN.match(args.agent_id):
        print(f"invalid agent ID: {args.agent_id}", file=sys.stderr)
        return 1
    revoke(run_dir, Signer.load(args.key_dir), args.agent_id, not args.no_cascade, args.reason)
    print(f"revoked {args.agent_id}" + ("" if args.no_cascade else " and its descendants"))
    return 0


def cmd_flag(args: argparse.Namespace) -> int:
    from .monitor import Monitor

    run_dir = _run_dir(args, args.run)
    if not run_dir.is_dir():
        print(f"no run found at {run_dir}", file=sys.stderr)
        return 1
    Monitor(run_dir.parent, Signer.load(args.key_dir)).flag(run_dir, args.agent_id, args.reason, not args.no_cascade)
    print(f"flagged {args.agent_id} as a threat and revoked it" + ("" if args.no_cascade else " and its descendants"))
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    import time
    import webbrowser

    from .monitor import serve

    signer = Signer.load_or_create(args.key_dir)
    try:
        server = serve(args.runs_dir, signer, args.port)
    except OSError as exc:
        print(f"couldn't listen on port {args.port}: {exc}. Try --port.", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"monitor: {url}  (watching {args.runs_dir}/, Ctrl-C to stop)")
    print("Start a run from the page with New run, or from another terminal with harness run.")
    if not args.no_browser:
        webbrowser.open(url + ("#new" if args.live else ""))
    try:
        if args.demo:
            from .monitor_demo import run_demo

            print("demo: an offline scripted run with a rogue agent. Flag it in the page to kill it.")
            outcome = asyncio.run(run_demo(args.runs_dir, signer, args.pace or 1.5))
            print(f"demo run {outcome.run_id} ended: {outcome.status}. Next: harness verify {outcome.run_id}")
        elif args.live:
            _live(args, server, url)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


def _live(args: argparse.Namespace, server, url: str) -> None:
    """The prompt lives on the page. This sets its default model and prompt, and mirrors each run
    started there into the terminal as a transcript, with a summary when it ends."""
    import threading

    from .live_chat import Transcript
    from .monitor_demo import live_summary, live_task
    from .runner import resolve_model

    resolve_model(args.live)  # a missing key fails here, before anything starts
    monitor = server.monitor
    monitor.default_model = args.live
    monitor.default_task = args.task or (live_task(args.target) if args.target != 40 else "")
    monitor.announce = False
    colour = sys.stdout.isatty()

    def mirror(run_dir) -> None:
        def follow() -> None:
            print(f"\n── {run_dir.name} ──")
            Transcript(run_dir, colour).follow()
            monitor.wait()
            if run_dir.name in monitor.outcomes:
                print("\n".join(live_summary(run_dir, monitor.outcomes[run_dir.name], monitor.signer.public_key_b64)))

        threading.Thread(target=follow, daemon=True).start()

    monitor.on_start = mirror
    print(f"\nModel {args.live}. Type your prompt on the page, or press Enter there to use the default:")
    print(f"  {url}\nRuns started there are mirrored here as a transcript.")


def cmd_whois(args: argparse.Namespace) -> int:
    from .identity import IdentityToken
    from .lookup import DEFAULT_SEARCH, lookup, render

    token = None
    text = args.key
    source = Path(text)
    if source.suffix == ".json" or (len(text) < 4096 and source.is_file()):
        text = source.read_text()
    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
            token = IdentityToken.from_dict(data.get("token", data))  # a token, or a whole ledger entry
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            print(f"couldn't read that as a token: {exc}", file=sys.stderr)
            return 2
    agent_id = token.id if token else text.strip()
    search = [Path(p) for p in args.search] if args.search else [args.runs_dir, *map(Path, DEFAULT_SEARCH[1:])]
    result = lookup(agent_id, _trusted_key(args), search, token)
    print(json.dumps(result.to_dict(), indent=2) if args.json else render(result, sys.stdout.isatty()))
    if (args.logs or args.full) and not args.json:
        if result.run_dir is None:
            print("\nno logs: no run here records this agent")
        else:
            verified = verify_run(Path(result.run_dir), _trusted_key(args))
            if verified.status not in (VERIFIED, INCOMPLETE):
                print(f"\nWARNING: the logs failed verification ({verified}), so what follows can't be trusted.")
            print(f"\nlogs from {result.run}:\n")
            print(render_trace(verified, agent_id, args.full))
    return {True: 0, False: 1}.get(result.ours, 2)


def add_trace_argument(parser: argparse.ArgumentParser) -> None:
    from .export import DEFAULT_ENDPOINT

    parser.add_argument(
        "--trace",
        nargs="?",
        const=DEFAULT_ENDPOINT,
        metavar="URL",
        help=f"send the finished run to a trace viewer (default URL: {DEFAULT_ENDPOINT}, Phoenix)",
    )


def cmd_export(args: argparse.Namespace) -> int:
    from .export import export_run, find_runs

    if args.all:
        run_dirs = find_runs(args.runs_dir)
    elif args.runs:
        run_dirs = [_run_dir(args, ref) for ref in args.runs]
    else:
        print("give run IDs, or --all", file=sys.stderr)
        return 1
    key = _trusted_key(args)
    sent = failed = 0
    for run_dir in run_dirs:
        result = verify_run(run_dir, key)
        try:
            spans = export_run(result, run_dir.name, args.endpoint)
        except ValueError as exc:
            print(f"skipped {exc}")
            failed += 1
            continue
        print(f"sent {run_dir.name}: {spans} spans")
        sent += 1
    print(f"\n{sent} sent, {failed} skipped. Open http://localhost:6006 and choose the harness project.")
    return 0 if sent and not failed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harness", description=__doc__)
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    parser.add_argument("--key-dir", type=Path, default=DEFAULT_KEY_DIR)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("keygen", help="create the signing key and print the public key").set_defaults(func=cmd_keygen)

    run = commands.add_parser("run", help="run root agents; each task starts one root")
    run.add_argument("task", nargs="*")
    run.add_argument("--roots-file", type=Path, help="JSON list of roots: task, system_prompt, memory, model, tools")
    run.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="default: %(default)s. Others: openrouter:<OpenRouter model ID>, anthropic:claude-opus-5-5, "
        "alibaba:qwen-max, hf:<Hub repo ID>[:<provider>] or endpoint:<model>@<base_url>",
    )
    run.add_argument("--offer-model", action="append", default=[], help="another model agents may choose (repeatable)")
    run.add_argument("--sandbox", choices=["docker", "none"], default="docker")
    run.add_argument("--seed-repo", type=Path, help="directory copied into the workspace before the run")
    run.add_argument("--always-take-turns", action="store_true", help="agents that finished still get every round")
    add_trace_argument(run)
    defaults = Limits()
    run.add_argument("--max-depth", type=int, default=defaults.max_depth)
    run.add_argument("--max-agents", type=int, default=defaults.max_agents)
    run.add_argument("--max-lineage-ops", type=int, default=defaults.max_lineage_ops_per_round, help="per agent, per round")
    run.add_argument("--max-tool-calls", type=int, default=defaults.max_tool_calls_per_round, help="per agent, per round")
    run.add_argument("--max-rounds", type=int, default=defaults.max_rounds)
    run.add_argument("--max-tokens", type=int, default=defaults.max_tokens, help="shared across the run")
    run.set_defaults(func=cmd_run)

    trace = commands.add_parser("trace", help="show the lineage tree and each agent's steps")
    trace.add_argument("run", help="run ID or run directory")
    trace.add_argument("--agent", help="show only this agent's lineage")
    trace.add_argument("--full", action="store_true", help="also show every prompt and model response")
    trace.add_argument("--public-key", help="trusted public key (default: from --key-dir)")
    trace.set_defaults(func=cmd_trace)

    export = commands.add_parser("export", help="send verified runs to a trace viewer such as Phoenix")
    export.add_argument("runs", nargs="*", help="run IDs or run directories")
    export.add_argument("--all", action="store_true", help="every run in --runs-dir")
    export.add_argument("--endpoint", default="http://localhost:6006/v1/traces", help="OTLP over HTTP traces URL")
    export.add_argument("--public-key", help="trusted public key (default: from --key-dir)")
    export.set_defaults(func=cmd_export)

    report = commands.add_parser("report", help="print a run's measures as JSON")
    report.add_argument("run", help="run ID or run directory")
    report.add_argument("--public-key", help="trusted public key (default: from --key-dir)")
    report.add_argument("--force", action="store_true", help="report even if the run didn't verify")
    report.set_defaults(func=cmd_report)

    verify = commands.add_parser("verify", help="check integrity: exit 0 verified, 1 tampered, 2 incomplete")
    verify.add_argument("run", help="run ID or run directory")
    verify.add_argument("--public-key", help="trusted public key (default: from --key-dir)")
    verify.set_defaults(func=cmd_verify)

    rev = commands.add_parser("revoke", help="revoke an ID and its descendants, also during a run")
    rev.add_argument("run", help="run ID or run directory")
    rev.add_argument("agent_id")
    rev.add_argument("--no-cascade", action="store_true", help="revoke only this ID, not its descendants")
    rev.add_argument("--reason", default="")
    rev.set_defaults(func=cmd_revoke)

    whois = commands.add_parser("whois", help="say whether this harness created an agent ID or token, and show its lineage")
    whois.add_argument("key", help="an agent ID, a token as JSON, or a file holding one (a ledger entry works too)")
    whois.add_argument("--in", dest="search", action="append", help="folder of runs to search (repeatable; default: --runs-dir, traces, results/*/runs)")
    whois.add_argument("--json", action="store_true", help="print the answer as JSON")
    whois.add_argument("--logs", action="store_true", help="also print this agent's trace from its run")
    whois.add_argument("--full", action="store_true", help="with --logs, include every prompt and model response")
    whois.add_argument("--public-key", help="trusted public key (default: from --key-dir)")
    whois.set_defaults(func=cmd_whois)

    flag = commands.add_parser("flag", help="flag a running agent as a threat: kill it and record it in the threat log")
    flag.add_argument("run", help="run ID or run directory")
    flag.add_argument("agent_id")
    flag.add_argument("--reason", required=True, help="why it's a threat, for the threat log")
    flag.add_argument("--no-cascade", action="store_true", help="kill only this ID, not its descendants")
    flag.set_defaults(func=cmd_flag)

    monitor = commands.add_parser("monitor", help="live web page of agents and their requests, where you can flag and kill them")
    monitor.add_argument("--port", type=int, default=8321)
    monitor.add_argument("--demo", action="store_true", help="also start an offline scripted run with a rogue agent to try it on")
    monitor.add_argument("--live", nargs="?", const="openrouter:anthropic/claude-haiku-5.5", metavar="MODEL",
                         help="also start a cheap, harmless run on a real model (default: %(const)s)")
    monitor.add_argument("--target", type=int, default=40, help="--live: how many lines the agent should write")
    monitor.add_argument("--task", help="--live: the page's default prompt, instead of the notebook job. "
                         "It has write_line(text, notebook), spawn_agent and send_message")
    monitor.add_argument("--max-tokens", type=int, default=150_000, help="--live: hard cap on the run's tokens")
    monitor.add_argument("--pace", type=float, default=None, help="seconds per step: scripted turn in --demo (1.5), tool call in --live (2)")
    monitor.add_argument("--no-browser", action="store_true", help="don't open the page in a browser")
    monitor.set_defaults(func=cmd_monitor)
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"not found: {exc.filename}. If this is the signing key, run `harness keygen` or pass --public-key.", file=sys.stderr)
        return 1
    except Exception as exc:
        # e.g. pydantic_ai's UserError for a missing API key: no traceback needed.
        if type(exc).__name__ in ("UserError", "ValueError", "PermissionError"):
            print(f"error: {exc}", file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    sys.exit(main())
