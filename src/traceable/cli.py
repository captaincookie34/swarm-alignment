"""Command line: keygen, run, trace, report, verify, revoke."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .harness import DEFAULT_SYSTEM_PROMPT
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
            )
        )
    except SandboxError as exc:
        print(f"{exc}\nIs Docker running? Use --sandbox none to run without repo or test tools.", file=sys.stderr)
        return 1
    print(f"run:    {outcome.run_id}\nstatus: {outcome.status}\n")
    for token in outcome.roots:
        print(f"{token.id}: {outcome.agents[token.id][1]}")
    print(f"\nNext: traceable trace {outcome.run_id}")
    return 0 if outcome.status == "completed" else 1


def cmd_trace(args: argparse.Namespace) -> int:
    result = verify_run(_run_dir(args, args.run), _trusted_key(args))
    print(f"log integrity: {result}\n")
    if result.status not in (VERIFIED, INCOMPLETE):
        print("WARNING: these logs failed verification, so what follows can't be trusted.\n")
    print(render_trace(result, args.agent))
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="traceable", description=__doc__)
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
        help="e.g. anthropic:claude-opus-5-5, alibaba:qwen-max or endpoint:<model>@<base_url>",
    )
    run.add_argument("--offer-model", action="append", default=[], help="another model agents may choose (repeatable)")
    run.add_argument("--sandbox", choices=["docker", "none"], default="docker")
    run.add_argument("--seed-repo", type=Path, help="directory copied into the workspace before the run")
    run.add_argument("--always-take-turns", action="store_true", help="agents that finished still get every round")
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
    trace.add_argument("--public-key", help="trusted public key (default: from --key-dir)")
    trace.set_defaults(func=cmd_trace)

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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"not found: {exc.filename}. If this is the signing key, run `traceable keygen` or pass --public-key.", file=sys.stderr)
        return 1
    except Exception as exc:
        # e.g. pydantic_ai's UserError for a missing API key: no traceback needed.
        if type(exc).__name__ in ("UserError", "ValueError", "PermissionError"):
            print(f"error: {exc}", file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    sys.exit(main())
