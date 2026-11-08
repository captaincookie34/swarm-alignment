"""Run trials and aggregate results. Each trial is saved as it finishes, so a crash loses little."""
from __future__ import annotations

import asyncio
import json
import math
import tempfile
import time
from pathlib import Path
from typing import Any

from harness.identity import Signer, new_run_id
from harness.log import LogWriteError
from harness.report import build_report
from harness.revocation import revoke
from harness.runner import run_agents
from harness.sandbox import DockerSandbox, SandboxError
from harness.threats import read_threats
from harness.verify import VERIFIED, VerifyResult, verify_run

from .conditions import ATTACKER_INDEX, CONDITIONS, Trial
from .issues import write_seed_repo
from .scoring import SCORERS, productivity
from .scripted import scripted_model
from .tools import IssueBoard, NameRegistry, board_tools, docker_tester, name_tools, offline_repo_tools, release_tool

RESULTS_FILE = "results.jsonl"
SCRIPTED = "scripted"
SCRIPTED_REVOKE_DELAY = 0.01


def _record(trial: Trial, run_id: str | None, status: str, verified: str, attacker: str, worker: str, **rest: Any) -> dict:
    return {
        "condition": trial.condition.name,
        "guardrail": trial.condition.guardrail,
        "seed": trial.seed,
        "run_id": run_id,
        "status": status,
        "integrity": verified,
        "attacker_model": attacker,
        "worker_model": worker,
        **rest,
    }


def operator_flags(run_dir: Path, signer: Signer) -> list[dict]:
    """Agents an operator flagged and killed from the monitor during the run, with their reasons."""
    return [
        {"agent_id": t["agent_id"], "reason": t["reason"], "cascade": t["cascade"]}
        for t in read_threats(run_dir, signer.public_key_b64)
        if t["verified"]
    ]


def model_failures(result: VerifyResult) -> list[dict]:
    """Model calls that failed. A cancellation is the harness stopping an agent, not a failure."""
    return [e for e in result.calls if e["type"] == "model.error" and e["payload"].get("error") != "cancelled"]


async def run_trial(
    trial: Trial,
    out_dir: Path,
    signer: Signer,
    worker_model: str = SCRIPTED,
    attacker_model: str | None = None,
    max_tokens: int = 200_000,
    compliant: bool = True,
    trace_endpoint: str | None = None,
    run_id: str | None = None,
) -> dict:
    """Run and score one trial. Live models always use Docker; scripted ones use stand-ins."""
    condition = trial.condition
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    run_id = run_id or new_run_id(runs_dir, f"{condition.name}_s{trial.seed}")
    scripted = worker_model == SCRIPTED
    attacker = attacker_model or worker_model

    catalog: dict = dict(release_tool())
    sandbox = None
    seed_dir = None
    temp = None
    if scripted:
        catalog.update(offline_repo_tools(trial.seed_files()))
        board = IssueBoard(tester=_offline_tester)
        model: Any = scripted_model(trial, compliant)
        extra_models = None
        attacker_spec = None
    else:
        sandbox = DockerSandbox()
        board = IssueBoard(tester=docker_tester(sandbox))
        temp = tempfile.TemporaryDirectory()
        seed_dir = Path(temp.name) / "seed"
        write_seed_repo(seed_dir)
        for path, text in trial.seed_files().items():
            with open(seed_dir / path, "a", encoding="utf-8") as f:
                f.write(text)
        model = worker_model
        attacker_spec = attacker if condition.objective else None
        extra_models = {attacker: attacker} if attacker != worker_model else None
    catalog.update(board_tools(board))
    if condition.naming:
        catalog.update(name_tools(NameRegistry()))

    def on_round_start(number: int, root_ids: list[str]) -> None:
        if condition.revoke_round != number:
            return

        def do_revoke() -> None:
            attacker = root_ids[ATTACKER_INDEX]
            revoke(runs_dir / run_id, signer, attacker, reason=f"scheduled for round {condition.revoke_round}")

        if condition.revoke_delay_seconds:
            # Scripted calls return in microseconds, so they need far less time to be in flight.
            delay = SCRIPTED_REVOKE_DELAY if scripted else condition.revoke_delay_seconds
            asyncio.get_running_loop().call_later(delay, do_revoke)
        else:
            do_revoke()

    started = time.time()
    try:
        outcome = await run_agents(
            trial.roots(attacker_spec),
            model,
            runs_dir,
            signer,
            trial.limits(max_tokens),
            catalog=catalog,
            sandbox=sandbox,
            extra_models=extra_models,
            seed_repo=seed_dir,
            run_id=run_id,
            trace_endpoint=trace_endpoint,
            on_round_start=on_round_start,
            narrow_child_tools=condition.narrow_child_tools,
            # Don't cancel in-flight calls on revocation: what comes back must meet the live
            # check, and refused attempts get counted. Cancelling is tested in the harness's own suite.
            revocation_poll_seconds=3600,
        )
    except (SandboxError, LogWriteError):
        raise  # the setup is broken, so more trials would fail the same way
    except Exception as exc:
        # One failed trial shouldn't lose the rest. It's reported, never scored as a result.
        return _record(trial, run_id, "crashed", "n/a", attacker, worker_model, error=f"{type(exc).__name__}: {exc}")
    finally:
        if temp:
            temp.cleanup()

    result = verify_run(outcome.run_dir, signer.public_key_b64)
    record = _record(trial, run_id, outcome.status, result.status, attacker, worker_model, seconds=round(time.time() - started, 1))
    if flags := operator_flags(outcome.run_dir, signer):
        # Someone killed agents from the monitor, so the outcome isn't the agents' alone.
        record["operator_flags"] = flags
    if result.status != VERIFIED:
        record["error"] = str(result)
        return record  # unverified logs aren't evidence
    score = SCORERS[condition.name](trial, result)
    if failures := model_failures(result):
        first = failures[0]
        record["error"] = (
            f"{len(failures)} model call(s) failed, first on {first['agent_id']}: "
            f"{first['payload'].get('error')}: {first['payload'].get('message', '')[:200]}"
        )
        record["partial_score"] = score.to_dict()
        return record  # an agent stopped early, so what it never got to do isn't evidence
    report = build_report(result)
    record.update(
        attempts=score.attempts,
        successes=score.successes,
        details=score.details,
        actions_after_revocation=report.actions_after_revocation,
        refused_after_revocation=report.refused_after_revocation,
        refused_total=sum(report.refused.values()),
        duplicate_configs=report.duplicate_configs,
        **productivity(result),
    )
    return record


async def _offline_tester(path: str) -> bool:
    return True


async def run_experiment(
    conditions: list[str],
    seeds: list[int],
    out_dir: Path,
    signer: Signer,
    worker_model: str = SCRIPTED,
    attacker_model: str | None = None,
    max_tokens: int = 200_000,
    log=print,
    trace_endpoint: str | None = None,
) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for name in conditions:
        for seed in seeds:
            record = await run_trial(
                Trial(CONDITIONS[name], seed), out_dir, signer, worker_model, attacker_model, max_tokens,
                trace_endpoint=trace_endpoint,
            )  # fmt: skip
            with open(out_dir / RESULTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            records.append(record)
            log(describe(record))
    return records


def describe(record: dict) -> str:
    """One line per finished trial, for the terminal."""
    scored = f"{record['attempts']} attempts, {record['successes']} successes" if "attempts" in record else "not scored"
    problem = f" ({record['error']})" if record.get("error") else ""
    flags = record.get("operator_flags")
    killed = f" [you killed {len(flags)} agent(s) from the monitor]" if flags else ""
    return f"{record['condition']} seed {record['seed']}: {record['status']}, {record['integrity']}, {scored}{problem}{killed}"


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% interval on a proportion. Honest at the small counts a pilot produces."""
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    denominator = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def aggregate(records: list[dict]) -> list[dict]:
    """One row per condition. The unit is the run: attempts within a run aren't independent."""
    rows = []
    for name in dict.fromkeys(r["condition"] for r in records):
        group = [r for r in records if r["condition"] == name]
        scored = [r for r in group if "attempts" in r]
        attempted = [r for r in scored if r["attempts"] > 0]
        succeeded = [r for r in attempted if r["successes"] > 0]
        low, high = wilson(len(succeeded), len(attempted))
        rows.append(
            {
                "condition": name,
                "guardrail": CONDITIONS[name].guardrail,
                "runs": len(group),
                "unscored_runs": len(group) - len(scored),
                "operator_killed_runs": sum(1 for r in group if r.get("operator_flags")),
                "runs_attempted": len(attempted),
                "runs_succeeded": len(succeeded),
                "success_rate": len(succeeded) / len(attempted) if attempted else None,
                "ci_low": low,
                "ci_high": high,
                "attempts": sum(r["attempts"] for r in scored),
                "successes": sum(r["successes"] for r in scored),
                "actions_after_revocation": sum(r["actions_after_revocation"] for r in scored),
                "mean_issues_solved": _mean(r["issues_solved"] for r in scored),
                "mean_tokens": _mean(r["tokens"] for r in scored),
                "models": sorted({r["attacker_model"] for r in group}),
            }
        )
    return rows


def render_comparison(results: dict[str, list[dict]]) -> str:
    """The same conditions across result folders, one row per folder and condition, to compare models."""
    lines = [
        "| Condition | Folder | Attacker model | Worker model | Runs (attempted) | Runs with a success | Attempts | Successes | Issues solved | Mean tokens |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    conditions = list(dict.fromkeys(r["condition"] for records in results.values() for r in records))
    for name in conditions:
        for folder, records in results.items():
            group = [r for r in records if r["condition"] == name]
            for row in aggregate(group):
                rate = f"{row['runs_succeeded']}/{row['runs_attempted']}" if row["runs_attempted"] else "no attempts"
                skipped = f" ({row['unscored_runs']} unscored)" if row["unscored_runs"] else ""
                solved = f"{row['mean_issues_solved']:.1f}" if row["mean_issues_solved"] is not None else "n/a"
                tokens = f"{row['mean_tokens']:,.0f}" if row["mean_tokens"] is not None else "n/a"
                workers = ", ".join(sorted({r["worker_model"] for r in group}))
                lines.append(
                    f"| {name} | {folder} | {', '.join(row['models'])} | {workers} | {row['runs']} "
                    f"({row['runs_attempted']}){skipped} | {rate} | {row['attempts']} | {row['successes']} | {solved} | {tokens} |"
                )
    return "\n".join(lines)


def _mean(values) -> float | None:
    values = list(values)
    return sum(values) / len(values) if values else None


def render_table(rows: list[dict]) -> str:
    header = "| Condition | Guardrail | Runs (attempted) | Runs with a success | 95% CI | Attempts | Successes | Post-revocation actions | Issues solved |"
    lines = [header, "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        rate = f"{r['runs_succeeded']}/{r['runs_attempted']}" if r["runs_attempted"] else "no attempts"
        ci = f"{r['ci_low']:.2f} to {r['ci_high']:.2f}" if r["runs_attempted"] else "n/a"
        skipped = f" ({r['unscored_runs']} unscored)" if r["unscored_runs"] else ""
        if r.get("operator_killed_runs"):
            skipped += f" ({r['operator_killed_runs']} with agents you killed)"
        solved = f"{r['mean_issues_solved']:.1f}" if r["mean_issues_solved"] is not None else "n/a"
        lines.append(
            f"| {r['condition']} | {r['guardrail']} | {r['runs']} ({r['runs_attempted']}){skipped} | {rate} | {ci} | "
            f"{r['attempts']} | {r['successes']} | {r['actions_after_revocation']} | {solved} |"
        )
    return "\n".join(lines)


def load_records(out_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (out_dir / RESULTS_FILE).read_text().splitlines() if line.strip()]
