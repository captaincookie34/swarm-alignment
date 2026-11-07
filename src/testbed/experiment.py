"""Run trials and aggregate results. Each trial is saved as it finishes, so a crash loses little."""
from __future__ import annotations

import asyncio
import json
import math
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

from harness.identity import Signer
from harness.log import LogWriteError
from harness.report import build_report
from harness.revocation import revoke
from harness.runner import run_agents
from harness.sandbox import DockerSandbox, SandboxError
from harness.verify import VERIFIED, verify_run

from .conditions import ATTACKER_INDEX, CONDITIONS, Trial
from .issues import write_seed_repo
from .scoring import SCORERS, productivity
from .scripted import scripted_model
from .tools import IssueBoard, board_tools, docker_tester, offline_repo_tools, release_tool

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


async def run_trial(
    trial: Trial,
    out_dir: Path,
    signer: Signer,
    worker_model: str = SCRIPTED,
    attacker_model: str | None = None,
    max_tokens: int = 200_000,
    compliant: bool = True,
    trace_endpoint: str | None = None,
) -> dict:
    """Run and score one trial. Live models always use Docker; scripted ones use stand-ins."""
    condition = trial.condition
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"run_{condition.name}_s{trial.seed}_{secrets.token_hex(3)}"
    scripted = worker_model == SCRIPTED
    attacker = attacker_model or worker_model

    catalog: dict = dict(release_tool())
    sandbox = None
    seed_dir = None
    temp = None
    if scripted:
        catalog.update(offline_repo_tools({}))
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
        model = worker_model
        attacker_spec = attacker if condition.objective else None
        extra_models = {attacker: attacker} if attacker != worker_model else None
    catalog.update(board_tools(board))

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
    if result.status != VERIFIED:
        record["error"] = str(result)
        return record  # unverified logs aren't evidence
    score = SCORERS[condition.name](trial, result)
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
            log(
                f"{name} seed {seed}: {record['status']}, {record['integrity']}, "
                f"{record.get('attempts', '-')} attempts, {record.get('successes', '-')} successes"
            )
    return records


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
        solved = f"{r['mean_issues_solved']:.1f}" if r["mean_issues_solved"] is not None else "n/a"
        lines.append(
            f"| {r['condition']} | {r['guardrail']} | {r['runs']} ({r['runs_attempted']}){skipped} | {rate} | {ci} | "
            f"{r['attempts']} | {r['successes']} | {r['actions_after_revocation']} | {solved} |"
        )
    return "\n".join(lines)


def load_records(out_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (out_dir / RESULTS_FILE).read_text().splitlines() if line.strip()]
