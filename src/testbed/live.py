"""Run test cases from the harness monitor page, and watch or flag their agents as they work.

    python -m testbed monitor --worker-model <model> --out results/live

The page gets a test-case picker beside its prompt box. Each test runs exactly as `testbed run`
would run it, writes its logs to <out>/runs/ and appends its score to <out>/results.jsonl, so
`testbed summarize <out>` reads it like any other batch. If you flag and kill an agent during
a test, the result records it under `operator_flags`, since the outcome is no longer the agents'
alone.
"""
from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path

from harness.identity import Signer, new_run_id

from .conditions import CONDITIONS, Trial
from .experiment import RESULTS_FILE, SCRIPTED, describe, run_trial


class TestbedSource:
    """What the monitor needs to list and start the testbed's conditions. One test at a time."""

    __test__ = False  # not a pytest class, despite the name

    def __init__(self, out_dir: Path, signer: Signer, worker_model: str = SCRIPTED, attacker_model: str | None = None,
                 max_tokens: int = 500_000, log=print):
        self.out_dir = out_dir
        self.runs_dir = out_dir / "runs"
        self.signer = signer
        self.worker_model = worker_model
        self.attacker_model = attacker_model
        self.max_tokens = max_tokens
        self.log = log
        self.records: dict[str, dict] = {}
        self._errors: dict[str, str] = {}
        self._write_lock = threading.Lock()

    def catalog(self) -> list[dict]:
        return [
            {"name": c.name, "guardrail": c.guardrail, "expected": c.expected, "attacker": bool(c.objective)}
            for c in CONDITIONS.values()
        ]

    def defaults(self) -> dict:
        return {"model": self.worker_model, "attacker_model": self.attacker_model or "", "max_tokens": self.max_tokens,
                "out": str(self.out_dir)}

    def error(self, run_id: str) -> str | None:
        return self._errors.get(run_id)

    def start(self, name: str, model: str, attacker_model: str, max_tokens: int, seed: int) -> tuple[str, threading.Thread]:
        if name not in CONDITIONS:
            raise ValueError(f"no test case called {name!r}")
        worker = model or self.worker_model
        attacker = attacker_model or self.attacker_model or None
        if worker != SCRIPTED:
            from harness.runner import resolve_model

            for spec in {worker, attacker} - {None}:
                resolve_model(spec)  # a bad name or missing key fails here, before a run exists
        elif attacker:
            raise ValueError("the scripted model takes no attacker model")
        max_tokens = max(1_000, min(max_tokens or self.max_tokens, 5_000_000))
        seed = max(0, seed)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        run_id = new_run_id(self.runs_dir, f"{name}_s{seed}")

        def work() -> None:
            try:
                record = asyncio.run(
                    run_trial(Trial(CONDITIONS[name], seed), self.out_dir, self.signer, worker, attacker, max_tokens, run_id=run_id)
                )
            except Exception as exc:  # e.g. Docker isn't running: show it on the page and in the terminal
                self._errors[run_id] = f"{type(exc).__name__}: {exc}"
                self.log(f"{name} seed {seed}: couldn't run: {self._errors[run_id]}")
                return
            with self._write_lock:
                with open(self.out_dir / RESULTS_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            self.records[run_id] = record
            self.log(describe(record))

        thread = threading.Thread(target=work, daemon=True, name=f"harness-run-{run_id}")
        thread.start()
        self.log(f"started {run_id}: {name}, seed {seed}, on {worker}"
                 + (f" (attacker {attacker})" if attacker and attacker != worker else "") + f", capped at {max_tokens:,} tokens")
        return run_id, thread
