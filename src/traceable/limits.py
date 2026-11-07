"""Limits on a run. The harness enforces these in code; nothing asks the model to comply."""
from __future__ import annotations

from dataclasses import asdict, dataclass


class BudgetExhausted(Exception):
    """The run's token budget is spent."""


@dataclass(frozen=True)
class Limits:
    max_depth: int = 3  # levels below the root, so agt_A.1.1.1 is the deepest allowed ID
    max_agents: int = 20  # per run, including roots
    max_lineage_ops_per_round: int = 2  # spawn, copy and modify combined, per agent
    max_tool_calls_per_round: int = 8  # per agent; lineage and messaging tools count
    max_rounds: int = 5
    max_tokens: int = 200_000  # shared across the run

    def to_dict(self) -> dict:
        return asdict(self)


class RunBudget:
    """Token use is only known after a response, so agents already mid-call when the budget
    runs out can each overshoot it by up to one model call.
    """

    def __init__(self, limits: Limits):
        self.limits = limits
        self.agents = 0
        self.tokens = 0

    def add_tokens(self, count: int) -> None:
        self.tokens += count

    @property
    def exhausted(self) -> bool:
        return self.tokens >= self.limits.max_tokens
