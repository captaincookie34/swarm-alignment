"""A scripted model for offline tests and demos. Costs nothing and is repeatable.

Like a real model it never learns its agent's ID, so scripts are keyed on the task
prompt. The turn is worked out from the message history, which makes it safe to share
one model across parallel agents.
"""
from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic_ai.messages import ModelMessage, ModelRequest, ModelResponse, TextPart, ToolCallPart, UserPromptPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from .capability import ROUND_ENDED

Step = list | Exception | Callable[[], Any | Awaitable[Any]]


def call(tool: str, **args: Any) -> ToolCallPart:
    return ToolCallPart(tool, args)


def say(text: str) -> TextPart:
    return TextPart(text)


def _first_prompt(messages: list[ModelMessage]) -> str:
    for message in messages:
        if isinstance(message, ModelRequest):
            for part in message.parts:
                if isinstance(part, UserPromptPart):
                    return str(part.content)
    return ""


def _is_round_end(response: ModelResponse) -> bool:
    """The harness wrote this one, so it isn't one of the script's turns."""
    return any(isinstance(p, TextPart) and p.content == ROUND_ENDED for p in response.parts)


class ScriptedModel(FunctionModel):
    """scripts maps a task prompt to one Step per model turn."""

    def __init__(self, scripts: dict[str, list[Step]]):
        self.scripts = scripts
        self.requests: list[tuple[list[ModelMessage], AgentInfo]] = []
        super().__init__(self._respond)

    async def _respond(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        self.requests.append((list(messages), info))
        prompt = _first_prompt(messages)
        if prompt not in self.scripts:
            raise KeyError(f"no script for prompt {prompt!r}")
        steps = self.scripts[prompt]
        turn = sum(isinstance(m, ModelResponse) and not _is_round_end(m) for m in messages)
        step = steps[min(turn, len(steps) - 1)]
        if callable(step):
            step = step()
            if inspect.isawaitable(step):
                step = await step
        if isinstance(step, Exception):
            raise step
        return ModelResponse(parts=step)
