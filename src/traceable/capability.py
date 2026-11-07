"""The single logging and enforcement point: one capability per agent, bound to its ID.

Hooks observe and gate calls but never rewrite past messages. Redaction happens only in
the logs, and newer Claude models require history to stay append-only.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import SkipModelRequest, SkipToolExecution, ToolRetryError
from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelResponse, TextPart, ToolCallPart

from .identity import ID_CLAIM, IdentityToken, canonical
from .limits import BudgetExhausted
from .log import LogWriteError

if TYPE_CHECKING:
    from .harness import Harness

ROUND_ENDED = "(The harness ended this round: tool call limit reached.)"


class AgentStopped(Exception):
    """The caller isn't allowed to make calls any more, e.g. it was revoked."""


class HarnessRefusal(Exception):
    """A tool refused the request for a policy reason. The message goes to the model."""


class NativeToolsForbidden(RuntimeError):
    """A provider-hosted tool would run where the harness can't see or log it."""


def _dump(messages: list) -> list[dict]:
    return ModelMessagesTypeAdapter.dump_python(messages, mode="json")


def _as_dict(args: Any) -> dict | None:
    if isinstance(args, dict):
        return args
    if not args:
        return {}
    try:
        parsed = json.loads(args)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _id_claims(value: Any) -> list[str]:
    """ID-like text anywhere in the arguments. It has no effect, but scoring needs to see it."""
    return sorted(set(ID_CLAIM.findall(json.dumps(value, default=str))))


@dataclass
class TraceCapability(AbstractCapability[Any]):
    harness: "Harness"
    token: IdentityToken
    allowed_tools: tuple[str, ...]
    _logged_messages: int = 0
    _ignored: dict[str, list[str]] = field(default_factory=dict)
    tool_calls_this_round: int = 0
    model_calls_this_round: int = 0

    def start_round(self) -> None:
        self.tool_calls_this_round = 0
        self.model_calls_this_round = 0

    @property
    def _id(self) -> str:
        return self.token.id

    def _log(self, type: str, payload: dict) -> None:
        self.harness.logs.call(self._id, type, payload)

    async def wrap_model_request(self, ctx, *, request_context, handler):
        reason = self.harness.refusal_for(self.token)
        if reason:
            self._log("action.refused", {"kind": "model", "reason": reason})
            raise AgentStopped(reason)
        budget = self.harness.budget
        if budget.exhausted:
            self._log("action.refused", {"kind": "model", "reason": "token budget exhausted"})
            raise BudgetExhausted("token budget exhausted")
        cap = budget.limits.max_tool_calls_per_round
        # The second check bounds rounds where a model keeps making calls that never run.
        if self.tool_calls_this_round >= cap or self.model_calls_this_round > cap:
            self._log("round.limit", {"tool_calls": self.tool_calls_this_round, "model_calls": self.model_calls_this_round})
            raise SkipModelRequest(ModelResponse(parts=[TextPart(ROUND_ENDED)]))
        native = request_context.model_request_parameters.native_tools
        if native:
            self._log("action.refused", {"kind": "model", "reason": "native tools forbidden"})
            raise NativeToolsForbidden(f"provider-hosted tools are not allowed: {native}")
        self.model_calls_this_round += 1

        # Log only what's new: full history on every turn would grow quadratically.
        messages = _dump(request_context.messages)
        new = [m for m in messages[self._logged_messages :] if m.get("kind") != "response"]
        self._logged_messages = len(messages)
        tools = request_context.model_request_parameters.function_tools
        self._log(
            "model.request",
            {
                "new_messages": new,
                "history_hash": hashlib.sha256(canonical(messages)).hexdigest(),
                "history_length": len(messages),
                "tools": [t.name for t in tools],
            },
        )
        try:
            response = await handler(request_context)
        except asyncio.CancelledError:
            self._log("model.error", {"error": "cancelled"})
            raise
        except Exception as exc:
            self._log("model.error", {"error": type(exc).__name__, "message": str(exc)})
            raise
        budget.add_tokens(response.usage.total_tokens)
        self._log(
            "model.response",
            {
                "parts": _dump([response])[0]["parts"],
                "model": response.model_name,
                "provider": response.provider_name,
                "finish_reason": response.finish_reason,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "run_tokens": budget.tokens,
            },
        )
        # The framework rejects tools this agent wasn't given, before any tool hook runs.
        # The model still attempted them, so they count as refusals.
        for part in response.parts:
            if isinstance(part, ToolCallPart) and part.tool_name not in self.allowed_tools:
                self._log(
                    "action.refused",
                    {
                        "kind": "tool",
                        "tool": part.tool_name,
                        "call_id": part.tool_call_id,
                        "reason": "tool not in this agent's config",
                        "args": part.args_as_dict(),
                    },
                )
        return response

    async def before_tool_validate(self, ctx, *, call, tool_def, args):
        """Drop arguments the tool doesn't define, so a written-in ID is ignored, not an error."""
        parsed = _as_dict(args)
        if parsed is None:
            return args
        known = (tool_def.parameters_json_schema or {}).get("properties", {})
        extra = sorted(k for k in parsed if k not in known)
        if not extra:
            return args
        self._ignored[call.tool_call_id] = extra
        return {k: v for k, v in parsed.items() if k in known}

    async def on_tool_validate_error(self, ctx, *, call, tool_def, args, error):
        self._log(
            "action.refused",
            {
                "kind": "tool",
                "tool": call.tool_name,
                "call_id": call.tool_call_id,
                "reason": "invalid arguments",
                "ignored_args": self._ignored.pop(call.tool_call_id, []),
            },
        )
        raise error

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler):
        info = {"tool": call.tool_name, "call_id": call.tool_call_id}
        raw_args = call.args_as_dict()
        reason = self.harness.refusal_for(self.token)
        if reason is None and call.tool_name not in self.allowed_tools:
            reason = "tool not in this agent's config"  # a backstop: the model isn't offered it
        if reason is None and self.tool_calls_this_round >= self.harness.budget.limits.max_tool_calls_per_round:
            reason = "tool call limit for this round reached"
        if reason:
            self._log("action.refused", {**info, "kind": "tool", "reason": reason, "args": raw_args})
            raise SkipToolExecution(f"Refused by harness: {reason}.")
        self.tool_calls_this_round += 1

        # Write-ahead: on disk before the tool runs, so a crash can't hide a started action.
        start = {**info, "args": raw_args}
        if ignored := self._ignored.pop(call.tool_call_id, None):
            start["ignored_args"] = ignored
        if claims := _id_claims(raw_args):
            start["id_claims"] = claims
        self._log("action.start", start)
        try:
            result = await handler(args)
        except asyncio.CancelledError:
            self._log("action.end", {**info, "status": "cancelled"})
            raise
        except LogWriteError:
            raise
        except ToolRetryError as exc:
            self._log("action.end", {**info, "status": "retry", "message": str(exc)})
            raise
        except HarnessRefusal as exc:
            self._log("action.end", {**info, "status": "refused", "reason": str(exc)})
            return f"Refused by harness: {exc}"
        except Exception as exc:
            # Uncaught, this would abort the agent's turn and silently cancel sibling tools.
            self._log("action.end", {**info, "status": "error", "error": type(exc).__name__, "message": str(exc)})
            return f"Tool failed: {type(exc).__name__}: {exc}"
        self._log("action.end", {**info, "status": "ok", "result": result})
        return result
