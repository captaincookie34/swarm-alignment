"""Set up and tear down one run: key, logs, sandbox, harness."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic_ai.models import Model, infer_model
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from .config import AgentConfig
from .scheduler import DEFAULT_SYSTEM_PROMPT, Harness, ToolBuilder
from .identity import IdentityIssuer, IdentityToken, Signer, new_run_id
from .limits import Limits
from .log import HARNESS, RunLogs
from .sandbox import SandboxError

# Through OpenRouter, which needs only OPENROUTER_API_KEY. Direct providers still work by name,
# e.g. anthropic:claude-opus-5-5 with ANTHROPIC_API_KEY.
DEFAULT_MODEL = "openrouter:anthropic/claude-opus-5.5"
PUBLIC_KEY_FILE = "public_key.txt"
ENDPOINT_KEY_VARS = ("HF_TOKEN", "ENDPOINT_API_KEY")
# Hugging Face Inference Providers: one OpenAI-compatible router for models on the Hub.
HF_ROUTER_URL = "https://router.huggingface.co/v1"


@dataclass(frozen=True)
class RootSpec:
    """One root agent. Fields left as None use the run's defaults."""

    task: str
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    memory: str = ""
    model: str | None = None
    tools: tuple[str, ...] | None = None  # None means every tool the harness offers


@dataclass(frozen=True)
class RunOutcome:
    run_id: str
    run_dir: Path
    status: str
    agents: dict[str, tuple[str, str]]  # agent ID -> (status, output)
    roots: list[IdentityToken]


def resolve_model(spec: str) -> Model:
    """A Pydantic AI model name, `hf:<repo ID>[:<provider>]` for a Hub model served by
    Hugging Face Inference Providers, or `endpoint:<model>@<base_url>` for a dedicated
    OpenAI-compatible endpoint such as a Hugging Face Inference Endpoint.

    `hf:` models take an optional provider or policy suffix that HF's router understands,
    e.g. `hf:Qwen/Qwen3-32B:cerebras` or `hf:Qwen/Qwen3-32B:cheapest`; with none, HF picks.

    OpenRouter models are `openrouter:<OpenRouter model ID>`, such as
    `openrouter:qwen/qwen3.5-122b-a10b`. Each response records the model OpenRouter reports
    serving it, so a substitution would show in the call log.
    """
    if spec.startswith("hf:"):
        name = spec.removeprefix("hf:")
        if not name:
            raise ValueError("Hugging Face models look like hf:<repo ID>[:<provider>]")
        return OpenAIChatModel(name, provider=OpenAIProvider(base_url=HF_ROUTER_URL, api_key=_endpoint_key()))
    if spec.startswith("endpoint:"):
        name, sep, base_url = spec.removeprefix("endpoint:").partition("@")
        if not (name and sep and base_url):
            raise ValueError("endpoint models look like endpoint:<model>@<base_url>")
        # A local server (Ollama, vLLM, llama.cpp) usually takes no key, but the client needs one.
        api_key = "local" if _is_local(base_url) else None
        return EndpointChatModel(name, provider=OpenAIProvider(base_url=base_url, api_key=_endpoint_key(api_key)))
    return infer_model(spec)


class EndpointChatModel(OpenAIChatModel):
    """An OpenAI-compatible endpoint whose chat template allows system messages only at the start.

    Qwen's template on llama.cpp, for one, rejects a later system message with a 500 ("System
    message must be at the beginning"). Pydantic AI sends one mid-conversation when it retries an
    empty reply ("Please return text or call a tool"). This sends any such message as a user
    message instead. The system prompt at the start is unchanged, and the logs record Pydantic
    AI's messages, not this wire format, so runs stay comparable and verify as before.
    """

    async def _map_messages(self, *args: Any, **kwargs: Any) -> Any:
        messages = await super()._map_messages(*args, **kwargs)
        _demote_late_system_messages(messages)
        return messages


def _demote_late_system_messages(messages: list) -> None:
    """Turn every system or developer message after the leading ones into a user message."""
    leading = True
    for i, message in enumerate(messages):
        role = message.get("role")
        if role in ("system", "developer"):
            if leading:
                continue
            content = message.get("content")
            if isinstance(content, list):
                content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
            messages[i] = {"role": "user", "content": f"[Harness] {content}"}
        else:
            leading = False


def _is_local(url: str) -> bool:
    from urllib.parse import urlparse

    return urlparse(url).hostname in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def _endpoint_key(fallback: str | None = None) -> str:
    api_key = next((os.environ[v] for v in ENDPOINT_KEY_VARS if os.environ.get(v)), None)
    api_key = api_key or fallback
    if not api_key:
        raise ValueError(f"set one of {', '.join(ENDPOINT_KEY_VARS)} to use a Hugging Face or endpoint model")
    return api_key


def model_settings_for(name: str) -> dict:
    """Agents are non-streaming, so max_tokens stays within HTTP timeouts."""
    settings: dict = {"max_tokens": 16_000}
    if name.startswith("anthropic:"):
        settings["anthropic_effort"] = "medium"
    return settings


def _send_trace(run_dir: Path, signer: Signer, endpoint: str | None, exporter: Any) -> None:
    """A viewer being down mustn't turn a finished run into a failure."""
    import logging

    from .export import DEFAULT_ENDPOINT, export_run
    from .verify import verify_run

    try:
        export_run(verify_run(run_dir, signer.public_key_b64), run_dir.name, endpoint or DEFAULT_ENDPOINT, exporter)
    except Exception as exc:
        logging.getLogger(__name__).warning("couldn't send the trace for %s: %s", run_dir.name, exc)


async def run_agents(
    roots: list[RootSpec],
    model: Any = DEFAULT_MODEL,
    runs_dir: Path = Path("runs"),
    signer: Signer | None = None,
    limits: Limits = Limits(),
    catalog: dict[str, ToolBuilder] | None = None,
    sandbox: Any = None,
    extra_models: dict[str, Any] | None = None,
    seed_repo: Path | None = None,
    run_id: str | None = None,
    trace_endpoint: str | None = None,
    trace_exporter: Any = None,
    **harness_options: Any,
) -> RunOutcome:
    """Run root agents and everything they create.

    model is the default for roots. extra_models adds to what agents may choose from; values
    are specs or Model objects. With no sandbox, agents have only lineage, messaging and
    catalog tools. There's deliberately no fallback to running commands on the host.

    trace_endpoint (or trace_exporter, for tests) sends the finished, verified run to a trace
    viewer such as Phoenix.
    """
    signer = signer or Signer.load_or_create()
    # Resolve first: a bad model name or missing API key shouldn't leave a run behind.
    default_name = model if isinstance(model, str) else getattr(model, "harness_label", "scripted")
    specs: dict[str, Any] = {default_name: model, **(extra_models or {})}
    specs.update({r.model: r.model for r in roots if r.model and r.model not in specs})
    models = {name: resolve_model(m) if isinstance(m, str) else m for name, m in specs.items()}

    run_id = run_id or new_run_id(runs_dir)
    run_dir = runs_dir / run_id
    logs = RunLogs(run_dir, signer, run_id)
    # A convenience copy only. Verifying needs a key obtained outside this directory.
    (run_dir / PUBLIC_KEY_FILE).write_text(signer.public_key_b64 + "\n")
    logs.call(
        HARNESS,
        "run.start",
        {
            "run": run_id,
            "models": sorted(models),
            "limits": limits.to_dict(),
            "sandbox": type(sandbox).__name__ if sandbox else None,
        },
    )

    tools = dict(catalog or {})
    if sandbox is not None:
        from .tools import sandbox_tools

        try:
            await sandbox.start(run_dir / "workspace", seed_repo)
        except SandboxError as exc:
            logs.close("sandbox_error", {"error": str(exc)})
            raise
        tools.update(sandbox_tools(sandbox, logs))

    harness = Harness(
        run_dir,
        signer,
        IdentityIssuer(signer, run_id),
        logs,
        models,
        limits=limits,
        catalog=tools,
        model_settings=model_settings_for,
        **harness_options,
    )
    try:
        tokens = []
        for root in roots:
            names = tuple(harness.catalog) if root.tools is None else root.tools
            config = AgentConfig(root.model or default_name, root.system_prompt, root.memory, names)
            tokens.append(harness.start_root(config, root.task))
        status = await harness.run()
        logs.close(status, {"run_tokens": harness.budget.tokens, "agents": harness.budget.agents})
    finally:
        # If the run raised (e.g. a log failed), the heads stay open and verify says so.
        if sandbox is not None:
            await sandbox.stop()
    if trace_endpoint or trace_exporter is not None:
        _send_trace(run_dir, signer, trace_endpoint, trace_exporter)
    agents = {agent_id: (r.status, r.output) for agent_id, r in harness.agents.items()}
    return RunOutcome(run_id, run_dir, status, agents, tokens)
