"""An agent's config, and the hash that makes copies and modifications visible."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

from .identity import canonical
from .log import redact


@dataclass(frozen=True)
class AgentConfig:
    model: str
    system_prompt: str
    memory: str = ""
    tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", tuple(sorted(set(self.tools))))

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "system_prompt": self.system_prompt,
            "memory": self.memory,
            "tools": list(self.tools),
        }

    def changed(self, **fields) -> "AgentConfig":
        return replace(self, **{k: v for k, v in fields.items() if v is not None})

    @property
    def instructions(self) -> str:
        return f"{self.system_prompt}\n\nYour memory:\n{self.memory}" if self.memory else self.system_prompt

    @property
    def hash(self) -> str:
        return config_hash(self.to_dict())


def config_hash(config: dict) -> str:
    """Hash of model, system prompt, memory and tool set, in their logged (redacted) form.

    The ledger stores redacted configs, so hashing that form lets the verifier recompute
    the hash even when a prompt contains something that looks like a secret.
    """
    return hashlib.sha256(canonical(redact(config))).hexdigest()
