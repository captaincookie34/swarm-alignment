"""Agent identity: signing keys, path IDs, and signed ID tokens.

Only the harness holds the private key, so only the harness can issue IDs. A token's
ID contains its whole lineage, so one signature proves the path back to the root.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_KEY_DIR = Path.home() / ".config" / "harness"
ID_PATTERN = re.compile(r"^agt_[A-Z]+(\.[1-9][0-9]*)*$")
# Finds ID-like text in free-form strings, to flag claims a model makes about identity.
ID_CLAIM = re.compile(r"\bagt_[A-Za-z0-9]+(?:\.[0-9]+)*\b")

# Domain separation: a signature made for one purpose can't be replayed as another.
# These strings are part of the signature format, so they keep the project's original name:
# changing them would make every existing run fail verification.
TOKEN_DOMAIN = b"traceable-token-v1\0"
HEAD_DOMAIN = b"traceable-head-v1\0"
REVOCATION_DOMAIN = b"traceable-revocation-v1\0"


def canonical(obj: object) -> bytes:
    """Deterministic JSON encoding used for all hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class Signer:
    """Holds the private key. Never pass this to tools or the sandbox."""

    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, key_dir: Path = DEFAULT_KEY_DIR) -> "Signer":
        """Load an existing key. Raises FileNotFoundError rather than creating one."""
        path = key_dir / "signing.key"
        data = path.read_bytes()
        if path.stat().st_mode & 0o077:
            raise PermissionError(f"{path} must not be readable by group or others")
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 key")
        return cls(key)

    @classmethod
    def load_or_create(cls, key_dir: Path = DEFAULT_KEY_DIR) -> "Signer":
        path = key_dir / "signing.key"
        if path.exists():
            return cls.load(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        # O_EXCL: never overwrite a key another process just created.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return cls(key)

    def sign(self, domain: bytes, payload: object) -> str:
        return _b64(self._key.sign(domain + canonical(payload)))

    @property
    def public_key_b64(self) -> str:
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return _b64(raw)


def verify_signature(public_key_b64: str, domain: bytes, payload: object, signature: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature), domain + canonical(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def parent_of(agent_id: str) -> str | None:
    head, sep, _ = agent_id.rpartition(".")
    return head if sep else None


def root_of(agent_id: str) -> str:
    return agent_id.split(".", 1)[0]


def depth_of(agent_id: str) -> int:
    return agent_id.count(".")


def covers(ancestor: str, agent_id: str) -> bool:
    """True if agent_id is ancestor or a descendant. agt_A.1 covers agt_A.1.2, not agt_A.10."""
    return agent_id == ancestor or agent_id.startswith(ancestor + ".")


@dataclass(frozen=True)
class IdentityToken:
    id: str
    run: str
    issued_at: float
    depth: int
    signature: str

    def unsigned(self) -> dict:
        return {"id": self.id, "run": self.run, "issued_at": self.issued_at, "depth": self.depth}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "IdentityToken":
        return cls(data["id"], data["run"], data["issued_at"], data["depth"], data["signature"])


def verify_token(token: IdentityToken, public_key_b64: str, run: str | None = None) -> bool:
    """Check the signature and that the token's fields agree with its ID.

    IDs repeat between runs (every run has an agt_A), so pass run wherever one is known.
    """
    return (
        isinstance(token.id, str)
        and bool(ID_PATTERN.match(token.id))
        and (run is None or token.run == run)
        and token.depth == depth_of(token.id)
        and verify_signature(public_key_b64, TOKEN_DOMAIN, token.unsigned(), token.signature)
    )


def root_label(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    label = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        label = chr(ord("A") + remainder) + label
    return label


def new_run_id() -> str:
    return f"run_{secrets.token_hex(5)}"


class IdentityIssuer:
    """The only source of IDs for one run. Counters only go up, so IDs are never reused."""

    def __init__(self, signer: Signer, run_id: str):
        self._signer = signer
        self.run_id = run_id
        self._roots = 0
        self._child_counts: dict[str, int] = {}

    def _issue(self, agent_id: str) -> IdentityToken:
        unsigned = {
            "id": agent_id,
            "run": self.run_id,
            "issued_at": time.time(),
            "depth": depth_of(agent_id),
        }
        return IdentityToken(**unsigned, signature=self._signer.sign(TOKEN_DOMAIN, unsigned))

    def issue_root(self) -> IdentityToken:
        token = self._issue(f"agt_{root_label(self._roots)}")
        self._roots += 1
        return token

    def issue_child(self, parent: IdentityToken) -> IdentityToken:
        count = self._child_counts.get(parent.id, 0) + 1
        self._child_counts[parent.id] = count
        return self._issue(f"{parent.id}.{count}")
