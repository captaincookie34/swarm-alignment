"""Agent identity: signing keys, opaque IDs, signed ID tokens, and lineage from the ledger.

Only the harness holds the private key, so only the harness can issue IDs. Each team member's
harness has its own keypair, which is the root of trust for the IDs it issues. Every agent, root
or child, gets its own unguessable ID that names the issuing key:

    agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS
        |      |
        |      a ULID: a millisecond timestamp and 80 random bits, so IDs sort by time
        fingerprint of the issuing harness's public key

An ID says nothing about lineage, so a sibling's or child's ID can't be guessed and the shape of
the tree can't be read from an ID. Lineage lives in the ledger, a signed hash chain of every
root, spawn, copy and modify: `Lineage` rebuilds the tree from it. Each token also signs its
parent and root, so a token alone proves its parent link.

Older runs used path IDs, where a child was its parent's ID plus .1, .2 (and before that agt_A,
agt_B). Those still verify, and their lineage comes from the same ledger, but they're never issued.
"""
from __future__ import annotations

import base64
import hashlib
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
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # base32 without I, L, O, U
FINGERPRINT_LENGTH = 6
_PATH = r"(\.[1-9][0-9]*)*"
NEW_ID_PATTERN = re.compile(rf"^agt_([0-9a-hjkmnp-tv-z]{{{FINGERPRINT_LENGTH}}})_([{CROCKFORD}]{{26}}){_PATH}$")
LEGACY_ID_PATTERN = re.compile(rf"^agt_[A-Z]+{_PATH}$")  # still accepted, for old runs
ID_PATTERN = re.compile(rf"{NEW_ID_PATTERN.pattern}|{LEGACY_ID_PATTERN.pattern}")
# Finds ID-like text in free-form strings, to flag claims a model makes about identity.
ID_CLAIM = re.compile(r"\bagt_[A-Za-z0-9_]+(?:\.[0-9]+)*\b")

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

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key_b64)


def _base32(value: int, length: int) -> str:
    return "".join(CROCKFORD[(value >> (5 * i)) & 31] for i in reversed(range(length)))


def fingerprint(public_key_b64: str) -> str:
    """A short name for a public key, used in the IDs it issues. Lowercase, to stand apart."""
    digest = int.from_bytes(hashlib.sha256(base64.b64decode(public_key_b64)).digest()[:4], "big")
    return _base32(digest >> (32 - 5 * FINGERPRINT_LENGTH), FINGERPRINT_LENGTH).lower()


def new_ulid(now: float | None = None) -> str:
    """26 characters: 48 bits of milliseconds then 80 random bits, so they sort by time."""
    millis = int((time.time() if now is None else now) * 1000) & ((1 << 48) - 1)
    return _base32((millis << 80) | secrets.randbits(80), 26)


def short_id(agent_id: str) -> str:
    """agt_k7f2q9_01JCX...P3RS shown as agt_…P3RS, for traces (an older path ID keeps its .1.2).
    Logs keep the full ID."""
    match = NEW_ID_PATTERN.match(agent_id)
    if not match:
        return agent_id
    return f"agt_…{match.group(2)[-4:]}{agent_id[len(root_of(agent_id)):]}"


def verify_signature(public_key_b64: str, domain: bytes, payload: object, signature: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        key.verify(base64.b64decode(signature), domain + canonical(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# Path helpers, for older path IDs only. New IDs carry no lineage: use Lineage.


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
    parent: str | None = None  # signed in opaque-ID tokens; None for a root
    root: str | None = None  # signed in opaque-ID tokens; None marks an older path-ID token

    @property
    def opaque(self) -> bool:
        return self.root is not None

    def unsigned(self) -> dict:
        fields = {"id": self.id, "run": self.run, "issued_at": self.issued_at, "depth": self.depth}
        if self.opaque:
            fields.update(parent=self.parent, root=self.root)
        return fields

    def to_dict(self) -> dict:
        data = asdict(self)
        if not self.opaque:
            del data["parent"], data["root"]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "IdentityToken":
        return cls(data["id"], data["run"], data["issued_at"], data["depth"], data["signature"], data.get("parent"), data.get("root"))


def verify_token(token: IdentityToken, public_key_b64: str, run: str | None = None) -> bool:
    """Check the signature and that the token's fields agree with its ID.

    A new-format ID must name the key that signed it, so an ID always identifies the harness
    that issued it. Legacy IDs (agt_A) repeat between runs, so pass run wherever one is known.
    """
    new = NEW_ID_PATTERN.match(token.id) if isinstance(token.id, str) else None
    if token.opaque:
        # An opaque ID has no path, and its parent, root and depth must agree with each other.
        # Whether the parent really created it is checked against the ledger by the verifier.
        shape = (
            new is not None and "." not in token.id
            and isinstance(token.root, str) and bool(NEW_ID_PATTERN.match(token.root))
            and (token.parent is None or (isinstance(token.parent, str) and bool(ID_PATTERN.match(token.parent))))
            and isinstance(token.depth, int)
            and (token.parent is None) == (token.depth == 0) == (token.root == token.id)
        )  # fmt: skip
    else:
        shape = isinstance(token.id, str) and bool(ID_PATTERN.match(token.id)) and token.depth == depth_of(token.id)
    return (
        shape
        and (new is None or new.group(1) == fingerprint(public_key_b64))
        and (run is None or token.run == run)
        and verify_signature(public_key_b64, TOKEN_DOMAIN, token.unsigned(), token.signature)
    )


def new_run_id() -> str:
    return f"run_{new_ulid()}"


class IdentityIssuer:
    """The only source of IDs for one run. Every ID is fresh and random, so none is reused or guessable."""

    def __init__(self, signer: Signer, run_id: str):
        self._signer = signer
        self.run_id = run_id
        self._issued: set[str] = set()

    def _issue(self, parent: IdentityToken | None) -> IdentityToken:
        agent_id = f"agt_{self._signer.fingerprint}_{new_ulid()}"
        while agent_id in self._issued:  # 80 random bits make this all but impossible
            agent_id = f"agt_{self._signer.fingerprint}_{new_ulid()}"
        self._issued.add(agent_id)
        root = agent_id if parent is None else (parent.root if parent.opaque else root_of(parent.id))
        unsigned = {
            "id": agent_id,
            "run": self.run_id,
            "issued_at": time.time(),
            "depth": 0 if parent is None else parent.depth + 1,
            "parent": None if parent is None else parent.id,
            "root": root,
        }
        return IdentityToken(**unsigned, signature=self._signer.sign(TOKEN_DOMAIN, unsigned))

    def issue_root(self) -> IdentityToken:
        return self._issue(None)

    def issue_child(self, parent: IdentityToken) -> IdentityToken:
        return self._issue(parent)


LINEAGE_EDGES = ("root", "spawn", "copy", "modify")


class Lineage:
    """Who created whom. IDs carry no lineage, so the ledger is the source: build this from its
    root, spawn, copy and modify entries, in order. Works the same for older path-ID runs."""

    def __init__(self) -> None:
        self._parent: dict[str, str | None] = {}
        self._children: dict[str, list[str]] = {}

    @classmethod
    def from_ledger(cls, ledger: list[dict]) -> "Lineage":
        lineage = cls()
        for entry in ledger:
            if entry.get("type") in LINEAGE_EDGES:
                lineage.add(entry["child"], None if entry["type"] == "root" else entry["actor"])
        return lineage

    def add(self, child: str, parent: str | None) -> None:
        self._parent[child] = parent
        self._children.setdefault(child, [])
        if parent is not None:
            self._children.setdefault(parent, []).append(child)

    def __contains__(self, agent_id: object) -> bool:
        return agent_id in self._parent

    def parent(self, agent_id: str) -> str | None:
        return self._parent.get(agent_id)

    def ancestors(self, agent_id: str) -> list[str]:
        """Parent first, root last."""
        out, current = [], self._parent.get(agent_id)
        while current is not None:
            out.append(current)
            current = self._parent.get(current)
        return out

    def root(self, agent_id: str) -> str:
        chain = self.ancestors(agent_id)
        return chain[-1] if chain else agent_id

    def depth(self, agent_id: str) -> int:
        return len(self.ancestors(agent_id))

    def children(self, agent_id: str) -> list[str]:
        return list(self._children.get(agent_id, []))

    def descendants(self, agent_id: str) -> list[str]:
        out, stack = [], list(reversed(self.children(agent_id)))
        while stack:
            child = stack.pop()
            out.append(child)
            stack.extend(reversed(self.children(child)))
        return out

    def covers(self, ancestor: str, agent_id: str) -> bool:
        """True if agent_id is ancestor or one of its descendants."""
        return agent_id == ancestor or ancestor in self.ancestors(agent_id)

    def child_number(self, agent_id: str) -> int:
        """1 for a parent's first child, 2 for its second. 0 for a root or unknown agent."""
        parent = self._parent.get(agent_id)
        siblings = self._children.get(parent, []) if parent else []
        return siblings.index(agent_id) + 1 if agent_id in siblings else 0

    def path(self, agent_id: str) -> str:
        """The child numbers from the root down, e.g. "2.1" for the first child of the root's second
        child; "" for a root. For display only: the operator sees it, agents and IDs don't carry it."""
        chain = [agent_id, *self.ancestors(agent_id)][:-1]
        return ".".join(str(self.child_number(a)) for a in reversed(chain))
