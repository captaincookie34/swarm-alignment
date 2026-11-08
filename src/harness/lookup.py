"""Who is this agent? Given an agent ID, or a token, say whether this harness created it and
show its lineage.

    harness whois agt_k7f2q9_01JCX3Q7M2ZB8W4N6T0YH5P3RS
    harness whois token.json            # a token, as JSON, from a ledger entry or anywhere else

An ID names the key that issued it, so a different fingerprint means another harness made it.
A matching fingerprint isn't proof on its own, since anyone can type an ID. Proof is a signed
token, either the one handed in or the one in a run's ledger, plus that run's logs verifying.
Lineage comes from that run's ledger, the only place it's recorded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .identity import ID_PATTERN, LINEAGE_EDGES, NEW_ID_PATTERN, IdentityToken, Lineage, fingerprint, verify_token
from .verify import VERIFIED, verify_run

# Where runs are looked for by default, relative to the working directory.
DEFAULT_SEARCH = ("runs", "traces", "results/*/runs")


@dataclass
class Lookup:
    """The answer for one ID. `ours` is True (proven), False (another key, or a bad signature) or
    None (can't tell: nothing here records it and no token was given)."""

    agent_id: str
    ours: bool | None
    verdict: str
    issuer_fingerprint: str | None = None
    our_fingerprint: str = ""
    token_valid: bool | None = None
    run: str | None = None
    run_dir: str | None = None
    integrity: str | None = None
    created: dict | None = None
    status: str | None = None
    revoked_by: list[dict] = field(default_factory=list)
    ancestors: list[dict] = field(default_factory=list)  # root first, ending with the agent itself
    descendants: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def run_dirs(search: list[Path]) -> list[Path]:
    """Each run directory under the given folders. A folder may be a glob such as results/*/runs."""
    found: list[Path] = []
    for folder in search:
        parents = sorted(Path().glob(str(folder))) if any(c in str(folder) for c in "*?[") else [folder]
        for parent in parents:
            if (parent / "ledger.jsonl").exists():
                found.append(parent)
            elif parent.is_dir():
                found += sorted(d for d in parent.iterdir() if (d / "ledger.jsonl").exists())
    return list(dict.fromkeys(found))


def _find(agent_id: str, dirs: list[Path]) -> Path | None:
    """The run whose ledger issued this ID. A quick text search first, so most ledgers aren't parsed."""
    needle = f'"child": "{agent_id}"'
    for run_dir in dirs:
        try:
            text = (run_dir / "ledger.jsonl").read_text(encoding="utf-8")
        except OSError:
            continue
        if needle in text and any(
            e.get("child") == agent_id and e.get("type") in LINEAGE_EDGES
            for e in map(json.loads, filter(None, text.splitlines()))
        ):
            return run_dir
    return None


def _describe(entry: dict) -> dict:
    return {
        "id": entry["child"],
        "edge": entry["type"],
        "created_by": None if entry["type"] == "root" else entry["actor"],
        "round": entry.get("round"),
        "at": entry.get("ts"),
        "model": entry.get("config", {}).get("model"),
        "tools": entry.get("config", {}).get("tools", []),
        "task": entry.get("task", ""),
        "config_hash": entry.get("config_hash"),
    }


def lookup(agent_id: str, public_key_b64: str, search: list[Path], token: IdentityToken | None = None) -> Lookup:
    ours_fp = fingerprint(public_key_b64)
    if not isinstance(agent_id, str) or not ID_PATTERN.match(agent_id):
        return Lookup(str(agent_id), False, "not an agent ID: agent IDs look like agt_<key>_<26 characters>", our_fingerprint=ours_fp)
    match = NEW_ID_PATTERN.match(agent_id)
    issuer = match.group(1) if match else None
    result = Lookup(agent_id, None, "", issuer_fingerprint=issuer, our_fingerprint=ours_fp)
    if issuer is not None and issuer != ours_fp:
        result.ours = False
        result.verdict = f"not ours: issued by the key with fingerprint {issuer}, and ours is {ours_fp}"
        return result
    if token is not None:
        result.token_valid = token.id == agent_id and verify_token(token, public_key_b64)

    run_dir = _find(agent_id, run_dirs(search))
    if run_dir is None:
        if result.token_valid:
            result.ours, result.verdict = True, "ours: the token's signature checks out with our key, but no run here records it, so its lineage isn't available"
        elif result.token_valid is False:
            result.ours, result.verdict = False, "not ours: the token's signature doesn't check out with our key"
        else:
            result.verdict = (
                "can't tell: no run here records this ID. Its fingerprint matches our key, but anyone can type an ID. "
                "Pass its token, or point --in at the folder holding its run"
                if issuer else "can't tell: no run here records this ID"
            )
        return result

    verified = verify_run(run_dir, public_key_b64)
    result.run, result.run_dir, result.integrity = run_dir.name, str(run_dir), str(verified)
    ledger = verified.ledger or [json.loads(line) for line in (run_dir / "ledger.jsonl").read_text().splitlines() if line.strip()]
    entries = {e["child"]: e for e in ledger if e.get("type") in LINEAGE_EDGES}
    entry = entries[agent_id]
    ledger_token = IdentityToken.from_dict(entry["token"]) if isinstance(entry.get("token"), dict) else None
    ledger_token_valid = bool(ledger_token) and verify_token(ledger_token, public_key_b64, run_dir.name)
    if result.token_valid is None:
        result.token_valid = ledger_token_valid

    lineage = Lineage.from_ledger(ledger)
    result.created = _describe(entry)
    result.ancestors = [_describe(entries[a]) for a in reversed([agent_id, *lineage.ancestors(agent_id)]) if a in entries]
    result.descendants = [{**_describe(entries[d]), "depth": lineage.depth(d) - lineage.depth(agent_id)} for d in lineage.descendants(agent_id) if d in entries]
    result.revoked_by = [
        {"agent_id": e["child"], "by": e["actor"], "reason": e.get("reason", ""), "round": e.get("round"), "cascade": e.get("cascade", True)}
        for e in ledger
        if e.get("type") == "revoke" and (e["child"] == agent_id or (e.get("cascade", True) and lineage.covers(e["child"], agent_id)))
    ]
    calls = verified.calls or []
    ended = next((e["payload"].get("status") for e in reversed(calls) if e["type"] == "agent.end" and e["agent_id"] == agent_id), None)
    result.status = ended or ("revoked" if result.revoked_by else "no end recorded")

    if verified.status == VERIFIED and ledger_token_valid:
        result.ours, result.verdict = True, f"ours: issued by this harness in {run_dir.name}, and that run's logs verify"
    elif not ledger_token_valid:
        result.ours, result.verdict = False, f"not ours: {run_dir.name} records it, but its token doesn't verify with our key"
    else:
        result.ours = None
        result.verdict = f"can't confirm: {run_dir.name} records it with a valid token, but the run's logs don't verify ({verified.status}), so its lineage can't be trusted"
    return result


def render(result: Lookup, colour: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if colour else text

    mark = {True: paint("✓ ", "32"), False: paint("✗ ", "31"), None: paint("? ", "33")}[result.ours]
    out = [paint(result.agent_id, "1"), f"  {mark}{result.verdict}"]
    if result.issuer_fingerprint:
        out.append(f"  issuing key: {result.issuer_fingerprint} (ours: {result.our_fingerprint})")
    if result.token_valid is not None:
        out.append(f"  token signature: {'valid' if result.token_valid else 'INVALID'}")
    if result.run:
        out.append(f"  run: {result.run}  integrity: {result.integrity}")
    if result.created:
        c = result.created
        how = "root, started by the operator" if c["edge"] == "root" else f"{c['edge']} by {c['created_by']} in round {c['round']}"
        out += [f"  created: {how}", f"  model: {c['model']}  tools: {', '.join(c['tools']) or 'none'}", f"  task: {c['task']}"]
        out.append(f"  status: {result.status}")
        for r in result.revoked_by:
            via = "" if r["agent_id"] == result.agent_id else f" through its ancestor {r['agent_id']}"
            out.append(paint(f"  revoked{via} by {r['by']} in round {r['round']}: {r['reason']}", "31"))
    if result.ancestors:
        out.append("\nlineage, root first:")
        for depth, a in enumerate(result.ancestors):
            this = paint("  ← this agent", "1") if a["id"] == result.agent_id else ""
            how = "root" if a["edge"] == "root" else f"{a['edge']}, round {a['round']}"
            out.append(f"  {'   ' * depth}{'└─ ' if depth else ''}{a['id']}  ({how}){this}")
    if result.descendants:
        out.append(f"\ndescendants ({len(result.descendants)}):")
        for d in result.descendants:
            out.append(f"  {'   ' * (d['depth'] - 1)}└─ {d['id']}  ({d['edge']}, round {d['round']})")
    elif result.created:
        out.append("\ndescendants: none")
    return "\n".join(out)
