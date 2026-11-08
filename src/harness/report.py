"""Reads a verified run: the lineage tree, the trace, and the measures the design calls for."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .identity import Lineage, short_id
from .revocation import entry_covers
from .verify import VerifyResult


@dataclass
class RunReport:
    agents: int = 0
    edges: dict[str, int] = field(default_factory=dict)  # lineage events by type
    refused: dict[str, int] = field(default_factory=dict)  # refused calls by agent
    refused_after_revocation: int = 0
    actions_after_revocation: int = 0  # tool actions begun after the agent was revoked
    in_flight_at_revocation: int = 0  # began before the revocation, ended after it
    id_claims: int = 0  # tool calls whose arguments contain ID-like text
    ignored_args: int = 0  # tool calls where arguments the tool doesn't define were dropped
    duplicate_configs: list[list[str]] = field(default_factory=list)  # same hash, no copy edge

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def tree_order(lineage: Lineage, agents: list[str]) -> list[str]:
    """Agents in tree order: each root in creation order, followed by its descendants, depth first."""
    roots = [a for a in agents if lineage.parent(a) is None]
    return [a for r in roots for a in (r, *lineage.descendants(r))]


def build_report(result: VerifyResult) -> RunReport:
    report = RunReport()
    created = [e for e in result.ledger if e["type"] != "revoke"]
    report.agents = len(created)
    lineage = Lineage.from_ledger(result.ledger)
    order = {a: i for i, a in enumerate(tree_order(lineage, [e["child"] for e in created]))}
    for entry in result.ledger:
        report.edges[entry["type"]] = report.edges.get(entry["type"], 0) + 1

    # When was each agent revoked, as a position in the ledger?
    revokes = [e for e in result.ledger if e["type"] == "revoke"]

    def revoked_at(agent_id: str, ledger_seq: int) -> bool:
        return any(
            e["seq"] <= ledger_seq
            and entry_covers({"agent_id": e["child"], "cascade": e.get("cascade", True)}, agent_id, lineage)
            for e in revokes
        )

    started: dict[str, dict] = {}
    for entry in result.calls:
        kind, agent, payload = entry["type"], entry["agent_id"], entry["payload"]
        if kind == "action.refused" or (kind == "action.end" and payload.get("status") == "refused"):
            report.refused[agent] = report.refused.get(agent, 0) + 1
            if revoked_at(agent, entry["ledger_seq"]):
                report.refused_after_revocation += 1
        if kind == "action.start":
            started[payload["call_id"]] = entry
            report.id_claims += bool(payload.get("id_claims"))
            report.ignored_args += bool(payload.get("ignored_args"))
            if revoked_at(agent, entry["ledger_seq"]):
                report.actions_after_revocation += 1
        if kind == "action.end":
            begun = started.get(payload["call_id"])
            if begun and revoked_at(agent, entry["ledger_seq"]) and not revoked_at(agent, begun["ledger_seq"]):
                report.in_flight_at_revocation += 1

    # Matching configs that the ledger can't explain may be copies made outside the harness.
    groups: dict[str, list[dict]] = {}
    for entry in created:
        groups.setdefault(entry["config_hash"], []).append(entry)
    for entries in groups.values():
        unexplained = [e["child"] for e in entries if e["type"] != "copy"]
        if len(unexplained) > 1:
            report.duplicate_configs.append(sorted(unexplained, key=lambda a: order.get(a, len(order))))
    return report


def _summarize(entry: dict) -> str | None:
    kind, p = entry["type"], entry["payload"]
    if kind == "action.start":
        notes = ""
        if p.get("ignored_args"):
            notes += f"  [ignored args: {', '.join(p['ignored_args'])}]"
        if p.get("id_claims"):
            notes += f"  [ID-like text: {', '.join(p['id_claims'])}]"
        return f"{p['tool']} {json.dumps(p.get('args', {}), ensure_ascii=False)[:90]}{notes}"
    if kind == "action.end" and p.get("status") == "refused":
        return f"REFUSED {p['tool']}: {p.get('reason')}"
    if kind == "action.end" and p.get("status") != "ok":
        return f"{p['tool']} -> {p.get('status')} {p.get('error', '')}".rstrip()
    if kind == "action.refused":
        return f"REFUSED {p.get('tool', 'model call')}: {p.get('reason')}"
    if kind == "model.error":
        return f"model error: {p.get('error')}"
    if kind == "agent.revoked":
        return f"REVOKED (via {p.get('revoked_id')}) {p.get('reason', '')}".rstrip()
    if kind == "files.changed":
        names = [*p.get("created", {}), *p.get("modified", {}), *p.get("deleted", [])]
        return f"files changed: {', '.join(names)[:100]}"
    if kind == "files.unattributed":
        return f"UNATTRIBUTED file changes: {json.dumps(p, ensure_ascii=False)[:100]}"
    return None


def _clip(text: object, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _summarize_model(entry: dict) -> list[str]:
    """What an agent sent to its model and what came back, for `trace --full`."""
    kind, p = entry["type"], entry["payload"]
    lines = []
    if kind == "model.request":
        for message in p.get("new_messages", []):
            for part in message.get("parts", []):
                part_kind = part.get("part_kind")
                if part_kind == "user-prompt":
                    lines.append(f"PROMPT -> model: {_clip(part.get('content'))}")
                elif part_kind == "tool-return":
                    lines.append(f"TOOL RESULT -> model ({part.get('tool_name')}): {_clip(part.get('content'))}")
                elif part_kind == "retry-prompt":
                    lines.append(f"REJECTED CALL -> model: {_clip(part.get('content'))}")
    elif kind == "model.response":
        usage = f"{p.get('model') or 'unknown model'}, {p.get('input_tokens', 0)} in / {p.get('output_tokens', 0)} out tokens"
        for part in p.get("parts", []):
            part_kind = part.get("part_kind")
            if part_kind == "text" and part.get("content"):
                lines.append(f"RESPONSE <- model: {_clip(part['content'])}  [{usage}]")
            elif part_kind == "tool-call":
                lines.append(f"TOOL CALL <- model: {part.get('tool_name')} {_clip(part.get('args'), 100)}  [{usage}]")
        if not lines:
            lines.append(f"RESPONSE <- model: (no text or tool calls)  [{usage}]")
    return lines


def render_trace(result: VerifyResult, only_agent: str | None = None, full: bool = False) -> str:
    """The lineage tree with each agent's steps, or one agent's lineage back to its root.

    full adds every prompt sent to a model and every response, with model and token counts.
    """
    by_agent: dict[str, list[dict]] = {}
    for entry in result.calls:
        by_agent.setdefault(entry["agent_id"], []).append(entry)
    created = {e["child"]: e for e in result.ledger if e["type"] != "revoke"}
    lineage = Lineage.from_ledger(result.ledger)

    def describe(agent_id: str) -> list[str]:
        indent = "  " * lineage.depth(agent_id)
        event = created[agent_id]
        entries = by_agent.get(agent_id, [])
        turns = sum(e["type"] == "model.request" for e in entries)
        end = next((e["payload"] for e in entries if e["type"] == "agent.end"), {})
        title = (
            f"{indent}{short_id(agent_id)}  {event['type']}, config {event['config_hash'][:8]}, "
            f"born round {event['round']}  [{end.get('status', 'no end recorded')}]  {turns} model turns"
        )
        lines = [title]
        for entry in entries:
            texts = _summarize_model(entry) if full else []
            if text := _summarize(entry):
                texts.append(text)
            for text in texts:
                lines.append(f"{indent}  r{entry['round']} #{entry['seq']:<4} {text}")
        return lines

    if only_agent:
        if only_agent not in created:
            return f"{only_agent} isn't in this run's ledger."
        agents = [*reversed(lineage.ancestors(only_agent)), only_agent]
    else:
        agents = tree_order(lineage, list(created))
    # Traces show short IDs. The legend gives each one's full ID, for revoking or searching.
    legend = [f"{short_id(a)} = {a}" for a in agents if short_id(a) != a]
    body = "\n".join(line for agent_id in agents for line in describe(agent_id))
    return "\n".join([*legend, "", body]) if legend else body

