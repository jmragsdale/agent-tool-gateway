"""Evaluate recorded tool calls against a policy without executing anything.

Trace format: JSONL, one tool call per line.

    {"principal": "agent:1", "roles": ["support_agent"], "attrs": {"customer_id": "CUST-1042"},
     "taint_sources": [], "tool": "issue_refund", "args": {...}, "expect": "deny"}

`expect` is optional. With --assert, any line whose decision differs from its
`expect` fails the run, which is how the policy gets regression-tested in CI in
both directions: attacks must stay blocked and normal work must stay allowed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .gateway import VERDICTS, Gateway, Session
from .policy import Policy


class TraceError(ValueError):
    pass


def load_trace(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceError(f"{path}:{n}: {exc}") from exc
        for key in ("principal", "tool"):
            if key not in row:
                raise TraceError(f"{path}:{n}: missing '{key}'")
        if "expect" in row and row["expect"] not in VERDICTS:
            raise TraceError(f"{path}:{n}: expect must be one of {VERDICTS}")
        row["_line"] = n
        rows.append(row)
    return rows


def replay(policy: Policy, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gateway = Gateway(policy)
    sessions: dict[str, Session] = {}
    results = []
    for row in rows:
        key = row.get("session_id", row["principal"])
        session = sessions.setdefault(key, Session(
            principal=row["principal"],
            roles=set(row.get("roles", [])),
            attrs=dict(row.get("attrs", {})),
            session_id=key,
        ))
        for src in row.get("taint_sources", []):
            session.mark_tainted(src)

        decision = gateway.evaluate(session, row["tool"], dict(row.get("args", {})))
        # A call the policy would allow counts toward rate limits in later lines,
        # and a tool that returns untrusted content taints the rest of the session.
        if decision.verdict == "allow":
            gateway._record_call(session, row["tool"])
            tp = policy.tool(row["tool"])
            if tp and tp.taints_session:
                session.mark_tainted(row["tool"])

        expect = row.get("expect")
        results.append({
            "line": row["_line"],
            "tool": row["tool"],
            "principal": row["principal"],
            "verdict": decision.verdict,
            "expect": expect,
            "ok": expect is None or expect == decision.verdict,
            "rules": decision.rules,
            "reasons": [r.message for r in decision.reasons],
            "note": row.get("note", ""),
        })
    return results
