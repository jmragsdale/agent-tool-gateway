"""Append-only JSONL audit trail. One line per tool call, allowed or not.

Argument values are passed through the same redaction patterns as tool output,
so the audit log does not become the place secrets leak to.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .gateway import Decision, Session


class AuditLog:
    def __init__(self, path: str | Path | None, redact_patterns: list[re.Pattern[str]]) -> None:
        self.path = Path(path) if path else None
        self.patterns = redact_patterns
        self.records: list[dict[str, Any]] = []

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            for pat in self.patterns:
                value = pat.sub("[REDACTED]", value)
            return value
        if isinstance(value, dict):
            return {k: self._scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._scrub(v) for v in value]
        return value

    def write(self, session: "Session", tool: str, args: dict[str, Any], decision: "Decision") -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "session_id": session.session_id,
            "principal": session.principal,
            "roles": sorted(session.roles),
            "tainted": session.tainted,
            "taint_sources": list(session.taint_sources),
            "tool": tool,
            "args": self._scrub(args),
            "verdict": decision.verdict,
            "reasons": [
                {"rule": r.rule, "owasp": r.owasp, "message": self._scrub(r.message)}
                for r in decision.reasons
            ],
        }
        self.records.append(record)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record
