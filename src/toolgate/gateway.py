"""The enforcement point. Every tool call an agent makes goes through Gateway.call().

Order of evaluation is fixed and every failing check is recorded, not just the
first one, so the audit record explains the whole decision.

    TG-001  tool not in policy                      default deny
    TG-002  caller's roles not granted this tool
    TG-003  unexpected or missing argument          strict schema
    TG-004  argument violates a constraint          type, range, pattern, enum, domain
    TG-005  argument not bound to the principal     object-level authorization
    TG-006  rate limit exceeded
    TG-007  session tainted, tool denies on taint   indirect prompt injection
    TG-008  human approval required
    TG-009  human approval declined
    TG-010  secret redacted from tool output
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from .audit import AuditLog
from .policy import ArgRule, Policy, ToolPolicy

ALLOW, DENY, APPROVAL = "allow", "deny", "approval"
VERDICTS = (ALLOW, DENY, APPROVAL)

OWASP = {
    "TG-001": "LLM06", "TG-002": "LLM06", "TG-003": "LLM06", "TG-004": "LLM06",
    "TG-005": "LLM06", "TG-006": "LLM10", "TG-007": "LLM01", "TG-008": "LLM06",
    "TG-009": "LLM06", "TG-010": "LLM02",
}


@dataclass
class Session:
    """Identity and state supplied by the application. Never by the model."""

    principal: str
    roles: set[str] = field(default_factory=set)
    attrs: dict[str, Any] = field(default_factory=dict)
    taint_sources: list[str] = field(default_factory=list)
    session_id: str = "default"

    @property
    def tainted(self) -> bool:
        return bool(self.taint_sources)

    def mark_tainted(self, source: str) -> None:
        if source not in self.taint_sources:
            self.taint_sources.append(source)


@dataclass
class Reason:
    rule: str
    message: str

    @property
    def owasp(self) -> str:
        return OWASP.get(self.rule, "-")


@dataclass
class Decision:
    verdict: str
    reasons: list[Reason] = field(default_factory=list)

    @property
    def rules(self) -> list[str]:
        return [r.rule for r in self.reasons]


@dataclass
class ToolResult:
    tool: str
    decision: Decision
    output: Any = None

    @property
    def executed(self) -> bool:
        return self.decision.verdict == ALLOW

    def for_model(self) -> str:
        """What goes back into the model's context. Denials are explicit, not silent,
        so the agent can tell the user rather than retrying in a loop."""
        if self.executed:
            return str(self.output)
        why = "; ".join(r.message for r in self.decision.reasons) or "not permitted"
        return f"[tool '{self.tool}' was not executed: {why}]"


Approver = Callable[[Session, str, dict[str, Any], list[Reason]], bool]


def deny_all_approver(session: Session, tool: str, args: dict[str, Any], why: list[Reason]) -> bool:
    """Safe default for unattended runs: nothing that needs a human gets one."""
    return False


class Gateway:
    def __init__(
        self,
        policy: Policy,
        approver: Approver = deny_all_approver,
        audit: AuditLog | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self.approver = approver
        self.audit = audit or AuditLog(None, policy.redact_patterns)
        self._clock = clock
        self._impls: dict[str, Callable[..., Any]] = {}
        self._calls: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    # ----------------------------------------------------------------- registration

    def tool(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator. Registering an implementation does not grant it: policy does."""

        def register(fn: Callable[..., Any]) -> Callable[..., Any]:
            self._impls[name] = fn
            return fn

        return register

    def register(self, name: str, fn: Callable[..., Any]) -> None:
        self._impls[name] = fn

    # ----------------------------------------------------------------- evaluation

    def evaluate(self, session: Session, tool_name: str, args: dict[str, Any]) -> Decision:
        """Pure policy decision. Does not execute, does not ask for approval."""
        tp = self.policy.tool(tool_name)
        if tp is None:
            return Decision(DENY, [Reason("TG-001", f"'{tool_name}' is not a granted tool")])

        denies: list[Reason] = []
        approvals: list[Reason] = []

        if not session.roles & set(tp.allow_roles):
            denies.append(Reason("TG-002", f"roles {sorted(session.roles) or '[]'} may not call {tool_name}"))

        denies += self._check_schema(tp, args)
        for arg_name, rule in tp.args.items():
            if arg_name in args:
                denies += self._check_arg(rule, args[arg_name], session)

        if tp.rate_limit and self._rate_exceeded(session, tp):
            rl = tp.rate_limit
            denies.append(Reason("TG-006", f"rate limit {rl['calls']}/{rl['per_seconds']}s reached"))

        if session.tainted:
            src = ", ".join(session.taint_sources)
            if tp.on_taint == "deny":
                denies.append(Reason("TG-007", f"session holds untrusted content ({src})"))
            elif tp.on_taint == "approval":
                approvals.append(Reason("TG-008", f"session holds untrusted content ({src})"))

        if tp.require_approval:
            approvals.append(Reason("TG-008", f"{tool_name} always requires approval (risk={tp.risk})"))
        for arg_name, limit in tp.approval_threshold.items():
            value = args.get(arg_name)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value > limit:
                approvals.append(Reason("TG-008", f"{arg_name}={value} exceeds approval threshold {limit}"))

        if denies:
            return Decision(DENY, denies)
        if approvals:
            return Decision(APPROVAL, approvals)
        return Decision(ALLOW)

    def call(self, session: Session, tool_name: str, args: dict[str, Any] | None = None) -> ToolResult:
        args = dict(args or {})
        decision = self.evaluate(session, tool_name, args)

        if decision.verdict == APPROVAL:
            if self.approver(session, tool_name, args, decision.reasons):
                decision = Decision(ALLOW, decision.reasons)
            else:
                decision = Decision(DENY, decision.reasons + [Reason("TG-009", "approval declined")])

        output: Any = None
        if decision.verdict == ALLOW:
            impl = self._impls.get(tool_name)
            if impl is None:
                decision = Decision(DENY, [Reason("TG-001", f"'{tool_name}' has no registered implementation")])
            else:
                self._record_call(session, tool_name)
                output = impl(**args)
                tp = self.policy.tool(tool_name)
                assert tp is not None
                if tp.redact_output:
                    output, hits = self._redact(output)
                    if hits:
                        decision.reasons.append(Reason("TG-010", f"{hits} secret-shaped value(s) redacted from output"))
                if tp.taints_session:
                    session.mark_tainted(f"{tool_name}")

        self.audit.write(session, tool_name, args, decision)
        return ToolResult(tool_name, decision, output)

    # ----------------------------------------------------------------- checks

    @staticmethod
    def _check_schema(tp: ToolPolicy, args: dict[str, Any]) -> list[Reason]:
        out: list[Reason] = []
        extra = sorted(set(args) - set(tp.args))
        if extra:
            out.append(Reason("TG-003", f"unexpected argument(s) {extra}"))
        missing = sorted(n for n, r in tp.args.items() if r.required and n not in args)
        if missing:
            out.append(Reason("TG-003", f"missing argument(s) {missing}"))
        return out

    @staticmethod
    def _check_arg(rule: ArgRule, value: Any, session: Session) -> list[Reason]:
        n = rule.name
        type_ok = {
            "string": isinstance(value, str),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
        }[rule.type]
        if not type_ok:
            return [Reason("TG-004", f"{n} must be {rule.type}")]

        out: list[Reason] = []
        if rule.min is not None and value < rule.min:
            out.append(Reason("TG-004", f"{n}={value} below minimum {rule.min}"))
        if rule.max is not None and value > rule.max:
            out.append(Reason("TG-004", f"{n}={value} above maximum {rule.max}"))
        if rule.max_length is not None and isinstance(value, str) and len(value) > rule.max_length:
            out.append(Reason("TG-004", f"{n} longer than {rule.max_length} characters"))
        if rule.pattern is not None and not re.fullmatch(rule.pattern, str(value)):
            out.append(Reason("TG-004", f"{n} does not match required pattern"))
        if rule.enum is not None and value not in rule.enum:
            out.append(Reason("TG-004", f"{n} must be one of {rule.enum}"))
        if rule.domain_allowlist is not None:
            host = _host_of(str(value))
            if not host or not any(host == d or host.endswith("." + d) for d in rule.domain_allowlist):
                out.append(Reason("TG-004", f"{n} destination '{host or value}' is not on the allowlist"))
        if rule.bind is not None:
            attr = rule.bind.split(".", 1)[1]
            expected = session.attrs.get(attr)
            if expected is None or value != expected:
                out.append(Reason("TG-005", f"{n} is not bound to the caller's {attr}"))
        return out

    def _rate_exceeded(self, session: Session, tp: ToolPolicy) -> bool:
        assert tp.rate_limit is not None
        window = self._calls[(session.principal, tp.name)]
        now = self._clock()
        while window and now - window[0] >= tp.rate_limit["per_seconds"]:
            window.popleft()
        return len(window) >= tp.rate_limit["calls"]

    def _record_call(self, session: Session, tool_name: str) -> None:
        self._calls[(session.principal, tool_name)].append(self._clock())

    def _redact(self, output: Any) -> tuple[Any, int]:
        if not isinstance(output, str):
            return output, 0
        hits = 0
        for pat in self.policy.redact_patterns:
            output, n = pat.subn("[REDACTED]", output)
            hits += n
        return output, hits


def _host_of(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        return urlparse(value).hostname or ""
    if "@" in value:
        return value.rsplit("@", 1)[1]
    return value
