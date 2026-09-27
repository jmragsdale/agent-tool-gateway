"""agent-tool-gateway: enforce what an AI agent's tools may do, in code."""

from .audit import AuditLog
from .gateway import ALLOW, APPROVAL, DENY, Decision, Gateway, Reason, Session, ToolResult
from .policy import Policy, PolicyError, lint_policy, load_policy, parse_policy

__version__ = "0.1.0"

__all__ = [
    "ALLOW", "APPROVAL", "DENY", "AuditLog", "Decision", "Gateway", "Policy",
    "PolicyError", "Reason", "Session", "ToolResult", "lint_policy", "load_policy",
    "parse_policy", "__version__",
]
