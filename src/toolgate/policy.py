"""Policy model: what each tool may do, for whom, and under which conditions.

A policy is YAML. Everything not granted is denied. The model never supplies
any input to these decisions except the tool name and its arguments; identity,
roles and taint come from the application's session object.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

RISKS = ("low", "medium", "high", "critical")
ARG_TYPES = ("string", "number", "integer", "boolean")
TAINT_MODES = ("allow", "approval", "deny")


class PolicyError(ValueError):
    """Raised when a policy file is malformed. Fail closed: no policy, no tools."""


@dataclass
class ArgRule:
    name: str
    type: str = "string"
    required: bool = True
    min: float | None = None
    max: float | None = None
    max_length: int | None = None
    pattern: str | None = None
    enum: list[Any] | None = None
    domain_allowlist: list[str] | None = None
    bind: str | None = None  # "principal.<attr>": value must equal the session attribute

    def __post_init__(self) -> None:
        if self.type not in ARG_TYPES:
            raise PolicyError(f"arg '{self.name}': type must be one of {ARG_TYPES}")
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise PolicyError(f"arg '{self.name}': bad pattern: {exc}") from exc
        if self.bind is not None and not self.bind.startswith("principal."):
            raise PolicyError(f"arg '{self.name}': bind must look like 'principal.<attr>'")


@dataclass
class ToolPolicy:
    name: str
    risk: str = "medium"
    description: str = ""
    allow_roles: list[str] = field(default_factory=list)
    args: dict[str, ArgRule] = field(default_factory=dict)
    require_approval: bool = False
    approval_threshold: dict[str, float] = field(default_factory=dict)
    on_taint: str = "allow"
    taints_session: bool = False  # tool returns untrusted content (web, retrieval, email)
    egress: bool = False  # tool can move data outside the trust boundary
    rate_limit: dict[str, int] | None = None  # {"calls": N, "per_seconds": S}
    redact_output: bool = True

    def __post_init__(self) -> None:
        if self.risk not in RISKS:
            raise PolicyError(f"tool '{self.name}': risk must be one of {RISKS}")
        if self.on_taint not in TAINT_MODES:
            raise PolicyError(f"tool '{self.name}': on_taint must be one of {TAINT_MODES}")
        if not self.allow_roles:
            raise PolicyError(f"tool '{self.name}': allow_roles is empty; nobody could call it")
        for arg in self.approval_threshold:
            if arg not in self.args:
                raise PolicyError(f"tool '{self.name}': approval_threshold names unknown arg '{arg}'")
        if self.rate_limit is not None:
            if set(self.rate_limit) != {"calls", "per_seconds"}:
                raise PolicyError(f"tool '{self.name}': rate_limit needs exactly calls and per_seconds")


@dataclass
class Policy:
    name: str
    tools: dict[str, ToolPolicy]
    redact_patterns: list[re.Pattern[str]]
    source: str = "<memory>"

    def tool(self, name: str) -> ToolPolicy | None:
        return self.tools.get(name)


# Floor, not ceiling: common credential shapes that should never reach a model's
# context window or an audit log in the clear. Extend per environment.
DEFAULT_REDACT_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",  # AWS access key id
    r"sk-[A-Za-z0-9_\-]{16,}",  # common LLM / SaaS API key prefix
    r"ghp_[A-Za-z0-9]{36}",  # GitHub personal access token
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\b(?:\d[ -]?){13,16}\b",  # payment-card-shaped digit runs
]


def _build_tool(name: str, raw: dict[str, Any]) -> ToolPolicy:
    if not isinstance(raw, dict):
        raise PolicyError(f"tool '{name}' must be a mapping")
    known = {
        "risk", "description", "allow_roles", "args", "require_approval",
        "approval_threshold", "on_taint", "taints_session", "egress",
        "rate_limit", "redact_output",
    }
    unknown = set(raw) - known
    if unknown:
        raise PolicyError(f"tool '{name}': unknown keys {sorted(unknown)}")

    args: dict[str, ArgRule] = {}
    for arg_name, arg_raw in (raw.get("args") or {}).items():
        if not isinstance(arg_raw, dict):
            raise PolicyError(f"tool '{name}' arg '{arg_name}' must be a mapping")
        try:
            args[arg_name] = ArgRule(name=arg_name, **arg_raw)
        except TypeError as exc:
            raise PolicyError(f"tool '{name}' arg '{arg_name}': {exc}") from exc

    fields = {k: v for k, v in raw.items() if k != "args"}
    return ToolPolicy(name=name, args=args, **fields)


def parse_policy(doc: dict[str, Any], source: str = "<memory>") -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a mapping")
    if doc.get("version") != 1:
        raise PolicyError("policy 'version: 1' is required")
    if doc.get("default", "deny") != "deny":
        # Not configurable on purpose. An allow-by-default tool gateway is a logger.
        raise PolicyError("default must be 'deny'")
    raw_tools = doc.get("tools")
    if not isinstance(raw_tools, dict) or not raw_tools:
        raise PolicyError("policy grants no tools")

    tools = {name: _build_tool(name, raw) for name, raw in raw_tools.items()}
    patterns = DEFAULT_REDACT_PATTERNS + list(doc.get("redact_patterns") or [])
    try:
        compiled = [re.compile(p) for p in patterns]
    except re.error as exc:
        raise PolicyError(f"bad redact pattern: {exc}") from exc

    return Policy(name=doc.get("name", source), tools=tools, redact_patterns=compiled, source=source)


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    return parse_policy(doc, source=str(path))


def lint_policy(policy: Policy) -> list[str]:
    """Warnings for policies that load but are probably wrong."""
    warnings: list[str] = []
    for tool in policy.tools.values():
        bounded = tool.require_approval or tool.approval_threshold or any(
            a.max is not None or a.enum or a.domain_allowlist or a.bind
            for a in tool.args.values()
        )
        if tool.risk in ("high", "critical") and not bounded:
            warnings.append(
                f"{tool.name}: risk={tool.risk} but no approval and no bounded argument"
            )
        if tool.risk == "critical" and not tool.require_approval:
            warnings.append(f"{tool.name}: critical tool without require_approval")
        if tool.egress and tool.on_taint == "allow":
            warnings.append(
                f"{tool.name}: egress tool with on_taint=allow; injected content can exfiltrate"
            )
        if tool.egress and not any(a.domain_allowlist for a in tool.args.values()):
            warnings.append(f"{tool.name}: egress tool without a domain_allowlist on any argument")

    untrusted_in = [t.name for t in policy.tools.values() if t.taints_session]
    open_egress = [t.name for t in policy.tools.values() if t.egress and t.on_taint == "allow"]
    if untrusted_in and open_egress:
        warnings.append(
            "session can read untrusted content "
            f"({', '.join(untrusted_in)}) and then send data out "
            f"({', '.join(open_egress)}) with no taint gate: the exfiltration path is open"
        )
    return warnings
