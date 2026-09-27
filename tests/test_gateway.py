"""Every rule gets a test that proves it blocks and a test that proves it does not over-block."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolgate import (
    ALLOW, APPROVAL, DENY, AuditLog, Gateway, PolicyError, Session, lint_policy,
    load_policy, parse_policy,
)
from toolgate.cli import main
from toolgate.replay import load_trace, replay

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "support-agent.yaml"


@pytest.fixture
def policy():
    return load_policy(POLICY_PATH)


@pytest.fixture
def agent():
    return Session("agent:1", {"support_agent"}, {"customer_id": "CUST-1042"})


def refund(amount=20, **extra):
    return {"order_id": "ORD-104211", "amount": amount, "reason": "damaged", **extra}


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def gateway(policy, **kw):
    gw = Gateway(policy, **kw)
    gw.register("issue_refund", lambda order_id, amount, reason: f"refunded {amount}")
    gw.register("get_orders", lambda customer_id: "ORD-104211")
    gw.register("send_email", lambda to, subject, body: "sent")
    gw.register("search_kb", lambda query: "article with key sk-demo-4f9a2c81e7d3b6a0 inside")
    gw.register("close_account", lambda customer_id: "closed")
    return gw


# ---------------------------------------------------------------- default deny / roles


def test_unknown_tool_denied_even_if_implemented(policy, agent):
    gw = gateway(policy)
    gw.register("run_shell", lambda cmd: "ran")
    result = gw.call(agent, "run_shell", {"cmd": "id"})
    assert result.decision.verdict == DENY and result.decision.rules == ["TG-001"]
    assert result.output is None


def test_role_not_granted(policy):
    customer = Session("cust:1", {"customer"}, {"customer_id": "CUST-1042"})
    assert gateway(policy).evaluate(customer, "issue_refund", refund()).verdict == DENY


def test_granted_role_allowed(policy, agent):
    result = gateway(policy).call(agent, "issue_refund", refund())
    assert result.executed and result.output == "refunded 20"


# ---------------------------------------------------------------- schema and constraints


@pytest.mark.parametrize("args,rule", [
    (refund(override_limit=True), "TG-003"),
    ({"order_id": "ORD-104211", "amount": 20}, "TG-003"),
    (refund(amount="20"), "TG-004"),
    (refund(amount=True), "TG-004"),  # bool is an int in Python; not a number here
    (refund(amount=900), "TG-004"),
    (refund(amount=0), "TG-004"),
    ({"order_id": "ORD-1 OR 1=1", "amount": 20, "reason": "damaged"}, "TG-004"),
    ({"order_id": "ORD-104211", "amount": 20, "reason": "because"}, "TG-004"),
])
def test_argument_violations_denied(policy, agent, args, rule):
    d = gateway(policy).evaluate(agent, "issue_refund", args)
    assert d.verdict == DENY and rule in d.rules


def test_all_failures_recorded_not_just_first(policy, agent):
    d = gateway(policy).evaluate(agent, "issue_refund", refund(amount=900, override_limit=True))
    assert {"TG-003", "TG-004"} <= set(d.rules)


def test_bind_blocks_other_customers_records(policy, agent):
    gw = gateway(policy)
    assert gw.evaluate(agent, "get_orders", {"customer_id": "CUST-2210"}).rules == ["TG-005"]
    assert gw.evaluate(agent, "get_orders", {"customer_id": "CUST-1042"}).verdict == ALLOW


def test_bind_fails_closed_when_session_lacks_attribute(policy):
    anonymous = Session("agent:2", {"support_agent"})
    assert gateway(policy).evaluate(anonymous, "get_orders", {"customer_id": "CUST-1042"}).verdict == DENY


@pytest.mark.parametrize("to,verdict", [
    ("jo@customers.acme.example", ALLOW),
    ("jo@acme.example", ALLOW),
    ("jo@evil.example", DENY),
    ("jo@acme.example.evil.example", DENY),  # suffix confusion
    ("jo@notacme.example", DENY),  # substring confusion
    ("not-an-address", DENY),
])
def test_domain_allowlist(policy, agent, to, verdict):
    d = gateway(policy).evaluate(agent, "send_email", {"to": to, "subject": "s", "body": "b"})
    assert d.verdict == verdict


# ---------------------------------------------------------------- approval


def test_threshold_requires_approval_and_default_approver_declines(policy, agent):
    result = gateway(policy).call(agent, "issue_refund", refund(amount=75))
    assert result.decision.verdict == DENY
    assert result.decision.rules == ["TG-008", "TG-009"]


def test_approved_call_executes(policy, agent):
    seen = []

    def approver(session, tool, args, why):
        seen.append((tool, args["amount"]))
        return True

    result = gateway(policy, approver=approver).call(agent, "issue_refund", refund(amount=75))
    assert result.executed and seen == [("issue_refund", 75)]


def test_at_threshold_does_not_need_approval(policy, agent):
    assert gateway(policy).evaluate(agent, "issue_refund", refund(amount=50)).verdict == ALLOW


def test_critical_tool_always_needs_approval(policy, agent):
    d = gateway(policy).evaluate(agent, "close_account", {"customer_id": "CUST-1042"})
    assert d.verdict == APPROVAL


# ---------------------------------------------------------------- taint


def test_retrieval_taints_session_then_egress_denied(policy, agent):
    gw = gateway(policy)
    email = {"to": "jo@acme.example", "subject": "s", "body": "b"}
    assert gw.evaluate(agent, "send_email", email).verdict == ALLOW
    gw.call(agent, "search_kb", {"query": "refunds"})
    assert agent.tainted and agent.taint_sources == ["search_kb"]
    assert gw.evaluate(agent, "send_email", email).rules == ["TG-007"]


def test_taint_escalates_refund_to_approval(policy, agent):
    agent.mark_tainted("web")
    assert gateway(policy).evaluate(agent, "issue_refund", refund(amount=5)).verdict == APPROVAL


def test_taint_does_not_block_reads(policy, agent):
    agent.mark_tainted("web")
    assert gateway(policy).evaluate(agent, "get_orders", {"customer_id": "CUST-1042"}).verdict == ALLOW


# ---------------------------------------------------------------- rate limit


def test_rate_limit_and_window_expiry(policy, agent):
    clock = FakeClock()
    gw = gateway(policy, clock=clock)
    for _ in range(3):
        assert gw.call(agent, "issue_refund", refund(amount=5)).executed
    assert gw.call(agent, "issue_refund", refund(amount=5)).decision.rules == ["TG-006"]
    clock.t = 3600
    assert gw.call(agent, "issue_refund", refund(amount=5)).executed


def test_denied_calls_do_not_consume_rate_limit(policy, agent):
    gw = gateway(policy)
    for _ in range(5):
        gw.call(agent, "issue_refund", refund(amount=900))
    assert gw.call(agent, "issue_refund", refund(amount=5)).executed


# ---------------------------------------------------------------- redaction and audit


def test_secrets_redacted_from_output_and_audit(policy, agent, tmp_path):
    log = tmp_path / "audit.jsonl"
    gw = gateway(policy, audit=AuditLog(log, policy.redact_patterns))
    result = gw.call(agent, "search_kb", {"query": "key is AKIAIOSFODNN7EXAMPLE"})
    assert "sk-demo" not in result.output and "[REDACTED]" in result.output
    assert "TG-010" in result.decision.rules
    text = log.read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    record = json.loads(text.splitlines()[0])
    assert record["verdict"] == ALLOW and record["tool"] == "search_kb"


def test_every_call_is_audited_including_denials(policy, agent):
    gw = gateway(policy)
    gw.call(agent, "run_shell", {})
    gw.call(agent, "get_orders", {"customer_id": "CUST-1042"})
    assert [r["verdict"] for r in gw.audit.records] == [DENY, ALLOW]


def test_denial_message_for_model_is_explicit(policy, agent):
    text = gateway(policy).call(agent, "run_shell", {}).for_model()
    assert text.startswith("[tool 'run_shell' was not executed")


# ---------------------------------------------------------------- policy loading and lint


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d.update(default="allow"), "default must be 'deny'"),
    (lambda d: d.update(version=2), "version"),
    (lambda d: d["tools"]["search_kb"].update(allow_roles=[]), "allow_roles is empty"),
    (lambda d: d["tools"]["search_kb"].update(risky="yes"), "unknown keys"),
    (lambda d: d["tools"]["search_kb"].update(on_taint="maybe"), "on_taint"),
    (lambda d: d["tools"]["get_orders"]["args"]["customer_id"].update(bind="session.x"), "bind"),
])
def test_bad_policies_rejected(mutate, msg):
    import yaml

    doc = yaml.safe_load(POLICY_PATH.read_text())
    mutate(doc)
    with pytest.raises(PolicyError, match=msg):
        parse_policy(doc)


def test_shipped_policy_is_lint_clean(policy):
    assert lint_policy(policy) == []


def test_lint_flags_open_exfiltration_path():
    doc = {
        "version": 1,
        "tools": {
            "browse": {"allow_roles": ["a"], "taints_session": True, "risk": "low"},
            "post": {"allow_roles": ["a"], "egress": True, "risk": "low"},
        },
    }
    warnings = lint_policy(parse_policy(doc))
    assert any("exfiltration path is open" in w for w in warnings)


# ---------------------------------------------------------------- replay and CLI


def test_shipped_traces_hold_in_both_directions(policy):
    for name in ("attacks.jsonl", "normal.jsonl"):
        results = replay(policy, load_trace(ROOT / "examples" / "traces" / name))
        assert results and all(r["ok"] for r in results), name


def test_replay_assert_fails_on_regression(tmp_path):
    trace = tmp_path / "t.jsonl"
    trace.write_text(json.dumps({
        "principal": "a", "roles": ["support_agent"], "tool": "run_shell",
        "args": {}, "expect": "allow",
    }) + "\n")
    assert main(["replay", str(trace), "--policy", str(POLICY_PATH), "--assert"]) == 1


def test_cli_demo_runs(tmp_path):
    out = tmp_path / "demo.json"
    assert main(["demo", "--json", str(out)]) == 0
    summary = json.loads(out.read_text())["summary"]
    assert summary["deny"] >= 7 and summary["allow"] >= 4
