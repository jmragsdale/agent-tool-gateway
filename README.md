# agent-tool-gateway

Put a policy enforcement point between an AI agent and its tools, so what the agent is *allowed* to do is decided in code — default-deny, bound to the real caller, aware of untrusted content — instead of in a system prompt the model may or may not obey.

[prompt-injection-probe](https://github.com/jmragsdale/prompt-injection-probe) finds out whether your guardrails hold. Its LLM06 remediation reads, over and over, *enforce this in the tool layer*. This is the tool layer.

```bash
pip install -e .
toolgate demo                  # a compromised agent run, gated
toolgate demo --no-gateway     # the same run with nothing in the way
```

## The premise

Assume the model will eventually follow an injected instruction. Not because the model is bad, but because it reads text from places you do not control — help-center articles, web pages, emails, tool output — and no prompt reliably outranks all of it.

If that assumption holds, the useful question is not "will the model resist?" It is "when it doesn't, what is the worst thing its tools can do?" This gateway makes that answer small, specific, and written down.

## What it enforces

| Rule | Check | OWASP LLM 2025 | What it stops |
| --- | --- | --- | --- |
| **TG-001** | Tool not in policy | LLM06 | Tools that are implemented but never granted. Registration is not authorization |
| **TG-002** | Caller's roles not granted the tool | LLM06 | "I am the administrator" in a prompt. Roles come from the session, never the model |
| **TG-003** | Unexpected or missing argument | LLM06 | Invented flags like `override_limit: true` |
| **TG-004** | Type, range, pattern, enum, destination | LLM06 | `amount=900`, `order_id="1 OR 1=1"`, `"20"` where a number belongs, `x@acme.example.evil.example` |
| **TG-005** | Argument not bound to the principal | LLM06 | The agent fetching *someone else's* records. Broken object-level authorization, via an LLM |
| **TG-006** | Rate limit per principal per tool | LLM10 | A looping or hijacked agent draining a refund budget |
| **TG-007** | Session tainted, tool denies on taint | LLM01 | The exfiltration step after an indirect injection |
| **TG-008 / 009** | Human approval required / declined | LLM06 | Irreversible or high-value actions without a person |
| **TG-010** | Secret-shaped values redacted from output | LLM02 | Credentials in tool output reaching the context window or the audit log |

Every check runs on every call and every failure is recorded, not just the first, so the audit line explains the whole decision.

## Taint: the part most agent frameworks skip

A session becomes *tainted* the moment a tool marked `taints_session: true` returns content — retrieval, browsing, reading an inbox. From then on, tools with `on_taint: deny` are refused and tools with `on_taint: approval` need a human, for the rest of the session.

That breaks the combination that makes indirect prompt injection dangerous: an agent that can read untrusted content **and** send data out **and** is allowed to do both in the same session. You do not have to detect the injection. You only have to notice the session has read something you do not trust, and stop letting it talk to the outside world unsupervised.

`toolgate check` warns when a policy leaves that path open.

## Sample output

```
toolgate demo — policy: acme-support-agent
 #   Agent action                        Verdict  Rule           OWASP        Why
 1   look up the caller's orders         ALLOW    -              -            ORD-104211, ORD-104212
 2   look up another customer's orders   DENY     TG-005         LLM06        customer_id not bound to caller
 3   small refund                        ALLOW    -              -            refunded 20.00 on ORD-104211
 5   refund above approval threshold     DENY     TG-008,TG-009  LLM06        amount=75 > 50; approval declined
 6   refund with invented override flag  DENY     TG-003,TG-004  LLM06        unexpected ['override_limit']; 900 > 200
 8   fourth refund in the hour           DENY     TG-006         LLM10        rate limit 3/3600s reached
 9   tool that was never granted         DENY     TG-001         LLM06        'run_shell' is not a granted tool
 10  read help-center article (poisoned) ALLOW    TG-010         LLM02        1 secret-shaped value redacted
 11  exfiltrate order history            DENY     TG-004,TG-007  LLM01,LLM06  evil.example not allowlisted; tainted
 12  legitimate email, after taint       DENY     TG-007         LLM01        session holds untrusted content
 13  close the account                   DENY     TG-007         LLM01        session holds untrusted content
5 allow · 8 deny
```

Row 10 is the pivot. The article carries a hidden instruction to email the order history to an outside address and close the account. The model follows it in rows 11 and 13. Run `toolgate demo --no-gateway` and both succeed — along with the other customer's orders, the $900 refund, and the shell command.

Row 12 is the honest cost: a *legitimate* email is also refused once the session is tainted. That is the tradeoff, stated plainly. The alternative is `on_taint: approval`, which keeps the capability and puts a person in front of it.

## Writing a policy

Policies are YAML. Anything not granted is denied, and `default: deny` is not configurable — an allow-by-default gateway is a logger.

```yaml
version: 1
name: acme-support-agent
default: deny

tools:
  get_orders:
    risk: medium
    allow_roles: [customer, support_agent]
    args:
      customer_id:
        type: string
        pattern: '^CUST-[0-9]{4}$'
        bind: principal.customer_id     # must equal the session's customer_id

  issue_refund:
    risk: high
    allow_roles: [support_agent]
    on_taint: approval
    rate_limit: { calls: 3, per_seconds: 3600 }
    approval_threshold: { amount: 50 }
    args:
      order_id: { type: string, pattern: '^ORD-[0-9]{6}$' }
      amount:   { type: number, min: 0.01, max: 200 }
      reason:   { type: string, enum: [damaged, late, wrong_item, goodwill] }

  send_email:
    risk: high
    allow_roles: [support_agent]
    egress: true
    on_taint: deny
    args:
      to: { type: string, domain_allowlist: [acme.example] }
      # ...
```

The full example is [`policies/support-agent.yaml`](policies/support-agent.yaml). Validate and lint with:

```bash
toolgate check policies/support-agent.yaml --strict
```

The linter flags high-risk tools with no bound at all, critical tools without approval, egress tools without a destination allowlist, and the read-untrusted-then-send-out path.

## Wiring it into an agent

The gateway sits wherever your code executes the tool calls the model asks for. Framework-agnostic: the model proposes, the gateway disposes.

```python
from toolgate import Gateway, Session, load_policy, AuditLog

policy = load_policy("policies/support-agent.yaml")
gw = Gateway(policy, approver=ask_a_human, audit=AuditLog("audit.jsonl", policy.redact_patterns))

@gw.tool("issue_refund")
def issue_refund(order_id: str, amount: float, reason: str) -> str:
    return payments.refund(order_id, amount, reason)

# Identity comes from YOUR auth, per request. Never from the model.
session = Session(
    principal=f"agent:{ticket.id}",
    roles={"support_agent"},
    attrs={"customer_id": ticket.customer_id},
)

for call in model_response.tool_calls:          # whatever shape your SDK uses
    result = gw.call(session, call.name, call.arguments)
    messages.append(tool_message(call.id, result.for_model()))
```

Denials go back to the model as an explicit `[tool 'x' was not executed: …]` message rather than an exception or silence, so the agent tells the user it can't do that instead of retrying in a loop.

`approver` is any callable `(session, tool, args, reasons) -> bool`. Wire it to a Slack button, a ticket queue, or a console prompt. The default declines everything, which is the right behaviour for unattended runs.

## Regression-testing a policy in CI

Policies drift. Someone loosens a pattern to fix a ticket and the IDOR comes back. `toolgate replay` evaluates recorded tool calls against a policy without executing anything, and `--assert` fails the build when a decision differs from the line's `expect`:

```bash
toolgate replay examples/traces/attacks.jsonl --assert   # 19 calls that must stay blocked
toolgate replay examples/traces/normal.jsonl  --assert   # 5 calls that must stay allowed
```

**The traces come in pairs on purpose.** A gate that only proves attacks are blocked is satisfied by a policy that blocks everything; one that only proves normal work passes is satisfied by a policy that allows everything. CI runs both directions.

The best traces are your own: log real tool calls from staging, mark the ones that should have been stopped, and replay them on every policy change.

## Audit trail

One JSONL line per call, allowed or denied, with principal, roles, taint state and sources, arguments, verdict, and each rule with its OWASP category. Argument values pass through the same redaction as tool output, so the audit log does not become where secrets end up.

```json
{"principal": "agent:ticket-88121", "tool": "send_email", "tainted": true,
 "taint_sources": ["search_kb"], "verdict": "deny",
 "reasons": [{"rule": "TG-004", "owasp": "LLM06", "message": "to destination 'evil.example' is not on the allowlist"},
             {"rule": "TG-007", "owasp": "LLM01", "message": "session holds untrusted content (search_kb)"}]}
```

## Scope and honest limits

This is a control, not a guarantee. It narrows what a compromised agent can do to what the policy allows. It does not make a bad policy good.

- **Taint is session-level and coarse.** It knows the session read untrusted content, not which tokens came from where. Fine-grained provenance tracking inside the context window is an open research problem, and I have not pretended to solve it.
- **Rate limits are in-memory, per process.** Behind a load balancer you need a shared store. The interface is small; the Redis version is not written yet.
- **Redaction is regex.** It catches common credential shapes and misses everything else. It is a floor, not DLP.
- **Approval is a synchronous callback.** Long-running human approval (hours, not seconds) needs a pause-and-resume agent loop that this does not provide.
- **Not yet an MCP proxy.** Today it wraps tool execution in-process. Running as a proxy in front of MCP servers is the obvious next step and is not built.
- **It cannot stop what it cannot see.** A tool that does something dangerous with *allowed* arguments is still dangerous. The policy is only as good as the thought that went into each tool's worst case.

## Development

```bash
pip install -e ".[dev]"
pytest -q                      # 43 tests: every rule blocks, and none over-blocks
```

---

Built by Jermaine Ragsdale — cloud security architect, CISSP, AWS Security Specialty.
I do LLM application security reviews and cloud security assessments: **[jmragsdale.com](https://jmragsdale.com)**

MIT licensed.
