# Development Log - agent-tool-gateway

Working notes: decisions, dead ends, and the reasoning behind the shape of this repo.

## 2026-09-27 - Initial build

**Why this exists.**
`prompt-injection-probe` finds out whether an LLM application's guardrails hold.
Its most common remediation, especially for LLM06, is some version of "enforce
this in the tool layer, not the prompt." This repo is that tool layer, so the
portfolio has both halves: the test and the control.

**The premise: assume the model will be compromised.**
Detecting prompt injection reliably is an open problem. Constraining what a
compromised model can do is not. Every design choice here asks the second
question: when the model follows an injected instruction, what is the worst the
tools can do, and for whom?

**Why `default: deny` is not configurable.**
An allow-by-default gateway only logs. Making it a setting would mean someone
eventually sets it to allow "temporarily" to unblock a demo. The parser rejects
any other value.

**Why identity comes from a Session object, never from the model.**
Roles and attributes are supplied by the application from its own auth, per
request. Nothing the model says can change them. That is what makes TG-002
(role) and TG-005 (argument bound to principal) real controls rather than
suggestions: "I am the administrator" in a prompt grants nothing.

**Taint instead of injection detection.**
The session is marked tainted when a tool flagged `taints_session` returns
content: retrieval, browsing, reading an inbox. Egress tools can then deny or
require approval for the rest of the session. This breaks the dangerous
combination (read untrusted content, then send data out) without having to
recognise the injection itself. The cost is real and stated in the README: a
legitimate email after a tainted read is also refused unless the policy chooses
`on_taint: approval`.

**Every check runs; every failure is recorded.**
Short-circuiting on the first failed rule produces audit lines that explain
half a decision. The evaluator collects all deny reasons, so one record shows
that a call was both over the refund limit and carrying an invented argument.

**Denied calls do not consume rate limit.**
Only executed calls are counted. Otherwise an attacker could burn a legitimate
user's refund budget with calls that were never going to run.

**Paired traces in CI.**
`examples/traces/attacks.jsonl` must stay blocked and `normal.jsonl` must stay
allowed, both asserted on every push. A gate that only proves one direction is
satisfied by a policy that denies (or allows) everything. Same reasoning as the
paired fixtures in `iac-policy-pipeline`.

**Domain allowlist edge cases.**
Matching is exact-host or dot-prefixed subdomain only. Tests cover suffix
confusion (`acme.example.evil.example`) and substring confusion
(`notacme.example`), the two ways naive `endswith` checks fail.

**What is deliberately not here.**
No MCP proxy yet, no shared rate-limit store, no asynchronous approval. Each is
listed in the README's honest-limits section rather than implied.
