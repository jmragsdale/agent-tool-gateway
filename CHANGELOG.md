# Changelog - agent-tool-gateway

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-09-27

### Added

- `Gateway` policy enforcement point with ten rules (TG-001..TG-010), each
  mapped to an OWASP Top 10 for LLM Applications (2025) category.
- YAML policy format with default deny, role grants, strict argument schemas,
  range / pattern / enum / domain-allowlist constraints, principal binding,
  approval thresholds, per-principal rate limits and taint handling.
- Session taint: tools marked `taints_session` taint the session when they
  return content; `on_taint: deny | approval` gates tools afterwards.
- Pluggable human approver; the default declines everything.
- Secret redaction on tool output and in the JSONL audit trail.
- `toolgate` CLI: `demo` (with `--no-gateway` contrast), `check` (policy
  validation and lint, including an open-exfiltration-path warning) and
  `replay --assert` for policy regression testing.
- Paired attack and normal traces, asserted in both directions in CI.
- 43 unit tests; CI runs tests, strict lint, both replays, the demo contrast
  and gitleaks.
- Architecture diagram (`agent-tool-gateway.svg`).
