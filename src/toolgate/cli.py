"""Command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .audit import AuditLog
from .demo import run_demo
from .gateway import Gateway
from .policy import PolicyError, lint_policy, load_policy
from .replay import TraceError, load_trace, replay

DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "policies" / "support-agent.yaml"

STYLE = {"allow": "green", "deny": "red", "approval": "yellow", "executed": "magenta"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolgate",
        description="Enforce what an AI agent's tools may do, in code rather than in the prompt.",
    )
    parser.add_argument("--version", action="version", version=f"toolgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="replay a compromised agent run against mock tools")
    demo.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    demo.add_argument("--no-gateway", action="store_true", help="run the same calls with no enforcement")
    demo.add_argument("--audit", type=Path, help="write the JSONL audit trail here")
    demo.add_argument("--json", type=Path, help="write results as JSON")

    check = sub.add_parser("check", help="validate and lint a policy file")
    check.add_argument("policy", type=Path)
    check.add_argument("--strict", action="store_true", help="treat lint warnings as errors")

    rep = sub.add_parser("replay", help="evaluate recorded tool calls against a policy")
    rep.add_argument("trace", type=Path, nargs="+")
    rep.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    rep.add_argument("--assert", dest="assert_", action="store_true",
                     help="exit 1 if any decision differs from the line's 'expect'")
    rep.add_argument("--json", type=Path, help="write results as JSON")
    return parser


def _demo(args, console: Console) -> int:
    policy = load_policy(args.policy)
    gateway = None
    if not args.no_gateway:
        gateway = Gateway(policy, audit=AuditLog(args.audit, policy.redact_patterns))
    rows = run_demo(gateway)

    title = "no enforcement" if args.no_gateway else f"policy: {policy.name}"
    table = Table(title=f"toolgate demo — {title}", show_lines=False)
    for col in ("#", "Agent action", "Verdict", "Rule", "OWASP", "Why"):
        table.add_column(col, overflow="fold")
    for r in rows:
        v = r["verdict"]
        table.add_row(str(r["n"]), r["label"], f"[{STYLE[v]}]{v.upper()}[/]",
                      ",".join(r["rules"]) or "-", ",".join(r["owasp"]) or "-", r["why"][:90])
    console.print(table)

    counts = {k: sum(1 for r in rows if r["verdict"] == k) for k in STYLE}
    parts = [f"{n} {k}" for k, n in counts.items() if n]
    console.print(" · ".join(parts))
    if args.no_gateway:
        console.print("[magenta]Every call ran, including the exfiltration and the account closure.[/]")
    if args.json:
        args.json.write_text(json.dumps({"rows": rows, "summary": counts}, indent=2))
    return 0


def _check(args, console: Console) -> int:
    policy = load_policy(args.policy)
    warnings = lint_policy(policy)
    console.print(f"[green]OK[/] {args.policy}: {len(policy.tools)} tools granted, default deny")
    for w in warnings:
        console.print(f"[yellow]warn[/] {w}")
    return 1 if (warnings and args.strict) else 0


def _replay(args, console: Console) -> int:
    policy = load_policy(args.policy)
    all_results = []
    for trace in args.trace:
        results = replay(policy, load_trace(trace))
        table = Table(title=str(trace))
        for col in ("Line", "Tool", "Verdict", "Expected", "Rule", "Note"):
            table.add_column(col, overflow="fold")
        for r in results:
            mark = "" if r["ok"] else " [red]✗[/]"
            table.add_row(str(r["line"]), r["tool"], f"[{STYLE[r['verdict']]}]{r['verdict']}[/]{mark}",
                          r["expect"] or "-", ",".join(r["rules"]) or "-", r["note"])
        console.print(table)
        for r in results:
            r["trace"] = str(trace)
        all_results += results

    failed = [r for r in all_results if not r["ok"]]
    console.print(f"{len(all_results)} calls · {len(failed)} unexpected decision(s)")
    if args.json:
        args.json.write_text(json.dumps(all_results, indent=2))
    return 1 if (args.assert_ and failed) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return {"demo": _demo, "check": _check, "replay": _replay}[args.command](args, console)
    except (PolicyError, TraceError, OSError) as exc:
        console.print(f"[red]error:[/] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
