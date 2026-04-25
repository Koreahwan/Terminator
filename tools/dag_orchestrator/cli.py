#!/usr/bin/env python3
"""
DAG Orchestrator CLI

Usage:
    python3 tools/dag_orchestrator/cli.py run --pipeline ctf_pwn --target challenge_name
    python3 tools/dag_orchestrator/cli.py run --pipeline bounty --target example.com
    python3 tools/dag_orchestrator/cli.py list
    python3 tools/dag_orchestrator/cli.py visualize --pipeline ctf_pwn --target demo
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools.dag_orchestrator.pipelines import PIPELINES, get_pipeline


def scope_first_gate_status(args):
    profile = os.environ.get("TERMINATOR_RUNTIME_PROFILE", "")
    if profile != "scope-first-hybrid":
        return {"enabled": False, "status": "not_applicable"}
    work_dir = os.path.abspath(getattr(args, "work_dir", "."))
    contract = os.path.join(work_dir, "scope_contract.json")
    if not os.path.exists(contract):
        return {
            "enabled": True,
            "status": "would_block" if not getattr(args, "execute", False) else "block",
            "reason": "scope_contract_missing",
            "scope_contract": contract,
        }
    try:
        from tools.scope_contract import validate_contract
        from pathlib import Path
        rc, payload = validate_contract(Path(contract))
    except Exception as exc:
        return {
            "enabled": True,
            "status": "block",
            "reason": f"scope_contract_validation_error:{type(exc).__name__}:{exc}",
            "scope_contract": contract,
        }
    return {
        "enabled": True,
        "status": "pass" if rc == 0 else "block",
        "reason": "" if rc == 0 else "scope_contract_invalid",
        "scope_contract": contract,
        "validation": payload,
    }


def cmd_list(args):
    print("Available pipelines:")
    descriptions = {
        "target_discovery": "Bug bounty target discovery: target_discovery→target_evaluator→critic→reporter",
        "ctf_pwn": "CTF Pwn 6-agent: reverser→trigger→chain→critic→verifier→reporter",
        "ctf_rev": "CTF Reversing/Crypto 4-agent: reverser→solver→critic→verifier→reporter",
        "bounty":  "Bug Bounty v3 8-agent: target_evaluator→scout+analyst→exploiter→reporter→...",
        "firmware":"Firmware 5-agent: reverser→cve+secret+code scanners→exploiter→reporter",
    }
    for name in sorted(PIPELINES.keys()):
        print(f"  {name:<12} -- {descriptions.get(name, '')}")


def cmd_visualize(args):
    dag = get_pipeline(args.pipeline, args.target or "demo")
    print(dag.visualize())


def cmd_run(args):
    if not args.pipeline:
        print("Error: --pipeline required", file=sys.stderr)
        sys.exit(1)

    target = args.target or "target"
    dag = get_pipeline(args.pipeline, target)
    os.environ["TERMINATOR_ACTIVE_PIPELINE"] = args.pipeline

    # Attach backend handler if --execute mode
    if getattr(args, 'execute', False):
        try:
            from .claude_handler import BackendAgentHandler
        except ImportError:
            from tools.dag_orchestrator.claude_handler import BackendAgentHandler
        import uuid
        session_id = getattr(args, 'session_id', None) or str(uuid.uuid4())[:8]
        handler = BackendAgentHandler(
            work_dir=os.path.abspath(getattr(args, 'work_dir', '.')),
            session_id=session_id,
            target=target,
            backend=getattr(args, 'backend', 'claude'),
        )
        handler.attach_to_dag(dag)
        print(f"[Orchestrator] Execute mode: agents will be spawned via {handler.backend}")
        print(f"[Orchestrator] Session: {session_id}, Work dir: {handler.work_dir}")
    else:
        print(f"[Orchestrator] Dry-run mode (use --execute for real execution)")

    # Inject context from --context JSON if provided
    if args.context:
        try:
            ctx = json.loads(args.context)
            for k, v in ctx.items():
                dag.set_context(k, v)
        except json.JSONDecodeError as e:
            print(f"Error parsing --context JSON: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"[Orchestrator] Running pipeline '{args.pipeline}' for target '{target}'")
    print(dag.visualize())
    print()

    gate_status = scope_first_gate_status(args)
    summary = dag.run()
    summary["scope_first_gate"] = gate_status

    print("\n" + "=" * 50)
    print(f"Pipeline: {summary['pipeline']}")
    print(f"Total time: {summary['total_time']}s")
    print(f"Completed: {summary['completed']}")
    print(f"Failed:    {summary['failed']}")
    print("\nNode Details:")
    for name, info in summary["nodes"].items():
        status_icon = {"completed": "✓", "failed": "✗", "skipped": "⊘",
                       "running": "◉", "pending": "○"}.get(info["status"], "?")
        print(f"  {status_icon} {name:<20} [{info['status']:<10}] "
              f"{info['duration']}s  retries={info['retries']}")
        if info.get("error"):
            print(f"      ERROR: {info['error']}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\n[Orchestrator] Summary saved to {args.out}")

    # Exit code: 0 if no failures
    sys.exit(0 if not summary["failed"] else 1)


def main():
    parser = argparse.ArgumentParser(
        description="Terminator DAG Orchestrator CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("command", choices=["run", "list", "visualize"])
    parser.add_argument("--pipeline", "-p", help="Pipeline name")
    parser.add_argument("--target", "-t", help="Target name (challenge, domain, etc.)")
    parser.add_argument("--context", "-c", help="JSON context to inject into pipeline")
    parser.add_argument("--out", "-o", help="Output file for execution summary")
    parser.add_argument("--execute", action="store_true",
                        help="Execute agents via Claude Code CLI (default: dry-run)")
    parser.add_argument("--work-dir", "-w", default=".",
                        help="Working directory for agent artifacts")
    parser.add_argument("--session-id", "-s", default=None,
                        help="Session ID for DB tracking")
    parser.add_argument("--backend", default="claude",
                        help="Execution backend: claude | codex | hybrid")

    args = parser.parse_args()

    dispatch = {
        "run": cmd_run,
        "list": cmd_list,
        "visualize": cmd_visualize,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
