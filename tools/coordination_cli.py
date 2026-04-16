#!/usr/bin/env python3
"""CLI utilities for shared coordination state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.coordination import CoordinationStore, stable_session_id


def _load_json_arg(raw: str | None) -> Any:
    if not raw:
        return {}
    return json.loads(raw)


def cmd_ensure_session(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    manifest = store.ensure_session(
        session_id=args.session,
        cwd=args.cwd,
        leader=args.leader,
        tool=args.tool,
        lead_mode=args.lead_mode,
        status=args.status,
        metadata=_load_json_arg(args.metadata_json),
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


def cmd_event(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    event = store.append_event(args.session, args.event_type, _load_json_arg(args.payload_json))
    print(json.dumps(event, indent=2, ensure_ascii=False))
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    checkpoint = store.update_checkpoint(
        args.session,
        actor=args.actor,
        stage=args.stage,
        status=args.status,
        payload=_load_json_arg(args.payload_json),
    )
    print(json.dumps(checkpoint, indent=2, ensure_ascii=False))
    return 0


def cmd_register_artifact(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    artifact = store.register_artifact(
        args.session,
        artifact_path=args.path,
        artifact_type=args.artifact_type,
        producer=args.producer,
        status=args.status,
        replaces=args.replaces,
        metadata=_load_json_arg(args.metadata_json),
    )
    print(json.dumps(artifact, indent=2, ensure_ascii=False))
    return 0


def cmd_discover_skills(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    catalog = store.discover_skills(args.session, include_plugin_cache=not args.skip_plugin_cache)
    print(json.dumps(catalog, indent=2, ensure_ascii=False))
    return 0


def cmd_relevant_skills(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    matches = store.relevant_skills(args.session, args.query, limit=args.limit)
    print(json.dumps({"skills": matches}, indent=2, ensure_ascii=False))
    return 0


def cmd_discover_instructions(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    catalog = store.discover_instruction_docs(args.session)
    print(json.dumps(catalog, indent=2, ensure_ascii=False))
    return 0


def cmd_relevant_instructions(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    matches = store.relevant_instruction_docs(args.session, args.query, limit=args.limit)
    print(json.dumps({"documents": matches}, indent=2, ensure_ascii=False))
    return 0


def cmd_latest_digest(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    digest = store.latest_digest(args.session, kind=args.kind)
    print(json.dumps(digest or {}, indent=2, ensure_ascii=False))
    return 0


def cmd_set_leader(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    leader_state = store.set_leader(
        args.session,
        leader=args.leader,
        tool=args.tool,
        reason=args.reason,
        responsibilities=args.responsibility,
        handoff_ref=args.handoff_ref,
        latest_digest_ref=args.latest_digest_ref,
    )
    print(json.dumps(leader_state, indent=2, ensure_ascii=False))
    return 0


def cmd_write_handoff(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    record = store.write_handoff(
        args.session,
        from_actor=args.from_actor,
        to_actor=args.to_actor,
        reason=args.reason,
        expected_decision_scope=args.decision_scope,
        input_digest_refs=args.input_digest_ref,
        artifact_refs=args.artifact_ref,
        required_outputs=args.required_output,
        open_risks=args.open_risk,
        metadata=_load_json_arg(args.metadata_json),
    )
    print(json.dumps(record, indent=2, ensure_ascii=False))
    return 0


def cmd_consume_handoff(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    payload = store.consume_handoff(args.session, to_actor=args.to_actor)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_sync_omx_state(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    payload = store.sync_omx_state(args.session, cwd=args.cwd)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_sync_claude_state(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    payload = store.sync_claude_state(args.session, cwd=args.cwd)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_bootstrap_codex(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    payload = store.bootstrap_codex(session_id=args.session, cwd=args.cwd)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_session_status(args: argparse.Namespace) -> int:
    store = CoordinationStore.from_env()
    payload = store.session_status(args.session)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def cmd_derive_session(args: argparse.Namespace) -> int:
    session_id = stable_session_id(args.cwd)
    print(json.dumps({"session_id": session_id}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shared coordination state CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    ensure = sub.add_parser("ensure-session")
    ensure.add_argument("--session")
    ensure.add_argument("--cwd", default=".")
    ensure.add_argument("--leader", default="unknown")
    ensure.add_argument("--tool", default="unknown")
    ensure.add_argument("--lead-mode", default="auto")
    ensure.add_argument("--status", default="active")
    ensure.add_argument("--metadata-json")
    ensure.set_defaults(func=cmd_ensure_session)

    event = sub.add_parser("event")
    event.add_argument("--session", required=True)
    event.add_argument("--type", dest="event_type", required=True)
    event.add_argument("--payload-json")
    event.set_defaults(func=cmd_event)

    checkpoint = sub.add_parser("checkpoint")
    checkpoint.add_argument("--session", required=True)
    checkpoint.add_argument("--actor", required=True)
    checkpoint.add_argument("--stage", required=True)
    checkpoint.add_argument("--status", required=True)
    checkpoint.add_argument("--payload-json")
    checkpoint.set_defaults(func=cmd_checkpoint)

    artifact = sub.add_parser("register-artifact")
    artifact.add_argument("--session", required=True)
    artifact.add_argument("--path", required=True)
    artifact.add_argument("--artifact-type", required=True)
    artifact.add_argument("--producer", required=True)
    artifact.add_argument("--status", default="valid")
    artifact.add_argument("--replaces")
    artifact.add_argument("--metadata-json")
    artifact.set_defaults(func=cmd_register_artifact)

    skills = sub.add_parser("discover-skills")
    skills.add_argument("--session", required=True)
    skills.add_argument("--skip-plugin-cache", action="store_true")
    skills.set_defaults(func=cmd_discover_skills)

    relevant = sub.add_parser("relevant-skills")
    relevant.add_argument("--session", required=True)
    relevant.add_argument("--query", required=True)
    relevant.add_argument("--limit", type=int, default=5)
    relevant.set_defaults(func=cmd_relevant_skills)

    instructions = sub.add_parser("discover-instructions")
    instructions.add_argument("--session", required=True)
    instructions.set_defaults(func=cmd_discover_instructions)

    relevant_docs = sub.add_parser("relevant-instructions")
    relevant_docs.add_argument("--session", required=True)
    relevant_docs.add_argument("--query", required=True)
    relevant_docs.add_argument("--limit", type=int, default=5)
    relevant_docs.set_defaults(func=cmd_relevant_instructions)

    latest = sub.add_parser("latest-digest")
    latest.add_argument("--session", required=True)
    latest.add_argument("--kind")
    latest.set_defaults(func=cmd_latest_digest)

    leader = sub.add_parser("set-leader")
    leader.add_argument("--session", required=True)
    leader.add_argument("--leader", required=True)
    leader.add_argument("--tool", required=True)
    leader.add_argument("--reason", required=True)
    leader.add_argument("--responsibility", action="append", default=[])
    leader.add_argument("--handoff-ref")
    leader.add_argument("--latest-digest-ref")
    leader.set_defaults(func=cmd_set_leader)

    handoff = sub.add_parser("write-handoff")
    handoff.add_argument("--session", required=True)
    handoff.add_argument("--from", dest="from_actor", required=True)
    handoff.add_argument("--to", dest="to_actor", required=True)
    handoff.add_argument("--reason", required=True)
    handoff.add_argument("--decision-scope", required=True)
    handoff.add_argument("--input-digest-ref", action="append", default=[])
    handoff.add_argument("--artifact-ref", action="append", default=[])
    handoff.add_argument("--required-output", action="append", default=[])
    handoff.add_argument("--open-risk", action="append", default=[])
    handoff.add_argument("--metadata-json")
    handoff.set_defaults(func=cmd_write_handoff)

    consume = sub.add_parser("consume-handoff")
    consume.add_argument("--session", required=True)
    consume.add_argument("--to", dest="to_actor")
    consume.set_defaults(func=cmd_consume_handoff)

    sync = sub.add_parser("sync-omx-state")
    sync.add_argument("--session", required=True)
    sync.add_argument("--cwd", default=".")
    sync.set_defaults(func=cmd_sync_omx_state)

    claude_sync = sub.add_parser("sync-claude-state")
    claude_sync.add_argument("--session", required=True)
    claude_sync.add_argument("--cwd", default=".")
    claude_sync.set_defaults(func=cmd_sync_claude_state)

    bootstrap = sub.add_parser("bootstrap-codex")
    bootstrap.add_argument("--session")
    bootstrap.add_argument("--cwd", default=".")
    bootstrap.set_defaults(func=cmd_bootstrap_codex)

    status = sub.add_parser("session-status")
    status.add_argument("--session", required=True)
    status.set_defaults(func=cmd_session_status)

    derive = sub.add_parser("derive-session")
    derive.add_argument("--cwd", default=".")
    derive.set_defaults(func=cmd_derive_session)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
