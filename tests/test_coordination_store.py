from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.coordination.store import CoordinationStore, build_digest_payload, stable_session_id


def test_stable_session_id_uses_directory_name() -> None:
    session_id = stable_session_id("/tmp/example-project")
    assert session_id.startswith("example-project-")
    assert len(session_id.split("-")[-1]) == 12


def test_ensure_session_and_digest_flow(tmp_path: Path) -> None:
    store = CoordinationStore(tmp_path)

    manifest = store.ensure_session(
        session_id="sess-1",
        cwd=tmp_path,
        leader="claude",
        tool="claude_code",
        metadata={"mode": "interactive"},
    )

    assert manifest["session_id"] == "sess-1"
    assert manifest["current_leader"] == "claude"
    assert manifest["tool_roles"]["claude_code"] == "claude"

    payload = build_digest_payload(
        title="Knowledge digest",
        text="Critical finding: use digest first\nNext action: reuse summary cache",
        kind="task_knowledge",
        source_refs=["graphrag:local"],
        generated_by="unit-test",
        model="heuristic",
    )

    first = store.write_digest("sess-1", payload, cache_key="abc123")
    second = store.write_digest("sess-1", payload, cache_key="abc123")

    assert first["payload"]["kind"] == "task_knowledge"
    assert first["payload"]["cache_hit"] is False
    assert second["payload"]["cache_hit"] is True

    latest = store.latest_digest("sess-1", kind="task_knowledge")
    assert latest is not None
    assert latest["payload"]["title"] == "Knowledge digest"


def test_register_artifact_and_checkpoint(tmp_path: Path) -> None:
    store = CoordinationStore(tmp_path)
    store.ensure_session(session_id="sess-2", cwd=tmp_path, leader="codex", tool="omx")

    artifact = tmp_path / "report.md"
    artifact.write_text("# report\n", encoding="utf-8")

    entry = store.register_artifact(
        "sess-2",
        artifact_path=str(artifact),
        artifact_type="report",
        producer="reporter",
    )
    assert entry["type"] == "report"
    assert entry["producer"] == "reporter"

    checkpoint = store.update_checkpoint(
        "sess-2",
        actor="pre_compact",
        stage="context_compaction",
        status="in_progress",
        payload={"in_progress": "saving context"},
    )
    assert checkpoint["stage"] == "context_compaction"
    assert checkpoint["in_progress"] == "saving context"


def test_leader_state_and_handoff_flow(tmp_path: Path) -> None:
    store = CoordinationStore(tmp_path)
    store.ensure_session(session_id="sess-3", cwd=tmp_path, leader="claude", tool="claude_code")

    digest = store.write_digest(
        "sess-3",
        build_digest_payload(
            title="Cross-tool digest",
            text="Critical: ready for Codex handoff\nNext action: review latest plan",
            kind="handoff_digest",
            generated_by="unit-test",
            model="heuristic",
        ),
    )

    report = tmp_path / "report.md"
    report.write_text("handoff evidence\n", encoding="utf-8")
    artifact = store.register_artifact(
        "sess-3",
        artifact_path=str(report),
        artifact_type="report",
        producer="reporter",
    )

    handoff = store.write_handoff(
        "sess-3",
        from_actor="claude",
        to_actor="codex",
        reason="need structural review",
        expected_decision_scope="review latest exploit/report package",
        input_digest_refs=[digest["path"]],
        artifact_refs=[artifact["path"]],
        required_outputs=["review_summary.md"],
        open_risks=["logic regression"],
    )

    leader = store.set_leader(
        "sess-3",
        leader="codex",
        tool="omx",
        reason="review handoff accepted",
        responsibilities=["review", "coordination"],
        handoff_ref=handoff["path"],
        latest_digest_ref=digest["path"],
    )
    assert leader["leader"] == "codex"
    assert leader["handoff_ref"] == handoff["path"]
    assert leader["previous_leader"] == "claude"

    consumed = store.consume_handoff("sess-3", to_actor="codex")
    assert consumed["handoff"] is not None
    assert consumed["handoff"]["payload"]["reason"] == "need structural review"
    assert consumed["latest_digest"]["path"] == digest["path"]

    status = store.session_status("sess-3")
    assert status["current_leader"] == "codex"
    assert status["pending_handoff"] is False


def test_skill_discovery_and_relevance(tmp_path: Path, monkeypatch) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    local_skill = project_root / ".claude" / "skills" / "bounty"
    local_skill.mkdir(parents=True)
    (local_skill / "SKILL.md").write_text("# Bounty Skill\nFast API access-control workflow\n", encoding="utf-8")

    fake_home = tmp_path / "home"
    codex_skill = fake_home / ".codex" / "skills" / "planner"
    codex_skill.mkdir(parents=True)
    (codex_skill / "SKILL.md").write_text("# Planner\nPlanning and orchestration help\n", encoding="utf-8")

    from tools.coordination import store as store_module

    monkeypatch.setattr(store_module.Path, "home", lambda: fake_home)

    store = CoordinationStore(project_root)
    store.ensure_session(session_id="sess-4", cwd=project_root, leader="claude", tool="claude_code")
    catalog = store.discover_skills("sess-4", include_plugin_cache=False)

    assert catalog["count"] == 2

    matches = store.relevant_skills("sess-4", "need bounty api planner", limit=5)
    names = {item["name"] for item in matches}
    assert "bounty" in names
    assert "planner" in names

    manifest_path = project_root / "coordination" / "sessions" / "sess-4" / "session_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["latest_skill_index_ref"].endswith("skill_index.json")


def test_instruction_discovery_from_nested_cwd(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    nested = project_root / "targets" / "demo"
    nested.mkdir(parents=True)

    (project_root / "CLAUDE.md").write_text("# Root Claude\nGlobal instructions\n", encoding="utf-8")
    (project_root / "targets" / "AGENTS.md").write_text("# Target Agents\nScoped target instructions\n", encoding="utf-8")
    (nested / "AGENTS.md").write_text("# Demo Agents\nUse the local demo rules\n", encoding="utf-8")

    store = CoordinationStore(project_root)
    store.ensure_session(session_id="sess-5", cwd=nested, leader="claude", tool="claude_code")
    index = store.discover_instruction_docs("sess-5")

    assert index["count"] >= 3
    top_path = index["documents"][0]["path"]
    assert top_path.endswith("targets/demo/AGENTS.md")

    relevant = store.relevant_instruction_docs("sess-5", "demo target rules", limit=3)
    assert relevant
    assert relevant[0]["path"].endswith("targets/demo/AGENTS.md")


def test_bootstrap_codex_syncs_omx_state(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    nested = project_root / "workspace"
    nested.mkdir(parents=True)

    (project_root / "AGENTS.md").write_text("# Repo Agents\nUse coordination first\n", encoding="utf-8")
    (project_root / "CLAUDE.md").write_text("# Repo Claude\nUse handoff JSON\n", encoding="utf-8")

    omx_state = project_root / ".omx" / "state"
    omx_state.mkdir(parents=True)
    (omx_state / "session.json").write_text(
        json.dumps(
            {
                "session_id": "omx-test-session",
                "cwd": str(project_root),
                "started_at": "2026-03-06T00:00:00Z",
                "pid": 1234,
            }
        ),
        encoding="utf-8",
    )
    (project_root / ".omx" / "notepad.md").write_text(
        "Critical finding: digest-first\nNext action: sync the plan\n",
        encoding="utf-8",
    )
    plans_dir = project_root / ".omx" / "plans"
    plans_dir.mkdir(parents=True)
    (plans_dir / "coordination-upgrade.md").write_text(
        "# Coordination upgrade\nImplement hook sync\n",
        encoding="utf-8",
    )

    store = CoordinationStore(project_root)
    result = store.bootstrap_codex(cwd=nested)

    assert result["session_id"] == "omx-test-session"
    assert result["leader_state"]["leader"] == "codex"
    assert result["skills"]["count"] >= 0
    assert result["instructions"]["count"] >= 2
    assert result["latest_digest"]["payload"]["kind"] == "codex_bootstrap"

    artifact_types = {item["type"] for item in result["artifact_index"]["artifacts"]}
    assert {"omx_session", "omx_notepad", "omx_plan"}.issubset(artifact_types)

    manifest = store.session_manifest("omx-test-session")
    assert manifest["current_leader"] == "codex"
    assert manifest["metadata"]["omx_session_id"] == "omx-test-session"


def test_coordination_cli_runs_from_non_project_cwd(tmp_path: Path) -> None:
    outside_cwd = tmp_path / "outside"
    outside_cwd.mkdir()

    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "tools" / "coordination_cli.py"),
            "derive-session",
            "--cwd",
            str(outside_cwd),
        ],
        cwd=str(outside_cwd),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["session_id"].startswith("outside-")


def test_coordination_cli_bootstrap_respects_env_project_root(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "AGENTS.md").write_text("# Agents\ncoordination\n", encoding="utf-8")
    omx_state = project_root / ".omx" / "state"
    omx_state.mkdir(parents=True)
    (omx_state / "session.json").write_text(
        json.dumps({"session_id": "omx-cli-session", "cwd": str(project_root)}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "tools" / "coordination_cli.py"),
            "bootstrap-codex",
            "--cwd",
            str(project_root),
        ],
        cwd=str(project_root),
        env={**os.environ, "COORD_PROJECT_ROOT": str(project_root)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["session_id"] == "omx-cli-session"
    assert payload["leader_state"]["leader"] == "codex"
