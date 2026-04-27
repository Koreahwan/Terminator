from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HOOK_PATH = PROJECT_ROOT / ".claude" / "hooks" / "knowledge_inject.sh"


def _run_hook(payload: dict, coord_root: Path) -> dict:
    env = os.environ.copy()
    env["COORD_PROJECT_ROOT"] = str(coord_root)
    env["COORD_SKIP_GRAPHRAG"] = "1"

    result = subprocess.run(
        ["bash", str(HOOK_PATH)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(PROJECT_ROOT),
        env=env,
        check=True,
    )
    return json.loads(result.stdout)


def _session_dir(coord_root: Path, session_id: str) -> Path:
    return coord_root / "coordination" / "sessions" / session_id


def _event_types(session_dir: Path) -> list[str]:
    events_path = session_dir / "events" / "events.jsonl"
    return [json.loads(line)["event_type"] for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _task_knowledge_digests(session_dir: Path) -> list[dict]:
    digests: list[dict] = []
    for path in (session_dir / "summaries").glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        payload = record.get("payload", record)
        if payload.get("kind") == "task_knowledge":
            digests.append(payload)
    return digests


def test_knowledge_inject_supports_task_payload(tmp_path: Path) -> None:
    session_id = "hook-task-session"
    response = _run_hook(
        {
            "tool_name": "Task",
            "session_id": session_id,
            "cwd": str(PROJECT_ROOT),
            "tool_input": {
                "subagent_type": "scout",
                "prompt": "Review the target surface and report the endpoint map.",
                "team_name": "bounty-demo",
            },
        },
        tmp_path,
    )

    assert "systemMessage" in response
    assert "scout" in response["systemMessage"]

    session_dir = _session_dir(tmp_path, session_id)
    assert session_dir.exists()
    assert "task_knowledge_injected" in _event_types(session_dir)
    assert _task_knowledge_digests(session_dir)


def test_knowledge_inject_supports_agent_payload(tmp_path: Path) -> None:
    session_id = "hook-agent-session"
    response = _run_hook(
        {
            "tool_name": "Agent",
            "session_id": session_id,
            "cwd": str(PROJECT_ROOT),
            "tool_input": {
                "subagent_type": "target-evaluator",
                "description": "Score ROI and decide GO or NO-GO.",
                "prompt": "",
            },
        },
        tmp_path,
    )

    assert "systemMessage" in response
    assert "target-evaluator" in response["systemMessage"]

    session_dir = _session_dir(tmp_path, session_id)
    assert session_dir.exists()
    assert "task_knowledge_injected" in _event_types(session_dir)

    digests = _task_knowledge_digests(session_dir)
    assert digests
    summary_text = "\n".join(digests[-1].get("high_signal_facts", []))
    assert "target-evaluator" in response["systemMessage"] or "target-evaluator" in summary_text
