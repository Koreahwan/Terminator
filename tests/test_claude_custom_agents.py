from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AGENTS_DIR = PROJECT_ROOT / ".claude" / "agents"

CANONICAL_NAMES = {
    "ai-recon.md": "ai-recon",
    "analyst.md": "analyst",
    "architect.md": "architect",
    "critic.md": "critic",
    "defi-auditor.md": "defi-auditor",
    "exploiter.md": "exploiter",
    "mobile-analyst.md": "mobile-analyst",
    "patch-hunter.md": "patch-hunter",
    "recon-scanner.md": "recon-scanner",
    "reporter.md": "reporter",
    "scope-auditor.md": "scope-auditor",
    "scout.md": "scout",
    "source-auditor.md": "source-auditor",
    "submission-review.md": "submission-review",
    "target-discovery.md": "target-discovery",
    "target_evaluator.md": "target-evaluator",
    "threat-modeler.md": "threat-modeler",
    "triager_sim.md": "triager-sim",
    "web-tester.md": "web-tester",
    "workflow-auditor.md": "workflow-auditor",
}


def _read_frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{path} is missing YAML frontmatter start"
    _, frontmatter, _ = text.split("---\n", 2)

    result: dict[str, str] = {}
    for raw_line in frontmatter.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def test_all_custom_agents_have_required_frontmatter() -> None:
    files = sorted(AGENTS_DIR.glob("*.md"))
    assert len(files) == len(CANONICAL_NAMES)

    for path in files:
        frontmatter = _read_frontmatter(path)

        for key in ("name", "description", "model", "color", "permissionMode"):
            assert frontmatter.get(key), f"{path} missing {key}"

        assert re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,48}[a-z0-9])?", frontmatter["name"]), path
        assert frontmatter["model"] in {"haiku", "sonnet", "claude-opus-4-6[1m]", "inherit"}
        assert frontmatter["color"] in {
            "blue",
            "cyan",
            "gold",
            "green",
            "indigo",
            "lime",
            "magenta",
            "orange",
            "purple",
            "red",
            "teal",
            "yellow",
        }
        assert frontmatter["permissionMode"] == "bypassPermissions"
        assert frontmatter["name"] == CANONICAL_NAMES[path.name]
        assert frontmatter["description"].startswith("Use this agent when "), path


def test_core_docs_use_canonical_runtime_agent_ids() -> None:
    docs = [
        PROJECT_ROOT / "CLAUDE.md",
        PROJECT_ROOT / ".claude" / "skills" / "bounty" / "SKILL.md",
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "README.ko.md",
    ]
    forbidden = [
        '@target_evaluator',
        '@triager_sim',
        'subagent_type="target_evaluator"',
        'subagent_type="triager_sim"',
        'subagent_type="fw_profiler"',
        'subagent_type="fw_inventory"',
        'subagent_type="fw_surface"',
        'subagent_type="fw_validator"',
    ]

    for path in docs:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            assert pattern not in text, f"{path} still contains legacy runtime identifier: {pattern}"
