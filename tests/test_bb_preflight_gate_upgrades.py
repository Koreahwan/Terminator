"""Regression tests for bb_preflight gate-alignment upgrades.

This file is standard-library-only so it can run both via pytest discovery
and direct `python3 tests/test_bb_preflight_gate_upgrades.py`.
"""

from __future__ import annotations

import io
import json
import math
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
import bb_preflight


def _write(path: Path, name: str, content: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / name).write_text(content, encoding="utf-8")


class TestCoverageCheck(unittest.TestCase):
    def test_coverage_check_uses_risk_weighting_and_status_prefixes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_cov_weighted_") as td:
            target = Path(td)
            _write(
                target,
                "endpoint_map.md",
                """\
## Endpoint Table

| Endpoint | Method | Auth | Status | Risk | Notes |
|----------|--------|------|--------|------|-------|
| /admin/users | GET | Required | VULN (ID-1) | HIGH | critical auth surface |
| /billing/pay | POST | Required | UNTESTED | HIGH | payment flow |
| /health | GET | None | TESTED | LOW | simple health |
| /docs | GET | None | SAFE | LOW | docs |
| /search | GET | None | TESTED | LOW | search |
| /profile | GET | Required | TESTED | LOW | profile |
| /notifications | GET | Required | TESTED | LOW | notifications |
| /assets | GET | None | TESTED | LOW | assets |
| /export | POST | Required | UNTESTED | LOW | export |
| /about | GET | None | UNTESTED | LOW | marketing |
""",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = bb_preflight.coverage_check(str(target), threshold=70, json_output=True)
            payload = json.loads(buf.getvalue())

            self.assertEqual(rc, 1)
            self.assertTrue(payload["risk_weighting_active"])
            self.assertEqual(payload["tested"], 7)
            self.assertEqual(payload["weighted_tested"], 8)
            self.assertEqual(payload["weighted_testable"], 12)
            self.assertTrue(math.isclose(payload["coverage"], 66.7, abs_tol=0.1))

    def test_coverage_check_falls_back_cleanly_without_risk_column(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_cov_fallback_") as td:
            target = Path(td)
            _write(
                target,
                "endpoint_map.md",
                """\
## Endpoint Table

| Endpoint | Method | Auth | Status | Notes |
|----------|--------|------|--------|-------|
| /a | GET | None | TESTED | one |
| /b | GET | None | SAFE | two |
| /c | GET | None | UNTESTED | three |
| /d | GET | None | TESTED | four |
| /e | GET | None | TESTED | five |
| /f | GET | None | SAFE | six |
| /g | GET | None | TESTED | seven |
| /h | GET | None | UNTESTED | eight |
| /i | GET | None | UNTESTED | nine |
| /j | GET | None | TESTED | ten |
""",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = bb_preflight.coverage_check(str(target), threshold=60, json_output=True)
            payload = json.loads(buf.getvalue())

            self.assertEqual(rc, 0)
            self.assertFalse(payload["risk_weighting_active"])
            self.assertEqual(payload["weighted_tested"], 7)
            self.assertEqual(payload["weighted_testable"], 10)
            self.assertTrue(math.isclose(payload["coverage"], 70.0, abs_tol=0.1))


class TestWorkflowCheck(unittest.TestCase):
    def test_workflow_check_fails_when_semantic_sections_are_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_workflow_fail_") as td:
            target = Path(td)
            _write(
                target,
                "workflow_map.md",
                """\
# Workflow Map

## Workflow 1: Checkout

### State Diagram
[INIT] -> [PAID] -> [DONE]

### Transitions
| From | To | Trigger |
|------|----|---------|
| INIT | PAID | POST /pay |
""",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = bb_preflight.workflow_check(str(target))
            output = buf.getvalue().lower()

            self.assertEqual(rc, 1)
            self.assertIn("rollback", output)
            self.assertIn("attack", output)

    def test_workflow_check_passes_with_semantically_complete_map(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_workflow_pass_") as td:
            target = Path(td)
            _write(
                target,
                "workflow_map.md",
                """\
# Workflow Map

## Workflow 1: Checkout

### State Diagram
[INIT] -> [PAID] -> [FULFILLED]

Entry state: INIT
Rollback: CANCELLED before fulfillment
Terminal: FULFILLED or CANCELLED

### Transitions
| From | To | Trigger | Reversible |
|------|----|---------|------------|
| INIT | PAID | POST /pay | No |
| PAID | FULFILLED | POST /ship | No |

### 5-Class Attack Analysis
| Attack Class | Applicable? | Risk |
|-------------|-------------|------|
| Skip-Step | NO | LOW |
| Replay | YES | MEDIUM |
| Race Condition | YES | HIGH |
| State Reversal | NO | LOW |
| Partial-Failure | YES | MEDIUM |
""",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = bb_preflight.workflow_check(str(target))
            output = buf.getvalue().lower()

            self.assertEqual(rc, 0)
            self.assertIn("passes semantic validation", output)

    def test_workflow_check_fails_if_one_workflow_section_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_workflow_mixed_") as td:
            target = Path(td)
            _write(
                target,
                "workflow_map.md",
                """\
# Workflow Map

## Workflow 1: Complete
Entry point: POST /start
Rollback: CANCELLED
Terminal: DONE

### Transitions
| From | To | Trigger |
|------|----|---------|
| INIT | DONE | POST /finish |

### 5-Class Attack Analysis
| Attack Class | Applicable? |
|-------------|-------------|
| Skip-Step | NO |
| Replay | YES |
| Race Condition | YES |
| State Reversal | NO |
| Partial-Failure | YES |

## Workflow 2: Incomplete
Entry point: POST /other
Terminal: BROKEN

### Transitions
| From | To | Trigger |
|------|----|---------|
| INIT | BROKEN | POST /break |
""",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = bb_preflight.workflow_check(str(target))
            output = buf.getvalue().lower()

            self.assertEqual(rc, 1)
            self.assertIn("workflow 2", output)
            self.assertIn("rollback", output)


class TestDuplicateGraphCheck(unittest.TestCase):
    def test_duplicate_graph_check_reports_graph_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_dup_graph_") as td:
            target = Path(td)
            with patch.object(
                bb_preflight,
                "_graphrag_duplicate_lookup",
                return_value={
                    "available": True,
                    "matched": True,
                    "mode": "graph+heuristic",
                    "reason": "graph_query_ok",
                    "text": "similar finding from graph",
                },
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = bb_preflight.duplicate_graph_check(
                        str(target),
                        "glorpqux frobnicator lattice violation with nonce shadowing",
                        json_output=True,
                    )
                payload = json.loads(buf.getvalue())

            self.assertEqual(rc, 1)
            self.assertEqual(payload["match_mode"], "graph+heuristic")
            self.assertEqual(payload["matches"][0]["source"], "graphrag/similar_findings")

    def test_duplicate_graph_check_reports_fallback_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bbpf_dup_fallback_") as td:
            target = Path(td)
            with patch.object(
                bb_preflight,
                "_graphrag_duplicate_lookup",
                return_value={
                    "available": False,
                    "matched": False,
                    "mode": "heuristic_fallback",
                    "reason": "graph_env_gap",
                    "text": "",
                },
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = bb_preflight.duplicate_graph_check(
                        str(target),
                        "xylophonic nebula preimage drift hypernonce quux",
                        json_output=True,
                    )
                payload = json.loads(buf.getvalue())

            self.assertEqual(rc, 0)
            self.assertEqual(payload["match_mode"], "heuristic_fallback")
            self.assertEqual(payload["duplicates_found"], 0)


if __name__ == "__main__":
    unittest.main()
