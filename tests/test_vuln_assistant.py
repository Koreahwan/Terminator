from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.vuln_assistant.hint_engine import build_candidates
from tools.vuln_assistant.models import SurfaceItem
from tools.vuln_assistant.normalizer import load_inputs


def test_taxonomy_scores_access_control_and_business_logic() -> None:
    items = [
        SurfaceItem(method="GET", path="/api/users/{id}/invoices", params=["id"], source="endpoint_map"),
        SurfaceItem(method="POST", path="/api/billing/refund", body_fields=["amount", "invoice_id"], source="openapi"),
    ]
    candidates = build_candidates(items, mode="bounty", domain="web")

    invoice = next(c for c in candidates if "invoices" in c.endpoint())
    refund = next(c for c in candidates if "refund" in c.endpoint())

    assert "access_control" in invoice.risk_categories
    assert "data_exposure_privacy" in invoice.risk_categories or "business_logic" in invoice.risk_categories
    assert invoice.risk_score >= 7
    assert invoice.confidence_score < 70
    assert invoice.status == "candidate"

    assert "business_logic" in refund.risk_categories
    assert refund.risk_score == 10
    assert "MANUAL_REVIEW_REQUIRED" in refund.safe_poc


def test_raw_endpoint_review_keeps_low_score_state_changing_endpoint() -> None:
    item = SurfaceItem(method="POST", path="/api/process", params=["x"], source="endpoint_map")
    candidate = build_candidates([item], mode="bounty", domain="web")[0]

    assert candidate.review_bucket in {"high_value", "raw_review"}
    assert candidate.raw_review_reasons
    assert "state-changing method" in candidate.raw_review_reasons


def test_cli_writes_client_pitch_without_confirmed_claims(tmp_path: Path) -> None:
    endpoint_map = tmp_path / "endpoint_map.md"
    endpoint_map.write_text(
        "\n".join(
            [
                "| Endpoint | Method | Auth | Status | Risk | Notes |",
                "|---|---|---|---|---|---|",
                "| /api/users/{id}/invoices | GET | required | UNTESTED | HIGH | billing object |",
                "| /api/v0/export | GET | unknown | 403 | MEDIUM | legacy export |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.vuln_assistant",
            "analyze",
            "--mode",
            "client-pitch",
            "--domain",
            "web",
            "--endpoint-map",
            str(endpoint_map),
            "--out",
            str(out_dir),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout

    attack_surface = json.loads((out_dir / "attack_surface.json").read_text(encoding="utf-8"))
    assert attack_surface["summary"]["raw_items"] == 2
    assert (out_dir / "raw_endpoint_review.md").exists()
    pitch = (out_dir / "security_assessment_pitch.md").read_text(encoding="utf-8").lower()
    assert "confirmed vulnerability" not in pitch
    assert "risk indication" in pitch


def test_load_inputs_preserves_raw_inventory(tmp_path: Path) -> None:
    urls = tmp_path / "urls.txt"
    urls.write_text(
        "https://app.example.com/api/users/123?view=full\n"
        "https://app.example.com/static/app.js?cache=1&v=2\n",
        encoding="utf-8",
    )
    items = load_inputs([urls])
    assert len(items) == 2
    assert any("view" in item.params for item in items)
    assert any(len(item.params) == 2 for item in items)


def test_endpoint_map_plain_lines_preserve_http_method(tmp_path: Path) -> None:
    endpoint_map = tmp_path / "endpoint_map.md"
    endpoint_map.write_text(
        "POST https://app.example.com/api/billing/refund\n"
        "PATCH /api/users/{id}/profile\n",
        encoding="utf-8",
    )

    items = load_inputs([], endpoint_map=endpoint_map)

    assert any(item.method == "POST" and item.path == "/api/billing/refund" for item in items)
    assert any(item.method == "PATCH" and item.path == "/api/users/{id}/profile" for item in items)
