from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.vuln_assistant.idor_analyzer import build_idor_candidates, detect_object_refs
from tools.vuln_assistant.models import SurfaceItem
from tools.vuln_assistant.normalizer import load_inputs


def test_detects_query_object_reference() -> None:
    item = SurfaceItem(method="GET", url="https://api.example.com/invoices?invoice_id=inv_123", path="/invoices", source="har", status_code=200)
    candidates = build_idor_candidates([item])

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.object_refs[0].name == "invoice_id"
    assert candidate.object_refs[0].location == "query"
    assert candidate.risk_score >= 8
    assert candidate.confidence_score >= 70
    assert candidate.eligible_for_read_only_verification is True
    assert candidate.status == "needs_verification"


def test_detects_path_and_unnamed_path_object_references() -> None:
    named = SurfaceItem(method="GET", path="/api/users/{id}/invoices", params=["id"], source="openapi")
    unnamed = SurfaceItem(method="GET", url="https://api.example.com/users/123/profile", path="/users/123/profile", source="har")

    named_refs = detect_object_refs(named)
    unnamed_refs = detect_object_refs(unnamed)

    assert any(ref.location == "path" and ref.safely_replaceable for ref in named_refs)
    assert any(ref.location == "path_segment" and not ref.safely_replaceable for ref in unnamed_refs)


def test_detects_body_field_and_marks_unsafe_methods_manual_only() -> None:
    item = SurfaceItem(method="POST", path="/api/billing/refund", body_fields=["invoice_id", "amount"], source="openapi")
    candidate = build_idor_candidates([item])[0]

    assert any(ref.name == "invoice_id" and ref.location == "body" for ref in candidate.object_refs)
    assert candidate.eligible_for_read_only_verification is False
    assert candidate.manual_review_only is True


def test_body_and_graphql_refs_are_not_marked_read_only_verifiable() -> None:
    body_item = SurfaceItem(method="GET", path="/api/export", body_fields=["invoice_id"], source="openapi")
    graphql_item = SurfaceItem(
        method="GET",
        path="/graphql",
        source="graphql",
        raw={"graphql_variables": {"invoice_id": "gid://app/Invoice/123"}},
    )

    candidates = build_idor_candidates([body_item, graphql_item])
    body_candidate = next(c for c in candidates if c.endpoint() == "/api/export")
    graphql_candidate = next(c for c in candidates if c.endpoint() == "/graphql")

    assert body_candidate.eligible_for_read_only_verification is False
    assert body_candidate.manual_review_only is True
    assert graphql_candidate.eligible_for_read_only_verification is False
    assert graphql_candidate.manual_review_only is True


def test_detects_graphql_object_references() -> None:
    item = SurfaceItem(
        method="POST",
        path="/graphql",
        source="graphql",
        raw={"graphql_variables": {"user_id": "gid://app/User/123"}},
    )
    candidate = build_idor_candidates([item])[0]

    assert any(ref.location == "graphql" for ref in candidate.object_refs)


def test_sorts_by_risk_then_confidence() -> None:
    low = SurfaceItem(method="GET", url="https://api.example.com/users?id=1", path="/users", source="txt")
    high = SurfaceItem(method="GET", url="https://api.example.com/billing/invoices?invoice_id=inv_1", path="/billing/invoices", source="har", status_code=200)
    candidates = build_idor_candidates([low, high])

    assert "invoice" in candidates[0].endpoint()


def test_attack_surface_input_uses_raw_inventory_only(tmp_path: Path) -> None:
    attack_surface = tmp_path / "attack_surface.json"
    attack_surface.write_text(
        json.dumps(
            {
                "summary": {"raw_items": 1},
                "raw_inventory": [
                    {
                        "method": "GET",
                        "url": "https://api.example.com/invoices?invoice_id=inv_1",
                        "path": "/invoices",
                        "params": ["invoice_id"],
                        "source": "har",
                    }
                ],
                "candidates": [{"url": "https://noise.example.com/users?id=2"}],
            }
        ),
        encoding="utf-8",
    )

    items = load_inputs([attack_surface])

    assert len(items) == 1
    assert items[0].url.startswith("https://api.example.com")


def test_idor_passive_cli_writes_outputs(tmp_path: Path) -> None:
    urls = tmp_path / "urls.txt"
    urls.write_text("GET https://api.example.com/invoices?invoice_id=inv_123\n", encoding="utf-8")
    out_dir = tmp_path / "idor"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.vuln_assistant",
            "idor-passive",
            "--input",
            str(urls),
            "--out",
            str(out_dir),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (out_dir / "idor_candidates.json").exists()
    assert (out_dir / "idor_manual_queue.md").exists()
