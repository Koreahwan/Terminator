#!/usr/bin/env python3
"""Route candidates into mode-specific artifact sets."""

from __future__ import annotations

import json
from pathlib import Path

from .models import FindingCandidate, SurfaceItem
from .reporter import (
    attack_surface_payload,
    render_bug_bounty_report,
    render_external_risk_summary,
    render_high_value_targets,
    render_manual_test_queue,
    render_raw_endpoint_review,
    render_recommended_scope,
    render_safe_pocs,
    render_security_pitch,
)


def write_outputs(out_dir: Path, items: list[SurfaceItem], candidates: list[FindingCandidate], *, mode: str, domain: str) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    def write(name: str, content: str) -> None:
        path = out_dir / name
        path.write_text(content, encoding="utf-8")
        paths[name] = str(path)

    (out_dir / "attack_surface.json").write_text(json.dumps(attack_surface_payload(items, candidates, mode=mode, domain=domain), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    paths["attack_surface.json"] = str(out_dir / "attack_surface.json")
    (out_dir / "vuln_hints.json").write_text(json.dumps([c.to_dict() for c in candidates], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    paths["vuln_hints.json"] = str(out_dir / "vuln_hints.json")

    write("endpoint_map.md", render_endpoint_map(items, candidates))
    write("high_value_targets.md", render_high_value_targets(candidates))
    write("raw_endpoint_review.md", render_raw_endpoint_review(candidates))
    write("manual_test_queue.md", render_manual_test_queue(candidates))
    write("safe_pocs.md", render_safe_pocs(candidates))

    if mode == "client-pitch":
        write("external_risk_summary.md", render_external_risk_summary(candidates))
        write("security_assessment_pitch.md", render_security_pitch(candidates))
        write("recommended_test_scope.md", render_recommended_scope(candidates))
    elif mode == "ai-security" or domain == "ai":
        write("ai_security_report_draft.md", render_bug_bounty_report(candidates, title="AI Security Report Draft", ai=True))
        write("external_risk_summary.md", render_external_risk_summary(candidates))
    else:
        write("bug_bounty_report_draft.md", render_bug_bounty_report(candidates))

    return paths


def render_endpoint_map(items: list[SurfaceItem], candidates: list[FindingCandidate]) -> str:
    by_key = {(c.method, c.endpoint()): c for c in candidates}
    lines = [
        "# Endpoint Map",
        "",
        "| Endpoint | Method | Auth | Status | Risk | Categories | Possible Vulns | Source | Notes |",
        "|---|---|---|---|---:|---|---|---|---|",
    ]
    for item in items:
        key = (item.method.upper(), item.url or item.path or "/")
        c = by_key.get(key)
        lines.append(
            "| {endpoint} | {method} | {auth} | {status} | {risk} | {cats} | {vulns} | {source} | {notes} |".format(
                endpoint=item.url or item.path or "/",
                method=item.method.upper(),
                auth=item.auth_hint,
                status=c.status if c else "signal",
                risk=c.risk_score if c else 1,
                cats=", ".join(c.risk_categories) if c else "",
                vulns=", ".join(c.possible_vulns) if c else "",
                source=item.source,
                notes=(item.notes or "")[:160].replace("|", "/"),
            )
        )
    return "\n".join(lines) + "\n"
