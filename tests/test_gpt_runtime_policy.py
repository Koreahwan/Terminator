from __future__ import annotations

import json
from pathlib import Path
import re
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.backend_runner import build_command, detect_failure_kind, launcher_backend, runtime_profile_for_backend
from tools.backend_runner import inject_policy_summary
from tools.backend_smoke import parse_agent_messages
from tools.implementation_intent_audit import Context, run_audit
from tools.runtime_policy import apply_profile, load_policy
from tools.runtime_intent import resolve
from tools.hybrid_completion_gate import validate as validate_hybrid_completion
from tools.runtime_hallucination_audit import Audit, validate_backend_smoke, validate_dag_matrix, validate_markdown_claims
from tools.scope_first_hybrid_audit import validate_code, validate_policy_gate_coverage
from tools.submission_candidate_replay import extract_first_json, validate_candidate_payload
from tools.submission_candidate_replay import collect_existing_results
from tools.submission_fixture_index import build_manifest, default_source_root, has_baseline_packages
from tools.submission_quality_compare import compare_scores_by_profile, score_report
from tools.terminator_dry_run_matrix import command_for, ensure_fixtures


SCOPE_FIRST_GPT_ROLES = {"target-discovery", "scout", "recon-scanner", "source-auditor", "analyst"}
SCOPE_FIRST_CLAUDE_ROLES = {"scope-auditor", "reporter", "submission-review"}
SCOPE_FIRST_DEBATE_ROLES = {"exploiter", "critic", "triager-sim"}
CLAUDE_OPUS_1M = "claude-opus-4-6[1m]"


def test_profile_defaults_for_requested_backend(monkeypatch) -> None:
    monkeypatch.delenv("TERMINATOR_RUNTIME_PROFILE", raising=False)
    assert runtime_profile_for_backend("claude") == "claude-only"
    assert runtime_profile_for_backend("codex") == "gpt-only"
    assert runtime_profile_for_backend("hybrid") == "scope-first-hybrid"
    assert launcher_backend("hybrid") == "claude"


def test_natural_intent_defaults_to_scope_first_target_discovery() -> None:
    payload = resolve("타겟 찾고 돌리자", timestamp="20260426_010000")

    assert payload["intent"] == "target_discovery_then_bounty"
    assert payload["runtime"]["backend"] == "hybrid"
    assert payload["runtime"]["failover_to"] == "none"
    assert payload["runtime"]["runtime_profile"] == "scope-first-hybrid"
    assert payload["commands"][0][:2] == ["python3", "tools/target_discovery.py"]
    assert payload["commands"][1][:2] == ["python3", "tools/bounty_live_ab.py"]


def test_natural_intent_codex_only_bounty_url() -> None:
    payload = resolve("codex로만 https://hackerone.com/example 돌려", dry_run=True)

    assert payload["intent"] == "bounty"
    assert payload["runtime"] == {
        "backend": "codex",
        "failover_to": "none",
        "runtime_profile": "gpt-only",
        "reason": "codex-only requested",
    }
    command = payload["commands"][0]
    assert command[:7] == [
        "./terminator.sh",
        "--backend",
        "codex",
        "--failover-to",
        "none",
        "--runtime-profile",
        "gpt-only",
    ]
    assert "--dry-run" in command


def test_natural_intent_claude_only_bounty_url() -> None:
    payload = resolve("claude only run https://hackerone.com/example")

    assert payload["runtime"]["backend"] == "claude"
    assert payload["runtime"]["failover_to"] == "none"
    assert payload["runtime"]["runtime_profile"] == "claude-only"


def test_hybrid_completion_gate_requires_role_split_ledger(tmp_path) -> None:
    (tmp_path / "endpoint_map.md").write_text("# endpoints\n", encoding="utf-8")

    missing = validate_hybrid_completion(tmp_path, mode="bounty")

    assert missing["status"] == "fail"
    assert "missing runtime_dispatch_log.jsonl completed role entries" in missing["failures"]

    (tmp_path / "runtime_dispatch_log.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"role": "scout", "backend": "codex", "status": "completed"}),
                json.dumps({"role": "scope-auditor", "backend": "claude", "status": "completed"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    passed = validate_hybrid_completion(tmp_path, mode="bounty")

    assert passed["status"] == "pass"
    assert passed["codex_roles"] == ["scout"]
    assert passed["claude_roles"] == ["scope-auditor"]


def test_terminator_dry_run_matrix_commands_are_safe(tmp_path) -> None:
    fixtures = ensure_fixtures(tmp_path)

    bounty = command_for("bounty", "scope-first-hybrid", fixtures)
    ai_security = command_for("ai-security", "gpt-only", fixtures)
    client_pitch = command_for("client-pitch", "claude-only", fixtures)

    assert "--dry-run" in bounty
    assert "--json" in bounty
    assert bounty[bounty.index("--backend") + 1] == "hybrid"
    assert bounty[bounty.index("--runtime-profile") + 1] == "scope-first-hybrid"
    assert "--failover-to" in ai_security
    assert ai_security[ai_security.index("--failover-to") + 1] == "none"
    assert "ai-security" in ai_security
    assert "--json" in client_pitch
    assert "client-pitch" in client_pitch


def test_gpt_only_routes_every_role_to_codex() -> None:
    policy = apply_profile(load_policy(), "gpt-only")
    roles = policy["roles"]
    assert roles
    assert {entry["backend"] for entry in roles.values()} == {"codex"}


def test_plain_hybrid_profile_removed_and_aliased_to_scope_first() -> None:
    policy = load_policy()
    assert policy["default_profile"] == "scope-first-hybrid"
    assert "hybrid" not in policy["profiles"]
    resolved = apply_profile(policy, "hybrid")
    assert resolved["active_profile"] == "scope-first-hybrid"


def test_scope_first_hybrid_policy_is_adjustable_but_guarded() -> None:
    policy = apply_profile(load_policy(), "scope-first-hybrid")
    roles = policy["roles"]
    for role in SCOPE_FIRST_GPT_ROLES:
        assert roles[role]["backend"] == "codex"
    for role in SCOPE_FIRST_CLAUDE_ROLES:
        assert roles[role]["backend"] == "claude"
    for role in SCOPE_FIRST_DEBATE_ROLES:
        assert roles[role]["debate_mode"] == "gpt-propose-claude-object-gpt-respond"
    assert roles["scope-auditor"]["disagreement_policy"] == "block-on-unknown-or-oos"


def test_scope_first_hybrid_has_retained_domain_overrides() -> None:
    ai = apply_profile(load_policy(), "scope-first-hybrid", "ai_security")["roles"]

    assert ai["ai-recon"]["backend"] == "codex"
    assert ai["analyst"]["backend"] == "codex"
    assert ai["triager-sim"]["backend"] == "codex"
    assert ai["reporter"]["backend"] == "claude"


def test_opus_runtime_roles_are_pinned_to_claude_opus_1m() -> None:
    policy = load_policy()
    for role, entry in policy["roles"].items():
        assert entry.get("model") != "opus", role
    for profile in policy["profiles"].values():
        for role, entry in profile.get("roles", {}).items():
            assert entry.get("model") != "opus", role
        for pipeline, roles in profile.get("pipeline_roles", {}).items():
            for role, entry in roles.items():
                assert entry.get("model") != "opus", f"{pipeline}:{role}"

    runtime_surfaces = [
        PROJECT_ROOT / "tools" / "dag_orchestrator" / "pipelines.py",
        PROJECT_ROOT / "tools" / "dag_orchestrator" / "claude_handler.py",
        PROJECT_ROOT / ".claude" / "agents" / "scope-auditor.md",
    ]
    forbidden_patterns = [
        r"model:\s*opus\b",
        r"_make_node\([^\n]*,\s*[\"']opus[\"']",
        r"[\"'](?:solver|chain|critic|exploiter|triager_sim|architect)[\"']:\s*[\"']opus[\"']",
    ]
    for path in runtime_surfaces:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            assert not re.search(pattern, text), f"{path}: {pattern}"
        if path.name == "scope-auditor.md":
            assert "model: " + CLAUDE_OPUS_1M in text


def test_codex_command_coerces_claude_alias_model() -> None:
    cmd, stdin_text = build_command("codex", work_dir=str(PROJECT_ROOT), model="sonnet", prompt="hi")
    assert stdin_text == "hi"
    assert "omx" in cmd[0]
    assert "-m" in cmd
    assert cmd[cmd.index("-m") + 1].startswith("gpt-")
    assert "sonnet" not in cmd


def test_hybrid_command_uses_launcher_backend(monkeypatch) -> None:
    monkeypatch.delenv("TERMINATOR_HYBRID_LAUNCHER_BACKEND", raising=False)

    cmd, stdin_text = build_command("hybrid", work_dir=str(PROJECT_ROOT), model="sonnet", prompt="hi")

    assert stdin_text is None
    assert cmd[0] == "claude"
    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == "sonnet"


def test_successful_codex_warning_stream_is_completed() -> None:
    output = "\n".join(
        [
            "2026-04-24T10:26:48.950251Z WARN codex_state::runtime: state db unavailable",
            '{"type":"item.completed","item":{"type":"agent_message","text":"OK"}}',
            '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":1}}',
        ]
    )

    assert detect_failure_kind(output, returncode=0, timed_out=False) == "completed"


def test_nonzero_backend_error_is_classified_for_failover() -> None:
    assert detect_failure_kind("HTTP 503 Service Unavailable", returncode=1, timed_out=False) == "service_unavailable"


def test_policy_injection_can_be_disabled_for_replay_smoke(monkeypatch) -> None:
    monkeypatch.setenv("TERMINATOR_SKIP_POLICY_INJECTION", "1")

    assert inject_policy_summary("prompt", requested_backend="codex", launcher="codex", profile="gpt-only") == "prompt"


def test_backend_idle_timeout_env_is_documented() -> None:
    runner = (PROJECT_ROOT / "tools" / "backend_runner.py").read_text(encoding="utf-8")

    assert "TERMINATOR_BACKEND_IDLE_TIMEOUT" in runner


def test_backend_smoke_parses_codex_agent_messages() -> None:
    output = "\n".join(
        [
            "2026-04-24T10:26:48Z WARN local warning",
            '{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"OK"}}',
            '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":1}}',
        ]
    )

    assert parse_agent_messages(output) == ["OK"]


def test_submission_candidate_replay_extracts_json_from_message() -> None:
    message = 'short preface\\n```json\\n{"report_md":"r","poc_filename":"poc_replay.py","poc_body":"print(1)","evidence_summary_md":"e","triager_sim_result":{"decision":"NOT_SUBMIT"}}\\n```'

    payload = extract_first_json(message)

    assert payload["poc_filename"] == "poc_replay.py"
    assert validate_candidate_payload(payload) == []


def test_submission_candidate_replay_extracts_json_from_claude_stdout() -> None:
    output = '=== BACKEND ATTEMPT 1: claude ===\n{"report_md":"r","poc_filename":"poc_replay.py","poc_body":"print(1)","evidence_summary_md":"e","triager_sim_result":{"decision":"SUBMIT"}}\n=== BACKEND COMPLETE: claude ==='

    payload = extract_first_json(output)

    assert payload["triager_sim_result"]["decision"] == "SUBMIT"


def test_submission_candidate_replay_rejects_unsafe_filename() -> None:
    errors = validate_candidate_payload(
        {
            "report_md": "r",
            "poc_filename": "../poc.py",
            "poc_body": "print(1)",
            "evidence_summary_md": "e",
            "triager_sim_result": {},
        }
    )

    assert errors


def test_submission_candidate_replay_manifest_merges_existing_results(tmp_path) -> None:
    old_dir = tmp_path / "gpt-only" / "old"
    old_dir.mkdir(parents=True)
    (old_dir / "candidate_result.json").write_text(
        '{"profile":"gpt-only","name":"old","status":"pass"}\n',
        encoding="utf-8",
    )

    results = collect_existing_results(
        tmp_path,
        [{"profile": "gpt-only", "name": "new", "status": "pass"}],
    )

    assert [(item["profile"], item["name"]) for item in results] == [
        ("gpt-only", "new"),
        ("gpt-only", "old"),
    ]


def test_submission_candidate_replay_keeps_hybrid_claude_model_separate() -> None:
    source = (PROJECT_ROOT / "tools" / "submission_candidate_replay.py").read_text(encoding="utf-8")

    assert "--claude-model" in source
    assert 'profile in {"claude-only", "scope-first-hybrid"}' in source
    assert "It must be self-contained" in source
    assert "Avoid negative assertions" in source
    assert "CRITICAL OUTPUT CONTRACT" in source
    assert "Executive Conclusion" in source
    assert "Honest Severity Expectation" in source


def test_quality_compare_uses_report_scorer_json_even_when_below_threshold(tmp_path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Thin report\n\nNo useful evidence yet.\n", encoding="utf-8")

    result = score_report(report, poc_dir=tmp_path)

    assert result["external_score"] is not None
    assert result["score"] == int(result["external_score"])


def test_quality_compare_splits_candidate_profiles() -> None:
    baseline = [
        {"name": "case-a", "report": {"score": 80}},
        {"name": "case-b", "report": {"score": 90}},
    ]
    candidate = [
        {"name": "case-a", "package": "reports/runtime-eval/run/candidate_replay/gpt-only/case-a/submission", "report": {"score": 81}},
        {"name": "case-b", "package": "reports/runtime-eval/run/candidate_replay/gpt-only/case-b/submission", "report": {"score": 80}},
        {"name": "case-a", "package": "reports/runtime-eval/run/candidate_replay/scope-first-hybrid/case-a/submission", "report": {"score": 82}},
        {"name": "case-b", "package": "reports/runtime-eval/run/candidate_replay/scope-first-hybrid/case-b/submission", "report": {"score": 91}},
    ]

    result = compare_scores_by_profile(baseline, candidate)

    assert result["gpt-only"]["comparable"] == 2
    assert result["gpt-only"]["matched_or_better"] == 1
    assert result["scope-first-hybrid"]["matched_or_better"] == 2


def test_hallucination_audit_validates_backend_smoke(tmp_path) -> None:
    smoke = tmp_path / "backend_smoke.json"
    smoke.write_text(
        """
{
  "status": "pass",
  "backend": "codex",
  "runtime_profile": "gpt-only",
  "expected_text_observed": true,
  "failover_count": 0,
  "backend_runner_result": {"status": "completed"},
  "attempts": [{"failure_kind": "completed", "returncode": 0}]
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    audit = Audit()

    validate_backend_smoke(audit, smoke)

    assert {item["status"] for item in audit.checks} == {"pass"}


def test_hallucination_audit_accepts_target_discovery_matrix(tmp_path) -> None:
    matrix = tmp_path / "matrix.json"
    results = [
        {"profile": profile, "pipeline": pipeline, "status": "pass", "failure_count": 0}
        for profile in ["claude-only", "gpt-only", "scope-first-hybrid"]
        for pipeline in ["target_discovery", "bounty", "ai_security", "client-pitch"]
    ]
    matrix.write_text(json.dumps({"status": "pass", "results": results}), encoding="utf-8")
    audit = Audit()

    validate_dag_matrix(audit, matrix)

    assert {item["status"] for item in audit.checks} == {"pass"}


def test_hallucination_audit_skips_raw_program_markdown(tmp_path) -> None:
    raw_dir = tmp_path / "target" / "program_raw"
    raw_dir.mkdir(parents=True)
    (raw_dir / "bundle.md").write_text("comprehensive leveraging furthermore no evidence markers\n", encoding="utf-8")
    (tmp_path / "program_page_raw.md").write_text("comprehensive leveraging furthermore no evidence markers\n", encoding="utf-8")
    audit = Audit()

    validate_markdown_claims(audit, tmp_path)

    assert {item["status"] for item in audit.checks} == {"pass"}
    assert all("raw-source-skip" in item["name"] for item in audit.checks)


def test_scope_first_audit_checks_runtime_hard_gate_wiring() -> None:
    audit = Audit()

    validate_code(audit)
    validate_policy_gate_coverage(audit)

    failed = [item for item in audit.checks if item["status"] == "fail"]
    assert not failed
    names = {item["name"] for item in audit.checks}
    assert "gate:runtime-gate-call" in names
    assert "gate:runtime-fail-closed" in names
    assert "policy-gates:evidence-known" in names


def test_implementation_intent_audit_flags_missing_candidate_packages(tmp_path, monkeypatch) -> None:
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    (eval_dir / "submission_fixtures.json").write_text(
        """
{
  "packages": {
    "positive": [
      {"name": "proconnect-identite"}, {"name": "qwant"}, {"name": "llama_index"},
      {"name": "onnx"}, {"name": "kubeflow"}, {"name": "hrsgroup"}
    ],
    "negative": [
      {"name": "portofantwerp"}, {"name": "magiclabs-mbb-og"},
      {"name": "paradex"}, {"name": "zendesk"}
    ],
    "gold": [{"name": "rhinofi_prove"}]
  }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (eval_dir / "quality_delta.json").write_text(
        """
{
  "baseline": [
    {"name": "proconnect-identite"}, {"name": "qwant"}, {"name": "llama_index"},
    {"name": "onnx"}, {"name": "kubeflow"}, {"name": "hrsgroup"},
    {"name": "portofantwerp"}, {"name": "magiclabs-mbb-og"},
    {"name": "paradex"}, {"name": "zendesk"}, {"name": "rhinofi_prove"}
  ],
  "candidate": []
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (eval_dir / "quality_delta.md").write_text(
        "baseline-only fixture calibration\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        "tools.implementation_intent_audit.REQUIREMENTS",
        [
            req
            for req in __import__(
                "tools.implementation_intent_audit", fromlist=["REQUIREMENTS"]
            ).REQUIREMENTS
            if req.id == "submission-comparison"
        ],
    )

    payload = run_audit(Context(eval_dir))

    assert payload["status"] == "incomplete"
    requirement = payload["requirements"][0]
    assert requirement["status"] == "fail"
    assert any(
        check["status"] == "fail"
        and "candidate quality scores" in check["detail"]
        for check in requirement["checks"]
    )


def test_all_policy_codex_roles_have_compact_contracts() -> None:
    policy = apply_profile(load_policy(), "gpt-only")
    for role in policy["roles"]:
        contract = PROJECT_ROOT / "generated" / "role_contracts" / f"{role}.txt"
        assert contract.exists(), f"missing compact contract for {role}"
        assert contract.stat().st_size <= 8000


def test_submission_source_root_env_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("TERMINATOR_SUBMISSION_SOURCE_ROOT", str(tmp_path))

    assert default_source_root() == tmp_path


def test_submission_fixture_manifest_indexes_baseline_packages(tmp_path) -> None:
    root = tmp_path / "repo"
    submission = root / "targets" / "proconnect-identite" / "submission"
    submission.mkdir(parents=True)
    (submission / "report.md").write_text("# Report\n\nImpact and PoC evidence.\n", encoding="utf-8")
    (submission / "poc.py").write_text("print('poc output')\n", encoding="utf-8")
    (submission / "evidence_summary.md").write_text("poc_output: ok\n", encoding="utf-8")

    assert has_baseline_packages(root)
    manifest = build_manifest(root)
    positives = manifest["packages"]["positive"]

    assert [item["name"] for item in positives] == ["proconnect-identite"]
    assert positives[0]["files"]["reports"] == ["targets/proconnect-identite/submission/report.md"]
    assert positives[0]["files"]["pocs"] == ["targets/proconnect-identite/submission/poc.py"]
