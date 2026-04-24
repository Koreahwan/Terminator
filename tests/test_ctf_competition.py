from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.ctf_competition import (
    build_competition_prompt,
    build_benchmark_catalog,
    build_competition_dry_run_payload,
    classify_competition_challenge,
    detect_benchmark_layout,
    discover_benchmark_tasks,
    extract_ctf_flags,
)
from tools.runtime_contract import build_summary

_BENCHMARK_SPEC = importlib.util.spec_from_file_location(
    "terminator_benchmark_module",
    REPO_ROOT / "tests" / "benchmarks" / "benchmark.py",
)
_BENCHMARK_MODULE = importlib.util.module_from_spec(_BENCHMARK_SPEC)
assert _BENCHMARK_SPEC.loader is not None
_BENCHMARK_SPEC.loader.exec_module(_BENCHMARK_MODULE)
BenchmarkRunner = _BENCHMARK_MODULE.BenchmarkRunner


SCRIPT_PATH = REPO_ROOT / "terminator.sh"
CTF_FIXTURE = REPO_ROOT / "tests" / "benchmarks" / "ctftiny" / "baby_boi"


def test_classify_trivial_source(tmp_path: Path) -> None:
    (tmp_path / "solve.py").write_text("print('FLAG{demo}')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("simple source-only challenge\n", encoding="utf-8")

    plan = classify_competition_challenge(tmp_path)

    assert plan.lane == "trivial-source"
    assert plan.adapter == "source"
    assert plan.skip_reporter_on_critical_path is True
    assert "python" in plan.source_languages


def test_classify_hard_pwn_fixture() -> None:
    plan = classify_competition_challenge(CTF_FIXTURE)

    assert plan.lane == "hard-pwn"
    assert plan.adapter == "socket-binary"
    assert plan.pass_budget == 3
    assert "Docker" in " ".join(plan.rationale) or "remote-environment" in " ".join(plan.rationale)


def test_historypeats_no_longer_false_positives_to_judge() -> None:
    sample = Path("/tmp/ctf-bench/NYU_CTF_Bench/development/2013/CSAW-Finals/web/historypeats")
    if not sample.exists():
        return
    plan = classify_competition_challenge(sample)

    assert plan.lane != "judge"


def test_challenge_json_category_guides_routing() -> None:
    samples = {
        "/tmp/ctf-bench/NYU_CTF_Bench/development/2016/CSAW-Quals/rev/Rock": "rev",
        "/tmp/ctf-bench/NYU_CTF_Bench/development/2016/CSAW-Quals/forensics/Watchword": "forensics",
        "/tmp/ctf-bench/NYU_CTF_Bench/development/2016/CSAW-Quals/pwn/WarmUp": "hard-pwn",
        "/tmp/ctf-bench/NYU_CTF_Bench/development/2013/CSAW-Finals/web/historypeats": "browser-pwn",
    }
    for sample, expected_lane in samples.items():
        path = Path(sample)
        if not path.exists():
            continue
        plan = classify_competition_challenge(path)
        assert plan.lane == expected_lane, (sample, plan.lane)


def test_competition_prompt_skips_reporter_on_critical_path() -> None:
    plan = classify_competition_challenge(CTF_FIXTURE)
    prompt = build_competition_prompt(CTF_FIXTURE, REPO_ROOT / "reports" / "dummy", plan)

    assert "Do not invoke @reporter before verified flag." in prompt
    assert "Reporter, writeup, and knowledge/index updates are NOT on the critical path." in prompt
    assert "Detected lane: hard-pwn" in prompt


def test_competition_dry_run_payload_ignores_malformed_plan(tmp_path: Path) -> None:
    plan_path = tmp_path / "competition_plan.json"
    plan_path.write_text("{bad json", encoding="utf-8")

    payload = build_competition_dry_run_payload(
        challenge_dir=tmp_path,
        backend="claude",
        failover_to="codex",
        model="sonnet",
        report_dir=tmp_path / "report",
        timeout=0,
        session_id="sess-1",
        plan_path=plan_path,
    )

    assert payload["competition_mode"] is True
    assert payload["competition_warning"] == "invalid competition_plan.json ignored"
    assert payload["steps"] == []


def test_extract_ctf_flags_supports_challenge_json_plain_flag(tmp_path: Path) -> None:
    (tmp_path / "challenge.json").write_text(
        json.dumps({"flag": "And yes the nsa can read this to"}),
        encoding="utf-8",
    )
    log_text = "**FLAG: `And yes the nsa can read this to`**"

    flags = extract_ctf_flags(log_text, challenge_dir=tmp_path)

    assert flags == ["And yes the nsa can read this to"]


def test_extract_ctf_flags_supports_title_case_flag_prefix() -> None:
    flags = extract_ctf_flags("Flag{IoDJuvwxy\\tuvyxwxvwzx{\\z{vwxyz}")
    assert flags == ["Flag{IoDJuvwxy\\tuvyxwxvwzx{\\z{vwxyz}"]


def test_detect_and_discover_benchmark_layouts(tmp_path: Path) -> None:
    nyu_root = tmp_path / "NYU_CTF_Bench"
    (nyu_root / "development" / "chal-a").mkdir(parents=True)
    (nyu_root / "development" / "chal-a" / "README.md").write_text("dev\n", encoding="utf-8")
    (nyu_root / "test" / "chal-b").mkdir(parents=True)
    (nyu_root / "test" / "chal-b" / "README.md").write_text("test\n", encoding="utf-8")

    assert detect_benchmark_layout(nyu_root) == "nyu_ctf_bench"
    tasks = discover_benchmark_tasks(nyu_root)
    assert {task.split for task in tasks} == {"development", "test"}
    assert {task.name for task in tasks} == {"chal-a", "chal-b"}


def test_generic_discovery_prefers_challenge_roots_and_skips_hidden_noise(tmp_path: Path) -> None:
    root = tmp_path / "generic-root"
    challenge = root / "historypeats"
    nested = challenge / "csaw" / "fuel"
    hidden = challenge / ".idea"
    pycache = challenge / "__pycache__"
    nested.mkdir(parents=True)
    hidden.mkdir(parents=True)
    pycache.mkdir(parents=True)
    (challenge / "challenge.json").write_text(json.dumps({"flag": "x"}), encoding="utf-8")
    (challenge / "README.md").write_text("challenge\n", encoding="utf-8")
    (nested / "README.md").write_text("nested vendor tree\n", encoding="utf-8")
    (hidden / "misc.xml").write_text("noise\n", encoding="utf-8")
    (pycache / "cached.pyc").write_bytes(b"noise")

    tasks = discover_benchmark_tasks(root, layout="generic")

    assert [task.name for task in tasks] == ["historypeats"]


def test_generic_discovery_skips_cache_directories_without_markers(tmp_path: Path) -> None:
    root = tmp_path / "generic-root"
    challenge = root / "babycrypto"
    pycache = challenge / "__pycache__"
    pycache.mkdir(parents=True)
    (challenge / "README.md").write_text("challenge\n", encoding="utf-8")
    (pycache / "solver.cpython-312.pyc").write_bytes(b"noise")

    tasks = discover_benchmark_tasks(root, layout="generic")

    assert [task.name for task in tasks] == ["babycrypto"]


def test_runtime_summary_includes_competition_sidecar(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    (report_dir / "session.log").write_text("", encoding="utf-8")
    (report_dir / "competition_plan.json").write_text(
        json.dumps({"mode": "competition-v2", "lane": "crypto", "adapter": "artifact"}),
        encoding="utf-8",
    )

    summary = build_summary(
        report_dir,
        mode="ctf",
        target="/tmp/chal",
        start_ts=0,
        exit_code=0,
        status="completed",
    )

    assert summary["competition"]["mode"] == "competition-v2"
    assert summary["competition"]["lane"] == "crypto"


def test_runtime_summary_ignores_malformed_competition_sidecar(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    (report_dir / "session.log").write_text("", encoding="utf-8")
    (report_dir / "competition_plan.json").write_text("{bad json", encoding="utf-8")

    summary = build_summary(
        report_dir,
        mode="ctf",
        target="/tmp/chal",
        start_ts=0,
        exit_code=0,
        status="completed",
    )

    assert "competition" not in summary
    assert summary["competition_warning"] == "invalid competition_plan.json ignored"


def test_bash_summary_ignores_malformed_competition_sidecar(tmp_path: Path) -> None:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    (report_dir / "session.log").write_text("", encoding="utf-8")
    (report_dir / "competition_plan.json").write_text("{bad json", encoding="utf-8")

    subprocess.run(
        ["bash", "./terminator.sh", "_summary", str(report_dir), "ctf", "/tmp/chal", "1", "0", "completed"],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "TERM": "dumb"},
    )
    payload = json.loads((report_dir / "summary.json").read_text(encoding="utf-8"))

    assert "competition" not in payload
    assert payload["competition_warning"] == "invalid competition_plan.json ignored"


def test_benchmark_runner_catalog_summary(tmp_path: Path) -> None:
    nyu_root = tmp_path / "NYU_CTF_Bench"
    (nyu_root / "development" / "chal-a").mkdir(parents=True)
    (nyu_root / "development" / "chal-a" / "README.md").write_text("dev\n", encoding="utf-8")
    (nyu_root / "test" / "chal-b").mkdir(parents=True)
    (nyu_root / "test" / "chal-b" / "README.md").write_text("test\n", encoding="utf-8")

    runner = BenchmarkRunner()
    summary = runner.catalog_external_benchmark(str(nyu_root))

    assert summary["layout"] == "nyu_ctf_bench"
    assert summary["total_tasks"] == 2
    assert summary["selected_tasks"] == 2
    assert summary["by_split"] == {"development": 1, "test": 1}
    assert {task["name"] for task in summary["sample_tasks"]} == {"chal-a", "chal-b"}


def test_benchmark_catalog_filter_limit_and_export(tmp_path: Path) -> None:
    nyu_root = tmp_path / "NYU_CTF_Bench"
    (nyu_root / "development" / "chal-a").mkdir(parents=True)
    (nyu_root / "development" / "chal-a" / "README.md").write_text("dev\n", encoding="utf-8")
    (nyu_root / "development" / "chal-c").mkdir(parents=True)
    (nyu_root / "development" / "chal-c" / "README.md").write_text("dev2\n", encoding="utf-8")
    (nyu_root / "test" / "chal-b").mkdir(parents=True)
    (nyu_root / "test" / "chal-b" / "README.md").write_text("test\n", encoding="utf-8")

    catalog = build_benchmark_catalog(
        nyu_root,
        splits=["development"],
        limit=1,
        include_tasks=True,
    )

    assert catalog["layout"] == "nyu_ctf_bench"
    assert catalog["total_tasks"] == 3
    assert catalog["selected_tasks"] == 1
    assert catalog["by_split"] == {"development": 1}
    assert len(catalog["tasks"]) == 1
    assert catalog["tasks"][0]["split"] == "development"


def test_benchmark_catalog_missing_root_warns(tmp_path: Path) -> None:
    missing = tmp_path / "missing-root"
    catalog = build_benchmark_catalog(missing)

    assert catalog["total_tasks"] == 0
    assert catalog["selected_tasks"] == 0
    assert "catalog root does not exist" in catalog["warnings"]
    assert "no benchmark tasks discovered" in catalog["warnings"]


def test_benchmark_catalog_invalid_layout_rejected(tmp_path: Path) -> None:
    try:
        build_benchmark_catalog(tmp_path, layout="invalid_layout")
    except ValueError as exc:
        assert "Unsupported benchmark layout" in str(exc)
    else:
        raise AssertionError("expected invalid layout to raise ValueError")


def _run_terminator(*args: str) -> dict:
    result = subprocess.run(
        ["bash", str(SCRIPT_PATH), "--json", "--dry-run", *args],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "TERM": "dumb"},
    )
    return json.loads(result.stdout)


def test_terminator_ctf_legacy_dry_run_unchanged_shape() -> None:
    payload = _run_terminator("ctf", str(CTF_FIXTURE))

    assert payload["mode"] == "ctf"
    assert payload["dry_run"] is True
    assert "competition_mode" not in payload
    assert "spawn_reporter_agent" in payload["steps"]


def test_terminator_ctf_competition_dry_run_exposes_plan() -> None:
    payload = _run_terminator("--competition-v2", "ctf", str(CTF_FIXTURE))

    assert payload["mode"] == "ctf"
    assert payload["competition_mode"] is True
    assert payload["competition_plan"]["lane"] == "hard-pwn"
    assert "chain-best-of-n" in payload["steps"]


def test_terminator_report_dir_avoids_timestamp_collision() -> None:
    env = {**os.environ, "TERM": "dumb", "TERMINATOR_TIMESTAMP": "20990101_000000"}
    cleanup_paths = [
        REPO_ROOT / "reports" / "20990101_000000",
        REPO_ROOT / "reports" / "20990101_000000_1",
    ]
    for path in cleanup_paths:
        shutil.rmtree(path, ignore_errors=True)
    try:
        first = subprocess.run(
            ["bash", str(SCRIPT_PATH), "--json", "--dry-run", "ctf", str(CTF_FIXTURE)],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        second = subprocess.run(
            ["bash", str(SCRIPT_PATH), "--json", "--dry-run", "ctf", str(CTF_FIXTURE)],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)

        assert first_payload["report_dir"].endswith("/reports/20990101_000000")
        assert second_payload["report_dir"].endswith("/reports/20990101_000000_1")
    finally:
        for path in cleanup_paths:
            shutil.rmtree(path, ignore_errors=True)


def test_terminator_report_dir_avoids_parallel_timestamp_collision() -> None:
    env = {**os.environ, "TERM": "dumb", "TERMINATOR_TIMESTAMP": "20990101_000001"}
    cleanup_paths = [
        REPO_ROOT / "reports" / "20990101_000001",
        REPO_ROOT / "reports" / "20990101_000001_1",
        REPO_ROOT / "reports" / "20990101_000001_2",
    ]
    for path in cleanup_paths:
        shutil.rmtree(path, ignore_errors=True)
    try:
        procs = [
            subprocess.Popen(
                ["bash", str(SCRIPT_PATH), "--json", "--dry-run", "ctf", str(CTF_FIXTURE)],
                cwd=str(REPO_ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            for _ in range(2)
        ]
        outputs = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=120)
            if proc.returncode != 0:
                raise AssertionError(f"parallel dry-run failed: {stderr}")
            outputs.append(json.loads(stdout))

        report_dirs = sorted(payload["report_dir"] for payload in outputs)
        assert report_dirs[0].endswith("/reports/20990101_000001")
        assert report_dirs[1].endswith("/reports/20990101_000001_1")
        assert report_dirs[0] != report_dirs[1]
    finally:
        for path in cleanup_paths:
            shutil.rmtree(path, ignore_errors=True)


def test_benchmark_catalog_cli(tmp_path: Path) -> None:
    nyu_root = tmp_path / "NYU_CTF_Bench"
    (nyu_root / "development" / "chal-a").mkdir(parents=True)
    (nyu_root / "development" / "chal-a" / "README.md").write_text("dev\n", encoding="utf-8")
    (nyu_root / "test" / "chal-b").mkdir(parents=True)
    (nyu_root / "test" / "chal-b" / "README.md").write_text("test\n", encoding="utf-8")

    result = subprocess.run(
        ["python3", "tests/benchmarks/benchmark.py", "--catalog-root", str(nyu_root)],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    assert "TERMINATOR EXTERNAL BENCHMARK CATALOG" in result.stdout
    assert "nyu_ctf_bench" in result.stdout
    assert "chal-a" in result.stdout


def test_benchmark_catalog_cli_json_out(tmp_path: Path) -> None:
    nyu_root = tmp_path / "NYU_CTF_Bench"
    (nyu_root / "development" / "chal-a").mkdir(parents=True)
    (nyu_root / "development" / "chal-a" / "README.md").write_text("dev\n", encoding="utf-8")
    (nyu_root / "development" / "chal-c").mkdir(parents=True)
    (nyu_root / "development" / "chal-c" / "README.md").write_text("dev2\n", encoding="utf-8")
    (nyu_root / "test" / "chal-b").mkdir(parents=True)
    (nyu_root / "test" / "chal-b" / "README.md").write_text("test\n", encoding="utf-8")
    json_out = tmp_path / "catalog.json"

    subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--catalog-root",
            str(nyu_root),
            "--catalog-split",
            "development",
            "--catalog-limit",
            "1",
            "--catalog-json-out",
            str(json_out),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["layout"] == "nyu_ctf_bench"
    assert payload["selected_tasks"] == 1
    assert payload["filters"]["splits"] == ["development"]
    assert payload["filters"]["limit"] == 1
    assert len(payload["tasks"]) == 1


def test_competition_tool_catalog_cli_json_out(tmp_path: Path) -> None:
    nyu_root = tmp_path / "NYU_CTF_Bench"
    (nyu_root / "development" / "chal-a").mkdir(parents=True)
    (nyu_root / "development" / "chal-a" / "README.md").write_text("dev\n", encoding="utf-8")
    (nyu_root / "test" / "chal-b").mkdir(parents=True)
    (nyu_root / "test" / "chal-b" / "README.md").write_text("test\n", encoding="utf-8")
    json_out = tmp_path / "tool-catalog.json"

    result = subprocess.run(
        [
            "python3",
            "tools/ctf_competition.py",
            "catalog",
            "--root",
            str(nyu_root),
            "--split",
            "test",
            "--limit",
            "1",
            "--json-out",
            str(json_out),
            "--json",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    stdout_payload = json.loads(result.stdout)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert stdout_payload["selected_tasks"] == 1
    assert stdout_payload["filters"]["splits"] == ["test"]
    assert file_payload == stdout_payload


def test_competition_tool_catalog_cli_invalid_layout_fails(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            "tools/ctf_competition.py",
            "catalog",
            "--root",
            str(tmp_path),
            "--layout",
            "invalid_layout",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
    )

    assert result.returncode != 0
    assert "invalid choice" in result.stderr.lower()


def test_benchmark_ledger_initialization_from_manifest(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    runner = BenchmarkRunner()
    ledger = runner.initialize_external_run_ledger(str(manifest_path), label="nyu-dev-run")

    assert ledger["label"] == "nyu-dev-run"
    assert ledger["selected_tasks"] == 1
    assert ledger["by_split"] == {"development": 1}
    assert ledger["entries"][0]["status"] == "pending"
    assert ledger["entries"][0]["id"] == "nyu_ctf_bench:development:chal-a"


def test_benchmark_runner_command_honors_extra_args(monkeypatch=None) -> None:
    runner = BenchmarkRunner()
    old_runner = os.environ.get("TERMINATOR_BENCHMARK_RUNNER")
    old_args = os.environ.get("TERMINATOR_BENCHMARK_RUNNER_ARGS")
    try:
        os.environ["TERMINATOR_BENCHMARK_RUNNER"] = "bash ./terminator.sh"
        os.environ["TERMINATOR_BENCHMARK_RUNNER_ARGS"] = "--wait --timeout 300"
        command = runner._build_external_runner_command("/tmp/chal")
    finally:
        if old_runner is None:
            os.environ.pop("TERMINATOR_BENCHMARK_RUNNER", None)
        else:
            os.environ["TERMINATOR_BENCHMARK_RUNNER"] = old_runner
        if old_args is None:
            os.environ.pop("TERMINATOR_BENCHMARK_RUNNER_ARGS", None)
        else:
            os.environ["TERMINATOR_BENCHMARK_RUNNER_ARGS"] = old_args

    assert command[:5] == ["bash", "./terminator.sh", "--wait", "--timeout", "300"]
    assert command[-4:] == ["--json", "--competition-v2", "ctf", "/tmp/chal"]


def test_benchmark_ledger_cli_json_out(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    ledger_path = tmp_path / "ledger.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-manifest",
            str(manifest_path),
            "--ledger-out",
            str(ledger_path),
            "--ledger-label",
            "nyu-dev-run",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert "TERMINATOR HELD-OUT RUN LEDGER" in result.stdout
    assert payload["label"] == "nyu-dev-run"
    assert payload["entries"][0]["status"] == "pending"


def test_benchmark_ledger_update_and_summary(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    runner = BenchmarkRunner()
    ledger = runner.initialize_external_run_ledger(str(manifest_path), label="nyu-dev-run")
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    updated = runner.update_external_run_ledger(
        str(ledger_path),
        entry_id="nyu_ctf_bench:development:chal-a",
        status="passed",
        notes="first solved candidate",
        result_path="/tmp/result.json",
        attempt={"first_flag_latency_sec": 12.5, "pass_k": 1},
    )

    assert updated["entries"][0]["status"] == "passed"
    assert updated["entries"][0]["notes"] == "first solved candidate"
    assert updated["entries"][0]["result_path"] == "/tmp/result.json"
    assert updated["entries"][0]["attempts"][0]["pass_k"] == 1

    summary = runner.summarize_external_run_ledger(str(ledger_path))
    assert summary["by_status"] == {"passed": 1}
    assert summary["by_split"]["development"]["passed"] == 1
    assert summary["total_attempts"] == 1
    assert summary["avg_first_flag_latency_sec"] == 12.5
    assert summary["pass_rate_pct"] == 100.0
    assert summary["completion_rate_pct"] == 100.0


def test_benchmark_ledger_cli_update_and_report(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    ledger_path = tmp_path / "ledger.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-manifest",
            str(manifest_path),
            "--ledger-out",
            str(ledger_path),
            "--ledger-label",
            "nyu-dev-run",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    update = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-update",
            str(ledger_path),
            "--ledger-entry-id",
            "nyu_ctf_bench:development:chal-a",
            "--ledger-status",
            "failed",
            "--ledger-notes",
            "timed out",
            "--ledger-attempt-json",
            '{"first_flag_latency_sec": 30.0, "pass_k": 3}',
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    report = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-report",
            str(ledger_path),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert "TERMINATOR HELD-OUT RUN LEDGER" in update.stdout
    assert payload["entries"][0]["status"] == "failed"
    assert payload["entries"][0]["attempts"][0]["pass_k"] == 3
    assert "TERMINATOR HELD-OUT RUN LEDGER SUMMARY" in report.stdout
    assert "failed" in report.stdout


def test_benchmark_ledger_next_entry_and_summary_ingest(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 2},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            },
            {
                "benchmark": "nyu_ctf_bench",
                "split": "test",
                "name": "chal-b",
                "path": str(tmp_path / "NYU_CTF_Bench" / "test" / "chal-b"),
            },
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    runner = BenchmarkRunner()
    ledger = runner.initialize_external_run_ledger(str(manifest_path), label="nyu-run")
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    next_entry = runner.get_next_external_run_entry(str(ledger_path), splits=["development"])
    assert next_entry is not None
    assert next_entry["id"] == "nyu_ctf_bench:development:chal-a"

    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-20T12:00:00Z",
                "mode": "ctf",
                "target": "/tmp/chal-a",
                "duration_seconds": 9,
                "exit_code": 0,
                "flags_found": ["FLAG{demo}"],
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "files_generated": ["summary.json"],
                "status": "completed",
                "backend": "claude",
                "backend_requested": "claude",
                "failover_used": False,
                "failover_count": 0,
                "session_id": "sess-1",
                "competition": {"lane": "crypto"},
            }
        ),
        encoding="utf-8",
    )

    updated = runner.record_summary_to_external_run_ledger(
        str(ledger_path),
        entry_id="nyu_ctf_bench:development:chal-a",
        summary_path=str(summary_path),
    )

    entry = updated["entries"][0]
    assert entry["status"] == "passed"
    assert "FLAG{demo}" in entry["notes"]
    assert entry["attempts"][0]["ledger_status"] == "passed"
    assert entry["attempts"][0]["competition_lane"] == "crypto"


def test_benchmark_ledger_summary_ingest_falls_back_to_session_log_flag(tmp_path: Path) -> None:
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    (challenge_dir / "challenge.json").write_text(
        json.dumps({"flag": "And yes the nsa can read this to"}),
        encoding="utf-8",
    )
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(challenge_dir),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report_dir = tmp_path / "report"
    report_dir.mkdir()
    (report_dir / "session.log").write_text("FLAG: `And yes the nsa can read this to`\n", encoding="utf-8")
    summary_path = report_dir / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-20T12:00:00Z",
                "mode": "ctf",
                "target": str(challenge_dir),
                "duration_seconds": 9,
                "exit_code": 0,
                "flags_found": [],
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "files_generated": ["summary.json"],
                "status": "completed",
                "backend": "claude",
                "backend_requested": "claude",
                "failover_used": False,
                "failover_count": 0,
                "session_id": "sess-1",
                "competition": {"lane": "crypto"},
            }
        ),
        encoding="utf-8",
    )

    runner = BenchmarkRunner()
    ledger = runner.initialize_external_run_ledger(str(manifest_path), label="nyu-run")
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    updated = runner.record_summary_to_external_run_ledger(
        str(ledger_path),
        entry_id="nyu_ctf_bench:development:chal-a",
        summary_path=str(summary_path),
    )

    entry = updated["entries"][0]
    assert entry["status"] == "passed"
    assert "And yes the nsa can read this to" in entry["notes"]
    repaired_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert repaired_summary["flags_found"] == ["And yes the nsa can read this to"]


def test_benchmark_ledger_cli_next_and_record_summary(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    ledger_path = tmp_path / "ledger.json"
    summary_path = tmp_path / "summary.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    summary_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-20T12:00:00Z",
                "mode": "ctf",
                "target": "/tmp/chal-a",
                "duration_seconds": 13,
                "exit_code": 0,
                "flags_found": [],
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "files_generated": ["summary.json"],
                "status": "completed",
                "backend": "claude",
                "backend_requested": "claude",
                "failover_used": False,
                "failover_count": 0,
                "session_id": "sess-1",
            }
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-manifest",
            str(manifest_path),
            "--ledger-out",
            str(ledger_path),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    next_entry = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-next",
            str(ledger_path),
            "--ledger-next-split",
            "development",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )
    next_payload = json.loads(next_entry.stdout)
    assert next_payload["id"] == "nyu_ctf_bench:development:chal-a"

    record = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-record-summary",
            str(ledger_path),
            "--ledger-entry-id",
            "nyu_ctf_bench:development:chal-a",
            "--ledger-summary-path",
            str(summary_path),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert "TERMINATOR HELD-OUT RUN LEDGER" in record.stdout
    assert payload["entries"][0]["status"] == "no_flag"
    assert payload["entries"][0]["attempts"][0]["ledger_status"] == "no_flag"


def test_benchmark_ledger_run_next_with_stub_runner(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    ledger_path = tmp_path / "ledger.json"
    report_dir = tmp_path / "stub-report"
    report_dir.mkdir()
    summary_path = report_dir / "summary.json"
    stub_path = tmp_path / "stub_runner.py"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    stub_path.write_text(
        "\n".join(
            [
                "import json",
                "import os",
                "from pathlib import Path",
                f"summary_path = Path({str(summary_path)!r})",
                "summary_path.parent.mkdir(parents=True, exist_ok=True)",
                "summary_path.write_text(json.dumps({",
                "  'timestamp': '2026-04-20T12:00:00Z',",
                "  'mode': 'ctf',",
                "  'target': '/tmp/chal-a',",
                "  'duration_seconds': 8,",
                "  'exit_code': 0,",
                "  'flags_found': ['FLAG{demo}'],",
                "  'findings': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},",
                "  'files_generated': ['summary.json'],",
                "  'status': 'completed',",
                "  'backend': 'claude',",
                "  'backend_requested': 'claude',",
                "  'failover_used': False,",
                "  'failover_count': 0,",
                "  'session_id': 'sess-1',",
                "  'competition': {'lane': 'crypto'}",
                "}), encoding='utf-8')",
                "print(summary_path)",
            ]
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-manifest",
            str(manifest_path),
            "--ledger-out",
            str(ledger_path),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    result = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-run-next",
            str(ledger_path),
            "--run-wait-seconds",
            "1",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
        env={
            **os.environ,
            "TERM": "dumb",
            "TERMINATOR_BENCHMARK_RUNNER": f"python3 {stub_path}",
        },
    )

    payload = json.loads(result.stdout)
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert payload["status"] == "completed"
    assert ledger["entries"][0]["status"] == "passed"
    assert ledger["entries"][0]["attempts"][-1]["ledger_status"] == "passed"


def test_benchmark_ledger_run_batch_with_stub_runner(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 2},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            },
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-b",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-b"),
            },
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    ledger_path = tmp_path / "ledger.json"
    report_dir = tmp_path / "stub-report"
    report_dir.mkdir()
    stub_path = tmp_path / "stub_runner.py"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    stub_path.write_text(
        "\n".join(
            [
                "import json, sys",
                "from pathlib import Path",
                "target = Path(sys.argv[-1])",
                f"report_dir = Path({str(report_dir)!r})",
                "report_dir.mkdir(parents=True, exist_ok=True)",
                "summary_path = report_dir / f'{target.name}-summary.json'",
                "flags = ['FLAG{demo}'] if target.name.endswith('a') else []",
                "summary_path.write_text(json.dumps({",
                "  'timestamp': '2026-04-20T12:00:00Z',",
                "  'mode': 'ctf',",
                "  'target': str(target),",
                "  'duration_seconds': 10 if flags else 14,",
                "  'exit_code': 0,",
                "  'flags_found': flags,",
                "  'findings': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},",
                "  'files_generated': [summary_path.name],",
                "  'status': 'completed',",
                "  'backend': 'claude',",
                "  'backend_requested': 'claude',",
                "  'failover_used': False,",
                "  'failover_count': 0,",
                "  'session_id': f'sess-{target.name}',",
                "  'competition': {'lane': 'crypto' if flags else 'rev'}",
                "}), encoding='utf-8')",
                "print(summary_path)",
            ]
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-manifest",
            str(manifest_path),
            "--ledger-out",
            str(ledger_path),
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
    )

    result = subprocess.run(
        [
            "python3",
            "tests/benchmarks/benchmark.py",
            "--ledger-run-batch",
            str(ledger_path),
            "--ledger-next-split",
            "development",
            "--run-wait-seconds",
            "1",
            "--batch-max-tasks",
            "2",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
        env={
            **os.environ,
            "TERM": "dumb",
            "TERMINATOR_BENCHMARK_RUNNER": f"python3 {stub_path}",
        },
    )

    payload = json.loads(result.stdout)
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    statuses = [entry["status"] for entry in ledger["entries"]]
    assert payload["processed"] == 2
    assert payload["stop_reason"] == "max_tasks"
    assert statuses == ["passed", "no_flag"]
    assert payload["summary"]["by_status"] == {"no_flag": 1, "passed": 1}
    assert payload["summary"]["pass_rate_pct"] == 50.0
    assert payload["summary"]["completion_rate_pct"] == 100.0
    assert payload["summary"]["by_lane"]["crypto"]["passed"] == 1
    assert payload["summary"]["by_lane"]["rev"]["no_flag"] == 1


def test_benchmark_ledger_refresh_running_entries(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-20T12:00:00Z",
                "mode": "ctf",
                "target": "/tmp/chal-a",
                "duration_seconds": 5,
                "exit_code": 0,
                "flags_found": ["FLAG{demo}"],
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "files_generated": ["summary.json"],
                "status": "completed",
                "backend": "claude",
                "backend_requested": "claude",
                "failover_used": False,
                "failover_count": 0,
                "session_id": "sess-1",
                "competition": {"lane": "crypto"},
            }
        ),
        encoding="utf-8",
    )

    runner = BenchmarkRunner()
    ledger = runner.initialize_external_run_ledger(str(manifest_path), label="nyu-dev-run")
    ledger["entries"][0]["status"] = "running"
    ledger["entries"][0]["result_path"] = str(summary_path)
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    refreshed = runner.refresh_external_run_ledger(str(ledger_path))

    assert refreshed["refreshed"] == ["nyu_ctf_bench:development:chal-a"]
    assert refreshed["summary"]["by_status"] == {"passed": 1}
    updated = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert updated["entries"][0]["status"] == "passed"


def test_benchmark_ledger_refresh_skips_missing_summary(tmp_path: Path) -> None:
    manifest = {
        "catalog_root": str(tmp_path / "NYU_CTF_Bench"),
        "layout": "nyu_ctf_bench",
        "filters": {"splits": ["development"], "limit": 1},
        "tasks": [
            {
                "benchmark": "nyu_ctf_bench",
                "split": "development",
                "name": "chal-a",
                "path": str(tmp_path / "NYU_CTF_Bench" / "development" / "chal-a"),
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    runner = BenchmarkRunner()
    ledger = runner.initialize_external_run_ledger(str(manifest_path), label="nyu-dev-run")
    ledger["entries"][0]["status"] = "running"
    ledger["entries"][0]["result_path"] = str(tmp_path / "missing-summary.json")
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    refreshed = runner.refresh_external_run_ledger(str(ledger_path))

    assert refreshed["refreshed"] == []
    assert refreshed["skipped"][0]["reason"] == "summary_not_ready"


def test_external_run_wrapper_with_stub_runner(tmp_path: Path) -> None:
    root = tmp_path / "NYU_CTF_Bench"
    (root / "development" / "chal-a").mkdir(parents=True)
    (root / "development" / "chal-a" / "README.md").write_text("dev-a\n", encoding="utf-8")
    (root / "development" / "chal-b").mkdir(parents=True)
    (root / "development" / "chal-b" / "README.md").write_text("dev-b\n", encoding="utf-8")
    (root / "test" / "chal-c").mkdir(parents=True)
    (root / "test" / "chal-c" / "README.md").write_text("test-c\n", encoding="utf-8")
    stub_report_dir = tmp_path / "stub-report"
    stub_report_dir.mkdir()
    stub_path = tmp_path / "stub_runner.py"
    stub_path.write_text(
        "\n".join(
            [
                "import json, sys",
                "from pathlib import Path",
                "target = Path(sys.argv[-1])",
                f"report_dir = Path({str(stub_report_dir)!r})",
                "report_dir.mkdir(parents=True, exist_ok=True)",
                "summary_path = report_dir / f'{target.name}-summary.json'",
                "flags = ['FLAG{demo}'] if target.name.endswith('a') else []",
                "summary_path.write_text(json.dumps({",
                "  'timestamp': '2026-04-20T12:00:00Z',",
                "  'mode': 'ctf',",
                "  'target': str(target),",
                "  'duration_seconds': 7 if flags else 9,",
                "  'exit_code': 0,",
                "  'flags_found': flags,",
                "  'findings': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},",
                "  'files_generated': [summary_path.name],",
                "  'status': 'completed',",
                "  'backend': 'claude',",
                "  'backend_requested': 'claude',",
                "  'failover_used': False,",
                "  'failover_count': 0,",
                "  'session_id': f'sess-{target.name}',",
                "  'competition': {'lane': 'crypto' if flags else 'rev'}",
                "}), encoding='utf-8')",
                "print(summary_path)",
            ]
        ),
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "TERM": "dumb",
        "TERMINATOR_BENCHMARK_RUNNER": f"python3 {stub_path}",
    }
    result = subprocess.run(
        [
            "bash",
            "tests/benchmarks/external_run.sh",
            "--root",
            str(root),
            "--split",
            "development",
            "--limit",
            "2",
            "--label",
            "nyu-dev-wrapper",
            "--wait-seconds",
            "1",
            "--batch-max",
            "2",
        ],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )

    assert "Terminator Held-out External Run" in result.stdout
    assert "Artifacts:" in result.stdout
    assert "Selected:     2" in result.stdout


def _run_manual_self_check() -> None:
    with tempfile.TemporaryDirectory() as td1:
        test_classify_trivial_source(Path(td1))
    test_classify_hard_pwn_fixture()
    test_competition_prompt_skips_reporter_on_critical_path()
    with tempfile.TemporaryDirectory() as td1b:
        test_competition_dry_run_payload_ignores_malformed_plan(Path(td1b))
    with tempfile.TemporaryDirectory() as td1c:
        test_extract_ctf_flags_supports_challenge_json_plain_flag(Path(td1c))
    test_extract_ctf_flags_supports_title_case_flag_prefix()
    with tempfile.TemporaryDirectory() as td2:
        test_detect_and_discover_benchmark_layouts(Path(td2))
    with tempfile.TemporaryDirectory() as td2b:
        test_generic_discovery_prefers_challenge_roots_and_skips_hidden_noise(Path(td2b))
    test_challenge_json_category_guides_routing()
    with tempfile.TemporaryDirectory() as td3:
        test_runtime_summary_includes_competition_sidecar(Path(td3))
    with tempfile.TemporaryDirectory() as td3b:
        test_runtime_summary_ignores_malformed_competition_sidecar(Path(td3b))
    with tempfile.TemporaryDirectory() as td3c:
        test_bash_summary_ignores_malformed_competition_sidecar(Path(td3c))
    with tempfile.TemporaryDirectory() as td4:
        test_benchmark_runner_catalog_summary(Path(td4))
    with tempfile.TemporaryDirectory() as td4b:
        test_benchmark_catalog_filter_limit_and_export(Path(td4b))
    with tempfile.TemporaryDirectory() as td4c:
        test_benchmark_catalog_missing_root_warns(Path(td4c))
    with tempfile.TemporaryDirectory() as td4d:
        test_benchmark_catalog_invalid_layout_rejected(Path(td4d))
    test_terminator_ctf_legacy_dry_run_unchanged_shape()
    test_terminator_ctf_competition_dry_run_exposes_plan()
    test_terminator_report_dir_avoids_timestamp_collision()
    test_terminator_report_dir_avoids_parallel_timestamp_collision()
    with tempfile.TemporaryDirectory() as td5:
        test_benchmark_catalog_cli(Path(td5))
    with tempfile.TemporaryDirectory() as td6:
        test_benchmark_catalog_cli_json_out(Path(td6))
    with tempfile.TemporaryDirectory() as td7:
        test_competition_tool_catalog_cli_json_out(Path(td7))
    with tempfile.TemporaryDirectory() as td8:
        test_competition_tool_catalog_cli_invalid_layout_fails(Path(td8))
    with tempfile.TemporaryDirectory() as td9:
        test_benchmark_ledger_initialization_from_manifest(Path(td9))
    test_benchmark_runner_command_honors_extra_args()
    with tempfile.TemporaryDirectory() as td10:
        test_benchmark_ledger_cli_json_out(Path(td10))
    with tempfile.TemporaryDirectory() as td11:
        test_benchmark_ledger_update_and_summary(Path(td11))
    with tempfile.TemporaryDirectory() as td12:
        test_benchmark_ledger_cli_update_and_report(Path(td12))
    with tempfile.TemporaryDirectory() as td13:
        test_benchmark_ledger_next_entry_and_summary_ingest(Path(td13))
    with tempfile.TemporaryDirectory() as td13b:
        test_benchmark_ledger_summary_ingest_falls_back_to_session_log_flag(Path(td13b))
    with tempfile.TemporaryDirectory() as td14:
        test_benchmark_ledger_cli_next_and_record_summary(Path(td14))
    with tempfile.TemporaryDirectory() as td15:
        test_benchmark_ledger_run_next_with_stub_runner(Path(td15))
    with tempfile.TemporaryDirectory() as td16:
        test_benchmark_ledger_run_batch_with_stub_runner(Path(td16))
    with tempfile.TemporaryDirectory() as td16b:
        test_benchmark_ledger_refresh_running_entries(Path(td16b))
    with tempfile.TemporaryDirectory() as td16c:
        test_benchmark_ledger_refresh_skips_missing_summary(Path(td16c))
    with tempfile.TemporaryDirectory() as td17:
        test_external_run_wrapper_with_stub_runner(Path(td17))
    print("ctf_competition self-check: ok")


if __name__ == "__main__":
    _run_manual_self_check()
