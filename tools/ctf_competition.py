#!/usr/bin/env python3
"""Competition-focused CTF routing and benchmark scaffolding."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


SOURCE_LANGS = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".kt": "kotlin",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sage": "sage",
    ".sol": "solidity",
    ".ts": "typescript",
}

FORENSICS_EXTS = {
    ".ad1",
    ".binwalk",
    ".cap",
    ".core",
    ".dmp",
    ".evtx",
    ".img",
    ".log",
    ".mem",
    ".pcap",
    ".pcapng",
    ".raw",
}

WEB_EXTS = {
    ".cgi",
    ".css",
    ".erb",
    ".gohtml",
    ".html",
    ".htm",
    ".js",
    ".jsx",
    ".jsp",
    ".php",
    ".py",
    ".rb",
    ".shtml",
    ".sql",
    ".ts",
    ".tsx",
    ".vue",
}
WEB_FILE_HINTS = {"index.html", "index.php", "package.json", "requirements.txt", "server.py"}
WEB_DIR_HINTS = {"public", "static", "templates", "views"}
WEB_TEXT_HINTS = {"express", "fastapi", "flask", "http", "nginx", "route", "web"}

IMAGE_EXTS = {".bmp", ".gif", ".jpg", ".jpeg", ".png", ".svg", ".tiff", ".webp"}
BINARY_EXTS = {".bin", ".dll", ".dylib", ".elf", ".exe", ".out", ".so"}
ARCHIVE_HINTS = {".zip", ".tar", ".gz", ".bz2", ".xz", ".7z"}
JUDGE_EXTS = {".in", ".out", ".ans"}

README_NAMES = {"readme", "readme.md", "readme.txt", "description.txt", "task.txt"}
IGNORE_BINARY_NAMES = {
    "dockerfile",
    "flag",
    "flag.txt",
    "makefile",
    "readme",
    "readme.md",
    "readme.txt",
}

PWN_HINTS = {
    "bof",
    "buffer overflow",
    "format string",
    "fsop",
    "heap",
    "one_gadget",
    "overflow",
    "pwn",
    "ret2",
    "rop",
    "shellcode",
    "uaf",
}
REV_HINTS = {
    "bytecode",
    "crackme",
    "dfa",
    "emulate",
    "keygen",
    "reverse",
    "reversing",
    "rev",
    "vm",
    "z3",
}
CRYPTO_HINTS = {
    "aes",
    "cipher",
    "crypto",
    "curve",
    "dh",
    "ecb",
    "hash",
    "lattice",
    "lcg",
    "rsa",
    "sage",
}
BROWSER_HINTS = {"browser", "chrome", "firefox", "jsc", "spidermonkey", "v8", "wasm", "webpwn"}
JUDGE_HINTS = {
    "online judge",
    "codeforces",
    "atcoder",
    "kattis",
    "project euler",
    "submit your answer",
    "submission format",
    "doj",
    "boj",
}
SUPPORTED_BENCHMARK_LAYOUTS = {
    "nyu_ctf_bench",
    "cybench",
    "ctf_archive",
    "ctf_dojo",
    "generic",
}
NOISE_DIR_NAMES = {
    "__pycache__",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
}


@dataclass
class CompetitionPlan:
    mode: str
    lane: str
    adapter: str
    retry_budget: int
    pass_budget: int
    skip_reporter_on_critical_path: bool
    source_languages: list[str] = field(default_factory=list)
    file_count: int = 0
    binary_candidates: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    execution_steps: list[str] = field(default_factory=list)
    signals: dict[str, object] = field(default_factory=dict)


@dataclass
class BenchmarkTask:
    benchmark: str
    split: str
    name: str
    path: str


def build_competition_dry_run_payload(
    *,
    challenge_dir: str | Path,
    backend: str,
    failover_to: str,
    model: str,
    report_dir: str | Path,
    timeout: int,
    session_id: str,
    plan_path: str | Path,
) -> dict[str, object]:
    challenge_path = Path(challenge_dir).resolve()
    resolved_plan_path = Path(plan_path).resolve()
    payload: dict[str, object] = {
        "dry_run": True,
        "mode": "ctf",
        "competition_mode": True,
        "target": str(challenge_path),
        "backend": backend,
        "failover_to": failover_to,
        "model": model,
        "report_dir": str(Path(report_dir).resolve()),
        "timeout": timeout,
        "session_id": session_id,
        "steps": [],
    }
    try:
        plan = json.loads(resolved_plan_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        payload["competition_warning"] = "invalid competition_plan.json ignored"
        return payload

    payload["competition_plan"] = plan
    payload["steps"] = list(plan.get("execution_steps", []))
    return payload


def _read_expected_flag(challenge_dir: str | Path) -> str | None:
    challenge_path = Path(challenge_dir).resolve()
    challenge_json = challenge_path / "challenge.json"
    try:
        data = json.loads(challenge_json.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    flag = data.get("flag")
    return flag.strip() if isinstance(flag, str) and flag.strip() else None


def _read_challenge_category(challenge_dir: str | Path) -> str | None:
    challenge_path = Path(challenge_dir).resolve()
    challenge_json = challenge_path / "challenge.json"
    try:
        data = json.loads(challenge_json.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    category = data.get("category")
    return category.strip().lower() if isinstance(category, str) and category.strip() else None


def extract_ctf_flags(log_text: str, challenge_dir: str | Path | None = None) -> list[str]:
    """Extract likely flags from a CTF log, with optional challenge.json fallback."""
    patterns = [
        r"(DH\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
        r"(Flag\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(CTF\{[^}]+\})",
        r"(GoN\{[^}]+\})",
        r"(CYAI\{[^}]+\})",
    ]
    found: list[str] = []
    for pattern in patterns:
        found.extend(match.group(1) for match in re.finditer(pattern, log_text))

    if challenge_dir is not None:
        expected_flag = _read_expected_flag(challenge_dir)
        if expected_flag and expected_flag in log_text:
            found.append(expected_flag)

    deduped = []
    seen = set()
    for item in found:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _iter_files(challenge_dir: Path) -> list[Path]:
    return sorted(path for path in challenge_dir.rglob("*") if path.is_file())


def _read_text_hints(challenge_dir: Path) -> str:
    chunks: list[str] = []
    for path in _iter_files(challenge_dir):
        if path.name.lower() not in README_NAMES and path.suffix.lower() not in {".md", ".txt"}:
            continue
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="ignore")[:32768].lower())
        except OSError:
            continue
    return "\n".join(chunks)


def _binary_candidates(files: Iterable[Path]) -> list[str]:
    candidates: list[str] = []
    for path in files:
        name = path.name.lower()
        if path.suffix.lower() in BINARY_EXTS:
            candidates.append(path.name)
            continue
        if (
            "." not in path.name
            and name not in IGNORE_BINARY_NAMES
            and path.stat().st_size > 0
            and not _looks_like_text_script(path)
        ):
            candidates.append(path.name)
    return sorted(set(candidates))


def _source_languages(files: Iterable[Path]) -> list[str]:
    langs = {SOURCE_LANGS[path.suffix.lower()] for path in files if path.suffix.lower() in SOURCE_LANGS}
    return sorted(langs)


def _has_any_token(text: str, tokens: set[str]) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in tokens)


def _looks_like_text_script(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:1024]
    except OSError:
        return False
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def classify_competition_challenge(challenge_dir: str | Path) -> CompetitionPlan:
    root = Path(challenge_dir).resolve()
    files = _iter_files(root)
    names = [path.name.lower() for path in files]
    joined_names = "\n".join(names)
    text_hints = _read_text_hints(root)
    combined_hints = f"{joined_names}\n{text_hints}"

    source_languages = _source_languages(files)
    binary_candidates = _binary_candidates(files)
    has_source = bool(source_languages)
    has_binary = bool(binary_candidates)
    has_docker = any(name == "dockerfile" for name in names) or any(name == "docker-compose.yml" for name in names)
    has_forensics = any(path.suffix.lower() in FORENSICS_EXTS for path in files)
    has_images = any(path.suffix.lower() in IMAGE_EXTS for path in files)
    has_archives = any(path.suffix.lower() in ARCHIVE_HINTS for path in files)
    has_judge_io = sum(1 for path in files if path.suffix.lower() in JUDGE_EXTS) >= 2
    has_web = any(path.suffix.lower() in {".css", ".htm", ".html", ".jsp", ".php", ".tsx", ".vue"} for path in files) or any(
        path.name.lower() in WEB_FILE_HINTS or any(part.lower() in WEB_DIR_HINTS for part in path.parts[:-1])
        for path in files
    ) or _has_any_token(combined_hints, WEB_TEXT_HINTS)
    has_browser = any(
        path.suffix.lower() == ".wasm" or any(token in path.name.lower() for token in BROWSER_HINTS)
        for path in files
    ) or _has_any_token(combined_hints, BROWSER_HINTS)
    pwnish = _has_any_token(combined_hints, PWN_HINTS)
    revish = _has_any_token(combined_hints, REV_HINTS)
    cryptoish = _has_any_token(combined_hints, CRYPTO_HINTS)
    judgeish = has_judge_io or _has_any_token(combined_hints, JUDGE_HINTS)
    declared_category = _read_challenge_category(root)

    rationale: list[str] = []
    lane = "misc"
    adapter = "artifact"
    retry_budget = 1
    pass_budget = 1

    if declared_category == "pwn":
        if has_binary and (has_docker or any("libc" in name or name.startswith("ld-") for name in names)):
            lane = "hard-pwn"
            adapter = "socket-binary"
            retry_budget = 2
            pass_budget = 3
        else:
            lane = "classic-pwn"
            adapter = "socket-binary"
            retry_budget = 2
        rationale.append("challenge.json category declares pwn.")
    elif declared_category in {"rev", "reversing"}:
        lane = "rev"
        adapter = "binary" if has_binary else "artifact"
        retry_budget = 2
        rationale.append("challenge.json category declares rev/reversing.")
    elif declared_category == "crypto":
        lane = "crypto"
        adapter = "artifact"
        retry_budget = 2
        rationale.append("challenge.json category declares crypto.")
    elif declared_category == "forensics":
        lane = "forensics"
        adapter = "artifact"
        rationale.append("challenge.json category declares forensics.")
    elif declared_category == "web":
        lane = "browser-pwn" if has_browser else "web-misc"
        adapter = "browser" if has_browser else "http-or-local-web"
        retry_budget = 2
        rationale.append("challenge.json category declares web.")
    elif judgeish:
        lane = "judge"
        adapter = "submission"
        rationale.append("Detected judge/submission style challenge artifacts or wording.")
    elif has_forensics:
        lane = "forensics"
        adapter = "artifact"
        rationale.append("Detected forensics-style artifacts such as pcap, log, memory, or image dumps.")
    elif has_browser:
        lane = "browser-pwn"
        adapter = "browser"
        retry_budget = 2
        pass_budget = 3
        rationale.append("Detected browser/WebAssembly or browser-engine hints.")
    elif cryptoish:
        lane = "crypto"
        adapter = "artifact"
        retry_budget = 2
        rationale.append("Detected crypto/math keywords or Sage-style sources.")
    elif has_web and not has_binary:
        lane = "web-misc"
        adapter = "http-or-local-web"
        retry_budget = 2
        rationale.append("Detected web application files without primary binary artifacts.")
    elif has_source and not has_binary:
        lane = "trivial-source"
        adapter = "source"
        rationale.append("Source is present without a primary binary, favoring a direct solver path.")
    elif has_binary and (has_docker or any("libc" in name or name.startswith("ld-") for name in names)):
        lane = "hard-pwn"
        adapter = "socket-binary"
        retry_budget = 2
        pass_budget = 3
        rationale.append("Binary challenge ships with Docker/libc style remote-environment artifacts.")
    elif has_binary and pwnish:
        lane = "classic-pwn"
        adapter = "socket-binary"
        retry_budget = 2
        rationale.append("Binary challenge includes classic exploitation hints.")
    elif has_binary and revish:
        lane = "rev"
        adapter = "binary"
        retry_budget = 2
        rationale.append("Binary challenge includes reverse-engineering/VM/constraint hints.")
    elif has_binary:
        lane = "binary-unknown"
        adapter = "binary"
        retry_budget = 2
        rationale.append("Binary artifacts detected, but problem family is ambiguous.")
    elif has_images or has_archives:
        lane = "misc"
        adapter = "artifact"
        rationale.append("Challenge appears artifact-driven without a dominant binary/web signal.")
    else:
        rationale.append("Fallback lane: insufficient signals for a more specific competition profile.")

    steps_map = {
        "trivial-source": [
            "fast-classify-source",
            "single-agent-solve",
            "direct-local-verify",
            "remote-verify-if-needed",
        ],
        "classic-pwn": [
            "reverser",
            "chain",
            "verifier",
            "optional-critic-on-instability",
        ],
        "hard-pwn": [
            "reverser",
            "trigger-if-needed",
            "chain-best-of-n",
            "critic",
            "verifier",
        ],
        "rev": [
            "reverser",
            "solver",
            "verifier",
            "critic-on-hard-assumptions",
        ],
        "crypto": [
            "reverser",
            "solver",
            "verifier",
            "parallel-math-fallbacks",
        ],
        "forensics": [
            "artifact-survey",
            "specialized-tool-pass",
            "single-agent-synthesis",
            "flag-verification",
        ],
        "browser-pwn": [
            "scout",
            "analyst",
            "exploit-attempts-best-of-n",
            "verification",
        ],
        "web-misc": [
            "scout",
            "analyst",
            "exploiter",
            "verification",
        ],
        "judge": [
            "extract-io-contract",
            "solver-or-ctf-solver",
            "local-check",
            "submission-ready-output",
        ],
        "binary-unknown": [
            "fast-reverser",
            "family-decision",
            "focused-solver-or-chain",
            "verification",
        ],
        "misc": [
            "artifact-triage",
            "ctf-solver",
            "verification",
        ],
    }

    signals = {
        "has_archives": has_archives,
        "has_binary": has_binary,
        "has_browser": has_browser,
        "has_docker": has_docker,
        "has_forensics": has_forensics,
        "has_images": has_images,
        "has_source": has_source,
        "has_web": has_web,
        "judgeish": judgeish,
        "pwnish": pwnish,
        "revish": revish,
        "cryptoish": cryptoish,
        "declared_category": declared_category,
    }

    return CompetitionPlan(
        mode="competition-v2",
        lane=lane,
        adapter=adapter,
        retry_budget=retry_budget,
        pass_budget=pass_budget,
        skip_reporter_on_critical_path=True,
        source_languages=source_languages,
        file_count=len(files),
        binary_candidates=binary_candidates,
        rationale=rationale,
        execution_steps=steps_map[lane],
        signals=signals,
    )


def build_competition_prompt(challenge_dir: str | Path, report_dir: str | Path, plan: CompetitionPlan | None = None) -> str:
    challenge_path = Path(challenge_dir).resolve()
    report_path = Path(report_dir).resolve()
    resolved_plan = plan or classify_competition_challenge(challenge_path)
    files = [path.name for path in _iter_files(challenge_path)[:40]]
    file_list = "\n".join(f"- {name}" for name in files) if files else "- (no files detected)"
    rationale = "\n".join(f"- {item}" for item in resolved_plan.rationale)

    return f"""You are Terminator Competition Lead. Solve this unseen CTF challenge for first verified flag rate, not writeup quality.

Mode: {resolved_plan.mode}
Challenge directory: {challenge_path}
Report directory: {report_path}
Detected lane: {resolved_plan.lane}
Adapter: {resolved_plan.adapter}
Retry budget: {resolved_plan.retry_budget}
Pass budget: {resolved_plan.pass_budget}

Files detected:
{file_list}

Routing rationale:
{rationale}

MANDATORY:
- Read .claude/rules-ctf/_ctf_pipeline.md and follow custom agent definitions where useful.
- Objective is the first verified real flag as fast as possible.
- Reporter, writeup, and knowledge/index updates are NOT on the critical path.
- Stop critical-path work after verified flag. Postmortem/writeup is optional and only if budget remains.
- Do not spend time polishing reports before a verified solve.
- Prefer the minimum viable agent set for the detected lane.
- If the lane is hard-pwn, binary-unknown, browser-pwn, or crypto and the first attempt stalls, diversify strategies up to the pass budget.

Competition lane policy:
- trivial-source: prefer @ctf-solver or a direct solver path.
- classic-pwn: reverser -> chain -> verifier. Add critic only if exploit is unstable or assumptions are brittle.
- hard-pwn: reverser -> [trigger if needed] -> diverse chain attempts -> critic -> verifier.
- rev/crypto: reverser -> solver -> verifier. Add critic after a candidate solve or if constants/assumptions remain risky.
- forensics/misc: prioritize tool-driven artifact extraction before broad reasoning.
- web-misc/browser-pwn: use only the minimum set of scout/analyst/exploiter passes needed to get to a verified flag.
- binary-unknown: do one fast family-discovery pass, then commit to the best matching exploit/solver lane.

Deliverables before completion:
- solve artifact(s) needed to reproduce the flag
- verification evidence showing the real flag or local-to-remote validation path
- concise note of lane and decisive observation

Do not invoke @reporter before verified flag.
"""


def write_competition_artifacts(
    challenge_dir: str | Path,
    report_dir: str | Path,
    *,
    prompt_out: str | Path,
    plan_out: str | Path,
) -> CompetitionPlan:
    plan = classify_competition_challenge(challenge_dir)
    prompt_path = Path(prompt_out)
    plan_path = Path(plan_out)
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_text(build_competition_prompt(challenge_dir, report_dir, plan), encoding="utf-8")
    plan_path.write_text(json.dumps(asdict(plan), indent=2) + "\n", encoding="utf-8")
    return plan


def detect_benchmark_layout(root: str | Path) -> str:
    path = Path(root).resolve()
    if (path / "development").is_dir() and (path / "test").is_dir():
        return "nyu_ctf_bench"
    if (path / "benchmark" / "tasks").is_dir() or (path / "tasks").is_dir():
        return "cybench"
    if path.name == "ctf-archive" or (path / "ctfs").is_dir():
        return "ctf_archive"
    if (path / "environments").is_dir() or (path / "challenges").is_dir():
        return "ctf_dojo"
    return "generic"


def normalize_benchmark_layout(layout: str) -> str:
    if layout == "auto":
        return layout
    if layout not in SUPPORTED_BENCHMARK_LAYOUTS:
        allowed = ", ".join(sorted(SUPPORTED_BENCHMARK_LAYOUTS))
        raise ValueError(f"Unsupported benchmark layout '{layout}'. Expected one of: {allowed}")
    return layout


def _challenge_dirs(parent: Path, split: str, benchmark: str, depth_limit: int = 4) -> list[BenchmarkTask]:
    tasks: list[BenchmarkTask] = []
    if not parent.is_dir():
        return tasks
    all_dirs = [parent, *sorted(path for path in parent.rglob("*") if path.is_dir())]

    marker_dirs: list[Path] = []
    for path in all_dirs:
        try:
            rel_parts = path.relative_to(parent).parts
        except ValueError:
            rel_parts = ()
        if any(part.startswith(".") or part in NOISE_DIR_NAMES for part in rel_parts):
            continue
        depth = len(rel_parts)
        if depth > depth_limit:
            continue
        if not (path / "challenge.json").is_file():
            continue
        if any(path != existing and path.is_relative_to(existing) for existing in marker_dirs):
            continue
        marker_dirs.append(path)

    if marker_dirs:
        return [
            BenchmarkTask(benchmark=benchmark, split=split, name=path.name, path=str(path))
            for path in marker_dirs
        ]

    for path in all_dirs[1:]:
        try:
            rel_parts = path.relative_to(parent).parts
        except ValueError:
            rel_parts = ()
        if any(part.startswith(".") or part in NOISE_DIR_NAMES for part in rel_parts):
            continue
        if not path.is_dir():
            continue
        depth = len(rel_parts)
        if depth > depth_limit:
            continue
        has_files = any(child.is_file() for child in path.iterdir())
        if not has_files:
            continue
        tasks.append(BenchmarkTask(benchmark=benchmark, split=split, name=path.name, path=str(path)))
    return tasks


def discover_benchmark_tasks(root: str | Path, layout: str = "auto") -> list[BenchmarkTask]:
    base = Path(root).resolve()
    normalize_benchmark_layout(layout)
    resolved_layout = detect_benchmark_layout(base) if layout == "auto" else layout

    if resolved_layout == "nyu_ctf_bench":
        return _challenge_dirs(base / "development", "development", resolved_layout) + _challenge_dirs(
            base / "test", "test", resolved_layout
        )
    if resolved_layout == "cybench":
        tasks_root = base / "benchmark" / "tasks"
        if not tasks_root.is_dir():
            tasks_root = base / "tasks"
        return _challenge_dirs(tasks_root, "tasks", resolved_layout, depth_limit=3)
    if resolved_layout == "ctf_archive":
        archive_root = base / "ctfs" if (base / "ctfs").is_dir() else base
        return _challenge_dirs(archive_root, "archive", resolved_layout, depth_limit=5)
    if resolved_layout == "ctf_dojo":
        for candidate in (base / "challenges", base / "environments", base):
            if candidate.is_dir():
                tasks = _challenge_dirs(candidate, "dojo", resolved_layout, depth_limit=4)
                if tasks:
                    return tasks
        return []
    return _challenge_dirs(base, "generic", resolved_layout, depth_limit=3)


def select_benchmark_tasks(
    tasks: Iterable[BenchmarkTask],
    *,
    splits: Iterable[str] | None = None,
    limit: int | None = None,
) -> list[BenchmarkTask]:
    selected = list(tasks)
    if splits:
        normalized = {split.strip().lower() for split in splits if split.strip()}
        selected = [task for task in selected if task.split.lower() in normalized]
    if limit is not None and limit >= 0:
        selected = selected[:limit]
    return selected


def build_benchmark_catalog(
    root: str | Path,
    *,
    layout: str = "auto",
    splits: Iterable[str] | None = None,
    limit: int | None = None,
    include_tasks: bool = False,
) -> dict[str, object]:
    base = Path(root).resolve()
    normalize_benchmark_layout(layout)
    resolved_layout = detect_benchmark_layout(base) if layout == "auto" else layout
    discovered = discover_benchmark_tasks(base, layout=resolved_layout)
    selected = select_benchmark_tasks(discovered, splits=splits, limit=limit)
    warnings: list[str] = []
    if not base.exists():
        warnings.append("catalog root does not exist")
    elif not base.is_dir():
        warnings.append("catalog root is not a directory")
    if not discovered:
        warnings.append("no benchmark tasks discovered")

    by_split: dict[str, int] = {}
    for task in selected:
        by_split[task.split] = by_split.get(task.split, 0) + 1

    catalog: dict[str, object] = {
        "catalog_root": str(base),
        "layout": resolved_layout,
        "filters": {
            "splits": list(splits or []),
            "limit": limit,
        },
        "total_tasks": len(discovered),
        "selected_tasks": len(selected),
        "by_split": by_split,
        "warnings": warnings,
        "sample_tasks": [asdict(task) for task in selected[:20]],
    }
    if include_tasks:
        catalog["tasks"] = [asdict(task) for task in selected]
    return catalog


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    plan_cmd = sub.add_parser("plan")
    plan_cmd.add_argument("--challenge-dir", required=True)
    plan_cmd.add_argument("--report-dir", required=True)
    plan_cmd.add_argument("--prompt-out", required=True)
    plan_cmd.add_argument("--plan-out", required=True)
    plan_cmd.add_argument("--json", action="store_true")

    catalog_cmd = sub.add_parser("catalog")
    catalog_cmd.add_argument("--root", required=True)
    catalog_cmd.add_argument("--layout", default="auto",
                             choices=["auto", *sorted(SUPPORTED_BENCHMARK_LAYOUTS)])
    catalog_cmd.add_argument("--split", action="append", dest="splits",
                             help="Limit to one split (repeatable)")
    catalog_cmd.add_argument("--limit", type=int, default=None,
                             help="Limit the number of selected tasks after filtering")
    catalog_cmd.add_argument("--json", action="store_true")
    catalog_cmd.add_argument("--json-out", default=None,
                             help="Write the machine-readable catalog to this path")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "plan":
        plan = write_competition_artifacts(
            args.challenge_dir,
            args.report_dir,
            prompt_out=args.prompt_out,
            plan_out=args.plan_out,
        )
        if args.json:
            print(json.dumps(asdict(plan), indent=2))
        return 0

    catalog = build_benchmark_catalog(
        args.root,
        layout=args.layout,
        splits=args.splits,
        limit=args.limit,
        include_tasks=True,
    )
    if args.json_out:
        output_path = Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(catalog, indent=2))
    else:
        for task in catalog.get("tasks", []):
            print(f"{task['benchmark']}:{task['split']}:{task['name']}:{task['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
