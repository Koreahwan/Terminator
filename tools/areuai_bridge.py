#!/usr/bin/env python3
"""Terminator bridge for the global areuai CLI.

The global installation under ``~/.areuai`` is the canonical implementation.
This bridge keeps Terminator resilient by falling back to an inline taxonomy
snapshot when the CLI is missing or fails.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any


AREUAI_HOME = Path.home() / ".areuai"
AREUAI_BIN = AREUAI_HOME / "bin" / "areuai.py"
FALLBACK_TAXONOMY_VERSION = "2026.04.25"

_FALLBACK_PATTERNS: tuple[tuple[str, str, float, str], ...] = (
    (r"\bit is (?:important|crucial|worth) to note\b", "template", 1.0, "Delete the phrase and state the finding directly."),
    (r"\bit should be noted\b", "template", 1.0, "Delete it; lead with the observed fact."),
    (r"\b(?:in conclusion|in summary|to summarize|in essence)\b", "template", 1.0, "Use a concrete result statement instead."),
    (r"\bin today'?s (?:digital |modern |evolving )?(?:landscape|world|era|age)\b", "template", 1.2, "Start with the target, endpoint, or affected asset."),
    (r"\bcomprehensive(?:ly)?\b", "buzzword", 0.8, "Replace with exact scope."),
    (r"\brobust(?:ly)?\b", "buzzword", 0.9, "Replace with tested property."),
    (r"\bseamless(?:ly)?\b", "buzzword", 0.9, "Replace with concrete behavior."),
    (r"\bleverag(?:e|es|ed|ing)\b", "buzzword", 0.8, "Use 'use', 'apply', or 'call'."),
    (r"\butiliz(?:e|es|ed|ing|ation)\b", "buzzword", 0.8, "Use 'use' or a precise verb."),
    (r"\b(?:holistic|paradigm|synerg(?:y|ies|istic)|multifaceted)\b", "buzzword", 1.0, "Replace with specific technical language."),
    (r"\b(?:furthermore|moreover|additionally|notably|importantly|subsequently|consequently|therefore)\b", "transition", 0.5, "Prefer direct next fact."),
    (r"\b(?:could|might|would)\s+potentially\b", "hedge", 1.0, "Replace with a proven condition or remove."),
    (r"\b(?:theoretically|presumably|probably|most likely)\b", "hedge", 0.7, "Use only with explicit uncertainty."),
    (r"\b(?:appears|seems) to be\b", "hedge", 0.5, "Use 'testing showed' if verified."),
    (r"\b(?:is|are|was|were|be|been|being)\s+(?:\w+ed|validated|identified|observed|discovered|detected|found|noted|processed|handled|implemented|performed|executed|granted|leaked|accepted|created)\b", "structural", 0.35, "Rewrite passive constructions to active voice."),
    (r"\bthis\s+(?:allows|enables|occurs|results|means|represents|ensures|prevents|causes|grants|permits|facilitates|affects)\b", "structural", 0.5, "Name the concrete subject."),
    (r"\u2014", "punctuation", 0.2, "Replace em dash with comma, semicolon, or period."),
    (r"되어지(?:다|는|고|며|면|었다)|하여지(?:다|는|고|며|면|었다)", "translationese", 0.9, "'되다/하다' 계열로 줄이세요."),
    (r"(?:\w+의\s+){3,}\w+", "translationese", 0.8, "'의' 체이닝을 끊으세요."),
    (r"주목할 필요가 있(?:다|습니다)|포괄적(?:인|으로)?|결론적으로|요약하자면|종합하면", "ko_ai_idiom", 0.8, "한국어 AI 관용구를 자연스러운 표현으로 바꾸세요."),
)

_HUMAN_SIGNALS: tuple[tuple[str, float, str], ...] = (
    (r"0x[0-9a-fA-F]{8,}", -2.0, "hex address/hash"),
    (r"block\s*#?\d{6,}", -2.0, "block number"),
    (r"tx\s*(?:hash)?:?\s*0x[0-9a-fA-F]{20,}", -2.5, "transaction hash"),
    (r"[a-zA-Z_][\w./-]+\.[a-z]{2,4}:\d+", -1.5, "file:line reference"),
    (r"```[\s\S]{20,}```", -1.5, "code block"),
    (r"\bcurl\s+-", -1.5, "curl command"),
    (r"HTTP/\d\.\d\s+\d{3}", -1.5, "HTTP response"),
    (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", -1.0, "ISO timestamp"),
    (r"CVE-\d{4}-\d+", -0.5, "CVE reference"),
    (r"CWE-\d+", -0.3, "CWE reference"),
    (r"\d{1,3}(?:\.\d{1,3}){3}", -1.0, "IP address"),
)

_INVISIBLE_CHARS = "\u200b\ufeff\u200c\u200d\u2060\u00ad\u202f\u200e\u200f\u2061\u2062\u2063\u2064\u180e"


def find_areuai() -> str | None:
    configured = os.environ.get("AREUAI_BIN")
    if configured:
        return configured
    if AREUAI_BIN.exists():
        return str(AREUAI_BIN)
    return shutil.which("areuai") or shutil.which("areuai.py")


def run_areuai(args: list[str], *, input_text: str | None = None, timeout: int = 30) -> dict[str, Any]:
    binary = find_areuai()
    if not binary:
        return {"ok": False, "fallback": True, "error": "areuai CLI not found"}
    cmd = [binary, *args]
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "fallback": True, "exit_code": 124, "error": f"timed out after {timeout}s", "stdout": exc.stdout or "", "stderr": exc.stderr or ""}
    payload: dict[str, Any] = {"ok": proc.returncode in (0, 1, 2), "exit_code": proc.returncode, "command": cmd, "stdout": proc.stdout, "stderr": proc.stderr}
    try:
        payload["data"] = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        payload["parse_error"] = "stdout was not JSON"
    return payload


def _sentence_stats(text: str) -> dict[str, float]:
    sentences = [s.strip() for s in re.split(r"[.!?。！？]+\s+", text) if len(s.split()) > 2]
    if len(sentences) < 3:
        return {"count": float(len(sentences)), "uniformity": 0.0}
    lengths = [len(s.split()) for s in sentences]
    avg = sum(lengths) / len(lengths)
    variance = sum((n - avg) ** 2 for n in lengths) / len(lengths)
    cv = (variance ** 0.5) / max(avg, 1.0)
    return {"count": float(len(sentences)), "uniformity": 1.0 - min(cv, 1.0)}


def _fallback_analyze(text: str, *, mode: str = "report", lang: str = "auto") -> dict[str, Any]:
    text_lower = text.lower()
    score = 0.0
    spans: list[dict[str, Any]] = []
    details: list[str] = []
    for idx, (pattern, category, weight, hint) in enumerate(_FALLBACK_PATTERNS):
        for match in re.finditer(pattern, text_lower if category != "translationese" and not category.startswith("ko") else text, re.IGNORECASE | re.MULTILINE):
            score += weight
            spans.append({"pattern_id": f"fallback.{idx}", "text": match.group(0), "start": match.start(), "end": match.end(), "category": category, "weight": weight, "fix_hint": hint})
    stats = _sentence_stats(text)
    if stats["uniformity"] > 0.70:
        penalty = (stats["uniformity"] - 0.5) * 4
        score += penalty
        details.append(f"sentence uniformity {stats['uniformity']:.2f}: +{penalty:.1f}")
    word_count = len(text.split())
    if word_count > 100 and not re.search(r"0x[0-9a-fA-F]{6,}|HTTP/\d|:\d{2,5}\b|\b\d{4}-\d{2}-\d{2}\b|CVE-\d{4}-", text):
        score += 2.0
        details.append("no concrete values/hashes/IPs/dates: +2.0")
    if word_count < 500:
        score *= min(500 / max(word_count, 100), 2.0)
    human = 0.0
    human_details: list[str] = []
    for pattern, deduction, label in _HUMAN_SIGNALS:
        count = len(re.findall(pattern, text, re.IGNORECASE | re.MULTILINE))
        if count:
            applied = deduction * min(count, 3)
            human += applied
            human_details.append(f"{label} x{count} ({applied:+.1f})")
    human = max(human, -score * 0.6)
    final = max(0.0, min(10.0, score + human))
    if human_details:
        details.append("human signals: " + ", ".join(human_details[:5]))
    verdict = "PASS" if final <= 2 else "WARN" if final <= 5 else "FAIL"
    return {
        "ok": True,
        "fallback": True,
        "taxonomy_version": FALLBACK_TAXONOMY_VERSION,
        "score": round(final, 2),
        "raw_score": round(score, 2),
        "word_count": word_count,
        "verdict": verdict,
        "exit_code": 0 if verdict == "PASS" else 1 if verdict == "WARN" else 2,
        "mode": mode,
        "lang": lang,
        "spans": spans,
        "details": details,
        "stats": stats,
    }


def analyze_text(text: str, mode: str = "report", lang: str = "auto") -> dict[str, Any]:
    payload = run_areuai(["analyze", "--json", "--mode", mode, "--lang", lang, "-"], input_text=text)
    data = payload.get("data")
    if isinstance(data, dict) and payload.get("ok"):
        data["fallback"] = False
        return data
    result = _fallback_analyze(text, mode=mode, lang=lang)
    result["bridge_warning"] = payload.get("error") or payload.get("parse_error") or payload.get("stderr")
    return result


def scrub_text(text: str) -> str:
    payload = run_areuai(["scrub", "--stdin", "--dry-run", "-"], input_text=text)
    if payload.get("ok") and payload.get("stdout", "").startswith("--- before"):
        # Dry-run is intended for humans; get exact text through non-dry-run stdout for stdin.
        payload = run_areuai(["scrub", "--stdin", "-"], input_text=text)
        stdout = payload.get("stdout") or ""
        if stdout and not stdout.startswith("areuai scrub:"):
            return stdout
    cleaned = text.translate({ord(ch): None for ch in _INVISIBLE_CHARS})
    cleaned = re.sub(r"\s*\u2014\s*", ", ", cleaned)
    cleaned = re.sub(r" {2,}", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned


def check_slop_score(text: str) -> int:
    return int(round(float(analyze_text(text, mode="report").get("score", 10))))


def evade_text(text: str, targets: list[str] | None = None) -> str:
    target_arg = ",".join(targets or ["zerogpt"])
    payload = run_areuai(["evade", "--stdin", "--target", target_arg, "-"], input_text=text)
    stdout = payload.get("stdout") or ""
    if payload.get("ok") and stdout and not stdout.startswith("areuai evade:"):
        return stdout
    # Fallback: conservative scrub plus common phrase replacement.
    out = scrub_text(text)
    replacements = {
        r"\bit is (?:important|crucial|worth) to note that\s+": "",
        r"\bit is (?:important|crucial|worth) to note\b": "",
        r"\bin conclusion,?\s*": "",
        r"\bin summary,?\s*": "",
        r"\b(?:furthermore|moreover),?\s*": "",
        r"\b(?:could|might|would)\s+potentially\b": "can",
        r"\bthis vulnerability\b": "this finding",
        r"\bsignificant impact\b": "measurable impact",
        r"\bcomprehensive\b": "detailed",
        r"\brobust\b": "strict",
        r"\bseamless(?:ly)?\b": "direct",
        r"\bleverag(?:e|ing|ed|es)\b": "use",
        r"\butiliz(?:e|ing|ed|es)\b": "use",
        r"\bholistic\b": "full-scope",
        r"되어지": "되",
        r"결론적으로": "정리하면",
    }
    for old, new in replacements.items():
        out = re.sub(old, new, out, flags=re.IGNORECASE)
    sentences = re.split(r"(?<=[.!?])\s+", out.strip())
    if len(sentences) == 3 and max(len(s.split()) for s in sentences if s.strip()) <= 14:
        out = sentences[0].rstrip(".!?") + "; " + sentences[1][0].lower() + sentences[1][1:] + " " + sentences[2]
    return out


def export_fallback_taxonomy() -> dict[str, Any]:
    return {
        "version": FALLBACK_TAXONOMY_VERSION,
        "patterns": _FALLBACK_PATTERNS,
        "human_signals": _HUMAN_SIGNALS,
    }


def doctor() -> dict[str, Any]:
    binary = find_areuai()
    payload: dict[str, Any] = {
        "ok": bool(binary),
        "binary": binary,
        "fallback_taxonomy_version": FALLBACK_TAXONOMY_VERSION,
    }
    if not binary:
        payload["warning"] = "areuai CLI missing; bridge fallback is active"
        return payload
    result = run_areuai(["doctor"], timeout=10)
    payload["cli"] = result.get("data") or result
    cli_version = (payload.get("cli") or {}).get("taxonomy_version") if isinstance(payload.get("cli"), dict) else None
    if cli_version and cli_version != FALLBACK_TAXONOMY_VERSION:
        payload["warning"] = f"fallback taxonomy {FALLBACK_TAXONOMY_VERSION} differs from CLI {cli_version}"
    return payload


def _json_print(payload: dict[str, Any]) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return int(payload.get("exit_code", 0) or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("doctor")
    p.set_defaults(func=lambda _args: _json_print(doctor()))
    p = sub.add_parser("analyze")
    p.add_argument("file")
    p.add_argument("--mode", default="report")
    p.add_argument("--lang", default="auto")
    p.set_defaults(func=lambda args: _json_print(analyze_text(Path(args.file).read_text(encoding="utf-8"), mode=args.mode, lang=args.lang)))
    p = sub.add_parser("slop-score")
    p.add_argument("file")
    p.set_defaults(func=lambda args: _json_print({"ok": True, "score": check_slop_score(Path(args.file).read_text(encoding="utf-8"))}))
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
