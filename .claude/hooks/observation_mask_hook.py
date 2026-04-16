#!/usr/bin/env python3
"""PostToolUse:Bash|Read — Observation masking hook.

When tool output exceeds thresholds or contains problematic patterns
(ASCII art, repetitive text), saves full output to file and returns
additionalContext with the file path.

Pattern-based masking (Anthropic Cyber Competitions lesson): ASCII art
and repetitive log spam can fill agent context windows instantly,
rendering them non-functional. Detect and mask these at 100+ lines.
"""
import json, sys, os, hashlib, re
from datetime import datetime
from collections import Counter

LINE_THRESHOLD = 500
LOW_LINE_THRESHOLD = 100  # Pattern-based masking kicks in at 100 lines
REPETITION_THRESHOLD = 0.6  # 60%+ identical lines = repetitive text
SAVE_DIR = "/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/.omc/masked_observations"

ASCII_ART_PATTERNS = [
    re.compile(r'[╔╗╚╝║═┌┐└┘│─┬┴├┤┼]'),
    re.compile(r'[░▒▓█▄▀■□▪▫]'),
    re.compile(r'[<>\/\\|_\-=\+\*]{10,}'),
]


def is_repetitive(lines):
    """60%+ identical lines = repetitive text (log spam, banners, etc.)"""
    if len(lines) < LOW_LINE_THRESHOLD:
        return False
    counts = Counter(line.strip() for line in lines if line.strip())
    if not counts:
        return False
    return counts.most_common(1)[0][1] / len(lines) >= REPETITION_THRESHOLD


def has_ascii_art(text):
    """Detect box drawing, block elements, long special char sequences."""
    for pattern in ASCII_ART_PATTERNS:
        if len(pattern.findall(text)) > 20:
            return True
    return False

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        print(json.dumps({}))
        return

    tool_name = input_data.get("tool_name", "")
    if tool_name not in ("Bash", "Read"):
        print(json.dumps({}))
        return

    output = input_data.get("tool_output", "")
    if not output:
        print(json.dumps({}))
        return

    lines = output.split('\n')

    # Pattern-based early masking (ASCII art, repetitive text — from 100 lines)
    force_mask = False
    mask_reason = ""
    if len(lines) > LOW_LINE_THRESHOLD:
        if is_repetitive(lines):
            force_mask = True
            mask_reason = "REPETITIVE_TEXT"
        elif has_ascii_art(output):
            force_mask = True
            mask_reason = "ASCII_ART_DETECTED"

    if not force_mask and len(lines) <= LINE_THRESHOLD:
        print(json.dumps({}))
        return

    reason = mask_reason or "LINE_THRESHOLD_EXCEEDED"
    os.makedirs(SAVE_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    content_hash = hashlib.sha256(output.encode()).hexdigest()[:8]
    filename = f"{timestamp}_{tool_name}_{content_hash}.txt"
    filepath = os.path.join(SAVE_DIR, filename)

    with open(filepath, 'w') as f:
        f.write(output)

    head = lines[:15]
    tail = lines[-15:]
    elided_count = len(lines) - 30

    summary = '\n'.join(head)
    summary += f'\n\n[... {elided_count} lines elided. Full output: {filepath} ...]\n\n'
    summary += '\n'.join(tail)

    result = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": f"[OBS MASKED:{reason}] {len(lines)} lines saved to {filepath}. First/last 15 lines shown in tool result."
        }
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
