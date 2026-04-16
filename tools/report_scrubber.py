#!/usr/bin/env python3
"""AI Signature Scrubber for Terminator Reports.

Removes invisible Unicode watermarks and AI-telltale patterns from
vulnerability reports before submission. Based on seomachine's
content_scrubber.py, adapted for security report context.

Usage:
    python3 tools/report_scrubber.py <report.md>                 # In-place scrub
    python3 tools/report_scrubber.py <report.md> -o cleaned.md   # Output to new file
    python3 tools/report_scrubber.py <report.md> --dry-run       # Preview changes

Exit: 0=success, 1=error
"""

import argparse
import re
import sys
import unicodedata
from pathlib import Path

# ---------------------------------------------------------------------------
# Invisible Unicode characters to remove
# ---------------------------------------------------------------------------
INVISIBLE_CHARS = {
    "\u200b": "zero-width space",
    "\ufeff": "byte order mark",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\u00ad": "soft hyphen",
    "\u202f": "narrow no-break space",
    "\u200e": "left-to-right mark",
    "\u200f": "right-to-left mark",
    "\u2061": "function application",
    "\u2062": "invisible times",
    "\u2063": "invisible separator",
    "\u2064": "invisible plus",
    "\u180e": "mongolian vowel separator",
}

# ---------------------------------------------------------------------------
# Em-dash contextual replacement rules
# ---------------------------------------------------------------------------
CONJUNCTIVE_ADVERBS = {
    "however", "therefore", "moreover", "furthermore", "nevertheless",
    "consequently", "meanwhile", "otherwise", "instead", "thus",
    "accordingly", "specifically", "notably", "additionally",
}

# ---------------------------------------------------------------------------
# AI slop patterns to flag (not auto-replace — reporter should rewrite)
# ---------------------------------------------------------------------------
SLOP_PATTERNS = [
    (r"\bIn today'?s (digital |modern |evolving )?(landscape|world|era|age)\b", "generic-opening"),
    (r"\bIt is important to note that\b", "filler"),
    (r"\bIn conclusion\b", "filler"),
    (r"\bcomprehensive\b", "buzzword"),
    (r"\brobust\b", "buzzword"),
    (r"\bseamless(ly)?\b", "buzzword"),
    (r"\bleverag(e|ing)\b", "buzzword"),
    (r"\butiliz(e|ing)\b", "buzzword"),
    (r"\bholistic\b", "buzzword"),
    (r"\bcutting[\s-]edge\b", "buzzword"),
    (r"\bstate[\s-]of[\s-]the[\s-]art\b", "buzzword"),
    (r"\bparadigm\b", "buzzword"),
    (r"\bgame[\s-]chang(er|ing)\b", "buzzword"),
]


class ReportScrubber:
    def __init__(self):
        self.stats = {
            "unicode_watermarks_removed": 0,
            "format_control_removed": 0,
            "em_dashes_replaced": 0,
            "whitespace_normalized": 0,
            "slop_patterns_flagged": 0,
        }
        self.slop_warnings: list[str] = []

    def remove_invisible_chars(self, text: str) -> str:
        for char, name in INVISIBLE_CHARS.items():
            count = text.count(char)
            if count > 0:
                self.stats["unicode_watermarks_removed"] += count
                text = text.replace(char, "")
        return text

    def remove_format_control(self, text: str) -> str:
        result = []
        for ch in text:
            if unicodedata.category(ch) == "Cf" and ch not in ("\n", "\r", "\t"):
                self.stats["format_control_removed"] += 1
            else:
                result.append(ch)
        return "".join(result)

    def replace_em_dashes(self, text: str) -> str:
        def replacer(match: re.Match) -> str:
            full = match.group(0)
            before = match.string[:match.start()].rstrip()
            after = match.string[match.end():].lstrip()

            self.stats["em_dashes_replaced"] += 1

            # Before conjunctive adverb → semicolon
            first_word_after = after.split()[0].lower().rstrip(",;:.") if after else ""
            if first_word_after in CONJUNCTIVE_ADVERBS:
                return "; "

            # Between independent clauses (both sides have verbs / are substantial)
            before_words = before.split()
            after_words = after.split()
            if len(before_words) > 4 and len(after_words) > 4:
                # If after starts with capital → period
                if after and after[0].isupper():
                    return ". "
                return "; "

            # Simple parenthetical / apposition → comma
            return ", "

        text = re.sub(r"\s*\u2014\s*", replacer, text)
        return text

    def normalize_whitespace(self, text: str) -> str:
        original = text
        # Multiple spaces → single
        text = re.sub(r" {2,}", " ", text)
        # Space before punctuation
        text = re.sub(r" ([.,;:!?])", r"\1", text)
        # Ensure space after punctuation (but not in URLs or file paths)
        text = re.sub(r"([.,;:!?])([A-Za-z])", r"\1 \2", text)
        # Excessive blank lines (3+ → 2)
        text = re.sub(r"\n{3,}", "\n\n", text)

        if text != original:
            self.stats["whitespace_normalized"] += 1
        return text

    def flag_slop_patterns(self, text: str) -> str:
        for pattern, category in SLOP_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                self.stats["slop_patterns_flagged"] += len(matches)
                match_text = matches[0] if isinstance(matches[0], str) else matches[0][0] if matches[0] else pattern
                self.slop_warnings.append(
                    f"[{category}] '{match_text}' ({len(matches)}x)"
                )
        return text  # Flagging only, no auto-replace

    def scrub(self, text: str) -> str:
        text = self.remove_invisible_chars(text)
        text = self.remove_format_control(text)
        text = self.replace_em_dashes(text)
        text = self.normalize_whitespace(text)
        self.flag_slop_patterns(text)
        return text


def main():
    parser = argparse.ArgumentParser(
        description="Remove AI signatures from vulnerability reports"
    )
    parser.add_argument("report", help="Path to report markdown file")
    parser.add_argument("-o", "--output", help="Output file (default: in-place)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing")
    parser.add_argument("--json", action="store_true",
                        help="Output stats as JSON")
    args = parser.parse_args()

    path = Path(args.report)
    if not path.exists():
        print(f"Error: File not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    original = path.read_text(encoding="utf-8")
    scrubber = ReportScrubber()
    cleaned = scrubber.scrub(original)

    if args.json:
        output = {
            "stats": scrubber.stats,
            "slop_warnings": scrubber.slop_warnings,
            "changed": original != cleaned,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    # Print stats
    total_changes = sum(scrubber.stats.values())
    print(f"\nReport Scrubbing {'(DRY RUN) ' if args.dry_run else ''}Complete:")
    print(f"  Unicode watermarks removed:  {scrubber.stats['unicode_watermarks_removed']}")
    print(f"  Format-control chars removed: {scrubber.stats['format_control_removed']}")
    print(f"  Em-dashes replaced:          {scrubber.stats['em_dashes_replaced']}")
    print(f"  Whitespace normalized:       {scrubber.stats['whitespace_normalized']}")

    if scrubber.slop_warnings:
        print(f"\n  AI Slop Warnings ({scrubber.stats['slop_patterns_flagged']} patterns):")
        for warn in scrubber.slop_warnings:
            print(f"    - {warn}")
        print("  (These require manual rewrite — not auto-replaced)")

    if total_changes == 0 and not scrubber.slop_warnings:
        print("\n  Report is clean. No changes needed.")
        return

    if not args.dry_run:
        out_path = Path(args.output) if args.output else path
        out_path.write_text(cleaned, encoding="utf-8")
        print(f"\n  Written to: {out_path}")


# Need json for --json mode
import json  # noqa: E402

if __name__ == "__main__":
    main()
