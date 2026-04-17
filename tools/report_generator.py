#!/usr/bin/env python3
"""Report generator stub — SARIF + PDF auto-generation placeholder.

Original tools/report_generator.py was lost to git-filter-repo collateral
(v13.5.3 forensics — see `git log` for commit 6ab4eb0 / 6433c40). No
source could be located in the codex_terminator sibling repo nor in any
other checked-out tree on this host. This stub accepts the terminator.sh
invocation signature (--report-dir, --all) so the pipeline's optional
post-run SARIF/PDF export does not emit FileNotFoundError — the call
site in terminator.sh uses `|| true`, so pipeline semantics were never
actually broken by the missing file, but the noise masked real errors.

Reimplement when SARIF/PDF export is needed. Suggested scope:
  * Read report_dir/session.log, extract [CRITICAL]/[HIGH]/[MEDIUM] lines
  * Emit SARIF 2.1.0 JSON at report_dir/report.sarif
  * Emit PDF at report_dir/report.pdf (reportlab or weasyprint)

Until that work lands, this stub always exits 0 with an informational
stderr note.
"""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report-dir", required=True)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--sarif", action="store_true")
    ap.add_argument("--pdf", action="store_true")
    args = ap.parse_args()
    print(
        f"[report_generator stub] --report-dir={args.report_dir} --all={args.all} "
        f"--sarif={args.sarif} --pdf={args.pdf}",
        file=sys.stderr,
    )
    print(
        "[report_generator stub] SARIF/PDF export not implemented — stub PASS. "
        "Reimplement per docstring when export is required.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
