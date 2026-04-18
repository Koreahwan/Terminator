#!/usr/bin/env bash
# v14 retrospective re-fetch: populate program_raw/bundle.md for active
# targets that predate the raw-bundle layer. Skips private/auth-gated
# programs with a clear message (use scripts/playwright_login.sh first).
#
# Usage:
#   ./scripts/refetch_active_targets.sh [--dry-run] [--only target-slug]
#
# Manifest format: lines of `<target-dir>|<program-url>|<visibility>`
# visibility ∈ {public, auth-required, skip}
set -euo pipefail

REPO="${REPO:-/mnt/c/Users/KH/All_Projects/Terminator}"
DRY_RUN=0
ONLY=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --only) shift; ONLY="${1:-}" ;;
    --only=*) ONLY="${arg#--only=}" ;;
  esac
done

cd "$REPO"

# Inline manifest — keep sync with coordination/SUBMISSIONS.md.
# Extendable: add one line per new active target.
MANIFEST=(
  "targets/qwant|https://yeswehack.com/programs/qwant|public"
  "targets/proconnect-identite|https://yeswehack.com/programs/proconnect-identite|public"
  "targets/llama_index|https://huntr.com/repos/run-llama/llama_index|public"
  "targets/onnx|https://huntr.com/repos/onnx/onnx|public"
  "targets/kubeflow|https://huntr.com/repos/kubeflow/kubeflow|public"
  "targets/magiclabs-mbb-og|https://bugcrowd.com/magic-labs|public"
  "targets/zendesk|https://bugcrowd.com/engagements/zendesk|auth-required"
  "targets/dexalot|https://hackenproof.com/programs/dexalot|public"
  "targets/portofantwerp|https://app.intigriti.com/programs/portofantwerp/portofantwerpbruges|auth-required"
  "targets/hrsgroup|https://app.intigriti.com/programs/hrs-group/hrs-group|auth-required"
)

ok=0
skipped=0
failed=0

for row in "${MANIFEST[@]}"; do
  IFS='|' read -r tdir url visibility <<<"$row"
  [ -z "$tdir" ] && continue
  if [ -n "$ONLY" ] && [[ "$tdir" != *"$ONLY"* ]]; then
    continue
  fi
  if [ ! -d "$tdir" ]; then
    echo "[skip] $tdir — directory missing"
    skipped=$((skipped+1))
    continue
  fi
  if [ "$visibility" = "auth-required" ] && [ ! -s "$HOME/.config/playwright-bounty-profile/Default/Cookies" ]; then
    echo "[skip] $tdir ($url) — auth-required, no Playwright profile session. Run scripts/playwright_login.sh first."
    skipped=$((skipped+1))
    continue
  fi
  if [ "$visibility" = "skip" ]; then
    echo "[skip] $tdir — marked skip"
    skipped=$((skipped+1))
    continue
  fi

  if [ $DRY_RUN -eq 1 ]; then
    echo "[dry-run] would fetch: $tdir <- $url ($visibility)"
    ok=$((ok+1))
    continue
  fi

  echo "[fetch] $tdir <- $url ($visibility)"
  # fetch-program returns exit 2 on HOLD — which is fine for raw-bundle
  # purposes since the HOLD still writes artifacts. Judge success by
  # bundle.md existence, not exit code.
  set +e
  timeout 180 python3 tools/bb_preflight.py fetch-program "$tdir" "$url" --no-cache 2>&1 | tail -3 || true
  set -e
  if [ -f "$tdir/program_raw/bundle.md" ]; then
    size="$(wc -c < "$tdir/program_raw/bundle.md")"
    echo "  → bundle.md ${size} bytes"
    ok=$((ok+1))
  else
    echo "  ✗ bundle.md not created"
    failed=$((failed+1))
  fi
done

echo
echo "=== Summary ==="
echo "  OK:      $ok"
echo "  Skipped: $skipped"
echo "  Failed:  $failed"
[ $failed -eq 0 ]
