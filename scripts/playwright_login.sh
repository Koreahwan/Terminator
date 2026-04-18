#!/usr/bin/env bash
# v14: one-time browser login for invitation-only SPA programs.
# Launches Chromium with a persistent user-data-dir so subsequent
# headless raw_bundle captures can reuse the session cookies.
#
# Usage:
#   ./scripts/playwright_login.sh <url>
#
# Workflow:
#   1. Run this with a platform login URL (e.g. https://app.intigriti.com/auth/login)
#   2. Chromium opens visibly. Log in normally (OAuth / 2FA / whatever).
#   3. Close the browser window.
#   4. Profile is saved to $PLAYWRIGHT_BOUNTY_PROFILE
#      (default: ~/.config/playwright-bounty-profile).
#   5. Future `bb_preflight.py fetch-program` auto-detects the profile
#      and uses it for Playwright tier 4 escalation.

set -euo pipefail

URL="${1:-https://app.intigriti.com/auth/login}"
PROFILE="${PLAYWRIGHT_BOUNTY_PROFILE:-$HOME/.config/playwright-bounty-profile}"

mkdir -p "$PROFILE"

echo "[playwright-login] Profile: $PROFILE"
echo "[playwright-login] Navigating to: $URL"
echo "[playwright-login] Log in, then close the browser window."
echo

# Prefer google-chrome; fall back to chromium if Playwright's bundled
# browser exists; last resort the snap/apt chromium binary.
if command -v google-chrome >/dev/null 2>&1; then
  BROWSER=google-chrome
elif command -v chromium >/dev/null 2>&1; then
  BROWSER=chromium
elif command -v chromium-browser >/dev/null 2>&1; then
  BROWSER=chromium-browser
else
  echo "[playwright-login] ERROR: no Chrome/Chromium binary found."
  echo "Install one of: google-chrome, chromium, chromium-browser."
  exit 1
fi

exec "$BROWSER" \
  --user-data-dir="$PROFILE" \
  --no-first-run \
  --no-default-browser-check \
  --disable-extensions \
  "$URL"
