#!/bin/bash
# gmail_session_init.sh — SessionStart hook
# 1. Outputs instruction for Claude to run initial Gmail check
# 2. Outputs instruction to register 7 Gmail cron jobs
# 3. Checks label/filter setup status

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MONITOR="$PROJECT_ROOT/tools/gmail_monitor.py"

# Get current state summary
STATUS=""
LABEL_STATUS=""
if [[ -f "$PROJECT_ROOT/.gmail_monitor_state.json" ]]; then
    REPORTS=$(python3 "$MONITOR" list-reports 2>/dev/null | grep -c "^\S" || echo 0)
    CVES=$(python3 "$MONITOR" list-cves 2>/dev/null | grep -c "^\S" || echo 0)
    DRAFTS=$(python3 "$MONITOR" list-drafts 2>/dev/null | grep -c "PENDING" || echo 0)
    ALERTS=$(python3 "$MONITOR" list-target-alerts 2>/dev/null | grep -c "PENDING" || echo 0)
    PAYMENTS=$(python3 "$MONITOR" payment-summary 2>/dev/null | grep "Total:" | head -1 || echo "0")
    STATUS="Tracked: ${REPORTS} reports, ${CVES} CVEs, ${DRAFTS} pending drafts, ${ALERTS} target alerts. ${PAYMENTS}"
else
    STATUS="No previous Gmail monitor state found. Fresh start."
fi

if [[ -f "$PROJECT_ROOT/.gmail_label_ids.json" ]]; then
    LABEL_COUNT=$(python3 -c "import json; print(len(json.load(open('$PROJECT_ROOT/.gmail_label_ids.json'))))" 2>/dev/null || echo 0)
    LABEL_STATUS="Labels: ${LABEL_COUNT}/19 configured."
else
    LABEL_STATUS="Labels: NOT SET UP. Run setup-labels first."
fi

if [[ -f "$PROJECT_ROOT/.gmail_filter_ids.json" ]]; then
    FILTER_COUNT=$(python3 -c "import json; print(len(json.load(open('$PROJECT_ROOT/.gmail_filter_ids.json'))))" 2>/dev/null || echo 0)
    LABEL_STATUS="${LABEL_STATUS} Filters: ${FILTER_COUNT}/8 configured."
else
    LABEL_STATUS="${LABEL_STATUS} Filters: NOT SET UP."
fi

cat <<EOFMSG | jq -Rsc '{systemMessage: .}'
[GMAIL MONITOR INIT]
$STATUS
$LABEL_STATUS

ACTION REQUIRED: Run the following immediately after session start:

1. INITIAL CHECK — run Gmail searches now:
   - mcp__gmail__search_emails("from:bugcrowd.com OR from:immunefi.com OR from:hackenproof.com OR from:yeswehack.com OR from:intigriti.com OR from:hackerone.com", maxResults=10)
   - mcp__gmail__search_emails("from:mitre.org subject:CVE", maxResults=5)
   - mcp__gmail__search_emails("subject:(bounty OR reward OR payment)", maxResults=5)
   - Process NEW emails via tools/gmail_monitor.py (is-seen / mark-seen / update-report / add-cve / add-payment)

2. REGISTER 7 CRON JOBS (read prompts from tools/gmail_cron_prompts.json):
   - #1 Platform alerts: cron="13 * * * *"
   - #2 CVE tracking: cron="37 */3 * * *"
   - #3 Submission confirm + queue sync: cron="43 */2 * * *"
   - #4 Report status dashboard: cron="7 */2 * * *"
   - #5 Triager question → Gmail draft: cron="27 */4 * * *"
   - #6 New target alerts: cron="52 */6 * * *"
   - #7 Bounty payment tracking: cron="17 */6 * * *"

3. If labels NOT SET UP: run python3 tools/gmail_monitor.py setup-labels and create via MCP
EOFMSG
