#!/bin/bash
# Terminator - Autonomous Security Agent Launcher
# Uses Claude Code, Codex/OMX, or hybrid runtime routing with bypassPermissions
#
# Usage:
#   ./terminator.sh [--json] [--timeout N] [--dry-run] bounty https://target.com "*.target.com"
#   ./terminator.sh [--json] [--timeout N] [--dry-run] ai-security https://app.example.com "scope"
#   ./terminator.sh [--json] [--timeout N] [--dry-run] client-pitch https://company.com
#   ./terminator.sh status                         (check running sessions)
#   ./terminator.sh logs                           (tail latest session log)

set -euo pipefail

# Exit codes
EXIT_CLEAN=0
EXIT_CRITICAL=1
EXIT_HIGH=2
EXIT_MEDIUM=3
EXIT_ERROR=10

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log_info()  { printf '[*] %s\n' "$*" >&2; }
log_warn()  { printf '[!] %s\n' "$*" >&2; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
TIMESTAMP="${TERMINATOR_TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}"
REPORT_DIR=""
PID_DIR="$SCRIPT_DIR/.pids"
mkdir -p "$PID_DIR"
LOG_FILE="$SCRIPT_DIR/.terminator.log"

REQUESTED_BACKEND=""
REQUESTED_FAILOVER_TO=""
REQUESTED_RUNTIME_PROFILE=""
RESUME_SESSION=""
PARALLEL_GROUP_ID="${TERMINATOR_PARALLEL_GROUP_ID:-}"
MODEL="${TERMINATOR_MODEL:-}"
MAX_BOUNTY_CONCURRENT="${TERMINATOR_MAX_BOUNTY_CONCURRENT:-5}"

# --- Parse global flags ---
JSON_OUTPUT=false
TIMEOUT="${TERMINATOR_TIMEOUT:-0}"
DRY_RUN=false
WAIT_FOR_COMPLETION=false
PLATFORM="auto"
CTF_COMPETITION_V2=false
SANDBOX=false
ASSESSMENT_TEMPLATE=""
APPROVAL_MODE="${TERMINATOR_APPROVAL_MODE:-open}"

while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --wait) WAIT_FOR_COMPLETION=true; shift ;;
    --competition|--competition-v2) CTF_COMPETITION_V2=true; shift ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --backend) REQUESTED_BACKEND="$2"; shift 2 ;;
    --failover-to) REQUESTED_FAILOVER_TO="$2"; shift 2 ;;
    --runtime-profile) REQUESTED_RUNTIME_PROFILE="$2"; shift 2 ;;
    --resume-session) RESUME_SESSION="$2"; shift 2 ;;
    --sandbox) SANDBOX=true; shift ;;
    --template) ASSESSMENT_TEMPLATE="$2"; shift 2 ;;
    --approval-mode) APPROVAL_MODE="$2"; shift 2 ;;
    --parallel-targets)
      echo "[!] --parallel-targets is no longer supported. Terminator now runs Claude first and only uses Codex as spare on Claude token/context exhaustion or provider/API failure." >&2
      exit $EXIT_ERROR
      ;;
    --max-concurrent)
      echo "[!] --max-concurrent is no longer supported. Parallel target mode has been removed." >&2
      exit $EXIT_ERROR
      ;;
    *) break ;;
  esac
done

MODE="${1:-help}"
TARGET="${2:-}"
SCOPE="${3:-}"

if [ -n "$REQUESTED_BACKEND" ] && ! printf '%s' "$REQUESTED_BACKEND" | grep -Eq '^(auto|claude|codex|hybrid)$'; then
  echo "[!] Unsupported --backend value: $REQUESTED_BACKEND (expected auto|claude|codex|hybrid)" >&2
  exit $EXIT_ERROR
fi

if [ -n "$REQUESTED_FAILOVER_TO" ] && [ "$REQUESTED_FAILOVER_TO" != "claude" ] && [ "$REQUESTED_FAILOVER_TO" != "codex" ] && [ "$REQUESTED_FAILOVER_TO" != "auto" ] && [ "$REQUESTED_FAILOVER_TO" != "none" ]; then
  echo "[!] Unsupported --failover-to value: $REQUESTED_FAILOVER_TO (expected claude|codex|auto|none)" >&2
  exit $EXIT_ERROR
fi

BACKEND="${REQUESTED_BACKEND:-${TERMINATOR_PRIMARY_BACKEND:-hybrid}}"
FAILOVER_TO="${TERMINATOR_FAILOVER_TO:-codex}"
if [ -n "$REQUESTED_FAILOVER_TO" ]; then
  FAILOVER_TO="$REQUESTED_FAILOVER_TO"
fi
if [ "$BACKEND" = "hybrid" ] && [ -z "$REQUESTED_FAILOVER_TO" ] && [ -z "${TERMINATOR_FAILOVER_TO:-}" ]; then
  # Hybrid means role-split execution; Codex is assigned by runtime_policy, not
  # merely held as a spare continuation backend.
  FAILOVER_TO="none"
fi
RUNTIME_PROFILE="${REQUESTED_RUNTIME_PROFILE:-${TERMINATOR_RUNTIME_PROFILE:-}}"
if [ "$RUNTIME_PROFILE" = "hybrid" ]; then
  RUNTIME_PROFILE="scope-first-hybrid"
fi

# Auto-detect platform from URL
detect_platform() {
  local url="$1"
  # Major platforms (implemented)
  if echo "$url" | grep -q "immunefi.com"; then echo "immunefi"
  elif echo "$url" | grep -q "hackenproof.com"; then echo "hackenproof"
  elif echo "$url" | grep -q "hats.finance"; then echo "hatsfinance"
  elif echo "$url" | grep -q "bugcrowd.com"; then echo "bugcrowd"
  elif echo "$url" | grep -q "hackerone.com"; then echo "hackerone"
  elif echo "$url" | grep -q "intigriti.com"; then echo "intigriti"
  elif echo "$url" | grep -q "huntr.com"; then echo "huntr"
  elif echo "$url" | grep -q "yeswehack.com"; then echo "yeswehack"
  elif echo "$url" | grep -q "0din.ai\|0din"; then echo "0din"
  # Web3 / Audit
  elif echo "$url" | grep -q "code4rena.com"; then echo "code4rena"
  elif echo "$url" | grep -q "sherlock.xyz"; then echo "sherlock"
  elif echo "$url" | grep -q "cantina.xyz"; then echo "cantina"
  elif echo "$url" | grep -q "codehawks.cyfrin.io"; then echo "codehawks"
  elif echo "$url" | grep -q "certik.com"; then echo "certik"
  elif echo "$url" | grep -q "secure3.io"; then echo "secure3"
  elif echo "$url" | grep -q "slowmist.com"; then echo "slowmist"
  elif echo "$url" | grep -q "r\.xyz"; then echo "remedy"
  # Web2 major
  elif echo "$url" | grep -q "synack.com"; then echo "synack"
  elif echo "$url" | grep -q "cobalt.io"; then echo "cobalt"
  elif echo "$url" | grep -q "zerocopter.com"; then echo "zerocopter"
  elif echo "$url" | grep -q "federacy.com"; then echo "federacy"
  elif echo "$url" | grep -q "openbugbounty.org"; then echo "openbugbounty"
  elif echo "$url" | grep -q "zerodayinitiative.com"; then echo "zerodayinitiative"
  elif echo "$url" | grep -q "detectify.com"; then echo "detectify"
  elif echo "$url" | grep -q "topcoder.com"; then echo "topcoder"
  elif echo "$url" | grep -q "patchstack.com"; then echo "patchstack"
  elif echo "$url" | grep -q "wordfence.com"; then echo "wordfence"
  elif echo "$url" | grep -q "yogosha.com"; then echo "yogosha"
  elif echo "$url" | grep -q "inspectiv.com"; then echo "inspectiv"
  # Korea
  elif echo "$url" | grep -q "knvd.krcert.or.kr\|krcert.or.kr"; then echo "krcert_knvd"
  elif echo "$url" | grep -q "bugbounty.naver.com"; then echo "naver_whale"
  elif echo "$url" | grep -q "bugbounty.kakao.com"; then echo "kakao_bugbounty"
  elif echo "$url" | grep -q "genians.co.kr"; then echo "genians"
  elif echo "$url" | grep -q "lgsecurity.lge.com"; then echo "lgelectronics"
  elif echo "$url" | grep -q "samsungsds.com"; then echo "samsungsds"
  elif echo "$url" | grep -q "patchday.io"; then echo "patchday"
  # Europe
  elif echo "$url" | grep -q "auditone.io"; then echo "auditone"
  elif echo "$url" | grep -q "hckrt.com\|hackrate"; then echo "hackrate"
  elif echo "$url" | grep -q "hacktify.eu"; then echo "hacktify"
  elif echo "$url" | grep -q "testbirds.com"; then echo "testbirds"
  elif echo "$url" | grep -q "vulnerability-lab.com"; then echo "vulnerabilitylab"
  elif echo "$url" | grep -q "nordicdefender.com"; then echo "nordicdefender"
  elif echo "$url" | grep -q "compass-security.com"; then echo "compasssecurity"
  elif echo "$url" | grep -q "bugbounty.ch"; then echo "bugbountych"
  elif echo "$url" | grep -q "gobugfree.com"; then echo "gobugfree"
  elif echo "$url" | grep -q "cyscope.io"; then echo "cyscope"
  elif echo "$url" | grep -q "secur0.com"; then echo "secur0"
  # Russia / CIS
  elif echo "$url" | grep -q "bugbounty.bi.zone"; then echo "bi_zone"
  elif echo "$url" | grep -q "bugbounty.ru"; then echo "bugbounty_ru"
  elif echo "$url" | grep -q "standoff365.com"; then echo "standoff365"
  elif echo "$url" | grep -q "bugbounty.am"; then echo "bugbounty_am"
  # Asia/Middle East
  elif echo "$url" | grep -q "bugbounty.jp"; then echo "bugbounty_jp"
  elif echo "$url" | grep -q "issuehunt.io"; then echo "issuehunt"
  elif echo "$url" | grep -q "bugbase.ai"; then echo "bugbase"
  elif echo "$url" | grep -q "safehats.com"; then echo "safehats"
  elif echo "$url" | grep -q "comolho.com"; then echo "comolho"
  elif echo "$url" | grep -q "pentabug.com"; then echo "pentabug"
  elif echo "$url" | grep -q "butian.net"; then echo "butian"
  elif echo "$url" | grep -q "vulbox.com"; then echo "vulbox"
  elif echo "$url" | grep -q "cyberarmy.id"; then echo "cyberarmyid"
  elif echo "$url" | grep -q "redstorm.io"; then echo "redstorm"
  elif echo "$url" | grep -q "gerobug"; then echo "gerobug"
  elif echo "$url" | grep -q "buglab.io"; then echo "buglab"
  elif echo "$url" | grep -q "swarmnetics.com"; then echo "swarmnetics"
  elif echo "$url" | grep -q "secuna.io"; then echo "secuna"
  elif echo "$url" | grep -q "safevuln.com"; then echo "safevuln"
  elif echo "$url" | grep -q "whitehub.net"; then echo "whitehub"
  elif echo "$url" | grep -q "thebugbounty.com"; then echo "thebugbounty"
  elif echo "$url" | grep -q "bugv.io"; then echo "bugv"
  elif echo "$url" | grep -q "bugbounty.sa"; then echo "bugbounty_sa"
  elif echo "$url" | grep -q "ravro.ir"; then echo "ravro"
  elif echo "$url" | grep -q "crowdswarm.io"; then echo "crowdswarm"
  elif echo "$url" | grep -q "cybertalents.com"; then echo "cybertalents"
  # Oceania
  elif echo "$url" | grep -q "bugbop.com"; then echo "bugbop"
  elif echo "$url" | grep -q "capturethebug.xyz"; then echo "capturethebug"
  elif echo "$url" | grep -q "dvuln.com"; then echo "dvuln"
  elif echo "$url" | grep -q "hashlock.com"; then echo "hashlock"
  # Americas
  elif echo "$url" | grep -q "bughunt.com.br"; then echo "bughunt"
  elif echo "$url" | grep -q "vulnscope.com"; then echo "vulnscope"
  # Africa
  elif echo "$url" | grep -q "bugbountybox.com"; then echo "bugbountybox"
  elif echo "$url" | grep -q "teklabspace.com"; then echo "teklabspace"
  # Gov VDPs
  elif echo "$url" | grep -q "cisa.gov"; then echo "cisavdp"
  elif echo "$url" | grep -q "divd.nl"; then echo "divd"
  elif echo "$url" | grep -q "ncsc.gov.uk"; then echo "ukncsc"
  elif echo "$url" | grep -q "ncsc.admin.ch"; then echo "swissncsc"
  elif echo "$url" | grep -q "tech.gov.sg"; then echo "singapore_vdp"
  elif echo "$url" | grep -q "homeaffairs.gov.au"; then echo "auvdp"
  # Source-review fallback
  elif echo "$url" | grep -q "github.com"; then echo "source-review"
  else echo "unknown"
  fi
}

if [ "$PLATFORM" = "auto" ] && [ -n "$TARGET" ]; then
  PLATFORM="$(detect_platform "$TARGET")"
fi

# --- Helper functions ---

normalize_backend() {
  local backend="${1:-claude}"
  backend=$(printf '%s' "$backend" | tr '[:upper:]' '[:lower:]')
  case "$backend" in
    auto)
      printf '%s\n' "${TERMINATOR_PRIMARY_BACKEND:-hybrid}"
      ;;
    claude|codex|hybrid)
      printf '%s\n' "$backend"
      ;;
    *)
      echo "[!] Unsupported backend: $backend" >&2
      exit $EXIT_ERROR
      ;;
  esac
}

resolve_failover_backend() {
  local primary="$1"
  local requested="${2:-auto}"
  requested=$(printf '%s' "$requested" | tr '[:upper:]' '[:lower:]')
  case "$requested" in
    ""|none)
      printf '%s\n' ""
      ;;
    auto)
      if [ "$primary" = "claude" ] || [ "$primary" = "hybrid" ]; then
        printf '%s\n' "codex"
      else
        printf '%s\n' "claude"
      fi
      ;;
    claude|codex)
      if [ "$requested" = "$primary" ]; then
        printf '%s\n' ""
      else
        printf '%s\n' "$requested"
      fi
      ;;
    *)
      echo "[!] Unsupported failover backend: $requested" >&2
      exit $EXIT_ERROR
      ;;
  esac
}

backend_model() {
  local backend="$1"
  if [ -n "$MODEL" ]; then
    printf '%s\n' "$MODEL"
    return
  fi
  case "$backend" in
    codex) printf '%s\n' "${TERMINATOR_CODEX_MODEL:-gpt-5.5}" ;;
    hybrid) printf '%s\n' "${TERMINATOR_HYBRID_MODEL:-${TERMINATOR_CLAUDE_MODEL:-sonnet}}" ;;
    *) printf '%s\n' "${TERMINATOR_CLAUDE_MODEL:-sonnet}" ;;
  esac
}

runtime_profile_for_backend() {
  local backend="$1"
  if [ -n "$RUNTIME_PROFILE" ]; then
    printf '%s\n' "$RUNTIME_PROFILE"
    return
  fi
  case "$backend" in
    codex) printf '%s\n' "gpt-only" ;;
    hybrid) printf '%s\n' "scope-first-hybrid" ;;
    *) printf '%s\n' "claude-only" ;;
  esac
}

slugify() {
  printf '%s' "$1" | tr '/: ' '---' | tr -cd '[:alnum:]_.-'
}

build_session_id() {
  local mode="$1"
  local target="$2"
  if [ -n "$RESUME_SESSION" ]; then
    printf '%s\n' "$RESUME_SESSION"
    return
  fi
  printf '%s\n' "${TIMESTAMP}-$(slugify "$mode")-$(slugify "$target")"
}

init_report_dir() {
  if [ -n "${REPORT_DIR:-}" ] && [ -d "$REPORT_DIR" ]; then
    return 0
  fi

  local suffix=0
  local candidate=""
  mkdir -p "$SCRIPT_DIR/reports"
  while true; do
    if [ "$suffix" -eq 0 ]; then
      candidate="$SCRIPT_DIR/reports/$TIMESTAMP"
    else
      candidate="$SCRIPT_DIR/reports/${TIMESTAMP}_$suffix"
    fi
    if mkdir "$candidate" 2>/dev/null; then
      REPORT_DIR="$candidate"
      return 0
    fi
    suffix=$((suffix + 1))
  done
}

write_pid_meta() {
  local meta_path="$1"
  local pid="$2"
  local name="$3"
  local mode="$4"
  local target="$5"
  local backend="$6"
  local failover="$7"
  local session_id="$8"
  local report_dir="$9"
  local group_id="${10:-}"
  cat > "$meta_path" <<EOF
{
  "name": "$name",
  "pid": $pid,
  "mode": "$mode",
  "target": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$target"),
  "backend": "$backend",
  "failover_to": "$failover",
  "session_id": "$session_id",
  "report_dir": "$report_dir",
  "parallel_group_id": "$group_id"
}
EOF
}

count_running_sessions() {
  count_running_mode_sessions ""
}

count_running_mode_sessions() {
  local requested_mode="${1:-}"
  local count=0
  local pf
  for pf in "$PID_DIR"/*.pid; do
    [ -f "$pf" ] || continue
    local pid
    local meta_file="${pf%.pid}.json"
    local session_name
    local session_mode=""
    session_name="$(basename "$pf" .pid)"
    pid=$(cat "$pf" 2>/dev/null || true)
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$pf" "$meta_file"
      continue
    fi

    if [ -n "$requested_mode" ]; then
      if [ -f "$meta_file" ]; then
        session_mode="$(python3 - <<'PY' "$meta_file" 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        print((json.load(fh).get("mode") or "").strip())
except Exception:
    pass
PY
)"
      fi
      if [ -z "$session_mode" ]; then
        case "$session_name" in
          ai-*) session_mode="ai-security" ;;
          pitch-*) session_mode="client-pitch" ;;
          *) session_mode="bounty" ;;
        esac
      fi
      if [ "$session_mode" != "$requested_mode" ]; then
        continue
      fi
    fi

    count=$((count + 1))
  done
  printf '%s\n' "$count"
}

extract_if_zip() {
  local target="$1"
  if [[ "$target" == *.zip ]]; then
    local basename="$(basename "$target" .zip)"
    local extract_dir="$SCRIPT_DIR/tests/wargames/extracted/$basename"
    if [ -d "$extract_dir" ]; then
      echo "[*] Already extracted: $extract_dir" >&2
    else
      echo "[*] Extracting $target → $extract_dir" >&2
      mkdir -p "$extract_dir"
      unzip -o -q "$target" -d "$extract_dir"
    fi
    echo "$extract_dir"
  elif [ -d "$target" ]; then
    echo "$(realpath "$target")"
  else
    echo "[!] Not a zip or directory: $target" >&2
    exit 1
  fi
}

generate_summary() {
  local report_dir="$1"
  local mode="$2"
  local target="$3"
  local start_ts="$4"
  local exit_code="$5"
  local status="$6"

  local end_ts
  end_ts="$(date +%s)"
  local duration=$(( end_ts - start_ts ))

  local iso_ts
  iso_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Count flags
  local flags_json="[]"
  if [ -f "$report_dir/flags.txt" ]; then
    flags_json="$(python3 -c "
import json, sys
lines = open('$report_dir/flags.txt').read().strip().splitlines()
flags = [l.strip() for l in lines if l.strip()]
print(json.dumps(flags))
" 2>/dev/null || echo '[]')"
  fi

  # Count findings by severity from session.log
  local cnt_critical=0 cnt_high=0 cnt_medium=0 cnt_low=0 cnt_info=0
  if [ -f "$report_dir/session.log" ]; then
    cnt_critical=$(grep -c '\[CRITICAL\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_high=$(grep -c '\[HIGH\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_medium=$(grep -c '\[MEDIUM\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_low=$(grep -c '\[LOW\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_info=$(grep -c '\[INFO\]' "$report_dir/session.log" 2>/dev/null || true)
  fi

  # List generated files
  local files_json
  files_json="$(python3 -c "
import json, os
files = []
report_dir = '$report_dir'
try:
    for f in os.listdir(report_dir):
        fpath = os.path.join(report_dir, f)
        if os.path.isfile(fpath):
            files.append(f)
except Exception:
    pass
print(json.dumps(sorted(files)))
" 2>/dev/null || echo '[]')"

  local runtime_backend="unknown"
  local runtime_requested_backend="unknown"
  local runtime_failover_used="false"
  local runtime_failover_count="0"
  local runtime_session_id=""
  local runtime_profile="${RUNTIME_PROFILE:-}"
  if [ -f "$report_dir/runtime_result.json" ]; then
    runtime_backend="$(python3 -c "import json; d=json.load(open('$report_dir/runtime_result.json')); print(d.get('backend_used','unknown'))" 2>/dev/null || echo "unknown")"
    runtime_requested_backend="$(python3 -c "import json; d=json.load(open('$report_dir/runtime_result.json')); print(d.get('backend_requested','unknown'))" 2>/dev/null || echo "unknown")"
    runtime_failover_used="$(python3 -c "import json; d=json.load(open('$report_dir/runtime_result.json')); print(str(bool(d.get('failover_used', False))).lower())" 2>/dev/null || echo "false")"
    runtime_failover_count="$(python3 -c "import json; d=json.load(open('$report_dir/runtime_result.json')); print(d.get('failover_count',0))" 2>/dev/null || echo "0")"
    runtime_session_id="$(python3 -c "import json; d=json.load(open('$report_dir/runtime_result.json')); print(d.get('session_id',''))" 2>/dev/null || echo "")"
    runtime_profile="$(python3 -c "import json; d=json.load(open('$report_dir/runtime_result.json')); print(d.get('runtime_profile',''))" 2>/dev/null || echo "$runtime_profile")"
  fi
  REPORT_DIR_ENV="$report_dir" \
  ISO_TS_ENV="$iso_ts" \
  MODE_ENV="$mode" \
  TARGET_ENV="$target" \
  DURATION_ENV="$duration" \
  EXIT_CODE_ENV="$exit_code" \
  FLAGS_JSON_ENV="$flags_json" \
  FILES_JSON_ENV="$files_json" \
  STATUS_ENV="$status" \
  RUNTIME_BACKEND_ENV="$runtime_backend" \
  RUNTIME_REQUESTED_BACKEND_ENV="$runtime_requested_backend" \
  RUNTIME_FAILOVER_USED_ENV="$runtime_failover_used" \
  RUNTIME_FAILOVER_COUNT_ENV="$runtime_failover_count" \
  RUNTIME_SESSION_ID_ENV="$runtime_session_id" \
  RUNTIME_PROFILE_ENV="$runtime_profile" \
  CNT_CRITICAL_ENV="$cnt_critical" \
  CNT_HIGH_ENV="$cnt_high" \
  CNT_MEDIUM_ENV="$cnt_medium" \
  CNT_LOW_ENV="$cnt_low" \
  CNT_INFO_ENV="$cnt_info" \
  python3 - <<'PY' > "$report_dir/summary.json" 2>/dev/null || true
import json
import os

summary = {
    "timestamp": os.environ["ISO_TS_ENV"],
    "mode": os.environ["MODE_ENV"],
    "target": os.environ["TARGET_ENV"],
    "duration_seconds": int(os.environ["DURATION_ENV"]),
    "exit_code": int(os.environ["EXIT_CODE_ENV"]),
    "flags_found": json.loads(os.environ["FLAGS_JSON_ENV"]),
    "findings": {
        "critical": int(os.environ["CNT_CRITICAL_ENV"]),
        "high": int(os.environ["CNT_HIGH_ENV"]),
        "medium": int(os.environ["CNT_MEDIUM_ENV"]),
        "low": int(os.environ["CNT_LOW_ENV"]),
        "info": int(os.environ["CNT_INFO_ENV"]),
    },
    "files_generated": json.loads(os.environ["FILES_JSON_ENV"]),
    "status": os.environ["STATUS_ENV"],
    "backend": os.environ["RUNTIME_BACKEND_ENV"],
    "backend_requested": os.environ["RUNTIME_REQUESTED_BACKEND_ENV"],
    "runtime_profile": os.environ["RUNTIME_PROFILE_ENV"],
    "failover_used": os.environ["RUNTIME_FAILOVER_USED_ENV"].lower() == "true",
    "failover_count": int(os.environ["RUNTIME_FAILOVER_COUNT_ENV"]),
    "session_id": os.environ["RUNTIME_SESSION_ID_ENV"],
}

competition_path = os.path.join(os.environ["REPORT_DIR_ENV"], "competition_plan.json")
if os.path.exists(competition_path):
    try:
        with open(competition_path, "r", encoding="utf-8") as fh:
            summary["competition"] = json.load(fh)
    except json.JSONDecodeError:
        summary["competition_warning"] = "invalid competition_plan.json ignored"

print(json.dumps(summary, indent=2))
PY

  # Auto-generate SARIF + PDF reports
  python3 "$SCRIPT_DIR/tools/report_generator.py" \
    --report-dir "$report_dir" --all 2>/dev/null || true
}

determine_exit_code() {
  local report_dir="$1"
  local exit_code=$EXIT_CLEAN

  if [ -f "$report_dir/session.log" ]; then
    if grep -q '\[CRITICAL\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_CRITICAL
    elif grep -q '\[HIGH\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_HIGH
    elif grep -q '\[MEDIUM\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_MEDIUM
    fi
  fi

  echo "$exit_code"
}

# --- Docker auto-start ---
ensure_docker() {
  # Skip for non-operational modes
  case "${MODE:-}" in
    help|status|logs|_summary|_exit_code) return 0 ;;
  esac
  if [ "${DRY_RUN:-false}" = true ]; then
    return 0
  fi

  # Check if Docker daemon is running
  if ! docker info >/dev/null 2>&1; then
    echo "[*] Starting Docker daemon..."
    sudo service docker start 2>/dev/null || sudo dockerd &>/dev/null &
    local retries=0
    while ! docker info >/dev/null 2>&1 && [ $retries -lt 15 ]; do
      sleep 2
      retries=$((retries + 1))
    done
    if ! docker info >/dev/null 2>&1; then
      echo "[!] WARNING: Docker daemon failed to start. Continuing without Docker services."
      return 0
    fi
  fi

  # Dashboard: use docs/overview_server.py (watchdog SSE @ :8450) — Docker
  # terminator-dashboard removed in v13.5, 2026-04-17. See _archive/
  # web_dashboard_pre_v13.5/ for the previous FastAPI-based dashboard.

  # Start core services (db, knowledge-fts dependencies) if not running
  local core_containers=("terminator-db" "terminator-neo4j")
  local need_core=false
  for c in "${core_containers[@]}"; do
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$c"; then
      need_core=true
      break
    fi
  done
  if [ "$need_core" = true ]; then
    echo "[*] Starting core Docker services (db, neo4j)..."
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d db neo4j 2>/dev/null || true
  fi
}

# --- Main ---

ensure_docker

# --- Tool preflight check (katoolin-inspired) ---
preflight_tools() {
  case "${1:-}" in
    help|status|logs|_summary|_exit_code) return 0 ;;
  esac
  if [ "${DRY_RUN:-false}" = true ]; then
    return 0
  fi
  python3 "$SCRIPT_DIR/tools/tool_lifecycle.py" check --pipeline "$1" --json >/dev/null 2>&1 || {
    log_warn "Some tools for '$1' pipeline are missing. Run: python3 tools/tool_lifecycle.py install --pipeline $1"
  }
}
preflight_tools "$MODE"

# --- Sandbox mode (AIDA-inspired container isolation) ---
if [ "$SANDBOX" = "true" ]; then
  export TERMINATOR_EXEC_PREFIX="docker exec terminator-sandbox"
  log_info "Sandbox mode: commands will execute inside terminator-sandbox container"
fi

# --- Approval mode export ---
export TERMINATOR_APPROVAL_MODE="$APPROVAL_MODE"

# --- Assessment template preflight ---
if [ -n "$ASSESSMENT_TEMPLATE" ]; then
  TEMPLATE_FILE="$SCRIPT_DIR/tools/assessment_templates/${ASSESSMENT_TEMPLATE}.yaml"
  if [ ! -f "$TEMPLATE_FILE" ]; then
    log_warn "Template '$ASSESSMENT_TEMPLATE' not found at $TEMPLATE_FILE"
  fi
fi

case "$MODE" in
  ctf|firmware|robotics|supplychain|bounty-explore)
    echo "[!] Unsupported mode: $MODE"
    echo "[*] Terminator is now focused on bounty, ai-security, and client-pitch."
    exit $EXIT_ERROR
    ;;

  bounty)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh bounty https://target.com [scope]"
      exit $EXIT_ERROR
    fi

    SCOPE="${SCOPE:-$TARGET}"
    init_report_dir
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    FAILOVER_BACKEND="$(resolve_failover_backend "$PRIMARY_BACKEND" "$FAILOVER_TO")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "bounty" "$TARGET")"

    # Assessment persistence (AIDA-inspired) — create DB record if DB available
    ASSESSMENT_ID=""
    if [ "$DRY_RUN" != true ]; then
      ASSESSMENT_ID=$(python3 "$SCRIPT_DIR/tools/infra_client.py" assessment create \
        --target "$TARGET" --pipeline bounty \
        ${ASSESSMENT_TEMPLATE:+--template "$ASSESSMENT_TEMPLATE"} \
        --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null) || true
      if [ -n "$ASSESSMENT_ID" ]; then
        export TERMINATOR_ASSESSMENT_ID="$ASSESSMENT_ID"
      fi
    fi

    # Phase -1: verify-target gate (v12.3 — LiteLLM/Composio/ONNX $0 incidents)
    # Skip in dry-run mode; skip if TERMINATOR_SKIP_VERIFY=1 (emergency override)
    # Exit codes from verify-target:
    #   0 = GO
    #   1 = HARD NO-GO  (program unlisted / unsupported platform)
    #   2 = NO-GO CASH  ($0 / CVE-only) — override with TERMINATOR_ACCEPT_CVE_ONLY=1
    #   3 = WARN DUPLICATE  (high duplicate rate) — proceed with caution, override with TERMINATOR_ACCEPT_WARN=0 to block
    if [ "$DRY_RUN" != true ] && [ "${TERMINATOR_SKIP_VERIFY:-0}" != "1" ]; then
      _VERIFY_PLATFORM="$PLATFORM"
      [ "$_VERIFY_PLATFORM" = "unknown" ] || [ "$_VERIFY_PLATFORM" = "source-review" ] && _VERIFY_PLATFORM="huntr"
      echo "[*] Phase -1: verify-target $_VERIFY_PLATFORM $TARGET"
      _VERIFY_ARGS=()
      [ "${TERMINATOR_ACCEPT_CVE_ONLY:-0}" = "1" ] && _VERIFY_ARGS+=(--cve-only)
      set +e
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" verify-target "$_VERIFY_PLATFORM" "$TARGET" "${_VERIFY_ARGS[@]}"
      _VERIFY_EXIT=$?
      set -e
      case "$_VERIFY_EXIT" in
        0)
          echo "[*] verify-target: GO"
          ;;
        3)
          # WARN DUPLICATE — proceed unless user opts to block
          if [ "${TERMINATOR_BLOCK_WARN:-0}" = "1" ]; then
            echo "[!] verify-target returned WARN (exit 3) — blocked by TERMINATOR_BLOCK_WARN=1"
            exit $EXIT_ERROR
          fi
          echo "[*] verify-target: WARN (exit 3) — duplicate risk, proceeding. Override with TERMINATOR_BLOCK_WARN=1 to block."
          ;;
        *)
          echo "[!] verify-target FAILED with exit $_VERIFY_EXIT — target rejected at Phase -1"
          echo "[*] Overrides:"
          echo "    TERMINATOR_SKIP_VERIFY=1       skip verify-target entirely"
          echo "    TERMINATOR_ACCEPT_CVE_ONLY=1   accept \$0 / CVE-only programs"
          exit $EXIT_ERROR
          ;;
      esac
    fi

    # Check if same target is already running
    # Strip known generic suffixes (information, details, scope) that cause PID collisions
    _TMP_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/$||;s|/information$||;s|/details$||;s|/scope$||' | awk -F/ '{print $NF}' | sed 's|\.|-|g')"
    [ -z "$_TMP_NAME" ] && _TMP_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|\.|-|g')"
    _TMP_PID_FILE="$PID_DIR/${_TMP_NAME}.pid"
    if [ -f "$_TMP_PID_FILE" ]; then
      _TMP_PID=$(cat "$_TMP_PID_FILE")
      if kill -0 "$_TMP_PID" 2>/dev/null; then
        echo "[!] Target '$_TMP_NAME' is already running (PID: $_TMP_PID)"
        echo "[*] Use './terminator.sh status' to check all sessions"
        exit $EXIT_ERROR
      else
        rm -f "$_TMP_PID_FILE"
      fi
    fi

    if [ "$DRY_RUN" = true ]; then
      if [ "$JSON_OUTPUT" = true ]; then
        _SCOPE_FIRST_ENABLED=False
        if [ "$EFFECTIVE_PROFILE" = "scope-first-hybrid" ]; then
          _SCOPE_FIRST_ENABLED=True
        fi
        python3 -c "
import json
plan = {
    'dry_run': True,
    'mode': 'bounty',
    'target': '$TARGET',
    'scope': '$SCOPE',
    'backend': '$PRIMARY_BACKEND',
    'failover_to': '$FAILOVER_BACKEND',
    'runtime_profile': '$EFFECTIVE_PROFILE',
    'model': '$EFFECTIVE_MODEL',
    'report_dir': '$REPORT_DIR',
    'timeout': $TIMEOUT,
    'session_id': '$SESSION_ID',
    'scope_first_gate': {
        'enabled': $_SCOPE_FIRST_ENABLED,
        'scope_contract_required_before_phase_1': $_SCOPE_FIRST_ENABLED,
        'safety_wrapper_required_for_live_actions': $_SCOPE_FIRST_ENABLED,
        'artifact_scope_hash_required': $_SCOPE_FIRST_ENABLED,
        'dry_run_gate_status': 'would_require_scope_contract' if $_SCOPE_FIRST_ENABLED else 'not_applicable'
    },
    'hybrid_role_split': {
        'enabled': $_SCOPE_FIRST_ENABLED,
        'completion_requires_runtime_dispatch_log': $_SCOPE_FIRST_ENABLED,
        'codex_roles': ['scout', 'analyst', 'source-auditor', 'exploiter', 'critic', 'triager-sim'] if $_SCOPE_FIRST_ENABLED else [],
        'claude_roles': ['scope-auditor', 'reporter', 'submission-review'] if $_SCOPE_FIRST_ENABLED else [],
        'debate_required_roles': ['exploiter', 'critic', 'triager-sim'] if $_SCOPE_FIRST_ENABLED else []
    },
    'steps': [
        'phase_0_target_evaluator',
        'phase_0_scope_contract_create',
        'phase_0_scope_auditor',
        'phase_0_safety_wrapper_config',
        'phase_0_2_bb_preflight_rules',
        'phase_0_5_automated_tool_scan',
        'phase_1_scout_analyst_threat_modeler_patch_hunter',
        'phase_1_2_vuln_assistant_risk_triage',
        'raw_endpoint_review_queue',
        'phase_1_5_workflow_auditor_web_tester',
        'gate_1_2_coverage_workflow_check',
        'kill_gate_1_triager_sim_finding_viability',
        'phase_2_exploiter_poc_validation',
        'kill_gate_2_triager_sim_poc_destruction',
        'phase_3_reporter',
        'phase_4_parallel_review_critic_architect_codex',
        'phase_4_5_triager_sim_report_review',
        'phase_5_finalize_zip',
        'phase_6_cleanup'
    ]
}
print(json.dumps(plan, indent=2))
"
      else
        echo "[DRY-RUN] Bug Bounty mode"
        echo "  Target:  $TARGET"
        echo "  Scope:   $SCOPE"
        echo "  Backend: $PRIMARY_BACKEND"
        echo "  Runtime: $EFFECTIVE_PROFILE"
        echo "  Spare:   ${FAILOVER_BACKEND:-none} (Claude quota/context/API interruption only)"
        echo "  Model:   $EFFECTIVE_MODEL"
        echo "  Session: $SESSION_ID"
        echo "  Report:  $REPORT_DIR"
        echo "  Timeout: ${TIMEOUT}s (0=none)"
        if [ "$EFFECTIVE_PROFILE" = "scope-first-hybrid" ]; then
          echo "  Scope gate: scope_contract required before Phase 1; safety_wrapper required for live actions"
          echo "  Role split: runtime_dispatch log required; Codex handles scout/analyst/exploiter/critic/triager-sim"
        fi
        echo "  Would run: python3 tools/backend_runner.py run --backend $PRIMARY_BACKEND ..."
      fi
      exit $EXIT_CLEAN
    fi

    if ! printf '%s' "$MAX_BOUNTY_CONCURRENT" | grep -Eq '^[0-9]+$'; then
      echo "[!] TERMINATOR_MAX_BOUNTY_CONCURRENT must be a non-negative integer" >&2
      exit $EXIT_ERROR
    fi
    if [ "$MAX_BOUNTY_CONCURRENT" -gt 0 ]; then
      RUNNING_BOUNTY_COUNT="$(count_running_mode_sessions "bounty")"
      if [ "$RUNNING_BOUNTY_COUNT" -ge "$MAX_BOUNTY_CONCURRENT" ]; then
        echo "[!] Max concurrent bounty sessions reached ($RUNNING_BOUNTY_COUNT/$MAX_BOUNTY_CONCURRENT)." >&2
        echo "[*] Wait for an existing bounty run to finish or use './terminator.sh status' to inspect active sessions." >&2
        exit $EXIT_ERROR
      fi
    fi

    if [ "$JSON_OUTPUT" = false ]; then
      echo "╔══════════════════════════════════════════╗"
      echo "║     TERMINATOR - Bug Bounty Mode         ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Target:  $TARGET"
      echo "║ Scope:   $SCOPE"
      echo "║ Backend: $PRIMARY_BACKEND"
      echo "║ Runtime: $EFFECTIVE_PROFILE"
      echo "║ Spare:   ${FAILOVER_BACKEND:-none}"
      echo "║ Model:   $EFFECTIVE_MODEL"
      echo "║ Report:  $REPORT_DIR"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Running in background...                 ║"
      echo "║ Monitor:  tail -f $REPORT_DIR/session.log"
      echo "╚══════════════════════════════════════════╝"
    fi

    START_TS="$(date +%s)"

    # Derive target name from URL: use last meaningful path segment (e.g., "parallel" from /bug-bounty/parallel/)
    # Strip known generic suffixes (information, details, scope) that cause PID collisions
    TARGET_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/$||;s|/information$||;s|/details$||;s|/scope$||' | awk -F/ '{print $NF}' | sed 's|\.|-|g')"
    # Fallback to domain if path is empty
    [ -z "$TARGET_NAME" ] && TARGET_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|\.|-|g')"
    TARGET_DIR="$SCRIPT_DIR/targets/$TARGET_NAME"
    PID_FILE="$PID_DIR/${TARGET_NAME}.pid"
    PID_META="$PID_DIR/${TARGET_NAME}.json"

    # Scope-first Phase 0: MANDATORY for ALL bounty backends (not just hybrid)
    # Without bundle.md, agents "infer" scope → OOS items land in scope → submission accident
    # Root cause: NEAR Intents escrow-swap OOS collision (2026-04-26)
    # Override: TERMINATOR_SKIP_SCOPE_FIRST=1 (emergency only)
    if [ "${TERMINATOR_SKIP_SCOPE_FIRST:-0}" != "1" ]; then
      echo "[*] Scope-first Phase 0: passive program fetch + scope contract"
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" init "$TARGET_DIR" >/dev/null 2>&1 || true
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" fetch-program "$TARGET_DIR" "$TARGET" --hold-ok
      if [ ! -f "$TARGET_DIR/program_raw/bundle.md" ]; then
        log_error "SCOPE GATE FAIL: bundle.md not created — agents MUST NOT start without verbatim scope."
        log_error "Fix: check program URL, network, or Cloudflare. Override: TERMINATOR_SKIP_SCOPE_FIRST=1"
        exit $EXIT_ERROR
      fi
      # Reverse OOS check: bundle OOS items must not appear in rules_summary scope
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" verbatim-check "$TARGET_DIR" --warn >/dev/null 2>&1 || true
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" oos-scope-collision "$TARGET_DIR" 2>/dev/null || {
        _OOS_EXIT=$?
        if [ "${_OOS_EXIT:-0}" = "2" ]; then
          log_error "OOS-SCOPE COLLISION: Out-of-scope items found in scope section. Fix rules_summary before proceeding."
          exit $EXIT_ERROR
        fi
      }
      if [ "$EFFECTIVE_PROFILE" = "scope-first-hybrid" ]; then
        python3 "$SCRIPT_DIR/tools/scope_contract.py" create "$TARGET_DIR" --allow-hold
        if [ ! -f "$TARGET_DIR/scope_contract.json" ]; then
          log_error "SCOPE GATE FAIL: scope_contract.json not created — hybrid role dispatch must fail closed."
          exit $EXIT_ERROR
        fi
        echo "[*] Scope-first Phase 0: scope_contract.json ready"
      else
        echo "[*] Scope-first Phase 0: bundle.md ready (non-hybrid — no scope_contract)"
      fi
    else
      log_warn "TERMINATOR_SKIP_SCOPE_FIRST=1 — scope gate bypassed. Agents may infer incorrect scope."
    fi

    # Write prompt to file to avoid heredoc escaping issues
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<'PROMPT_TEMPLATE'
You are Terminator Team Lead running Bug Bounty Pipeline v12.

Target: __TARGET__
Scope: __SCOPE__
Platform: __PLATFORM__
Target directory: __TARGET_DIR__
Report directory: __REPORT_DIR__

## PIPELINE RULES — Read these files (they are the source of truth):
- CLAUDE.md (project root) — mandatory rules, agent model assignments, tool rules
- .claude/rules/bb_pipeline_v13.md — full phase-by-phase procedure, gates, time-boxes

Follow bb_pipeline_v13.md exactly. All rules (test accounts, gates, evidence tiers,
AI detection, Phase 5.7 live scope check, Phase 5.5b platform safety) are defined there.

## PRODUCT FOCUS — Bounty + Client Pitch Risk Engine

After scout produces endpoint_map.md/recon_report.json/recon_notes.md, run:

python3 -m tools.vuln_assistant analyze \
  --mode bounty \
  --domain web \
  --endpoint-map __TARGET_DIR__/endpoint_map.md \
  --input __TARGET_DIR__/recon_report.json \
  --input __TARGET_DIR__/recon_notes.md \
  --out __TARGET_DIR__/vuln_assistant

Use __TARGET_DIR__/vuln_assistant/high_value_targets.md and
__TARGET_DIR__/vuln_assistant/raw_endpoint_review.md before analyst prioritization.
Do not discard raw endpoints: low-score items may still contain legacy APIs,
undocumented workflows, or hidden business logic. Treat vuln_assistant outputs as
candidates until evidence and negative controls exist.

## SESSION-SPECIFIC RULES (not in pipeline docs):

### Existing Artifacts:
Check __TARGET_DIR__/ for prior results before starting each phase:
- scout_findings.md exists → skip Phase 1, proceed to Gate 1 with those candidates
- endpoint_map.md exists → skip scout, use existing map
- vulnerability_candidates.md exists → skip analyst, use existing candidates
- checkpoint.json exists → read status and resume from last completed phase
Do NOT redo work that already has artifacts.

### Autonomous Completion:
- Run FULL pipeline end-to-end. NEVER stop at intermediate phases.
- Gate KILL → check explore_candidates.md for remaining candidates → recycle or write final_sweep.md
- Gate GO → immediately proceed to next phase. No pause.
- No HIGH+ candidate after 2hr → write final_sweep.md → session complete
- Phase 5.8: No browser access. Write autofill_payload.json + submission_review.json only.

### On ANY exit:
- Check __TARGET_DIR__/test_accounts.json → cleanup if exists
- Write checkpoint.json with status="completed"
- If submission artifacts exist, log: "SUBMISSION READY: <target>/<finding>"

### Parallel Safety:
- When writing to knowledge/triage_objections/ or knowledge/decisions/, prefix filenames with
  the target name to avoid collisions with concurrent sessions.

SAFETY: Authorized target only. Safe payloads only.
Search knowledge-fts MCP with routed_search(role, query, phase, program) before each agent spawn; use broad smart_search only as fallback.
All artifacts save to __TARGET_DIR__/. Reports save to __REPORT_DIR__/.
PROMPT_TEMPLATE

    # Replace placeholders with actual values
    # Get platform config
    PLATFORM_INFO=""
    if [ -f "$SCRIPT_DIR/tools/platforms.json" ] && [ "$PLATFORM" != "unknown" ]; then
      PLATFORM_INFO="$(python3 -c "
import json
d = json.load(open('$SCRIPT_DIR/tools/platforms.json'))
p = d['platforms'].get('$PLATFORM', {})
if p:
    print(f'Platform: {p[\"name\"]}')
    print(f'Type: {p[\"type\"]}')
    print(f'Taxonomy: {p[\"taxonomy\"]}')
    print(f'Submission template: {p[\"submission_template\"]}')
    print(f'AI detection: {p[\"ai_detection\"]}')
    print(f'Post-edit: {p[\"post_edit\"]}')
" 2>/dev/null || echo "Platform: $PLATFORM")"
    fi

    sed -i "s|__TARGET__|$TARGET|g;s|__SCOPE__|$SCOPE|g;s|__TARGET_DIR__|$TARGET_DIR|g;s|__REPORT_DIR__|$REPORT_DIR|g;s|__PLATFORM__|$PLATFORM|g" "$PROMPT_FILE"

    # Append platform context to prompt
    if [ -n "$PLATFORM_INFO" ]; then
      printf "\n\nPLATFORM CONTEXT:\n%s\nRead the submission template file before writing any report.\n" "$PLATFORM_INFO" >> "$PROMPT_FILE"
    fi

    nohup bash -c "
      START_TS=$START_TS

      # Cleanup on crash/signal — ensure PID files are always removed
      _cleanup() {
        echo \"[SIGNAL] Session interrupted at \$(date)\" >> \"$REPORT_DIR/session.log\" 2>/dev/null || true
        if [ -f \"$TARGET_DIR/test_accounts.json\" ]; then
          echo '[WARNING] Test accounts exist but session was interrupted. Manual cleanup needed: $TARGET_DIR/test_accounts.json' >> \"$REPORT_DIR/session.log\" 2>/dev/null || true
        fi
        rm -f \"$PID_FILE\" \"$PID_META\"
        exit 1
      }
      trap _cleanup SIGTERM SIGINT SIGHUP

      TERMINATOR_TARGET_DIR=\"$TARGET_DIR\" \
      TERMINATOR_ACTIVE_PIPELINE=\"bounty\" \
      python3 -u \"$SCRIPT_DIR/tools/backend_runner.py\" run \
        --backend \"$PRIMARY_BACKEND\" \
        --failover-to \"${FAILOVER_BACKEND:-none}\" \
        --runtime-profile \"$EFFECTIVE_PROFILE\" \
        --prompt-file \"$PROMPT_FILE\" \
        --work-dir \"$SCRIPT_DIR\" \
        --report-dir \"$REPORT_DIR\" \
        --model \"$EFFECTIVE_MODEL\" \
        --mode bounty \
        --target \"$TARGET\" \
        --target-dir \"$TARGET_DIR\" \
        --scope \"$SCOPE\" \
        --session-id \"$SESSION_ID\" \
        --timeout \"$TIMEOUT\" \
        --result-file \"$REPORT_DIR/runtime_result.json\" 2>&1 | stdbuf -oL tee \"$REPORT_DIR/session.log\"
      RUNTIME_EXIT=\${PIPESTATUS[0]}

      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"

      # Determine exit code based on findings
      FINAL_EXIT=\$(bash $SCRIPT_DIR/terminator.sh _exit_code $REPORT_DIR 2>/dev/null || echo 0)
      echo \"\$FINAL_EXIT\" > \"$REPORT_DIR/exit_code\"

      # Determine status
      SESSION_STATUS='completed'
      if [ \"\$RUNTIME_EXIT\" -eq 124 ] 2>/dev/null; then
        SESSION_STATUS='timeout'
      elif [ \"\$RUNTIME_EXIT\" -ne 0 ] 2>/dev/null; then
        SESSION_STATUS='failed'
      fi

      # Warn about orphaned test accounts
      if [ -f \"$TARGET_DIR/test_accounts.json\" ]; then
        echo '[WARNING] Test accounts need cleanup: $TARGET_DIR/test_accounts.json' >> \"$REPORT_DIR/session.log\"
      fi

      # Generate summary.json
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR bounty '$TARGET' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true

      # Write completion marker for --wait detection
      echo \"\$SESSION_STATUS\" > \"$REPORT_DIR/.completed\"

      rm -f \"$PID_FILE\"
      rm -f \"$PID_META\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    write_pid_meta "$PID_META" "$BGPID" "$TARGET_NAME" "bounty" "$TARGET" "$PRIMARY_BACKEND" "${FAILOVER_BACKEND:-}" "$SESSION_ID" "$REPORT_DIR" "$PARALLEL_GROUP_ID"
    echo "$TIMESTAMP mode=bounty backend=$PRIMARY_BACKEND failover=${FAILOVER_BACKEND:-none} session=$SESSION_ID pid=$BGPID report=$REPORT_DIR target=$TARGET group=${PARALLEL_GROUP_ID:-none}" >> "$SCRIPT_DIR/.terminator.history"

    if [ "$JSON_OUTPUT" = true ]; then
      echo "$REPORT_DIR/summary.json"
    else
      echo ""
      echo "[*] PID: $BGPID"
      echo "[*] Session: $SESSION_ID"
      echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    fi

    # --wait: block until nohup session actually completes, then output results
    if [ "$WAIT_FOR_COMPLETION" = true ]; then
      echo "[*] --wait: blocking until session completes..."
      while kill -0 "$BGPID" 2>/dev/null; do
        sleep 15
      done
      echo ""
      echo "=== SESSION RESULT: $TARGET_NAME ==="
      cat "$REPORT_DIR/.completed" 2>/dev/null || echo "unknown"
      echo "---"
      tail -80 "$REPORT_DIR/session.log" 2>/dev/null
      echo "=== END ==="
    fi
    ;;

  client-pitch)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh client-pitch https://company.com"
      exit $EXIT_ERROR
    fi

    SCOPE="${SCOPE:-$TARGET}"
    init_report_dir
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "client-pitch" "$TARGET")"
    TARGET_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/$||;s|/.*||;s|\.|-|g')"
    [ -z "$TARGET_NAME" ] && TARGET_NAME="client"
    TARGET_DIR="$SCRIPT_DIR/targets/pitch-$TARGET_NAME"

    if [ "$DRY_RUN" = true ]; then
      if [ "$JSON_OUTPUT" = true ]; then
        python3 -c "
import json
print(json.dumps({
  'dry_run': True,
  'mode': 'client-pitch',
  'target': '$TARGET',
  'scope': '$SCOPE',
  'backend': '$PRIMARY_BACKEND',
  'runtime_profile': '$EFFECTIVE_PROFILE',
  'model': '$EFFECTIVE_MODEL',
  'report_dir': '$REPORT_DIR',
  'target_dir': '$TARGET_DIR',
  'session_id': '$SESSION_ID',
  'steps': [
    'passive_surface_seed',
    'vuln_assistant_risk_triage',
    'raw_endpoint_review_queue',
    'external_risk_summary',
    'security_assessment_pitch',
    'recommended_test_scope'
  ],
  'safety': 'passive_only_no_confirmed_vulnerability_language'
}, indent=2))
"
      else
        echo "[DRY-RUN] Client Pitch mode"
        echo "  Target:  $TARGET"
        echo "  Backend: $PRIMARY_BACKEND"
        echo "  Runtime: $EFFECTIVE_PROFILE"
        echo "  Model:   $EFFECTIVE_MODEL"
        echo "  Session: $SESSION_ID"
        echo "  Report:  $REPORT_DIR"
        echo "  Policy:  passive-only risk signals; no confirmed vulnerability claims"
        echo "  Would run: python3 -m tools.vuln_assistant analyze --mode client-pitch ..."
      fi
      exit $EXIT_CLEAN
    fi

    mkdir -p "$TARGET_DIR"
    SEED_FILE="$TARGET_DIR/client_pitch_seed.txt"
    printf '%s\n' "$TARGET" > "$SEED_FILE"
    python3 -m tools.vuln_assistant analyze \
      --mode client-pitch \
      --domain web \
      --input "$SEED_FILE" \
      --out "$TARGET_DIR/vuln_assistant" | tee "$REPORT_DIR/session.log"
    generate_summary "$REPORT_DIR" "client-pitch" "$TARGET" "$(date +%s)" "$EXIT_CLEAN" "completed" >/dev/null 2>&1 || true
    echo "[*] Client pitch artifacts: $TARGET_DIR/vuln_assistant"
    ;;

  ai-security)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh ai-security https://api.example.com [model-name]"
      exit $EXIT_ERROR
    fi

    SCOPE="${SCOPE:-$TARGET}"
    init_report_dir
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    FAILOVER_BACKEND="$(resolve_failover_backend "$PRIMARY_BACKEND" "$FAILOVER_TO")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "ai-security" "$TARGET")"
    _TMP_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/$||' | awk -F/ '{print $NF}' | sed 's|\.|-|g')"
    [ -z "$_TMP_NAME" ] && _TMP_NAME="$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|\.|-|g')"
    TARGET_DIR="$SCRIPT_DIR/targets/$_TMP_NAME"
    PID_FILE="$PID_DIR/ai-${_TMP_NAME}.pid"
    PID_META="$PID_DIR/ai-${_TMP_NAME}.json"

    if [ "$DRY_RUN" = true ]; then
      echo "[DRY-RUN] AI/LLM Security mode"
      echo "  Target:  $TARGET"
      echo "  Model:   $SCOPE"
      echo "  Backend: $PRIMARY_BACKEND"
      echo "  Runtime: $EFFECTIVE_PROFILE"
      echo "  Pipeline: ai_security (bounty track: Gate 1/2 + triager-sim)"
      echo "  Steps: target_evaluator → ai_recon+analyst → Gate 1 → exploiter → Gate 2 → reporter → critic → triager → final"
      echo "  Time-box: ~6.5hr"
      exit $EXIT_CLEAN
    fi

    START_TS="$(date +%s)"
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<PROMPT
You are Terminator Team Lead running AI/LLM Security Pipeline.

Target: $TARGET
Model/Scope: $SCOPE
Target directory: $TARGET_DIR
Report directory: $REPORT_DIR
Domain: ai

Follow the ai_security pipeline from pipelines.py (bounty track with Gate 1/2).
Use --domain ai for all bb_preflight.py calls.
Use domain=ai in all agent descriptions (analyst, exploiter, reporter, triager-sim).
AUP compliance is MANDATORY before any probing.

AUTONOMOUS COMPLETION RULES: Same as bounty mode — run full pipeline end-to-end.
Time-Box: Phase 0: 30min | Phase 0.5: 30min | Phase 1: 1.5hr | Phase 1.5: 30min | Phase 2: 2hr | Phase 3-5: 1.5hr
No findings at 1.5hr → ABANDON.
PROMPT

    if [ "$JSON_OUTPUT" = false ]; then
      echo "╔══════════════════════════════════════════╗"
      echo "║   TERMINATOR - AI/LLM Security Mode      ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Target:  $TARGET"
      echo "║ Model:   $SCOPE"
      echo "║ Backend: $PRIMARY_BACKEND"
      echo "║ Runtime: $EFFECTIVE_PROFILE"
      echo "║ Report:  $REPORT_DIR"
      echo "╚══════════════════════════════════════════╝"
    fi

    nohup bash -c "
      START_TS=$START_TS
      python3 -u \"$SCRIPT_DIR/tools/backend_runner.py\" run \
        --backend \"$PRIMARY_BACKEND\" \
        --failover-to \"${FAILOVER_BACKEND:-none}\" \
        --runtime-profile \"$EFFECTIVE_PROFILE\" \
        --prompt-file \"$PROMPT_FILE\" \
        --work-dir \"$SCRIPT_DIR\" \
        --report-dir \"$REPORT_DIR\" \
        --model \"$EFFECTIVE_MODEL\" \
        --mode ai-security \
        --target \"$TARGET\" \
        --scope \"$SCOPE\" \
        --session-id \"$SESSION_ID\" \
        --timeout \"$TIMEOUT\" \
        --result-file \"$REPORT_DIR/runtime_result.json\" 2>&1 | stdbuf -oL tee \"$REPORT_DIR/session.log\"
      RUNTIME_EXIT=\${PIPESTATUS[0]}
      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"
      FINAL_EXIT=\$(bash $SCRIPT_DIR/terminator.sh _exit_code $REPORT_DIR 2>/dev/null || echo 0)
      echo \"\$FINAL_EXIT\" > \"$REPORT_DIR/exit_code\"
      SESSION_STATUS='completed'
      if [ \"\$RUNTIME_EXIT\" -eq 124 ] 2>/dev/null; then SESSION_STATUS='timeout'
      elif [ \"\$RUNTIME_EXIT\" -ne 0 ] 2>/dev/null; then SESSION_STATUS='failed'; fi
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR ai-security '$TARGET' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true
      echo \"\$SESSION_STATUS\" > \"$REPORT_DIR/.completed\"
      rm -f \"$PID_FILE\" \"$PID_META\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    write_pid_meta "$PID_META" "$BGPID" "ai-${_TMP_NAME}" "ai-security" "$TARGET" "$PRIMARY_BACKEND" "${FAILOVER_BACKEND:-}" "$SESSION_ID" "$REPORT_DIR" "$PARALLEL_GROUP_ID"
    echo "$TIMESTAMP mode=ai-security backend=$PRIMARY_BACKEND session=$SESSION_ID pid=$BGPID report=$REPORT_DIR target=$TARGET" >> "$SCRIPT_DIR/.terminator.history"
    if [ "$JSON_OUTPUT" = true ]; then echo "$REPORT_DIR/summary.json"
    else echo ""; echo "[*] PID: $BGPID"; echo "[*] Session: $SESSION_ID"; echo "[*] To monitor: tail -f $REPORT_DIR/session.log"; fi
    if [ "$WAIT_FOR_COMPLETION" = true ]; then
      echo "[*] --wait: blocking until session completes..."
      while kill -0 "$BGPID" 2>/dev/null; do sleep 15; done
      echo ""; echo "=== SESSION RESULT: ai-${_TMP_NAME} ==="; cat "$REPORT_DIR/.completed" 2>/dev/null || echo "unknown"
      echo "---"; tail -80 "$REPORT_DIR/session.log" 2>/dev/null; echo "=== END ==="
    fi
    ;;

  # Internal subcommands (used by nohup post-processing blocks)
  _running_count)
    count_running_sessions
    ;;

  _exit_code)
    REPORT_DIR_ARG="${2:-}"
    if [ -n "$REPORT_DIR_ARG" ] && [ -f "$REPORT_DIR_ARG/session.log" ]; then
      if grep -q '\[CRITICAL\]' "$REPORT_DIR_ARG/session.log" 2>/dev/null; then
        echo $EXIT_CRITICAL
      elif grep -q '\[HIGH\]' "$REPORT_DIR_ARG/session.log" 2>/dev/null; then
        echo $EXIT_HIGH
      elif grep -q '\[MEDIUM\]' "$REPORT_DIR_ARG/session.log" 2>/dev/null; then
        echo $EXIT_MEDIUM
      else
        echo $EXIT_CLEAN
      fi
    else
      echo $EXIT_CLEAN
    fi
    ;;

  _summary)
    # Internal: _summary <report_dir> <mode> <target> <start_ts> <exit_code> <status>
    S_REPORT_DIR="${2:-}"
    S_MODE="${3:-unknown}"
    S_TARGET="${4:-}"
    S_START_TS="${5:-0}"
    S_EXIT_CODE="${6:-0}"
    S_STATUS="${7:-completed}"
    generate_summary "$S_REPORT_DIR" "$S_MODE" "$S_TARGET" "$S_START_TS" "$S_EXIT_CODE" "$S_STATUS"
    ;;

  status)
    RUNNING_COUNT=0
    for _pf in "$PID_DIR"/*.pid; do
      [ -f "$_pf" ] || continue
      _PID=$(cat "$_pf")
      _NAME=$(basename "$_pf" .pid)
      _META="${_pf%.pid}.json"
      if kill -0 "$_PID" 2>/dev/null; then
        if [ -f "$_META" ]; then
          _INFO="$(python3 - <<'PY' "$_META"
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(
    "mode={mode} backend={backend} failover={failover} session={session} group={group} target={target}".format(
        mode=data.get("mode", "unknown"),
        backend=data.get("backend", "unknown"),
        failover=data.get("failover_to") or "none",
        session=data.get("session_id", ""),
        group=data.get("parallel_group_id") or "none",
        target=data.get("target", ""),
    )
)
PY
)"
          echo "[*] RUNNING: $_NAME (PID: $_PID) $_INFO"
        else
          echo "[*] RUNNING: $_NAME (PID: $_PID)"
        fi
        RUNNING_COUNT=$((RUNNING_COUNT + 1))
      else
        echo "[*] STALE:   $_NAME (PID: $_PID) — cleaning up"
        rm -f "$_pf"
        rm -f "$_META"
      fi
    done
    # Backward compat: check old single pid file
    if [ -f "$SCRIPT_DIR/.terminator.pid" ]; then
      _PID=$(cat "$SCRIPT_DIR/.terminator.pid")
      if kill -0 "$_PID" 2>/dev/null; then
        echo "[*] RUNNING: (legacy) (PID: $_PID)"
        RUNNING_COUNT=$((RUNNING_COUNT + 1))
      else
        rm -f "$SCRIPT_DIR/.terminator.pid"
      fi
    fi
    if [ "$RUNNING_COUNT" -eq 0 ]; then
      echo "[*] No active sessions"
    else
      echo ""
      echo "[*] $RUNNING_COUNT session(s) running"
    fi
    echo ""
    echo "[*] Recent sessions:"
    tail -10 "$SCRIPT_DIR/.terminator.history" 2>/dev/null || echo "  (none)"
    ;;

  logs)
    LATEST=$(ls -td "$SCRIPT_DIR/reports"/20* 2>/dev/null | head -1)
    if [ -n "$LATEST" ] && [ -f "$LATEST/session.log" ]; then
      echo "[*] Tailing: $LATEST/session.log"
      echo "[*] Ctrl+C to stop"
      tail -f "$LATEST/session.log"
    else
      echo "[!] No session logs found"
    fi
    ;;

  help|*)
    echo "Terminator - Autonomous Security Agent"
    echo ""
    echo "Usage:"
    echo "  ./terminator.sh [OPTIONS] bounty <url> [scope]             Bug bounty assessment"
    echo "  ./terminator.sh [OPTIONS] ai-security <url> [scope]        AI/LLM security assessment"
    echo "  ./terminator.sh [OPTIONS] client-pitch <url>               Passive client pitch pack"
    echo "  ./terminator.sh status                                      Check running session"
    echo "  ./terminator.sh logs                                        Tail latest session log"
    echo ""
    echo "Options:"
    echo "  --json                  Suppress banner; print summary.json path on completion"
    echo "  --timeout N             Abort session after N seconds (0 = no limit)"
    echo "  --dry-run               Print execution plan without running a backend"
    echo "  --resume-session ID     Reuse an existing coordination session id"
    echo "  --backend NAME          Runtime launcher: claude|codex|hybrid|auto"
    echo "  --runtime-profile NAME  Runtime profile: claude-only|gpt-only|scope-first-hybrid"
    echo ""
    echo "Environment:"
    echo "  TERMINATOR_MODEL         Shared default model override"
    echo "  TERMINATOR_CLAUDE_MODEL  Claude model override (default: sonnet)"
    echo "  TERMINATOR_CODEX_MODEL   Codex model override (default: gpt-5.5)"
    echo "  TERMINATOR_PRIMARY_BACKEND  claude|codex|hybrid (default: hybrid)"
    echo "  TERMINATOR_RUNTIME_PROFILE  claude-only|gpt-only|scope-first-hybrid"
    echo "  TERMINATOR_FAILOVER_TO   Spare override (claude|codex|none, default: codex)"
    echo ""
    echo "Behavior:"
    echo "  claude-only uses Claude as launcher and role backend."
    echo "  gpt-only uses Codex/OMX as launcher and role backend."
    echo "  scope-first-hybrid routes selected roles to Codex and enforces scope/safety gates."
    echo ""
    echo "Exit Codes:"
    echo "  0   Clean (no findings or pitch generated)"
    echo "  1   Critical severity finding"
    echo "  2   High severity finding"
    echo "  3   Medium severity finding"
    echo "  10  Script error"
    echo ""
    echo "Reports: ./reports/<timestamp>/"
    echo "  session.log            Full session transcript"
    echo "  summary.json           Machine-readable session summary"
    echo "  exit_code              Numeric exit code based on findings"
    echo "  high_value_targets.md  Risk-ranked targets when vuln_assistant is used"
    echo "  security_assessment_pitch.md  Client pitch artifact"
    ;;
esac
