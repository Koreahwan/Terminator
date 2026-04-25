#!/bin/bash
# Terminator - Autonomous Security Agent Launcher
# Uses Claude Code, Codex/OMX, or hybrid runtime routing with bypassPermissions
#
# Usage:
#   ./terminator.sh [--json] [--timeout N] [--dry-run] [--competition-v2|--competition] ctf /path/to/challenge.zip
#   ./terminator.sh [--json] [--timeout N] [--dry-run] bounty https://target.com "*.target.com"
#   ./terminator.sh firmware /path/to/firmware.bin
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

BACKEND="${REQUESTED_BACKEND:-${TERMINATOR_PRIMARY_BACKEND:-claude}}"
FAILOVER_TO="${TERMINATOR_FAILOVER_TO:-codex}"
if [ -n "$REQUESTED_FAILOVER_TO" ]; then
  FAILOVER_TO="$REQUESTED_FAILOVER_TO"
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
      printf '%s\n' "${TERMINATOR_PRIMARY_BACKEND:-claude}"
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
    codex) printf '%s\n' "${TERMINATOR_CODEX_MODEL:-gpt-5.4}" ;;
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
          ctf-*) session_mode="ctf" ;;
          fw-*) session_mode="firmware" ;;
          ai-*) session_mode="ai-security" ;;
          robo-*) session_mode="robotics" ;;
          sc-*) session_mode="supplychain" ;;
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

case "$MODE" in
  ctf)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh ctf /path/to/challenge[.zip]"
      exit $EXIT_ERROR
    fi

    CHALLENGE_DIR="$(extract_if_zip "$(realpath "$TARGET")")"
    FILES=$(ls -1 "$CHALLENGE_DIR" 2>/dev/null | head -30)
    init_report_dir
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    FAILOVER_BACKEND="$(resolve_failover_backend "$PRIMARY_BACKEND" "$FAILOVER_TO")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "ctf" "$CHALLENGE_DIR")"
    PID_FILE="$PID_DIR/ctf-$(basename "$CHALLENGE_DIR").pid"
    PID_META="$PID_DIR/ctf-$(basename "$CHALLENGE_DIR").json"
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    COMPETITION_PLAN_FILE="$REPORT_DIR/competition_plan.json"

    if [ "$CTF_COMPETITION_V2" = true ]; then
      python3 "$SCRIPT_DIR/tools/ctf_competition.py" plan \
        --challenge-dir "$CHALLENGE_DIR" \
        --report-dir "$REPORT_DIR" \
        --prompt-out "$PROMPT_FILE" \
        --plan-out "$COMPETITION_PLAN_FILE" >/dev/null
    else
      cat > "$PROMPT_FILE" <<PROMPT
You are Terminator Team Lead. Use Claude Code Agent Teams to solve this CTF challenge.

Challenge directory: $CHALLENGE_DIR
Files found: $FILES
Report directory: $REPORT_DIR

MANDATORY: Read .claude/rules-ctf/_ctf_pipeline.md and follow it. Use custom agent types (NOT general-purpose).

STEP 1: Create team
- TeamCreate('terminator-ctf')

STEP 2: Pre-check (do this yourself before spawning agents)
- file and strings on binaries, checksec
- Determine problem type: pwn / reversing / crypto

STEP 3: Spawn pipeline agents (Task tool, team_name='terminator-ctf', mode=bypassPermissions)

For PWN:
  @reverser (subagent_type=reverser, model=sonnet) → reversal_map.md
  @trigger (subagent_type=trigger, model=sonnet) → trigger_report.md [if crash needed]
  @chain (subagent_type=chain, model=claude-opus-4-6[1m]) → solve.py
  @critic (subagent_type=critic, model=claude-opus-4-6[1m]) → critic_review.md
  @verifier (subagent_type=verifier, model=sonnet) → FLAG_FOUND
  @reporter (subagent_type=reporter, model=sonnet) → writeup

For REVERSING/CRYPTO:
  @reverser (subagent_type=reverser, model=sonnet) → reversal_map.md
  @solver (subagent_type=solver, model=claude-opus-4-6[1m]) → solve.py
  @critic (subagent_type=critic, model=claude-opus-4-6[1m]) → critic_review.md
  @verifier (subagent_type=verifier, model=sonnet) → FLAG_FOUND
  @reporter (subagent_type=reporter, model=sonnet) → writeup

Pass each agent's output to the next via structured HANDOFF.
Save solve.py to $CHALLENGE_DIR/solve.py
Save writeup to $REPORT_DIR/writeup.md

STEP 4: Collect results
- Verify FLAG_FOUND by running solve.py yourself
- Update knowledge/index.md
- TeamDelete

Flag formats: DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}
PROMPT
    fi

    if [ "$DRY_RUN" = true ]; then
      if [ "$JSON_OUTPUT" = true ]; then
        if [ "$CTF_COMPETITION_V2" = true ] && [ -f "$COMPETITION_PLAN_FILE" ]; then
          python3 - <<PY
import json
from tools.ctf_competition import build_competition_dry_run_payload
print(json.dumps(build_competition_dry_run_payload(
    challenge_dir='$CHALLENGE_DIR',
    backend='$PRIMARY_BACKEND',
    failover_to='$FAILOVER_BACKEND',
    model='$EFFECTIVE_MODEL',
    report_dir='$REPORT_DIR',
    timeout=$TIMEOUT,
    session_id='$SESSION_ID',
    plan_path='$COMPETITION_PLAN_FILE',
), indent=2))
PY
        else
          python3 -c "
import json
plan = {
    'dry_run': True,
    'mode': 'ctf',
    'target': '$CHALLENGE_DIR',
    'backend': '$PRIMARY_BACKEND',
    'failover_to': '$FAILOVER_BACKEND',
    'runtime_profile': '$EFFECTIVE_PROFILE',
    'model': '$EFFECTIVE_MODEL',
    'report_dir': '$REPORT_DIR',
    'timeout': $TIMEOUT,
    'session_id': '$SESSION_ID',
    'steps': [
        'extract_if_zip',
        'spawn_reverser_agent',
        'spawn_chain_agent',
        'spawn_verifier_agent',
        'spawn_reporter_agent',
        'generate_summary'
    ]
}
print(json.dumps(plan, indent=2))
"
        fi
      else
        if [ "$CTF_COMPETITION_V2" = true ] && [ -f "$COMPETITION_PLAN_FILE" ]; then
          COMPETITION_LANE="$(python3 -c "import json; print(json.load(open('$COMPETITION_PLAN_FILE')).get('lane','unknown'))" 2>/dev/null || echo "unknown")"
          COMPETITION_ADAPTER="$(python3 -c "import json; print(json.load(open('$COMPETITION_PLAN_FILE')).get('adapter','unknown'))" 2>/dev/null || echo "unknown")"
          COMPETITION_RETRY="$(python3 -c "import json; print(json.load(open('$COMPETITION_PLAN_FILE')).get('retry_budget',1))" 2>/dev/null || echo "1")"
          echo "[DRY-RUN] CTF competition-v2 mode"
          echo "  Challenge: $CHALLENGE_DIR"
          echo "  Files:     $FILES"
          echo "  Lane:      $COMPETITION_LANE"
          echo "  Adapter:   $COMPETITION_ADAPTER"
          echo "  Retries:   $COMPETITION_RETRY"
          echo "  Backend:   $PRIMARY_BACKEND"
          echo "  Runtime:   $EFFECTIVE_PROFILE"
          echo "  Spare:     ${FAILOVER_BACKEND:-none} (Claude quota/context/API interruption only)"
          echo "  Model:     $EFFECTIVE_MODEL"
          echo "  Session:   $SESSION_ID"
          echo "  Report:    $REPORT_DIR"
          echo "  Timeout:   ${TIMEOUT}s (0=none)"
          echo "  Would run: python3 tools/backend_runner.py run --backend $PRIMARY_BACKEND ..."
        else
          echo "[DRY-RUN] CTF mode"
        echo "  Challenge: $CHALLENGE_DIR"
        echo "  Files:     $FILES"
        echo "  Backend:   $PRIMARY_BACKEND"
        echo "  Runtime:   $EFFECTIVE_PROFILE"
        echo "  Spare:     ${FAILOVER_BACKEND:-none} (Claude quota/context/API interruption only)"
        echo "  Model:     $EFFECTIVE_MODEL"
        echo "  Session:   $SESSION_ID"
        echo "  Report:    $REPORT_DIR"
        echo "  Timeout:   ${TIMEOUT}s (0=none)"
        echo "  Would run: python3 tools/backend_runner.py run --backend $PRIMARY_BACKEND ..."
        fi
      fi
      exit $EXIT_CLEAN
    fi

    if [ "$JSON_OUTPUT" = false ]; then
      COMPETITION_LANE=""
      if [ "$CTF_COMPETITION_V2" = true ] && [ -f "$COMPETITION_PLAN_FILE" ]; then
        COMPETITION_LANE="$(python3 -c "import json; print(json.load(open('$COMPETITION_PLAN_FILE')).get('lane','unknown'))" 2>/dev/null || echo "unknown")"
      fi
      echo "╔══════════════════════════════════════════╗"
      echo "║        TERMINATOR - CTF Mode             ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Challenge: $(basename "$CHALLENGE_DIR")"
      echo "║ Files:     $FILES"
      if [ -n "$COMPETITION_LANE" ]; then
        echo "║ Profile:   competition-v2/$COMPETITION_LANE"
      fi
      echo "║ Backend:   $PRIMARY_BACKEND"
      echo "║ Runtime:   $EFFECTIVE_PROFILE"
      echo "║ Spare:     ${FAILOVER_BACKEND:-none}"
      echo "║ Model:     $EFFECTIVE_MODEL"
      echo "║ Report:    $REPORT_DIR"
      echo "║ Log:       $REPORT_DIR/session.log"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Running in background...                 ║"
      echo "║ Monitor:  tail -f $REPORT_DIR/session.log"
      echo "║ Status:   ./terminator.sh status         ║"
      echo "╚══════════════════════════════════════════╝"
    fi

    START_TS="$(date +%s)"

    # Run in background with nohup
    nohup bash -c "
      START_TS=$START_TS

      # Cleanup on crash/signal
      _cleanup() {
        echo \"[SIGNAL] Session interrupted at \$(date)\" >> \"$REPORT_DIR/session.log\" 2>/dev/null || true
        rm -f \"$PID_FILE\" \"$PID_META\"
        exit 1
      }
      trap _cleanup SIGTERM SIGINT SIGHUP

      python3 -u \"$SCRIPT_DIR/tools/backend_runner.py\" run \
        --backend \"$PRIMARY_BACKEND\" \
        --failover-to \"${FAILOVER_BACKEND:-none}\" \
        --runtime-profile \"$EFFECTIVE_PROFILE\" \
        --prompt-file \"$PROMPT_FILE\" \
        --work-dir \"$SCRIPT_DIR\" \
        --report-dir \"$REPORT_DIR\" \
        --model \"$EFFECTIVE_MODEL\" \
        --mode ctf \
        --target \"$CHALLENGE_DIR\" \
        --session-id \"$SESSION_ID\" \
        --timeout \"$TIMEOUT\" \
        --result-file \"$REPORT_DIR/runtime_result.json\" 2>&1 | stdbuf -oL tee \"$REPORT_DIR/session.log\"
      RUNTIME_EXIT=\${PIPESTATUS[0]}

      # Post-processing
      echo '' >> \"$REPORT_DIR/session.log\"
      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"
      echo \"Timestamp: \$(date)\" >> \"$REPORT_DIR/session.log\"

      # Extract flags
      FLAGS=\$(python3 - <<PY
import json
from pathlib import Path
from tools.ctf_competition import extract_ctf_flags
log_path = Path("$REPORT_DIR/session.log")
text = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
flags = extract_ctf_flags(text, challenge_dir="$CHALLENGE_DIR")
print("\\n".join(flags))
PY
)
      if [ -n \"\${FLAGS:-}\" ]; then
        echo \"FLAGS FOUND:\" >> \"$REPORT_DIR/session.log\"
        echo \"\$FLAGS\" >> \"$REPORT_DIR/session.log\"
        echo \"\$FLAGS\" > \"$REPORT_DIR/flags.txt\"
      else
        echo 'NO FLAGS FOUND' >> \"$REPORT_DIR/session.log\"
      fi

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

      # Generate summary.json
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR ctf '$CHALLENGE_DIR' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true

      # Write completion marker for --wait detection
      echo \"\$SESSION_STATUS\" > \"$REPORT_DIR/.completed\"

      rm -f \"$PID_FILE\"
      rm -f \"$PID_META\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    write_pid_meta "$PID_META" "$BGPID" "ctf-$(basename "$CHALLENGE_DIR")" "ctf" "$CHALLENGE_DIR" "$PRIMARY_BACKEND" "${FAILOVER_BACKEND:-}" "$SESSION_ID" "$REPORT_DIR" "$PARALLEL_GROUP_ID"
    echo "$TIMESTAMP mode=ctf backend=$PRIMARY_BACKEND failover=${FAILOVER_BACKEND:-none} session=$SESSION_ID pid=$BGPID report=$REPORT_DIR target=$CHALLENGE_DIR group=${PARALLEL_GROUP_ID:-none}" >> "$SCRIPT_DIR/.terminator.history"

    if [ "$JSON_OUTPUT" = true ]; then
      echo "$REPORT_DIR/summary.json"
    else
      echo ""
      echo "[*] PID: $BGPID"
      echo "[*] Session: $SESSION_ID"
      echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    fi

    if [ "$WAIT_FOR_COMPLETION" = true ]; then
      echo "[*] --wait: blocking until session completes..."
      while kill -0 "$BGPID" 2>/dev/null; do sleep 15; done
      echo ""; echo "=== SESSION RESULT: ctf-$(basename "$CHALLENGE_DIR") ==="
      cat "$REPORT_DIR/.completed" 2>/dev/null || echo "unknown"
      echo "---"; tail -80 "$REPORT_DIR/session.log" 2>/dev/null; echo "=== END ==="
    fi
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
    'steps': [
        'phase_0_target_evaluator',
        'phase_0_scope_contract_create',
        'phase_0_scope_auditor',
        'phase_0_safety_wrapper_config',
        'phase_0_2_bb_preflight_rules',
        'phase_0_5_automated_tool_scan',
        'phase_1_scout_analyst_threat_modeler_patch_hunter',
        'phase_1_5_workflow_auditor_web_tester',
        'gate_1_2_coverage_workflow_check',
        'kill_gate_1_triager_sim_finding_viability',
        'phase_2_exploiter_poc_validation',
        'kill_gate_2_triager_sim_poc_destruction',
        'phase_3_reporter',
        'phase_4_critic_factcheck',
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

    if [ "$EFFECTIVE_PROFILE" = "scope-first-hybrid" ]; then
      echo "[*] Scope-first Phase 0: passive program fetch + scope contract"
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" init "$TARGET_DIR" >/dev/null
      python3 "$SCRIPT_DIR/tools/bb_preflight.py" fetch-program "$TARGET_DIR" "$TARGET" --hold-ok
      python3 "$SCRIPT_DIR/tools/scope_contract.py" create "$TARGET_DIR" --allow-hold
      echo "[*] Scope-first Phase 0: scope_contract.json ready"
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
Search knowledge-fts MCP before each agent spawn.
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

  firmware)
    if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
      echo "Usage: ./terminator.sh firmware /path/to/firmware.bin"
      exit 1
    fi

    TARGET_PATH="$(realpath "$TARGET")"
    PID_FILE="$PID_DIR/fw-$(basename "$TARGET_PATH" | sed 's/\./-/g').pid"
    PID_META="$PID_DIR/fw-$(basename "$TARGET_PATH" | sed 's/\./-/g').json"
    FIRMWARE_PROFILE="${TERMINATOR_FIRMWARE_PROFILE:-analysis}"
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    FAILOVER_BACKEND="$(resolve_failover_backend "$PRIMARY_BACKEND" "$FAILOVER_TO")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "firmware" "$TARGET_PATH")"

    if [ "$FIRMWARE_PROFILE" != "analysis" ] && [ "$FIRMWARE_PROFILE" != "exploit" ]; then
      echo "[!] Invalid TERMINATOR_FIRMWARE_PROFILE='$FIRMWARE_PROFILE'. Allowed values: analysis, exploit."
      exit 1
    fi

    if [ "$DRY_RUN" = true ]; then
      echo "[DRY-RUN] Firmware mode"
      echo "  Firmware: $TARGET_PATH"
      echo "  Profile:  $FIRMWARE_PROFILE"
      echo "  Backend:  $PRIMARY_BACKEND"
      echo "  Runtime:  $EFFECTIVE_PROFILE"
      echo "  Spare:    ${FAILOVER_BACKEND:-none}"
      echo "  Model:    $EFFECTIVE_MODEL"
      echo "  Pipeline: firmware (profiler → inventory → surface → validator)"
      echo "  Safety:   no AIEdge execution; authorization gate not consumed"
      echo "  Would run: AIEdge initial subset, then backend_runner with --backend $PRIMARY_BACKEND"
      exit 0
    fi

    if [ "${TERMINATOR_ACK_AUTHORIZATION:-}" != "1" ]; then
      echo "[!] Firmware mode blocked: set TERMINATOR_ACK_AUTHORIZATION=1 to confirm explicit authorization."
      exit 1
    fi

    EXPLOIT_GATE_JSON=""
    PROMPT_EXPLOIT_GATE_BLOCK="- Analysis profile: no exploit stages."
    if [ "$FIRMWARE_PROFILE" = "exploit" ]; then
      if [ -z "${TERMINATOR_EXPLOIT_FLAG:-}" ] || [ -z "${TERMINATOR_EXPLOIT_ATTESTATION:-}" ] || [ -z "${TERMINATOR_EXPLOIT_SCOPE:-}" ]; then
        echo "[!] Firmware exploit profile blocked: set TERMINATOR_EXPLOIT_FLAG, TERMINATOR_EXPLOIT_ATTESTATION, and TERMINATOR_EXPLOIT_SCOPE."
        exit 1
      fi

      EXPLOIT_GATE_JSON=$(cat <<EOF
,
  "exploit_gate": {
    "flag": "${TERMINATOR_EXPLOIT_FLAG}",
    "attestation": "${TERMINATOR_EXPLOIT_ATTESTATION}",
    "scope": "${TERMINATOR_EXPLOIT_SCOPE}"
  }
EOF
)

      PROMPT_EXPLOIT_GATE_BLOCK=$(cat <<EOF
- Exploit profile: exploit stages are allowed within declared scope, with evidence bundles.
- Exploit authorization is lab-only and explicit for this run:
  - TERMINATOR_EXPLOIT_FLAG=${TERMINATOR_EXPLOIT_FLAG}
  - TERMINATOR_EXPLOIT_ATTESTATION=${TERMINATOR_EXPLOIT_ATTESTATION}
  - TERMINATOR_EXPLOIT_SCOPE=${TERMINATOR_EXPLOIT_SCOPE}
- Do not exceed stated scope. Treat this as authorized laboratory work only.
EOF
)
    fi

    init_report_dir
    cat > "$REPORT_DIR/firmware_handoff.json" <<EOF
{
  "mode": "firmware",
  "profile": "$FIRMWARE_PROFILE",
  "status": "pending",
  "policy": {
    "max_reruns_per_stage": 2,
    "max_total_stage_attempts": 10,
    "max_wallclock_per_run": 3600
  },
  "bundles": [],
  "stop_reason": ""${EXPLOIT_GATE_JSON},
  "aiedge": {
    "run_dir": "",
    "run_id": "",
    "stages_executed": []
  }
}
EOF
    : > "$REPORT_DIR/firmware_summary.md"
    : > "$REPORT_DIR/session.log"
    AIEDGE_HANDOFF_ADAPTER="$SCRIPT_DIR/aiedge_handoff_adapter.py"

    AIEDGE_RUN_DIR=""
    AIEDGE_RUN_ID=""
    AIEDGE_HOFF_STATUS="pending"
    AIEDGE_STOP_REASON=""

    INITIAL_STAGE_SUBSET="tooling,carving,firmware_profile,inventory"
    echo "[*] Running initial AIEdge stages: $INITIAL_STAGE_SUBSET" >> "$REPORT_DIR/session.log"
    set +e
    SCOUT_DIR="${SCOUT_DIR:-$HOME/SCOUT}"
    AIEDGE_CMD_OUTPUT="$(cd "$SCOUT_DIR" && PYTHONPATH="$SCOUT_DIR/src" python3 -m aiedge analyze "$TARGET_PATH" --case-id terminator-firmware --ack-authorization --no-llm --stages "$INITIAL_STAGE_SUBSET" 2>&1)"
    AIEDGE_CMD_STATUS=$?
    set -e
    if [ -n "$AIEDGE_CMD_OUTPUT" ]; then
      printf '%s\n' "$AIEDGE_CMD_OUTPUT" >> "$REPORT_DIR/session.log"
    fi

    AIEDGE_RUN_DIR="$(AIEDGE_OUTPUT="$AIEDGE_CMD_OUTPUT" python3 - <<'PY'
import os
import re
from pathlib import Path

output = os.environ.get("AIEDGE_OUTPUT", "")
lines = [line.strip() for line in output.splitlines() if line.strip()]
candidates = []

for line in lines:
    lowered = line.lower()
    if "run_dir" in lowered:
        match = re.search(r"(/[^\s]+)", line)
        if match:
            candidates.append(match.group(1).rstrip(".,:;\"'"))
    elif line.startswith("/"):
        candidates.append(line.rstrip(".,:;\"'"))

for candidate in reversed(candidates):
    run_dir = Path(candidate)
    if run_dir.is_dir() and (run_dir / "manifest.json").is_file():
        print(str(run_dir.resolve()))
        break
PY
)"

    if [ "$AIEDGE_CMD_STATUS" -eq 0 ] && [ -n "$AIEDGE_RUN_DIR" ]; then
      AIEDGE_RUN_ID="$(python3 - <<'PY' "$AIEDGE_RUN_DIR"
import json
import sys

manifest_path = sys.argv[1] + "/manifest.json"
try:
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
except Exception:
    print("")
    raise SystemExit(0)

run_id = manifest.get("run_id", "")
if isinstance(run_id, str):
    print(run_id)
else:
    print("")
PY
)"

      if [ -z "$AIEDGE_RUN_ID" ]; then
        AIEDGE_HOFF_STATUS="failed"
        AIEDGE_STOP_REASON="Initial AIEdge firmware subset run missing run_id in manifest.json"
      fi
    else
      AIEDGE_HOFF_STATUS="failed"
      AIEDGE_STOP_REASON="Initial AIEdge firmware subset run failed (exit $AIEDGE_CMD_STATUS): ${AIEDGE_CMD_OUTPUT//$'\n'/ | }"
      if [ -z "$AIEDGE_RUN_DIR" ]; then
        AIEDGE_STOP_REASON="$AIEDGE_STOP_REASON; run_dir not found"
      fi
    fi

    python3 - <<'PY' "$REPORT_DIR/firmware_handoff.json" "$AIEDGE_HOFF_STATUS" "$AIEDGE_STOP_REASON" "$AIEDGE_RUN_DIR" "$AIEDGE_RUN_ID" "$INITIAL_STAGE_SUBSET"
import json
import sys
from pathlib import Path

handoff_path = sys.argv[1]
status = sys.argv[2]
stop_reason = sys.argv[3]
run_dir = sys.argv[4]
run_id = sys.argv[5]
initial_stages_csv = sys.argv[6]
initial_stages = [stage.strip() for stage in initial_stages_csv.split(",") if stage.strip()]

with open(handoff_path, "r", encoding="utf-8") as fh:
    handoff = json.load(fh)

handoff["status"] = status
handoff["stop_reason"] = stop_reason
handoff["aiedge"]["run_dir"] = run_dir
handoff["aiedge"]["run_id"] = run_id
handoff["aiedge"]["stages_executed"] = initial_stages if run_dir else []

candidate_artifacts = [
    "stages/tooling/stage.json",
    "stages/tooling/attempts/attempt-1/stage.json",
    "stages/carving/stage.json",
    "stages/carving/attempts/attempt-1/stage.json",
    "stages/firmware_profile/stage.json",
    "stages/firmware_profile/attempts/attempt-1/stage.json",
    "stages/firmware_profile/firmware_profile.json",
    "stages/inventory/stage.json",
    "stages/inventory/attempts/attempt-1/stage.json",
    "stages/inventory/inventory.json",
    "report/report.json",
]

if run_dir:
    resolved_run_dir = Path(run_dir)
    bundle_artifacts = [
        artifact
        for artifact in candidate_artifacts
        if (resolved_run_dir / artifact).is_file()
    ]
else:
    bundle_artifacts = []

handoff.setdefault("bundles", []).append(
    {
        "claim": "Initial AIEdge firmware subset executed to seed evidence handoff.",
        "artifacts": bundle_artifacts,
        "confidence": "low",
        "limitations": [
            "Bundle reflects only initial subset coverage before rerun expansion.",
            "Confidence placeholder requires analyst review.",
        ],
        "next_stage_request": {
            "stages": [],
            "why": "Placeholder; follow fw_profiler routing from firmware_profile.json before scheduling reruns.",
        },
    }
)

with open(handoff_path, "w", encoding="utf-8") as fh:
    json.dump(handoff, fh, indent=2)
    fh.write("\n")
PY

    START_TS="$(date +%s)"

    echo "╔══════════════════════════════════════════╗"
    echo "║      TERMINATOR - Firmware Mode          ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║ Firmware: $TARGET_PATH"
    echo "║ Profile:  $FIRMWARE_PROFILE"
    echo "║ Backend:  $PRIMARY_BACKEND"
    echo "║ Runtime:  $EFFECTIVE_PROFILE"
    echo "║ Spare:    ${FAILOVER_BACKEND:-none}"
    echo "║ Model:    $EFFECTIVE_MODEL"
    echo "║ Report:   $REPORT_DIR"
    echo "║ Log:      $REPORT_DIR/session.log"
    echo "╠══════════════════════════════════════════╣"
    echo "║ Running in background...                 ║"
    echo "║ Monitor:  tail -f $REPORT_DIR/session.log"
    echo "║ Status:   ./terminator.sh status         ║"
    echo "╚══════════════════════════════════════════╝"

    cat > "$REPORT_DIR/firmware_prompt.txt" <<PROMPT
You are Terminator Firmware Team Lead. Run a firmware analysis pipeline with stage-level control using AIEdge.

Firmware target: $TARGET_PATH
Firmware profile: $FIRMWARE_PROFILE
Report directory: $REPORT_DIR
SCOUT root: \${SCOUT_DIR:-\$HOME/SCOUT}
AIEdge adapter contract: \${SCOUT_DIR:-\$HOME/SCOUT}/docs/aiedge_adapter_contract.md
Evidence bundle contract: $SCRIPT_DIR/knowledge/contracts/firmware_evidence_bundle.md

Requirements:
1) Use subprocess CLI execution for AIEdge only (no in-process API):
   PYTHONPATH=\${SCOUT_DIR:-\$HOME/SCOUT}/src python3 -m aiedge analyze \"$TARGET_PATH\" --ack-authorization --no-llm --stages <comma-separated-stage-subset>
2) Initialize policy in $REPORT_DIR/firmware_handoff.json and enforce caps with these defaults:
   - max_reruns_per_stage: 2
   - max_total_stage_attempts: 10
   - max_wallclock_per_run: 3600 (seconds)
3) Use --stages subsets to iterate per stage group as needed; rerun targeted stages only when evidence is incomplete.
    - Every rerun must cite AIEdge append-only manifest paths: stages/<stage>/attempts/attempt-<n>/stage.json
    - To schedule stages by name on an existing run dir, use the adapter command (subprocess-only + atomic handoff update):
      python3 $AIEDGE_HANDOFF_ADAPTER stages --handoff $REPORT_DIR/firmware_handoff.json --stages tooling,carving,firmware_profile,inventory --log-file $REPORT_DIR/session.log
    - The adapter executes exactly: PYTHONPATH=\${SCOUT_DIR:-\$HOME/SCOUT}/src python3 -m aiedge stages <run_dir> --stages <subset>
    - <run_dir> must come from $REPORT_DIR/firmware_handoff.json field aiedge.run_dir.
    - Do not manually edit firmware_handoff.json for reruns; always use adapter invocations so bundles/stages_executed stay consistent.
4) Treat stages/<stage>/stage.json manifests and report.json as source-of-truth evidence.
   - Never infer stage state from logs.
5) Evidence bundle output is JSON-first and must follow this shape for each stage claim:
   {\"claim\":\"...\",\"artifacts\":[...],\"confidence\":\"high|medium|low\",\"limitations\":[...],\"next_stage_request\":{\"stages\":[...],\"why\":\"...\"}}
6) Rerun policy is finite by design (no infinite loops):
   - If any cap is hit, set stop_reason in firmware_handoff.json and stop further reruns.
7) Follow the profile gate for exploit stage behavior.
8) Redaction and compliance:
   - Do not write secrets, credentials, access tokens, private keys, or personally identifying data to session.log, firmware_summary.md, or bundle artifacts.
   - If sensitive values are unavoidable in source artifacts, redact before quoting and mark redaction clearly.
9) Profile gate:
$PROMPT_EXPLOIT_GATE_BLOCK
10) Firmware planning roles (mandatory):
    - Read and follow these role definitions before each planning decision:
      - $SCRIPT_DIR/.claude/agents/fw_profiler.md
      - $SCRIPT_DIR/.claude/agents/fw_inventory.md
      - $SCRIPT_DIR/.claude/agents/fw_surface.md
      - $SCRIPT_DIR/.claude/agents/fw_validator.md
    - Use fw_profiler routing from stages/firmware_profile/firmware_profile.json:
      - branch_plan.inventory_mode=filesystem -> prioritize inventory + surface stages over extracted filesystem.
      - branch_plan.inventory_mode=binary_only -> prioritize binary-focused surface and graph stages.
     - Schedule every additional subset using the adapter; do not hand-edit firmware_handoff.json.
11) Tribunal adjudication (mandatory, JSONL + cache-aware):
    - Materialize tribunal artifacts under $REPORT_DIR/tribunal/:
      - analyst_candidates.jsonl
      - critic_reviews.jsonl
      - judged_findings.jsonl
      - decision_trace.jsonl
    - JSONL means one JSON object per line; keep machine-readable and deterministic.
    - Prefilter candidates to top-N before critic/judge passes; default top_n=50 unless stricter policy already exists in handoff.
    - Every judged finding MUST include admissible evidence refs:
      - evidence: [{"path":"run-relative-posix","sha256":"<hex-or-empty>","locator":"json_pointer|line-range|note"}]
    - Never write absolute host paths in tribunal artifacts; all evidence paths are run-relative POSIX.
    - Use cache key inputs: (a) candidate objects, (b) aiedge.run_id + stage manifest sha256s if available, (c) top_n.
    - Use helper: python3 $SCRIPT_DIR/bridge/tribunal_cache.py key --candidates-jsonl $REPORT_DIR/tribunal/analyst_candidates.jsonl --handoff $REPORT_DIR/firmware_handoff.json --top-n <N>
    - Cache store location: $REPORT_DIR/tribunal/cache/<cache_key>.json
    - On cache hit: reuse prior judged outputs (no regeneration), rewrite judged_findings.jsonl from cache, and record cache_hit=true in decision_trace.jsonl.
    - On cache miss: generate critic/judge outputs, then store cache via python3 $SCRIPT_DIR/bridge/tribunal_cache.py put --report-dir $REPORT_DIR --key <cache_key> --judged-jsonl $REPORT_DIR/tribunal/judged_findings.jsonl --top-n <N> --run-id <run_id>
    - decision_trace.jsonl must record top_n and actual judged_count.
    - Validate artifacts before completion:
      python3 $SCRIPT_DIR/bridge/validate_tribunal_artifacts.py --report-dir $REPORT_DIR
    - Run validator immediately after tribunal artifacts are materialized:
      python3 $SCRIPT_DIR/bridge/fw_validator.py --report-dir $REPORT_DIR
    - Enforce confirmed policy fail-closed:
      python3 $SCRIPT_DIR/bridge/validate_confirmed_policy.py --report-dir $REPORT_DIR
      - If this fails and operator chooses to continue, run auto-downgrade + continue:
        python3 $SCRIPT_DIR/bridge/enforce_confirmed_policy.py --report-dir $REPORT_DIR
      - Re-run policy validator after enforcement before final output.

Deliverables (must always exist at end):
- Update $REPORT_DIR/firmware_handoff.json with minimal machine-readable fields:
  {
    \"mode\": \"firmware\",
    \"profile\": \"analysis|exploit\",
    \"status\": \"completed\" | \"failed\",
    \"policy\": {
      \"max_reruns_per_stage\": 2,
      \"max_total_stage_attempts\": 10,
      \"max_wallclock_per_run\": 3600
    },
    \"bundles\": [
      {
        \"claim\": \"...\",
        \"artifacts\": [\"stages/<stage>/stage.json\", \"stages/<stage>/attempts/attempt-<n>/stage.json\"],
        \"confidence\": \"high|medium|low\",
        \"limitations\": [\"...\"],
        \"next_stage_request\": {\"stages\": [\"...\"], \"why\": \"...\"}
      }
    ],
    \"stop_reason\": \"\",
    \"exploit_gate\": {\"flag\": \"...\", \"attestation\": \"...\", \"scope\": \"...\"},
    \"aiedge\": {
      \"run_dir\": \"<absolute run dir>\",
      \"run_id\": \"<run id if present, else empty>\",
      \"stages_executed\": [\"tooling\", \"...\"]
    }
  }
- Include exploit_gate only when profile=exploit.
- Write concise analyst-facing markdown to $REPORT_DIR/firmware_summary.md.
- Keep concise execution notes in $REPORT_DIR/session.log.
- Produce and validate tribunal outputs under $REPORT_DIR/tribunal/ as specified above.

Execution guidance:
- Start with a minimal subset that includes firmware profiling in order (for example: tooling,carving,firmware_profile,inventory), then expand via --stages based on manifest/report evidence.
- Record exactly which stages were actually executed in firmware_handoff.json.
- For each rerun decision, use one adapter invocation and ensure it appends bundle(s) with claim/artifacts/confidence/limitations/next_stage_request.
- Route rerun subsets from firmware_profile.json (linux_fs/filesystem vs binary_only) and cite the artifact path used for the decision.
- If any cap is reached, set stop_reason with cap name + current counters, set status=failed, and end reruns.
- If a run fails, still write failed status with best-known run_dir/run_id and observed stages.
PROMPT

    nohup bash -c "
      python3 -u \"$SCRIPT_DIR/tools/backend_runner.py\" run \
        --backend \"$PRIMARY_BACKEND\" \
        --failover-to \"${FAILOVER_BACKEND:-none}\" \
        --runtime-profile \"$EFFECTIVE_PROFILE\" \
        --prompt-file \"$REPORT_DIR/firmware_prompt.txt\" \
        --work-dir \"$SCRIPT_DIR\" \
        --report-dir \"$REPORT_DIR\" \
        --model \"$EFFECTIVE_MODEL\" \
        --mode firmware \
        --target \"$TARGET_PATH\" \
        --session-id \"$SESSION_ID\" \
        --timeout \"$TIMEOUT\" \
        --result-file \"$REPORT_DIR/runtime_result.json\" 2>&1 | tee \"$REPORT_DIR/session.log\"
      RUNTIME_EXIT=\${PIPESTATUS[0]}

      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"
      FINAL_EXIT=\$(bash $SCRIPT_DIR/terminator.sh _exit_code $REPORT_DIR 2>/dev/null || echo 0)
      echo \"\$FINAL_EXIT\" > \"$REPORT_DIR/exit_code\"

      SESSION_STATUS='completed'
      if [ \"\$RUNTIME_EXIT\" -eq 124 ] 2>/dev/null; then
        SESSION_STATUS='timeout'
      elif [ \"\$RUNTIME_EXIT\" -ne 0 ] 2>/dev/null; then
        SESSION_STATUS='failed'
      fi

      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR firmware '$TARGET_PATH' $START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true
      echo \"\$SESSION_STATUS\" > \"$REPORT_DIR/.completed\"
      rm -f \"$PID_FILE\"
      rm -f \"$PID_META\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    write_pid_meta "$PID_META" "$BGPID" "fw-$(basename "$TARGET_PATH" | sed 's/\./-/g')" "firmware" "$TARGET_PATH" "$PRIMARY_BACKEND" "${FAILOVER_BACKEND:-}" "$SESSION_ID" "$REPORT_DIR" "$PARALLEL_GROUP_ID"
    echo "$TIMESTAMP mode=firmware backend=$PRIMARY_BACKEND failover=${FAILOVER_BACKEND:-none} session=$SESSION_ID pid=$BGPID report=$REPORT_DIR target=$TARGET_PATH group=${PARALLEL_GROUP_ID:-none}" >> "$SCRIPT_DIR/.terminator.history"
    echo ""
    echo "[*] PID: $BGPID"
    echo "[*] Session: $SESSION_ID"
    echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    if [ "$WAIT_FOR_COMPLETION" = true ]; then
      echo "[*] --wait: blocking until session completes..."
      while kill -0 "$BGPID" 2>/dev/null; do sleep 15; done
      echo ""; echo "=== SESSION RESULT: fw-$(basename "$TARGET_PATH") ==="; cat "$REPORT_DIR/.completed" 2>/dev/null || echo "unknown"
      echo "---"; tail -80 "$REPORT_DIR/session.log" 2>/dev/null; echo "=== END ==="
    fi
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

  robotics)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh robotics <ros-master-uri-or-ip> [robot-model]"
      exit $EXIT_ERROR
    fi

    SCOPE="${SCOPE:-$TARGET}"
    init_report_dir
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    FAILOVER_BACKEND="$(resolve_failover_backend "$PRIMARY_BACKEND" "$FAILOVER_TO")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "robotics" "$TARGET")"
    _TMP_NAME="$(echo "$TARGET" | sed 's|:|-|g;s|\.|-|g;s|/|-|g')"
    TARGET_DIR="$SCRIPT_DIR/targets/robo-${_TMP_NAME}"
    PID_FILE="$PID_DIR/robo-${_TMP_NAME}.pid"
    PID_META="$PID_DIR/robo-${_TMP_NAME}.json"

    if [ "$DRY_RUN" = true ]; then
      echo "[DRY-RUN] Robotics/ROS Security mode"
      echo "  Target:  $TARGET"
      echo "  Robot:   $SCOPE"
      echo "  Backend: $PRIMARY_BACKEND"
      echo "  Runtime: $EFFECTIVE_PROFILE"
      echo "  Pipeline: robotics (CVE track: no bounty gates)"
      echo "  Steps: target_evaluator → robo_scanner+analyst → exploiter → reporter(CVE) → critic → cve_manager"
      echo "  Time-box: ~6.5hr"
      exit $EXIT_CLEAN
    fi

    START_TS="$(date +%s)"
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<PROMPT
You are Terminator Team Lead running Robotics/ROS Security Pipeline (CVE track).

Target: $TARGET
Robot Model: $SCOPE
Target directory: $TARGET_DIR
Report directory: $REPORT_DIR
Domain: robotics

Follow the robotics pipeline from pipelines.py (CVE track — no bounty gates).
Use --domain robotics for all bb_preflight.py calls.
Use domain=robotics in all agent descriptions.
Reporter outputs CVE advisory format. Final handoff to cve-manager.
Simulator-first for all PoC. Real hardware ONLY with explicit approval.
Docker fallback for ROS2: docker run --rm --network host ros:humble

AUTONOMOUS COMPLETION RULES: Run full pipeline end-to-end.
Time-Box: Phase 0: 30min | Phase 0.5: 30min | Phase 1: 1.5hr | Phase 1.5: 1hr | Phase 2: 2hr | Phase 3-5: 1hr
PROMPT

    if [ "$JSON_OUTPUT" = false ]; then
      echo "╔══════════════════════════════════════════╗"
      echo "║  TERMINATOR - Robotics/ROS Security Mode ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Target:  $TARGET"
      echo "║ Robot:   $SCOPE"
      echo "║ Backend: $PRIMARY_BACKEND"
      echo "║ Runtime: $EFFECTIVE_PROFILE"
      echo "║ Track:   CVE (GHSA/MITRE)"
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
        --mode robotics \
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
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR robotics '$TARGET' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true
      echo \"\$SESSION_STATUS\" > \"$REPORT_DIR/.completed\"
      rm -f \"$PID_FILE\" \"$PID_META\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    write_pid_meta "$PID_META" "$BGPID" "robo-${_TMP_NAME}" "robotics" "$TARGET" "$PRIMARY_BACKEND" "${FAILOVER_BACKEND:-}" "$SESSION_ID" "$REPORT_DIR" "$PARALLEL_GROUP_ID"
    echo "$TIMESTAMP mode=robotics backend=$PRIMARY_BACKEND session=$SESSION_ID pid=$BGPID report=$REPORT_DIR target=$TARGET" >> "$SCRIPT_DIR/.terminator.history"
    if [ "$JSON_OUTPUT" = true ]; then echo "$REPORT_DIR/summary.json"
    else echo ""; echo "[*] PID: $BGPID"; echo "[*] Session: $SESSION_ID"; echo "[*] To monitor: tail -f $REPORT_DIR/session.log"; fi
    if [ "$WAIT_FOR_COMPLETION" = true ]; then
      echo "[*] --wait: blocking until session completes..."
      while kill -0 "$BGPID" 2>/dev/null; do sleep 15; done
      echo ""; echo "=== SESSION RESULT: robo-${_TMP_NAME} ==="; cat "$REPORT_DIR/.completed" 2>/dev/null || echo "unknown"
      echo "---"; tail -80 "$REPORT_DIR/session.log" 2>/dev/null; echo "=== END ==="
    fi
    ;;

  supplychain)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh supplychain https://github.com/org/repo [npm|pip|maven]"
      exit $EXIT_ERROR
    fi

    SCOPE="${SCOPE:-auto}"
    init_report_dir
    PRIMARY_BACKEND="$(normalize_backend "$BACKEND")"
    FAILOVER_BACKEND="$(resolve_failover_backend "$PRIMARY_BACKEND" "$FAILOVER_TO")"
    EFFECTIVE_MODEL="$(backend_model "$PRIMARY_BACKEND")"
    EFFECTIVE_PROFILE="$(runtime_profile_for_backend "$PRIMARY_BACKEND")"
    SESSION_ID="$(build_session_id "supplychain" "$TARGET")"
    _TMP_NAME="$(echo "$TARGET" | sed 's|https\?://github.com/||;s|/|-|g;s|\.|-|g')"
    [ -z "$_TMP_NAME" ] && _TMP_NAME="sc-target"
    TARGET_DIR="$SCRIPT_DIR/targets/sc-${_TMP_NAME}"
    PID_FILE="$PID_DIR/sc-${_TMP_NAME}.pid"
    PID_META="$PID_DIR/sc-${_TMP_NAME}.json"

    if [ "$DRY_RUN" = true ]; then
      echo "[DRY-RUN] Supply Chain Security mode"
      echo "  Target:  $TARGET"
      echo "  PkgMgr:  $SCOPE"
      echo "  Backend: $PRIMARY_BACKEND"
      echo "  Runtime: $EFFECTIVE_PROFILE"
      echo "  Pipeline: supplychain (bounty/CVE auto-detect)"
      echo "  Steps: target_evaluator → sc_scanner+analyst → [Gate 1 if bounty] → exploiter → [Gate 2 if bounty] → reporter → critic → [triager/cve_manager]"
      echo "  Time-box: ~4.5hr"
      exit $EXIT_CLEAN
    fi

    START_TS="$(date +%s)"
    PROMPT_FILE="$REPORT_DIR/prompt.txt"
    cat > "$PROMPT_FILE" <<PROMPT
You are Terminator Team Lead running Supply Chain Security Pipeline.

Target: $TARGET
Package Manager: $SCOPE
Target directory: $TARGET_DIR
Report directory: $REPORT_DIR
Domain: supplychain

Follow the supplychain pipeline from pipelines.py.
Phase 0 target-evaluator determines bounty_mode (bounty program exists → bounty track, else → CVE track).
Use --domain supplychain for all bb_preflight.py calls.
Use domain=supplychain in all agent descriptions.
NEVER upload packages to any registry. Namespace conflict = existence check only.
Private package names must be obfuscated in reports.

AUTONOMOUS COMPLETION RULES: Run full pipeline end-to-end.
Time-Box: Phase 0: 20min | Phase 0.5: 20min | Phase 1: 1hr | Phase 1.5: 30min | Phase 2: 1.5hr | Phase 3-5: 1hr
No findings at 1hr → ABANDON.
PROMPT

    if [ "$JSON_OUTPUT" = false ]; then
      echo "╔══════════════════════════════════════════╗"
      echo "║  TERMINATOR - Supply Chain Security Mode ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Target:  $TARGET"
      echo "║ PkgMgr:  $SCOPE"
      echo "║ Backend: $PRIMARY_BACKEND"
      echo "║ Runtime: $EFFECTIVE_PROFILE"
      echo "║ Track:   auto-detect (bounty/CVE)"
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
        --mode supplychain \
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
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR supplychain '$TARGET' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true
      echo \"\$SESSION_STATUS\" > \"$REPORT_DIR/.completed\"
      rm -f \"$PID_FILE\" \"$PID_META\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    write_pid_meta "$PID_META" "$BGPID" "sc-${_TMP_NAME}" "supplychain" "$TARGET" "$PRIMARY_BACKEND" "${FAILOVER_BACKEND:-}" "$SESSION_ID" "$REPORT_DIR" "$PARALLEL_GROUP_ID"
    echo "$TIMESTAMP mode=supplychain backend=$PRIMARY_BACKEND session=$SESSION_ID pid=$BGPID report=$REPORT_DIR target=$TARGET" >> "$SCRIPT_DIR/.terminator.history"
    if [ "$JSON_OUTPUT" = true ]; then echo "$REPORT_DIR/summary.json"
    else echo ""; echo "[*] PID: $BGPID"; echo "[*] Session: $SESSION_ID"; echo "[*] To monitor: tail -f $REPORT_DIR/session.log"; fi
    if [ "$WAIT_FOR_COMPLETION" = true ]; then
      echo "[*] --wait: blocking until session completes..."
      while kill -0 "$BGPID" 2>/dev/null; do sleep 15; done
      echo ""; echo "=== SESSION RESULT: sc-${_TMP_NAME} ==="; cat "$REPORT_DIR/.completed" 2>/dev/null || echo "unknown"
      echo "---"; tail -80 "$REPORT_DIR/session.log" 2>/dev/null; echo "=== END ==="
    fi
    ;;

  _parallel_targets)
    GROUP_ID="${PARALLEL_GROUP_ID:-group-$TIMESTAMP}"
    SPEC_SOURCE="$PARALLEL_TARGETS"
    if [ -z "$SPEC_SOURCE" ]; then
      echo "[!] --parallel-targets requires a JSON file path or inline JSON array"
      exit $EXIT_ERROR
    fi
    init_report_dir

    python3 - <<'PY' "$SPEC_SOURCE" > "$REPORT_DIR/parallel_targets.tsv"
import json
import os
import sys
from pathlib import Path

source = sys.argv[1]
raw = Path(source).read_text(encoding="utf-8") if Path(source).exists() else source
data = json.loads(raw)
if isinstance(data, dict):
    data = data.get("targets", [])
for item in data:
    print(
        "\t".join(
            [
                str(item.get("mode", "")),
                str(item.get("target", "")),
                str(item.get("scope", "")),
                str(item.get("backend", "")),
                str(item.get("failover_to", "")),
            ]
        )
    )
PY

    if [ "$DRY_RUN" = true ]; then
      echo "[DRY-RUN] Parallel target group: $GROUP_ID"
      cat "$REPORT_DIR/parallel_targets.tsv"
      exit 0
    fi

    while IFS=$'\t' read -r item_mode item_target item_scope item_backend item_failover; do
      [ -n "$item_mode" ] || continue
      while [ "$(count_running_sessions)" -ge "$MAX_CONCURRENT" ]; do
        sleep 2
      done
      launch_cmd=(env TERMINATOR_PARALLEL_GROUP_ID="$GROUP_ID" "$SCRIPT_DIR/terminator.sh")
      if [ "$JSON_OUTPUT" = true ]; then
        launch_cmd+=(--json)
      fi
      if [ "$TIMEOUT" -gt 0 ] 2>/dev/null; then
        launch_cmd+=(--timeout "$TIMEOUT")
      fi
      launch_cmd+=(--backend "${item_backend:-$BACKEND}" --failover-to "${item_failover:-$FAILOVER_TO}" "$item_mode" "$item_target")
      if [ -n "$item_scope" ]; then
        launch_cmd+=("$item_scope")
      fi
      "${launch_cmd[@]}"
    done < "$REPORT_DIR/parallel_targets.tsv"

    echo "[*] Parallel target group started: $GROUP_ID"
    echo "[*] Max concurrent sessions: $MAX_CONCURRENT"
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
    echo "  ./terminator.sh [OPTIONS] ctf /path/to/challenge[.zip]    Solve a CTF challenge"
    echo "  ./terminator.sh [OPTIONS] bounty <url> [scope]             Bug bounty assessment"
    echo "  ./terminator.sh [OPTIONS] firmware /path/to/firmware.bin   Firmware pipeline"
    echo "  ./terminator.sh status                                      Check running session"
    echo "  ./terminator.sh logs                                        Tail latest session log"
    echo ""
    echo "Options:"
    echo "  --json                  Suppress banner; print summary.json path on completion"
    echo "  --timeout N             Abort session after N seconds (0 = no limit)"
    echo "  --dry-run               Print execution plan without running a backend"
    echo "  --competition-v2        Enable the isolated competition-focused CTF lane (--competition alias)"
    echo "  --resume-session ID     Reuse an existing coordination session id"
    echo "  --backend NAME          Runtime launcher: claude|codex|hybrid|auto"
    echo "  --runtime-profile NAME  Runtime profile: claude-only|gpt-only|scope-first-hybrid"
    echo ""
    echo "Environment:"
    echo "  TERMINATOR_MODEL         Shared default model override"
    echo "  TERMINATOR_CLAUDE_MODEL  Claude model override (default: sonnet)"
    echo "  TERMINATOR_CODEX_MODEL   Codex model override (default: gpt-5.4)"
    echo "  TERMINATOR_PRIMARY_BACKEND  claude|codex|hybrid (default: claude)"
    echo "  TERMINATOR_RUNTIME_PROFILE  claude-only|gpt-only|scope-first-hybrid"
    echo "  TERMINATOR_FAILOVER_TO   Spare override (claude|codex|none, default: codex)"
    echo ""
    echo "Behavior:"
    echo "  claude-only uses Claude as launcher and role backend."
    echo "  gpt-only uses Codex/OMX as launcher and role backend."
    echo "  scope-first-hybrid routes selected roles to Codex and enforces scope/safety gates."
    echo ""
    echo "Exit Codes:"
    echo "  0   Clean (no findings or CTF solved)"
    echo "  1   Critical severity finding"
    echo "  2   High severity finding"
    echo "  3   Medium severity finding"
    echo "  10  Script error"
    echo ""
    echo "Reports: ./reports/<timestamp>/"
    echo "  session.log            Full session transcript"
    echo "  summary.json           Machine-readable session summary"
    echo "  exit_code              Numeric exit code based on findings"
    echo "  firmware_handoff.json  Firmware machine-readable handoff"
    echo "  firmware_summary.md    Firmware analysis summary"
    echo "  writeup.md             Challenge writeup"
    echo "  flags.txt              Extracted flags (if found)"
    ;;
esac
