#!/usr/bin/env python3
"""Terminator Overview — 파일 변경 이벤트 기반 실시간 반영 서버.

GET /                 → OVERVIEW.html
GET /api/status.json  → 현재 리포 상태 (git, 에이전트, MCP, 도구, 파이프라인 rules, knowledge DB …)
GET /api/events       → Server-Sent Events 스트림 (watchdog inotify)

watchdog이 리포 내 파일 변경을 감지하면 즉시 SSE "refresh" 이벤트를 브라우저에 push.
브라우저는 이벤트 수신 즉시 /api/status.json을 refetch해 카드/배너 갱신.
5초 polling은 fallback.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# WSL /mnt/c (DrvFs)는 inotify 미지원, PollingObserver도 시작이 불안정.
# 가벼운 self-polling 스레드로 대체한다 (1.5초).

ROOT = Path(__file__).resolve().parent.parent  # Terminator/
DOCS = Path(__file__).resolve().parent


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default

EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venvs", ".venv",
    ".playwright-mcp", ".pids", ".omc", ".omx", ".claude/skills/_reference",
    "reports", "evidence", "coordination/sessions",
}
EXCLUDE_SUFFIXES = {".pyc", ".log", ".db-shm", ".db-wal", ".tmp"}
IDLE_TIMEOUT = max(0, env_int("OVERVIEW_IDLE_TIMEOUT", 300))
_activity_lock = threading.Lock()
_last_activity_ts = time.time()
_shutdown_event = threading.Event()


def _touch_activity() -> None:
    global _last_activity_ts
    with _activity_lock:
        _last_activity_ts = time.time()


def _seconds_since_activity() -> float:
    with _activity_lock:
        return max(0.0, time.time() - _last_activity_ts)


def sh(*args: str) -> str:
    try:
        r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=8)
        return r.stdout.strip()
    except Exception:
        return ""


def count_lines(out: str) -> int:
    return 0 if not out else len([ln for ln in out.splitlines() if ln.strip()])


def count_yaml_services(path: Path) -> int:
    if not path.exists():
        return 0
    in_services = False
    count = 0
    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if re.match(r"^services:\s*$", ln):
            in_services = True
            continue
        if in_services:
            if re.match(r"^[A-Za-z_][\w-]*:\s*$", ln):
                break
            if re.match(r"^  [A-Za-z_][\w-]*:\s*$", ln):
                count += 1
    return count


def count_pipelines_in_claude_md() -> int:
    p = ROOT / "CLAUDE.md"
    if not p.exists():
        return 0
    in_section = False
    modes = 0
    for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        if ln.startswith("### Pipeline Selection"):
            in_section = True
            continue
        if in_section:
            if ln.startswith("##") or ln.startswith("###"):
                break
            if re.match(r"^-\s+\*\*", ln):
                modes += 1
    return modes


def _recent_changes() -> dict:
    commits = []
    out = sh("git", "log", "-5", "--pretty=format:%cI||%h||%s")
    for ln in out.splitlines():
        parts = ln.split("||", 2)
        if len(parts) == 3:
            commits.append({"ts": parts[0], "hash": parts[1], "msg": parts[2][:90]})
    changed: list[tuple[float, str]] = []
    for rel in WATCH_TARGETS:
        base = ROOT / rel
        if not base.exists():
            continue
        if base.is_file():
            try:
                changed.append((base.stat().st_mtime, rel))
            except Exception:
                pass
            continue
        for f in base.rglob("*"):
            if not f.is_file() or f.suffix in EXCLUDE_SUFFIXES:
                continue
            try:
                changed.append((f.stat().st_mtime, str(f.relative_to(ROOT))))
            except Exception:
                pass
    changed.sort(reverse=True)
    files = [{"mtime": m, "path": p} for m, p in changed[:5]]
    return {"commits": commits, "files": files}


def build_status() -> dict:
    agents_dir = ROOT / ".claude" / "agents"
    skills_dir = ROOT / ".claude" / "skills"
    rules_dir = ROOT / ".claude" / "rules"
    hooks_dir = ROOT / ".claude" / "hooks"
    tools_dir = ROOT / "tools"
    mcp_config = ROOT / ".mcp.json"

    agents = sorted(p.stem for p in agents_dir.glob("*.md")) if agents_dir.exists() else []
    skills = sorted(p.name for p in skills_dir.iterdir() if p.is_dir()) if skills_dir.exists() else []
    rules = sorted(p.name for p in rules_dir.glob("*.md")) if rules_dir.exists() else []
    hooks = sorted(p.name for p in hooks_dir.iterdir() if p.is_file() and p.suffix in (".py", ".sh")) if hooks_dir.exists() else []
    tools = sorted(p.name for p in tools_dir.iterdir() if p.is_file() and p.suffix in (".py", ".sh")) if tools_dir.exists() else []

    mcp_servers: list[str] = []
    if mcp_config.exists():
        try:
            mcp_servers = sorted(json.loads(mcp_config.read_text(encoding="utf-8")).get("mcpServers", {}).keys())
        except Exception:
            pass

    workflows_dir = ROOT / ".github" / "workflows"
    workflows = sorted(p.name for p in workflows_dir.glob("*.yml")) if workflows_dir.exists() else []

    branch = sh("git", "rev-parse", "--abbrev-ref", "HEAD")
    ahead_behind = sh("git", "rev-list", "--left-right", "--count", f"{branch}...@{{u}}") if branch else ""
    ahead, behind = (ahead_behind.split() + ["0", "0"])[:2] if ahead_behind else ("0", "0")
    last_commit = sh("git", "log", "-1", "--pretty=format:%h %s").strip()
    commit_date = sh("git", "log", "-1", "--pretty=format:%cI").strip()
    untracked = count_lines(sh("git", "ls-files", "--others", "--exclude-standard"))
    modified = count_lines(sh("git", "diff", "--name-only"))
    stash_count = count_lines(sh("git", "stash", "list"))

    knowledge_db = ROOT / "knowledge" / "knowledge.db"
    knowledge_present = knowledge_db.exists()
    knowledge_size_mb = round(knowledge_db.stat().st_size / (1024 * 1024), 1) if knowledge_present else 0.0

    docker_services = count_yaml_services(ROOT / "docker-compose.yml")
    pipeline_modes = count_pipelines_in_claude_md()

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "agents": {"count": len(agents), "names": agents},
        "skills": {"count": len(skills), "names": skills},
        "pipeline_rules": {"count": len(rules), "names": rules},
        "workflows": {"count": len(workflows), "names": workflows},
        "mcp_servers": {"count": len(mcp_servers), "names": mcp_servers},
        "tools": {"count": len(tools)},
        "hooks": {"count": len(hooks)},
        "docker_services": docker_services,
        "pipeline_modes": pipeline_modes,
        "knowledge_db": {"present": knowledge_present, "size_mb": knowledge_size_mb},
        "git": {
            "branch": branch,
            "ahead": int(ahead),
            "behind": int(behind),
            "last_commit": last_commit,
            "last_commit_date": commit_date,
            "untracked": untracked,
            "modified": modified,
            "stashes": stash_count,
        },
        "recent": _recent_changes(),
    }


# --- SSE broker ---

_subscribers: set[queue.Queue] = set()
_subs_lock = threading.Lock()
_MAX_SUBSCRIBERS = 32
_last_event_ts = 0.0
_debounce_timer: threading.Timer | None = None
_debounce_lock = threading.Lock()


def _broadcast(kind: str = "refresh") -> None:
    global _last_event_ts
    _last_event_ts = time.time()
    with _subs_lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(kind)
            except Exception:
                dead.append(q)
        for q in dead:
            _subscribers.discard(q)


def _schedule_broadcast() -> None:
    """파일 이벤트가 burst로 오는 경우 debounce(200ms) 후 1회만 broadcast."""
    global _debounce_timer
    with _debounce_lock:
        if _debounce_timer is not None:
            _debounce_timer.cancel()
        _debounce_timer = threading.Timer(0.2, _broadcast)
        _debounce_timer.daemon = True
        _debounce_timer.start()


WATCH_TARGETS = [
    ".claude/agents",
    ".claude/skills",
    ".claude/rules",
    ".claude/rules-ctf",
    ".claude/hooks",
    ".github/workflows",
    ".mcp.json",
    "docker-compose.yml",
    "README.md",
    "CLAUDE.md",
    "docs/OVERVIEW.html",
    "docs/overview_server.py",
]


def _dir_fingerprint() -> tuple[int, float]:
    """(파일 수, 최신 mtime) — 값이 바뀌면 broadcast."""
    file_count = 0
    latest = 0.0
    for rel in WATCH_TARGETS:
        base = ROOT / rel
        if not base.exists():
            continue
        if base.is_file():
            file_count += 1
            try:
                latest = max(latest, base.stat().st_mtime)
            except Exception:
                pass
            continue
        for f in base.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix in EXCLUDE_SUFFIXES:
                continue
            file_count += 1
            try:
                latest = max(latest, f.stat().st_mtime)
            except Exception:
                pass
    # git HEAD도 감시 (커밋, 브랜치 전환)
    head = ROOT / ".git" / "HEAD"
    if head.exists():
        try:
            latest = max(latest, head.stat().st_mtime)
        except Exception:
            pass
    return file_count, latest


def _start_watcher() -> threading.Thread:
    def loop():
        last = _dir_fingerprint()
        while True:
            time.sleep(1.5)
            try:
                cur = _dir_fingerprint()
                if cur != last:
                    last = cur
                    _schedule_broadcast()
            except Exception:
                pass
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def _start_idle_shutdown(server: ThreadingHTTPServer) -> threading.Thread | None:
    if IDLE_TIMEOUT <= 0:
        return None

    def loop():
        while not _shutdown_event.wait(5):
            if _seconds_since_activity() < IDLE_TIMEOUT:
                continue
            print(
                f"idle timeout reached ({IDLE_TIMEOUT}s without requests); shutting down",
                flush=True,
            )
            _shutdown_event.set()
            server.shutdown()
            return

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


# --- HTTP handlers ---

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    _ALLOWED_ORIGINS = {"http://127.0.0.1:8450", "http://localhost:8450"}

    def _cors_origin(self) -> str:
        origin = self.headers.get("Origin", "")
        return origin if origin in self._ALLOWED_ORIGINS else self._ALLOWED_ORIGINS.__iter__().__next__()

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str) -> None:
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_sse(self) -> None:
        with _subs_lock:
            if len(_subscribers) >= _MAX_SUBSCRIBERS:
                self.send_response(503)
                self.end_headers()
                return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.end_headers()
        q: queue.Queue = queue.Queue(maxsize=64)
        with _subs_lock:
            if len(_subscribers) >= _MAX_SUBSCRIBERS:
                self.send_response(503)
                self.end_headers()
                return
            _subscribers.add(q)
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            _touch_activity()
            while True:
                try:
                    kind = q.get(timeout=15)
                    self.wfile.write(f"event: {kind}\ndata: {int(time.time()*1000)}\n\n".encode())
                    self.wfile.flush()
                    _touch_activity()
                except queue.Empty:
                    # heartbeat (keeps proxies happy + detects disconnects)
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    _touch_activity()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _subs_lock:
                _subscribers.discard(q)

    def _get_db_conn(self):
        try:
            import psycopg2
            return psycopg2.connect(
                host=os.environ.get("TERMINATOR_DB_HOST", "localhost"),
                port=int(os.environ.get("TERMINATOR_DB_PORT", "5433")),
                dbname=os.environ.get("TERMINATOR_DB_NAME", "terminator"),
                user=os.environ.get("TERMINATOR_DB_USER", "shadowhunter"),
                password=os.environ.get("TERMINATOR_DB_PASS", "terminator"),
            )
        except Exception:
            return None

    def _get_assessments(self):
        conn = self._get_db_conn()
        if not conn:
            return {"error": "Database unavailable"}
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, target, pipeline, status, phase, template, created_at FROM assessments ORDER BY created_at DESC LIMIT 50")
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            conn.close()
            return {"assessments": rows}
        except Exception as e:
            return {"error": str(e)}

    def _get_findings(self):
        conn = self._get_db_conn()
        if not conn:
            return {"error": "Database unavailable"}
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, target, title, severity, status, cvss_score, evidence_tier, created_at FROM findings ORDER BY created_at DESC LIMIT 50")
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            conn.close()
            return {"findings": rows}
        except Exception as e:
            return {"error": str(e)}

    def _get_timeline(self):
        conn = self._get_db_conn()
        if not conn:
            return {"error": "Database unavailable"}
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, assessment_id, phase, event_type, severity, title, agent_role, created_at FROM timeline_events ORDER BY created_at DESC LIMIT 100")
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            conn.close()
            return {"events": rows}
        except Exception as e:
            return {"error": str(e)}

    def _get_tool_health(self):
        try:
            r = subprocess.run(
                ["python3", str(Path(__file__).resolve().parents[1] / "tools" / "tool_lifecycle.py"), "check", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            return json.loads(r.stdout)
        except Exception as e:
            return {"error": str(e)}

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        _touch_activity()
        if path == "/api/assessments":
            self._send_json(self._get_assessments())
            return
        if path == "/api/findings":
            self._send_json(self._get_findings())
            return
        if path == "/api/timeline":
            self._send_json(self._get_timeline())
            return
        if path == "/api/tool-health":
            self._send_json(self._get_tool_health())
            return
        if path == "/api/status.json":
            try:
                self._send_json(build_status())
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
            return
        if path == "/api/events":
            self._send_sse()
            return
        if path in ("/", "/OVERVIEW.html", "/index.html"):
            self._send_file(DOCS / "OVERVIEW.html", "text/html; charset=utf-8")
            return
        safe = (DOCS / path.lstrip("/")).resolve()
        if DOCS in safe.parents and safe.is_file():
            suffix = safe.suffix.lower()
            ctype = {
                ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml",
                ".json": "application/json", ".js": "application/javascript",
                ".css": "text/css", ".html": "text/html; charset=utf-8",
            }.get(suffix, "application/octet-stream")
            self._send_file(safe, ctype)
            return
        self.send_response(404)
        self.end_headers()


def main() -> None:
    port = int(os.environ.get("OVERVIEW_PORT", "8450"))
    host = os.environ.get("OVERVIEW_HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), Handler)
    _start_watcher()
    _start_idle_shutdown(server)
    print(f"Terminator Overview on http://{host}:{port}/", flush=True)
    print(f"  api: /api/status.json | events (SSE): /api/events", flush=True)
    print(f"  watcher: self-polling 1.5s on {len(WATCH_TARGETS)} targets", flush=True)
    if IDLE_TIMEOUT > 0:
        print(f"  idle shutdown: {IDLE_TIMEOUT}s without requests", flush=True)
    server.serve_forever()
    server.server_close()


if __name__ == "__main__":
    main()
