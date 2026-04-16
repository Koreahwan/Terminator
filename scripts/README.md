# scripts/ — Operator Scripts

오퍼레이터(사용자)가 직접 실행하거나 cron으로 걸어두는 스크립트 모음. 파이프라인(Agent 호출) 용 스크립트는 `tools/` 에 있습니다.

## 목록

| 스크립트 | 용도 | 실행 주기 |
|---------|------|-----------|
| `install_omx_wrapper.sh` | OMX 래퍼 설치 | 1회 (setup) |
| `sync_poc_github.sh` | nomi-sec/PoC-in-GitHub 주간 pull + knowledge-fts 재인덱싱 | 주 1회 (cron) |

## sync_poc_github.sh — cron 설정

```bash
# crontab 열기
crontab -e

# 일요일 03:00 실행 (로그는 홈 디렉터리에)
0 3 * * 0 /mnt/c/Users/KH/All_Projects/Terminator/scripts/sync_poc_github.sh >> ~/poc_github_sync.log 2>&1
```

**테스트**:
```bash
# dry-run 없음 — 실제 pull + reindex. skip-if-recent 로 과도한 호출 방지.
./scripts/sync_poc_github.sh
# 강제 실행 (6일 쿨다운 무시)
POC_FORCE=1 ./scripts/sync_poc_github.sh
```

**로그**:
- 최근 실행 로그: `.omc/logs/sync_poc_github_<timestamp>.log`
- cron 누적 로그: `~/poc_github_sync.log` (위 crontab에서 지정한 경로)

**종료 코드**:
- 0: 업데이트 성공 (새 커밋 + reindex 완료)
- 1: 업데이트 없음 (최근 pull이 6일 이내 또는 HEAD 변경 없음)
- 2: 에러 (pull 또는 reindex 실패)

**환경변수**:
- `POC_IN_GITHUB_DIR` — PoC-in-GitHub clone 경로 (기본: `~/PoC-in-GitHub`)
- `POC_FORCE=1` — 최근 pull 체크 무시

## 왜 파이프라인에 넣지 않는가

Terminator 파이프라인은 **작업 시작 시점의 knowledge 스냅샷**을 기준으로 동작합니다. 파이프라인 실행 중에 knowledge DB가 바뀌면 재현성이 무너집니다. 따라서 **cron으로 파이프라인과 독립적으로 갱신**하고, 파이프라인 세션에서는 읽기만 합니다.
