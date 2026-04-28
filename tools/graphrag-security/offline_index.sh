#!/bin/bash
# offline_index.sh - Build a complete GraphRAG parquet set without an external LLM.
# Uses GraphRAG's mock providers so entities/relationships/text_units are available
# even when the configured Ollama endpoint is down. Rebuild with settings.yaml for
# real LLM-quality community summaries and embeddings.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP_ROOT="$(mktemp -d)"

cleanup() {
    if [[ "${KEEP_GRAPHRAG_OFFLINE_ROOT:-0}" != "1" ]]; then
        rm -rf "$TMP_ROOT"
    else
        echo "[offline_index] Kept temp root: $TMP_ROOT" >&2
    fi
}
trap cleanup EXIT

GRAPHRAG_BIN="${GRAPHRAG_BIN:-}"
if [[ -z "$GRAPHRAG_BIN" ]]; then
    if command -v graphrag &>/dev/null; then
        GRAPHRAG_BIN="$(command -v graphrag)"
    elif [[ -x "$PROJECT_ROOT/.venv/bin/graphrag" ]]; then
        GRAPHRAG_BIN="$PROJECT_ROOT/.venv/bin/graphrag"
    else
        echo "[offline_index] ERROR: graphrag not found in PATH or repo .venv" >&2
        exit 2
    fi
fi

mkdir -p "$TMP_ROOT"
ln -s "$SCRIPT_DIR/input" "$TMP_ROOT/input"
ln -s "$SCRIPT_DIR/prompts" "$TMP_ROOT/prompts"
cp "$SCRIPT_DIR/settings.mock.yaml" "$TMP_ROOT/settings.yaml"

echo "[offline_index] Running: $GRAPHRAG_BIN index --root $TMP_ROOT --method fast --skip-validation $*"
"$GRAPHRAG_BIN" index --root "$TMP_ROOT" --method fast --skip-validation "$@"

for arg in "$@"; do
    if [[ "$arg" == "--dry-run" ]]; then
        echo "[offline_index] Dry run complete; no output copied."
        exit 0
    fi
done

rm -rf "$SCRIPT_DIR/output" "$SCRIPT_DIR/cache"
mkdir -p "$SCRIPT_DIR/logs"
cp -a "$TMP_ROOT/output" "$SCRIPT_DIR/output"
if [[ -d "$TMP_ROOT/cache" ]]; then
    cp -a "$TMP_ROOT/cache" "$SCRIPT_DIR/cache"
fi
if [[ -d "$TMP_ROOT/logs" ]]; then
    cp -a "$TMP_ROOT/logs/." "$SCRIPT_DIR/logs/"
fi

echo "[offline_index] Output ready: $SCRIPT_DIR/output"
