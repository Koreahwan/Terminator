#!/usr/bin/env bash
# Install the external seCall CLI and initialize Terminator-local seCall state.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECALL_REPO="${SECALL_REPO:-https://github.com/hang-in/seCall.git}"
SECALL_REF="${SECALL_REF:-fb107b3b02816acf5b1e7658f98877c1896aedb8}"
SECALL_SRC="${SECALL_SRC:-$HOME/.cache/terminator/seCall}"
SECALL_BIN="${SECALL_BIN:-}"
ORT_VERSION="${ORT_VERSION:-1.22.0}"
ORT_ROOT="${ORT_ROOT:-$HOME/.cache/terminator/onnxruntime/$ORT_VERSION}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "[!] cargo is required to build seCall. Install Rust first: https://rustup.rs" >&2
  exit 2
fi

if ! command -v pkg-config >/dev/null 2>&1 && [ -z "${OPENSSL_DIR:-}" ] && [ -z "${OPENSSL_LIB_DIR:-}" ]; then
  OPENSSL_LIB_CANDIDATE="$(compgen -G "/usr/lib/*/libssl.so" | head -1 || true)"
  if [ -f /usr/include/openssl/ssl.h ] && [ -n "$OPENSSL_LIB_CANDIDATE" ]; then
    export OPENSSL_INCLUDE_DIR=/usr/include
    export OPENSSL_LIB_DIR="$(dirname "$OPENSSL_LIB_CANDIDATE")"
    echo "[*] pkg-config not found; using OPENSSL_INCLUDE_DIR=$OPENSSL_INCLUDE_DIR"
    echo "[*] pkg-config not found; using OPENSSL_LIB_DIR=$OPENSSL_LIB_DIR"
  else
    echo "[!] pkg-config is missing and OpenSSL headers/libs were not found in /usr." >&2
    echo "    Install pkg-config + libssl-dev, or set OPENSSL_DIR/OPENSSL_LIB_DIR before running this script." >&2
    exit 2
  fi
fi

if [ -z "${ORT_LIB_LOCATION:-}" ]; then
  if [ ! -f "$ORT_ROOT/lib/libonnxruntime.so" ] && [ ! -f "$ORT_ROOT/lib/libonnxruntime.so.$ORT_VERSION" ]; then
    if ! command -v curl >/dev/null 2>&1; then
      echo "[!] curl is required to prefetch ONNX Runtime when ort-sys CDN download is unavailable." >&2
      echo "    Install curl or set ORT_LIB_LOCATION to an existing ONNX Runtime lib directory." >&2
      exit 2
    fi
    ORT_ARCHIVE="$(mktemp)"
    mkdir -p "$ORT_ROOT"
    echo "[*] Prefetching ONNX Runtime $ORT_VERSION for ort-sys from Microsoft GitHub releases"
    curl -fL \
      "https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VERSION/onnxruntime-linux-x64-$ORT_VERSION.tgz" \
      -o "$ORT_ARCHIVE"
    tar -xzf "$ORT_ARCHIVE" -C "$ORT_ROOT" --strip-components=1
    rm -f "$ORT_ARCHIVE"
  fi
  export ORT_LIB_LOCATION="$ORT_ROOT/lib"
  export LD_LIBRARY_PATH="$ORT_LIB_LOCATION:${LD_LIBRARY_PATH:-}"
  echo "[*] Using ORT_LIB_LOCATION=$ORT_LIB_LOCATION"
fi

mkdir -p "$(dirname "$SECALL_SRC")"

if [ ! -d "$SECALL_SRC/.git" ]; then
  git clone "$SECALL_REPO" "$SECALL_SRC"
fi

git -C "$SECALL_SRC" fetch --tags --force origin
git -C "$SECALL_SRC" checkout "$SECALL_REF"

cargo install --locked --path "$SECALL_SRC/crates/secall"

if [ -z "$SECALL_BIN" ]; then
  SECALL_BIN="$(command -v secall || true)"
fi

if [ -z "$SECALL_BIN" ]; then
  echo "[!] seCall installed but was not found on PATH. Add ~/.cargo/bin to PATH or set SECALL_BIN." >&2
  exit 2
fi

SECALL_BIN="$SECALL_BIN" python3 "$PROJECT_ROOT/tools/secall_bridge.py" init
SECALL_BIN="$SECALL_BIN" python3 "$PROJECT_ROOT/tools/secall_bridge.py" doctor

cat <<EOF

seCall is installed and initialized for Terminator.

Next:
  SECALL_BIN="$SECALL_BIN" python3 tools/secall_bridge.py ingest --auto
  SECALL_BIN="$SECALL_BIN" python3 tools/secall_bridge.py recall "your query"

MCP snippet:
  SECALL_BIN="$SECALL_BIN" python3 tools/secall_bridge.py mcp-config
EOF
