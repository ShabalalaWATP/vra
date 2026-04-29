#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
DIST="$ROOT/frontend/dist/index.html"
VENV_PYTHON="$ROOT/.venv/bin/python"

if [[ -x "$VENV_PYTHON" ]]; then
    PYTHON_BIN="$VENV_PYTHON"
elif command -v python3.12 >/dev/null 2>&1; then
    PYTHON_BIN="python3.12"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[!] Python 3.12 not found. Run ./install.sh first or install Python 3.12." >&2
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$PY_VERSION" != "3.12" ]]; then
    echo "[!] VRAgent requires Python 3.12 for the current tree-sitter-languages dependency. Found Python $PY_VERSION at $PYTHON_BIN." >&2
    exit 1
fi

if [[ ! -f "$DIST" ]]; then
    echo "[!] frontend/dist/index.html is missing. Build the frontend before using start.sh." >&2
fi

export VRAGENT_CORS_ORIGINS="${VRAGENT_CORS_ORIGINS:-http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000}"

cd "$BACKEND"
"$PYTHON_BIN" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
