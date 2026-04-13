#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
DIST="$ROOT/frontend/dist/index.html"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[!] Python not found. Install Python 3.11+ first." >&2
    exit 1
fi

if [[ ! -f "$DIST" ]]; then
    echo "[!] frontend/dist/index.html is missing. Build the frontend before using start.sh." >&2
fi

export VRAGENT_CORS_ORIGINS="${VRAGENT_CORS_ORIGINS:-http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000}"

cd "$BACKEND"
"$PYTHON_BIN" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
