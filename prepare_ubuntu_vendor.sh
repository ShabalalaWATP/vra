#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python_minor() {
    "$1" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' | tr -d '\r'
}

python_platform() {
    "$1" -c 'import platform; print(platform.system())' | tr -d '\r'
}

is_linux_python312() {
    [[ "$(python_minor "$1")" == "3.12" && "$(python_platform "$1")" == "Linux" ]]
}

find_python312() {
    if command -v python3.12 >/dev/null 2>&1 && is_linux_python312 "$(command -v python3.12)"; then
        command -v python3.12
        return 0
    fi
    for local_python in "$ROOT/.venv/bin/python"; do
        if [[ -x "$local_python" ]] && is_linux_python312 "$local_python"; then
            echo "$local_python"
            return 0
        fi
    done
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && is_linux_python312 "$(command -v "$candidate")"; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

PYTHON="$(find_python312 || true)"
if [[ -z "$PYTHON" ]]; then
    echo "[!] Native Linux Python 3.12 is required to prepare vendor/ubuntu." >&2
    echo "[!] Install python3.12 and python3.12-venv on a connected Ubuntu host that matches the target CPU architecture." >&2
    echo "[!] This wrapper intentionally will not use Windows Python from WSL, because that would build incompatible wheels." >&2
    exit 1
fi

cd "$ROOT/backend"
exec "$PYTHON" -m scripts.prepare_ubuntu_vendor "$@"
