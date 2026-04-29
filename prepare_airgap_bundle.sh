#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

python_minor() {
    "$1" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' | tr -d '\r'
}

python_platform() {
    "$1" -c 'import platform; print(platform.system())' | tr -d '\r'
}

native_platform() {
    case "$(uname -s)" in
        Linux*) echo "Linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "Windows" ;;
        Darwin*) echo "Darwin" ;;
        *) echo "" ;;
    esac
}

is_native_python312() {
    local candidate="$1"
    local expected_platform
    expected_platform="$(native_platform)"
    [[ "$(python_minor "$candidate")" == "3.12" ]] || return 1
    [[ -z "$expected_platform" || "$(python_platform "$candidate")" == "$expected_platform" ]]
}

find_python312() {
    if command -v python3.12 >/dev/null 2>&1 && is_native_python312 "$(command -v python3.12)"; then
        command -v python3.12
        return 0
    fi
    for local_python in "$ROOT/.venv/bin/python" "$ROOT/.venv/Scripts/python.exe"; do
        if [[ -x "$local_python" ]] && is_native_python312 "$local_python"; then
            echo "$local_python"
            return 0
        fi
    done
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && is_native_python312 "$(command -v "$candidate")"; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

PYTHON="$(find_python312 || true)"
if [[ -z "$PYTHON" ]]; then
    echo "[!] Native Python 3.12 for this shell/OS is required." >&2
    echo "[!] Install python3.12 and python3.12-venv first, then re-run this wrapper on the same OS/CPU architecture as the target machine." >&2
    exit 1
fi

cd "$ROOT/backend"
exec "$PYTHON" -m scripts.prepare_airgap_bundle "$@"
