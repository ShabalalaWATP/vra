#!/usr/bin/env bash
#
# VRAgent Installation Script (Linux/macOS)
#
# Installs all dependencies for VRAgent including:
#   - Python backend dependencies (pip)
#   - Node.js frontend dependencies (npm)
#   - Semgrep, Bandit (pip)
#   - ESLint (npm)
#   - CodeQL CLI (downloaded from GitHub)
#   - Semgrep rules (downloaded from GitHub)
#   - OSV advisory database (downloaded from GCS)
#   - Technology icons (downloaded from GitHub)
#   - SQLite database setup
#   - Database migrations
#
# Usage:
#   ./install.sh                    # Full install (internet required)
#   ./install.sh --offline          # Air-gapped install (offline packages required)
#   ./install.sh --skip-codeql      # Skip CodeQL download
#   ./install.sh --skip-db          # Skip database setup
#   ./install.sh --skip-data        # Skip data downloads
#   ./install.sh --db-path backend/data/custom.db
#
# Vendored Ubuntu assets at vendor/ubuntu/ are automatically preferred when present.
#
set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
OFFLINE_ROOT="$ROOT/offline-packages"
OFFLINE_PYTHON="$OFFLINE_ROOT/python"
OFFLINE_NODE="$OFFLINE_ROOT/node_modules.tar.gz"
OFFLINE_TOOLS="$OFFLINE_ROOT/tools"
VENDOR_ROOT="$ROOT/vendor/ubuntu"
VENDOR_PYTHON="$VENDOR_ROOT/python"
VENDOR_NODE="$VENDOR_ROOT/node_modules.tar.gz"
VENDOR_NODE_PART_GLOB="$VENDOR_ROOT/node_modules.tar.gz.part-*"
VENDOR_SCANNERS="$VENDOR_ROOT/tools/python_vendor"
VENDOR_SCANNERS_ARCHIVE="$VENDOR_ROOT/tools/python_vendor.tar.gz"
VENDOR_SCANNERS_PART_GLOB="$VENDOR_ROOT/tools/python_vendor.tar.gz.part-*"
VENDOR_CODEQL="$VENDOR_ROOT/tools/codeql"
VENDOR_CODEQL_ARCHIVE="$VENDOR_ROOT/tools/codeql.tar.gz"
VENDOR_CODEQL_PART_GLOB="$VENDOR_ROOT/tools/codeql.tar.gz.part-*"
VENDOR_JADX="$VENDOR_ROOT/tools/jadx"
VENDOR_JADX_ARCHIVE="$VENDOR_ROOT/tools/jadx.tar.gz"
VENDOR_JADX_PART_GLOB="$VENDOR_ROOT/tools/jadx.tar.gz.part-*"
LOCAL_SCANNERS="$BACKEND/tools/python_vendor"
VENV_DIR="$ROOT/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

OFFLINE=false
SKIP_CODEQL=false
SKIP_DB=false
SKIP_DATA=false
DB_PATH="$BACKEND/data/vragent.db"
VENDOR_USABLE=true
MIN_NODE_MAJOR=22
MIN_NPM_MAJOR=10

# ── Parse arguments ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --offline)      OFFLINE=true; shift ;;
        --skip-codeql)  SKIP_CODEQL=true; shift ;;
        --skip-db)      SKIP_DB=true; shift ;;
        --skip-data)    SKIP_DATA=true; shift ;;
        --db-path)      DB_PATH="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --offline        Install from offline packages only (no internet)"
            echo "  --skip-codeql    Skip CodeQL download"
            echo "  --skip-db        Skip SQLite setup and migrations"
            echo "  --skip-data      Skip downloading rules, advisories, icons"
            echo "  --db-path PATH   SQLite database path (default: backend/data/vragent.db)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Helpers ─────────────────────────────────────────────────────────
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

step()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()   { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()    { echo -e "  ${RED}[X]${NC} $1"; }

has_cmd() { command -v "$1" &>/dev/null; }
glob_exists() { compgen -G "$1" > /dev/null; }
major_version() {
    local raw="${1#v}"
    raw="${raw%%.*}"
    if [[ "$raw" =~ ^[0-9]+$ ]]; then
        echo "$raw"
    else
        echo 0
    fi
}

validate_vendor_manifest() {
    if [[ ! -d "$VENDOR_ROOT" ]]; then
        return 0
    fi
    if [[ ! -f "$VENDOR_ROOT/manifest.json" ]]; then
        warn "vendor/ubuntu exists but manifest.json is missing; ignoring vendored Ubuntu assets."
        VENDOR_USABLE=false
        return 0
    fi

    local target_python_minor
    local manifest_python_minor
    local target_machine
    local manifest_machine

    target_python_minor="$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    target_machine="$(uname -m)"
    manifest_python_minor="$("$SYSTEM_PYTHON" - "$VENDOR_ROOT/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = manifest.get("required_target", {})
prepared = manifest.get("prepared_on", {})
value = required.get("python_minor") or ".".join(str(prepared.get("python", "")).split(".")[:2])
print(value)
PY
)"
    manifest_machine="$("$SYSTEM_PYTHON" - "$VENDOR_ROOT/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = manifest.get("required_target", {})
prepared = manifest.get("prepared_on", {})
print(required.get("machine") or prepared.get("machine") or "")
PY
)"

    if [[ "$manifest_python_minor" != "$target_python_minor" ]]; then
        warn "Ignoring vendor/ubuntu: prepared for Python $manifest_python_minor, target is Python $target_python_minor."
        warn "Rebuild from the repo root with: bash ./prepare_ubuntu_vendor.sh"
        VENDOR_USABLE=false
    fi
    if [[ -n "$manifest_machine" && "$manifest_machine" != "$target_machine" ]]; then
        warn "Ignoring vendor/ubuntu: prepared for $manifest_machine, target is $target_machine."
        warn "Rebuild vendor/ubuntu on the same CPU architecture as the target Ubuntu host."
        VENDOR_USABLE=false
    fi
}

copy_tree() {
    local src="$1"
    local dest="$2"
    mkdir -p "$dest"
    cp -R "$src"/. "$dest/"
}

extract_tar_archive_into() {
    local archive_path="$1"
    local dest_root="$2"
    mkdir -p "$dest_root"
    tar xzf "$archive_path" -C "$dest_root"
}

extract_tar_archive_parts_into() {
    local part_glob="$1"
    local dest_root="$2"
    local temp_archive
    local parts=()
    shopt -s nullglob
    parts=($part_glob)
    shopt -u nullglob
    if [[ "${#parts[@]}" -eq 0 ]]; then
        return 1
    fi

    temp_archive="$(mktemp "${TMPDIR:-/tmp}/vragent-node-modules.XXXXXX.tar.gz")"
    cat "${parts[@]}" > "$temp_archive"
    mkdir -p "$dest_root"
    tar xzf "$temp_archive" -C "$dest_root"
    rm -f "$temp_archive"
}

header() {
    printf "\n${CYAN}%s${NC}\n" "$(printf '=%.0s' {1..60})"
    printf "${CYAN}  %s${NC}\n" "$1"
    printf "${CYAN}%s${NC}\n\n" "$(printf '=%.0s' {1..60})"
}

# ── Banner ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}  VRAgent Installer${NC}"
echo -e "  Offline AI-Assisted Static Vulnerability Research Platform"
echo ""

# ── Check prerequisites ────────────────────────────────────────────
header "Checking Prerequisites"

# Python 3.12 is required because tree-sitter-languages 1.10.2 does not
# publish wheels for Python 3.13 or 3.14.
if has_cmd python3.12; then
    SYSTEM_PYTHON="$(command -v python3.12)"
elif has_cmd python3 && [[ "$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" == "3.12" ]]; then
    SYSTEM_PYTHON="$(command -v python3)"
elif has_cmd python && [[ "$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" == "3.12" ]]; then
    SYSTEM_PYTHON="$(command -v python)"
else
    err "Python 3.12 is required. Install python3.12 and python3.12-venv first."
    exit 1
fi

step "Python for VRAgent: $("$SYSTEM_PYTHON" --version 2>&1) ($SYSTEM_PYTHON)"
validate_vendor_manifest

if [[ -x "$VENV_PYTHON" ]]; then
    VENV_VERSION="$("$VENV_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    if [[ "$VENV_VERSION" != "3.12" ]]; then
        warn "Existing .venv uses Python $VENV_VERSION; recreating it with Python 3.12."
        if [[ "$(cd "$VENV_DIR" && pwd)" == "$ROOT/.venv" ]]; then
            rm -rf "$VENV_DIR"
        else
            err "Refusing to remove unexpected venv path: $VENV_DIR"
            exit 1
        fi
    fi
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
    step "Creating local virtual environment: $VENV_DIR"
    "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
fi

PYTHON="$VENV_PYTHON"
if [[ "$OFFLINE" == true ]]; then
    if [[ "$VENDOR_USABLE" == true && -d "$VENDOR_PYTHON" ]]; then
        "$PYTHON" -m pip install --no-index --find-links="$VENDOR_PYTHON" --upgrade pip setuptools wheel >/dev/null || \
            warn "Could not upgrade pip/setuptools/wheel from vendored wheelhouse; continuing with venv defaults."
    elif [[ -d "$OFFLINE_PYTHON" ]]; then
        "$PYTHON" -m pip install --no-index --find-links="$OFFLINE_PYTHON" --upgrade pip setuptools wheel >/dev/null || \
            warn "Could not upgrade pip/setuptools/wheel from offline wheelhouse; continuing with venv defaults."
    else
        warn "No offline wheelhouse available for pip bootstrap; continuing with venv defaults."
    fi
else
    "$PYTHON" -m pip install --upgrade pip setuptools wheel >/dev/null
fi

# Node.js
if has_cmd node; then
    NODE_VERSION="$(node --version)"
    NODE_MAJOR="$(major_version "$NODE_VERSION")"
    if (( NODE_MAJOR < MIN_NODE_MAJOR )); then
        err "Node.js $MIN_NODE_MAJOR or newer is required. Current version: $NODE_VERSION"
        err "Install Node.js 22.x LTS from your internal mirror or NodeSource package mirror."
        exit 1
    fi
    step "Node.js: $NODE_VERSION"
else
    err "Node.js not found. Install Node.js 22.x LTS first."
    exit 1
fi

if has_cmd npm; then
    NPM_VERSION="$(npm --version)"
    NPM_MAJOR="$(major_version "$NPM_VERSION")"
    if (( NPM_MAJOR < MIN_NPM_MAJOR )); then
        err "npm $MIN_NPM_MAJOR or newer is required. Current version: $NPM_VERSION"
        err "Install the npm version bundled with Node.js 22.x LTS."
        exit 1
    fi
    step "npm: $NPM_VERSION"
else
    err "npm not found."
    exit 1
fi

# ── Install Python backend ─────────────────────────────────────────
header "Installing Backend Dependencies"

cd "$BACKEND"

if [[ "$OFFLINE" == true ]]; then
    if [[ "$VENDOR_USABLE" == true && -d "$VENDOR_PYTHON" ]]; then
        step "Installing from vendored Ubuntu wheelhouse: $VENDOR_PYTHON"
        "$PYTHON" -m pip install --no-index --find-links="$VENDOR_PYTHON" -e ".[dev]" 2>&1 | tail -1
    elif [[ -d "$OFFLINE_PYTHON" ]]; then
        step "Installing from offline packages: $OFFLINE_PYTHON"
        "$PYTHON" -m pip install --no-index --find-links="$OFFLINE_PYTHON" -e ".[dev]" 2>&1 | tail -1
    else
        err "No vendored Ubuntu wheelhouse or offline wheelhouse found."
        err "Expected one of:"
        err "  - $VENDOR_PYTHON"
        err "  - $OFFLINE_PYTHON"
        exit 1
    fi
elif [[ "$VENDOR_USABLE" == true && -d "$VENDOR_PYTHON" ]]; then
    step "Installing from vendored Ubuntu wheelhouse: $VENDOR_PYTHON"
    if ! "$PYTHON" -m pip install --no-index --find-links="$VENDOR_PYTHON" -e ".[dev]" 2>&1 | tail -1; then
        warn "Vendored Ubuntu wheelhouse install failed; falling back to PyPI/internal mirror."
        "$PYTHON" -m pip install -e ".[dev]" 2>&1 | tail -1
    fi
else
    step "Installing Python packages from PyPI..."
    "$PYTHON" -m pip install -e ".[dev]" 2>&1 | tail -1
fi
step "Backend dependencies installed"

# Bundle Semgrep + Bandit locally under backend/tools/
if [[ "$VENDOR_USABLE" == true && -d "$VENDOR_SCANNERS" ]]; then
    step "Restoring bundled Python scanners from vendored assets..."
    rm -rf "$LOCAL_SCANNERS"
    mkdir -p "$(dirname "$LOCAL_SCANNERS")"
    copy_tree "$VENDOR_SCANNERS" "$LOCAL_SCANNERS"
elif [[ "$VENDOR_USABLE" == true ]] && { [[ -f "$VENDOR_SCANNERS_ARCHIVE" ]] || glob_exists "$VENDOR_SCANNERS_PART_GLOB"; }; then
    step "Restoring bundled Python scanners from vendored archive..."
    rm -rf "$LOCAL_SCANNERS"
    if [[ -f "$VENDOR_SCANNERS_ARCHIVE" ]]; then
        extract_tar_archive_into "$VENDOR_SCANNERS_ARCHIVE" "$BACKEND/tools"
    else
        extract_tar_archive_parts_into "$VENDOR_SCANNERS_PART_GLOB" "$BACKEND/tools"
    fi
elif [[ "$OFFLINE" == true && -d "$OFFLINE_TOOLS/python_vendor" ]]; then
    step "Restoring bundled Python scanners from offline bundle..."
    rm -rf "$LOCAL_SCANNERS"
    mkdir -p "$(dirname "$LOCAL_SCANNERS")"
    copy_tree "$OFFLINE_TOOLS/python_vendor" "$LOCAL_SCANNERS"
else
    step "Bundling project-local Python scanners..."
    if [[ "$OFFLINE" == true ]]; then
        if [[ ! -d "$OFFLINE_PYTHON" ]]; then
            err "Offline Python packages not found: $OFFLINE_PYTHON"
            exit 1
        fi
        "$PYTHON" -m scripts.bundle_python_scanners --no-index --wheelhouse "$OFFLINE_PYTHON" 2>&1 | tail -3
    elif [[ "$VENDOR_USABLE" == true && -d "$VENDOR_PYTHON" ]]; then
        if ! "$PYTHON" -m scripts.bundle_python_scanners --no-index --wheelhouse "$VENDOR_PYTHON" 2>&1 | tail -3; then
            warn "Vendored scanner bundle failed; falling back to live download."
            "$PYTHON" -m scripts.bundle_python_scanners 2>&1 | tail -3
        fi
    else
        "$PYTHON" -m scripts.bundle_python_scanners 2>&1 | tail -3
    fi
fi

if [[ -f "$BACKEND/tools/bin/run_semgrep.py" && -d "$LOCAL_SCANNERS" ]]; then
    step "Bundled Semgrep ready: $("$PYTHON" "$BACKEND/tools/bin/run_semgrep.py" --version 2>&1 | sed '/^[[:space:]]*$/d' | head -1)"
else
    warn "Bundled Semgrep was not created successfully."
fi

if [[ -f "$BACKEND/tools/bin/run_bandit.py" && -d "$LOCAL_SCANNERS" ]]; then
    step "Bundled Bandit ready: $("$PYTHON" "$BACKEND/tools/bin/run_bandit.py" --version 2>&1 | sed '/^[[:space:]]*$/d' | head -1)"
else
    warn "Bundled Bandit was not created successfully."
fi

cd "$ROOT"

# ── Install Node.js frontend ───────────────────────────────────────
header "Installing Frontend Dependencies"

cd "$FRONTEND"

if [[ "$OFFLINE" == true ]]; then
    if [[ "$VENDOR_USABLE" == true && -f "$VENDOR_NODE" ]]; then
        step "Extracting vendored Ubuntu node_modules..."
        extract_tar_archive_into "$VENDOR_NODE" "$FRONTEND"
    elif [[ "$VENDOR_USABLE" == true ]] && glob_exists "$VENDOR_NODE_PART_GLOB"; then
        step "Extracting vendored Ubuntu node_modules from split archive..."
        extract_tar_archive_parts_into "$VENDOR_NODE_PART_GLOB" "$FRONTEND"
    elif [[ -f "$OFFLINE_NODE" ]]; then
        step "Extracting offline node_modules..."
        extract_tar_archive_into "$OFFLINE_NODE" "$FRONTEND"
    else
        err "No vendored Ubuntu node_modules archive or offline node_modules archive found."
        exit 1
    fi
elif [[ "$VENDOR_USABLE" == true && -f "$VENDOR_NODE" ]]; then
    step "Extracting vendored Ubuntu node_modules..."
    extract_tar_archive_into "$VENDOR_NODE" "$FRONTEND"
elif [[ "$VENDOR_USABLE" == true ]] && glob_exists "$VENDOR_NODE_PART_GLOB"; then
    step "Extracting vendored Ubuntu node_modules from split archive..."
    extract_tar_archive_parts_into "$VENDOR_NODE_PART_GLOB" "$FRONTEND"
else
    if [[ -f "$FRONTEND/package-lock.json" ]]; then
        step "Running npm ci..."
        if ! npm ci 2>&1 | tail -3; then
            warn "npm ci failed; falling back to npm install to refresh the lockfile."
            npm install 2>&1 | tail -3
        fi
    else
        step "Running npm install..."
        npm install 2>&1 | tail -3
    fi
fi
step "Frontend dependencies installed"

step "Building frontend..."
npm run build
step "Frontend build complete"

# ESLint
if [[ -x "$FRONTEND/node_modules/.bin/eslint" ]]; then
    step "ESLint available locally: $FRONTEND/node_modules/.bin/eslint"
else
    warn "Local ESLint binary not found. VRAgent will bootstrap frontend dependencies on first ESLint scan."
fi

cd "$ROOT"

# ── Download CodeQL ─────────────────────────────────────────────────
if [[ -f "$BACKEND/tools/codeql/codeql" ]]; then
    header "CodeQL"
    step "CodeQL already installed at: $BACKEND/tools/codeql/codeql"
elif [[ "$VENDOR_USABLE" == true && -f "$VENDOR_CODEQL/codeql" ]]; then
    header "CodeQL (Vendored Ubuntu Bundle)"
    step "Restoring CodeQL from $VENDOR_CODEQL"
    rm -rf "$BACKEND/tools/codeql"
    copy_tree "$VENDOR_CODEQL" "$BACKEND/tools/codeql"
    chmod +x "$BACKEND/tools/codeql/codeql" || true
    step "CodeQL restored to $BACKEND/tools/codeql/codeql"
elif [[ "$VENDOR_USABLE" == true ]] && { [[ -f "$VENDOR_CODEQL_ARCHIVE" ]] || glob_exists "$VENDOR_CODEQL_PART_GLOB"; }; then
    header "CodeQL (Vendored Ubuntu Archive)"
    step "Restoring CodeQL from vendored archive"
    rm -rf "$BACKEND/tools/codeql"
    if [[ -f "$VENDOR_CODEQL_ARCHIVE" ]]; then
        extract_tar_archive_into "$VENDOR_CODEQL_ARCHIVE" "$BACKEND/tools"
    else
        extract_tar_archive_parts_into "$VENDOR_CODEQL_PART_GLOB" "$BACKEND/tools"
    fi
    chmod +x "$BACKEND/tools/codeql/codeql" || true
    step "CodeQL restored to $BACKEND/tools/codeql/codeql"
elif [[ "$SKIP_CODEQL" == false && "$OFFLINE" == false ]]; then
    header "Installing CodeQL"

    CODEQL_BIN="$BACKEND/tools/codeql/codeql"
    if [[ -f "$CODEQL_BIN" ]]; then
        CODEQL_VER=$("$CODEQL_BIN" version --format=terse 2>&1)
        step "CodeQL already installed: v$CODEQL_VER"
    else
        step "Downloading CodeQL CLI (~500MB, please wait)..."
        cd "$BACKEND"
        "$PYTHON" -m scripts.download_codeql --output tools/codeql 2>&1 | while IFS= read -r line; do
            if [[ "$line" == *"Version:"* || "$line" == *"installed"* || "$line" == *"Binary:"* ]]; then
                step "$line"
            fi
        done
        cd "$ROOT"

        if [[ -f "$CODEQL_BIN" ]]; then
            step "CodeQL installed"
        else
            warn "CodeQL download may have failed. See README.md for manual install."
        fi
    fi
elif [[ "$SKIP_CODEQL" == true ]]; then
    header "Skipping CodeQL (--skip-codeql)"
    warn "CodeQL is optional but recommended for deep taint tracking."
elif [[ "$OFFLINE" == true ]]; then
    header "CodeQL (Offline Mode)"
    CODEQL_BIN="$BACKEND/tools/codeql/codeql"
    OFFLINE_CODEQL="$OFFLINE_TOOLS/codeql"
    if [[ ! -f "$CODEQL_BIN" && -d "$OFFLINE_CODEQL" ]]; then
        step "Restoring CodeQL from offline bundle..."
        mkdir -p "$BACKEND/tools/codeql"
        cp -R "$OFFLINE_CODEQL"/. "$BACKEND/tools/codeql/"
    fi
    if [[ -f "$CODEQL_BIN" ]]; then
        step "CodeQL found at: $CODEQL_BIN"
    else
        warn "CodeQL not found. For offline install:"
        warn "  1. Download codeql-bundle-linux64.tar.gz on a connected machine"
        warn "  2. Extract to: backend/tools/codeql/"
        warn "  3. Binary should be at: backend/tools/codeql/codeql"
    fi
fi

# ── Download jadx ──────────────────────────────────────────────────
if [[ -f "$BACKEND/tools/jadx/bin/jadx" ]]; then
    header "jadx (APK decompiler)"
    step "jadx already installed at: $BACKEND/tools/jadx/bin/jadx"
elif [[ "$VENDOR_USABLE" == true && -f "$VENDOR_JADX/bin/jadx" ]]; then
    header "jadx (Vendored Ubuntu Bundle)"
    step "Restoring jadx from $VENDOR_JADX"
    rm -rf "$BACKEND/tools/jadx"
    copy_tree "$VENDOR_JADX" "$BACKEND/tools/jadx"
    chmod +x "$BACKEND/tools/jadx/bin/jadx" || true
    step "jadx restored to $BACKEND/tools/jadx/bin/jadx"
elif [[ "$VENDOR_USABLE" == true ]] && { [[ -f "$VENDOR_JADX_ARCHIVE" ]] || glob_exists "$VENDOR_JADX_PART_GLOB"; }; then
    header "jadx (Vendored Ubuntu Archive)"
    step "Restoring jadx from vendored archive"
    rm -rf "$BACKEND/tools/jadx"
    if [[ -f "$VENDOR_JADX_ARCHIVE" ]]; then
        extract_tar_archive_into "$VENDOR_JADX_ARCHIVE" "$BACKEND/tools"
    else
        extract_tar_archive_parts_into "$VENDOR_JADX_PART_GLOB" "$BACKEND/tools"
    fi
    chmod +x "$BACKEND/tools/jadx/bin/jadx" || true
    step "jadx restored to $BACKEND/tools/jadx/bin/jadx"
elif [[ "$OFFLINE" == false ]]; then
    header "Installing jadx (APK decompiler)"

    JADX_BIN="$BACKEND/tools/jadx/bin/jadx"
    if [[ -f "$JADX_BIN" ]]; then
        step "jadx already installed at: $JADX_BIN"
    else
        step "Downloading jadx..."
        cd "$BACKEND"
        "$PYTHON" -m scripts.download_jadx --output tools/jadx 2>&1 | while IFS= read -r line; do
            if [[ "$line" == *"Version:"* || "$line" == *"installed"* || "$line" == *"Binary:"* ]]; then
                step "$line"
            fi
        done
        cd "$ROOT"

        if [[ -f "$JADX_BIN" ]]; then
            step "jadx installed"
        else
            warn "jadx download failed. APK scanning will be unavailable."
            warn "Manual install: https://github.com/skylot/jadx/releases"
            warn "Extract to: backend/tools/jadx/ (needs Java 11+)"
        fi
    fi
elif [[ "$OFFLINE" == true ]]; then
    header "jadx (Offline Mode)"
    JADX_BIN="$BACKEND/tools/jadx/bin/jadx"
    OFFLINE_JADX="$OFFLINE_TOOLS/jadx"
    if [[ ! -f "$JADX_BIN" && -d "$OFFLINE_JADX" ]]; then
        step "Restoring jadx from offline bundle..."
        mkdir -p "$BACKEND/tools/jadx"
        cp -R "$OFFLINE_JADX"/. "$BACKEND/tools/jadx/"
    fi
    if [[ -f "$JADX_BIN" ]]; then
        step "jadx found at: $JADX_BIN"
    else
        warn "jadx not found. For offline install:"
        warn "  1. Download jadx-<version>.zip on a connected machine"
        warn "  2. Extract to: backend/tools/jadx/"
        warn "  3. Binary should be at: backend/tools/jadx/bin/jadx"
        warn "  4. Requires Java 11+ at runtime"
    fi
fi

# ── Download offline data ───────────────────────────────────────────
if [[ "$SKIP_DATA" == false && "$OFFLINE" == false ]]; then
    header "Downloading Offline Data"

    cd "$BACKEND"

    # Semgrep rules
    RULES_DIR="$BACKEND/data/semgrep-rules"
    RULE_COUNT=$(find "$RULES_DIR" -name "*.yaml" 2>/dev/null | wc -l)
    if [[ "$RULE_COUNT" -gt 100 ]]; then
        step "Semgrep rules already present ($RULE_COUNT rules)"
    else
        step "Downloading Semgrep rules..."
        "$PYTHON" -m scripts.download_semgrep_rules --output data/semgrep-rules/ 2>&1 | tail -1 || \
            warn "Semgrep rules download failed. Using bundled rules."
    fi

    # Advisory database
    ADV_MANIFEST="$BACKEND/data/advisories/manifest.json"
    if [[ -f "$ADV_MANIFEST" ]]; then
        step "Advisory database already present"
    else
        step "Downloading OSV advisory database (~250MB)..."
        "$PYTHON" -m scripts.sync_advisories --output data/advisories/ 2>&1 | tail -1 || \
            warn "Advisory database download failed."
    fi

    # Icons
    ICONS_DIR="$BACKEND/data/icons"
    ICON_COUNT=$(find "$ICONS_DIR" -name "*.svg" 2>/dev/null | wc -l)
    if [[ "$ICON_COUNT" -gt 50 ]]; then
        step "Technology icons already present ($ICON_COUNT icons)"
    else
        step "Downloading technology icons..."
        "$PYTHON" -m scripts.download_icons --output data/icons/ 2>&1 | tail -1 || \
            warn "Icons download failed."
    fi

    cd "$ROOT"
fi

# ── Database setup ──────────────────────────────────────────────────
if [[ "$SKIP_DB" == false ]]; then
    header "Setting Up Database"

    if [[ "$DB_PATH" != /* ]]; then
        DB_PATH="$ROOT/$DB_PATH"
    fi
    mkdir -p "$(dirname "$DB_PATH")"
    CONN_STR="sqlite+aiosqlite:///${DB_PATH//\\//}"
    step "Using SQLite database: $DB_PATH"

    # Run migrations
    step "Running database migrations..."
    cd "$BACKEND"
    export VRAGENT_DATABASE_URL="$CONN_STR"
    "$PYTHON" -m alembic upgrade head 2>&1 | tail -1 || warn "Migration failed. Check SQLite database path."
    cd "$ROOT"
fi

# ── Summary ─────────────────────────────────────────────────────────
header "Installation Complete"

check_item() {
    if eval "$2"; then
        step "$1"
    else
        warn "$1 — not found"
    fi
}

check_item "Python backend"      "test -f $BACKEND/app/main.py"
check_item "Vendored Ubuntu wheelhouse" "test -d $VENDOR_PYTHON"
check_item "Vendored Ubuntu scanners" "test -d '$VENDOR_SCANNERS' || test -f '$VENDOR_SCANNERS_ARCHIVE' || compgen -G '$VENDOR_SCANNERS_PART_GLOB' > /dev/null"
check_item "Vendored Ubuntu CodeQL" "test -f '$VENDOR_CODEQL/codeql' || test -f '$VENDOR_CODEQL_ARCHIVE' || compgen -G '$VENDOR_CODEQL_PART_GLOB' > /dev/null"
check_item "Vendored Ubuntu jadx" "test -f '$VENDOR_JADX/bin/jadx' || test -f '$VENDOR_JADX_ARCHIVE' || compgen -G '$VENDOR_JADX_PART_GLOB' > /dev/null"
check_item "Frontend node_modules" "test -d $FRONTEND/node_modules"
check_item "Bundled Semgrep"     "test -f $BACKEND/tools/bin/run_semgrep.py -a -d $BACKEND/tools/python_vendor"
check_item "Bundled Bandit"      "test -f $BACKEND/tools/bin/run_bandit.py -a -d $BACKEND/tools/python_vendor"
check_item "ESLint"              "test -x $FRONTEND/node_modules/.bin/eslint"
check_item "CodeQL"              "test -f $BACKEND/tools/codeql/codeql"
check_item "jadx"                "test -f $BACKEND/tools/jadx/bin/jadx"
check_item "Semgrep rules"       "test $(find $BACKEND/data/semgrep-rules -name '*.yaml' 2>/dev/null | wc -l) -gt 100"
check_item "Advisory database"   "test -f $BACKEND/data/advisories/manifest.json"

echo ""
echo -e "  ${CYAN}To start VRAgent:${NC}"
echo ""
echo -e "    Preferred runtime (single process, serves frontend/dist):"
echo -e "      bash ./start.sh"
echo -e "      Then open: ${CYAN}http://localhost:8000${NC}"
echo ""
echo -e "    Development mode (two processes):"
echo -e "      Terminal 1: cd backend && ../.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo -e "      Terminal 2: cd frontend && npm run dev"
echo -e "      Then open: ${CYAN}http://localhost:3000${NC}"
echo ""
