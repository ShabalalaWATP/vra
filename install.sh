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
set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"

OFFLINE=false
SKIP_CODEQL=false
SKIP_DB=false
SKIP_DATA=false
DB_PATH="$BACKEND/data/vragent.db"

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

header() { echo -e "\n${CYAN}${"="*60}\n  $1\n${"="*60}${NC}\n"; }
step()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()   { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()    { echo -e "  ${RED}[X]${NC} $1"; }

has_cmd() { command -v "$1" &>/dev/null; }

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

# Python
if has_cmd python3; then
    PY_VER=$(python3 --version 2>&1)
    step "Python: $PY_VER"
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [[ "$PY_MINOR" -lt 11 ]]; then
        err "Python 3.11+ required. Found: $PY_VER"
        exit 1
    fi
elif has_cmd python; then
    PY_VER=$(python --version 2>&1)
    step "Python: $PY_VER"
else
    err "Python not found. Install Python 3.11+ first."
    exit 1
fi

PYTHON=$(has_cmd python3 && echo python3 || echo python)
PIP=$(has_cmd pip3 && echo pip3 || echo pip)

# Node.js
if has_cmd node; then
    step "Node.js: $(node --version)"
else
    err "Node.js not found. Install Node.js 18+ first."
    exit 1
fi

if has_cmd npm; then
    step "npm: $(npm --version)"
else
    err "npm not found."
    exit 1
fi

# ── Install Python backend ─────────────────────────────────────────
header "Installing Backend Dependencies"

cd "$BACKEND"

if [[ "$OFFLINE" == true ]]; then
    OFFLINE_DIR="$ROOT/offline-packages/python"
    if [[ -d "$OFFLINE_DIR" ]]; then
        step "Installing from offline packages: $OFFLINE_DIR"
        $PIP install --no-index --find-links="$OFFLINE_DIR" -e ".[dev]" 2>&1 | tail -1
    else
        err "Offline packages not found: $OFFLINE_DIR"
        err "Prepare offline packages first (see README.md)"
        exit 1
    fi
else
    step "Installing Python packages from PyPI..."
    $PIP install -e ".[dev]" 2>&1 | tail -1
fi
step "Backend dependencies installed"

# Semgrep
if has_cmd semgrep; then
    step "Semgrep already installed: $(semgrep --version 2>&1)"
else
    step "Installing Semgrep..."
    $PIP install semgrep 2>&1 | tail -1
    if has_cmd semgrep; then
        step "Semgrep installed: $(semgrep --version 2>&1)"
    else
        warn "Semgrep installation may have failed"
    fi
fi

# Bandit
if has_cmd bandit; then
    step "Bandit already installed"
else
    step "Installing Bandit..."
    $PIP install bandit 2>&1 | tail -1
    has_cmd bandit && step "Bandit installed" || warn "Bandit installation may have failed"
fi

cd "$ROOT"

# ── Install Node.js frontend ───────────────────────────────────────
header "Installing Frontend Dependencies"

cd "$FRONTEND"

if [[ "$OFFLINE" == true ]]; then
    OFFLINE_MODULES="$ROOT/offline-packages/node_modules.tar.gz"
    if [[ -f "$OFFLINE_MODULES" ]]; then
        step "Extracting offline node_modules..."
        tar xzf "$OFFLINE_MODULES"
    else
        err "Offline node_modules not found: $OFFLINE_MODULES"
        exit 1
    fi
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

# ESLint
if [[ -x "$FRONTEND/node_modules/.bin/eslint" ]]; then
    step "ESLint available locally: $FRONTEND/node_modules/.bin/eslint"
else
    warn "Local ESLint binary not found. VRAgent will bootstrap frontend dependencies on first ESLint scan."
fi

cd "$ROOT"

# ── Download CodeQL ─────────────────────────────────────────────────
if [[ "$SKIP_CODEQL" == false && "$OFFLINE" == false ]]; then
    header "Installing CodeQL"

    CODEQL_BIN="$BACKEND/tools/codeql/codeql"
    if [[ -f "$CODEQL_BIN" ]]; then
        CODEQL_VER=$("$CODEQL_BIN" version --format=terse 2>&1)
        step "CodeQL already installed: v$CODEQL_VER"
    else
        step "Downloading CodeQL CLI (~500MB, please wait)..."
        cd "$BACKEND"
        $PYTHON -m scripts.download_codeql --output tools/codeql 2>&1 | while IFS= read -r line; do
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
if [[ "$OFFLINE" == false ]]; then
    header "Installing jadx (APK decompiler)"

    JADX_BIN="$BACKEND/tools/jadx/bin/jadx"
    if [[ -f "$JADX_BIN" ]]; then
        step "jadx already installed at: $JADX_BIN"
    else
        step "Downloading jadx..."
        cd "$BACKEND"
        $PYTHON -m scripts.download_jadx --output tools/jadx 2>&1 | while IFS= read -r line; do
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
        $PYTHON -m scripts.download_semgrep_rules --output data/semgrep-rules/ 2>&1 | tail -1 || \
            warn "Semgrep rules download failed. Using bundled rules."
    fi

    # Advisory database
    ADV_MANIFEST="$BACKEND/data/advisories/manifest.json"
    if [[ -f "$ADV_MANIFEST" ]]; then
        step "Advisory database already present"
    else
        step "Downloading OSV advisory database (~250MB)..."
        $PYTHON -m scripts.sync_advisories --output data/advisories/ 2>&1 | tail -1 || \
            warn "Advisory database download failed."
    fi

    # Icons
    ICONS_DIR="$BACKEND/data/icons"
    ICON_COUNT=$(find "$ICONS_DIR" -name "*.svg" 2>/dev/null | wc -l)
    if [[ "$ICON_COUNT" -gt 50 ]]; then
        step "Technology icons already present ($ICON_COUNT icons)"
    else
        step "Downloading technology icons..."
        $PYTHON -m scripts.download_icons --output data/icons/ 2>&1 | tail -1 || \
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
    $PYTHON -m alembic upgrade head 2>&1 | tail -1 || warn "Migration failed. Check SQLite database path."
    cd "$ROOT"
fi

# ── Summary ─────────────────────────────────────────────────────────
header "Installation Complete"

check_item() {
    if $2; then
        step "$1"
    else
        warn "$1 — not found"
    fi
}

check_item "Python backend"      "test -f $BACKEND/app/main.py"
check_item "Frontend node_modules" "test -d $FRONTEND/node_modules"
check_item "Semgrep"             "has_cmd semgrep"
check_item "Bandit"              "has_cmd bandit"
check_item "ESLint"              "test -x $FRONTEND/node_modules/.bin/eslint"
check_item "CodeQL"              "test -f $BACKEND/tools/codeql/codeql"
check_item "jadx"                "test -f $BACKEND/tools/jadx/bin/jadx"
check_item "Semgrep rules"       "test $(find $BACKEND/data/semgrep-rules -name '*.yaml' 2>/dev/null | wc -l) -gt 100"
check_item "Advisory database"   "test -f $BACKEND/data/advisories/manifest.json"

echo ""
echo -e "  ${CYAN}To start VRAgent:${NC}"
echo ""
echo -e "    Terminal 1 (Backend):"
echo -e "      cd backend"
echo -e "      source venv/bin/activate  # if using venv"
echo -e "      uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo -e "    Terminal 2 (Frontend):"
echo -e "      cd frontend"
echo -e "      npm run dev"
echo ""
echo -e "    Then open: ${CYAN}http://localhost:3000${NC}"
echo ""
