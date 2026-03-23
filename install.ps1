#Requires -Version 5.1
<#
.SYNOPSIS
    VRAgent installation script for Windows.

.DESCRIPTION
    Installs all dependencies for VRAgent including:
    - Python backend dependencies (pip)
    - Node.js frontend dependencies (npm)
    - Semgrep and Bandit (pip)
    - ESLint (npm)
    - CodeQL CLI (downloaded from GitHub)
    - Semgrep rules (downloaded from GitHub)
    - OSV advisory database (downloaded from GCS)
    - Technology icons (downloaded from GitHub)
    - PostgreSQL database setup
    - Database migrations

    For air-gapped installs, run with -Offline and ensure offline packages
    are available (see README.md for preparation steps).

.PARAMETER Offline
    Skip all downloads. Install from local offline-packages/ only.

.PARAMETER SkipCodeQL
    Skip CodeQL download (it's optional but recommended).

.PARAMETER SkipDB
    Skip PostgreSQL database creation and migrations.

.PARAMETER SkipData
    Skip downloading Semgrep rules, advisories, and icons.

.PARAMETER DBUser
    PostgreSQL username (default: vragent)

.PARAMETER DBPassword
    PostgreSQL password (default: vragent)

.PARAMETER DBName
    PostgreSQL database name (default: vragent)

.PARAMETER DBHost
    PostgreSQL host (default: localhost)

.PARAMETER DBPort
    PostgreSQL port (default: 5432)

.EXAMPLE
    # Full install (internet required)
    .\install.ps1

    # Air-gapped install (offline packages must be prepared in advance)
    .\install.ps1 -Offline

    # Install without CodeQL
    .\install.ps1 -SkipCodeQL

    # Custom database settings
    .\install.ps1 -DBUser myuser -DBPassword mypass -DBName mydb
#>

param(
    [switch]$Offline,
    [switch]$SkipCodeQL,
    [switch]$SkipDB,
    [switch]$SkipData,
    [string]$DBUser = "vragent",
    [string]$DBPassword = "vragent",
    [string]$DBName = "vragent",
    [string]$DBHost = "localhost",
    [int]$DBPort = 5432
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ROOT = $PSScriptRoot
$BACKEND = Join-Path $ROOT "backend"
$FRONTEND = Join-Path $ROOT "frontend"

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "  [+] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  [!] $Text" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Text)
    Write-Host "  [X] $Text" -ForegroundColor Red
}

function Test-Command {
    param([string]$Name)
    $null = Get-Command $Name -ErrorAction SilentlyContinue
    return $?
}

# ── Banner ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  VRAgent Installer" -ForegroundColor Cyan
Write-Host "  Offline AI-Assisted Static Vulnerability Research Platform" -ForegroundColor DarkCyan
Write-Host ""

# ── Check prerequisites ────────────────────────────────────────────
Write-Header "Checking Prerequisites"

# Python
if (Test-Command "python") {
    $pyVer = python --version 2>&1
    Write-Step "Python: $pyVer"
    $pyMajor = [int]($pyVer -replace "Python (\d+)\.(\d+)\.\d+", '$1')
    $pyMinor = [int]($pyVer -replace "Python (\d+)\.(\d+)\.\d+", '$2')
    if ($pyMajor -lt 3 -or $pyMinor -lt 11) {
        Write-Err "Python 3.11+ is required. Found: $pyVer"
        exit 1
    }
} else {
    Write-Err "Python not found. Install Python 3.11+ and add to PATH."
    exit 1
}

# Node.js
if (Test-Command "node") {
    $nodeVer = node --version 2>&1
    Write-Step "Node.js: $nodeVer"
} else {
    Write-Err "Node.js not found. Install Node.js 18+ and add to PATH."
    exit 1
}

# npm
if (Test-Command "npm") {
    $npmVer = npm --version 2>&1
    Write-Step "npm: $npmVer"
} else {
    Write-Err "npm not found. Should come with Node.js."
    exit 1
}

# PostgreSQL (optional check)
if (-not $SkipDB) {
    if (Test-Command "psql") {
        $psqlVer = psql --version 2>&1
        Write-Step "PostgreSQL client: $psqlVer"
    } else {
        Write-Warn "psql not found in PATH. Database setup may fail."
        Write-Warn "Ensure PostgreSQL is installed and psql is in PATH."
    }
}

# ── Install Python backend ─────────────────────────────────────────
Write-Header "Installing Backend Dependencies"

Push-Location $BACKEND
try {
    if ($Offline) {
        $offlinePkgs = Join-Path $ROOT "offline-packages" "python"
        if (Test-Path $offlinePkgs) {
            Write-Step "Installing from offline packages: $offlinePkgs"
            pip install --no-index --find-links=$offlinePkgs -e ".[dev]" 2>&1 | Out-Null
        } else {
            Write-Err "Offline packages not found at: $offlinePkgs"
            Write-Err "Prepare offline packages first (see README.md)"
            exit 1
        }
    } else {
        Write-Step "Installing Python packages from PyPI..."
        pip install -e ".[dev]" 2>&1 | Out-Null
    }
    Write-Step "Backend dependencies installed"

    # Install Semgrep
    if (Test-Command "semgrep") {
        $sgVer = semgrep --version 2>&1
        Write-Step "Semgrep already installed: $sgVer"
    } else {
        Write-Step "Installing Semgrep..."
        pip install semgrep 2>&1 | Out-Null
        if (Test-Command "semgrep") {
            Write-Step "Semgrep installed: $(semgrep --version 2>&1)"
        } else {
            Write-Warn "Semgrep installation may have failed. Check: pip install semgrep"
        }
    }

    # Install Bandit
    if (Test-Command "bandit") {
        $bVer = bandit --version 2>&1
        Write-Step "Bandit already installed: $bVer"
    } else {
        Write-Step "Installing Bandit..."
        pip install bandit 2>&1 | Out-Null
        if (Test-Command "bandit") {
            Write-Step "Bandit installed"
        } else {
            Write-Warn "Bandit installation may have failed. Check: pip install bandit"
        }
    }
} finally {
    Pop-Location
}

# ── Install Node.js frontend ───────────────────────────────────────
Write-Header "Installing Frontend Dependencies"

Push-Location $FRONTEND
try {
    if ($Offline) {
        $offlineModules = Join-Path $ROOT "offline-packages" "node_modules.tar.gz"
        if (Test-Path $offlineModules) {
            Write-Step "Extracting offline node_modules..."
            tar xzf $offlineModules
        } else {
            Write-Err "Offline node_modules not found at: $offlineModules"
            exit 1
        }
    } else {
        Write-Step "Running npm install..."
        npm install 2>&1 | Out-Null
    }
    Write-Step "Frontend dependencies installed"

    # ESLint
    if (Test-Command "eslint") {
        Write-Step "ESLint already installed"
    } else {
        Write-Step "Installing ESLint globally..."
        npm install -g eslint 2>&1 | Out-Null
        if (Test-Command "eslint") {
            Write-Step "ESLint installed"
        } else {
            Write-Warn "ESLint global install may have failed. VRAgent will try local eslint."
        }
    }
} finally {
    Pop-Location
}

# ── Download CodeQL ─────────────────────────────────────────────────
if (-not $SkipCodeQL -and -not $Offline) {
    Write-Header "Installing CodeQL"

    $codeqlBin = Join-Path $BACKEND "tools" "codeql" "codeql.exe"
    if (Test-Path $codeqlBin) {
        $codeqlVer = & $codeqlBin version --format=terse 2>&1
        Write-Step "CodeQL already installed: v$codeqlVer"
    } else {
        Write-Step "Downloading CodeQL CLI (~500MB, please wait)..."
        Push-Location $BACKEND
        try {
            python -m scripts.download_codeql --output tools/codeql 2>&1 | ForEach-Object {
                if ($_ -match "^\s+\[") { Write-Host "`r  $_" -NoNewline }
                elseif ($_ -match "Version:|installed|Binary:") { Write-Step $_ }
            }
        } catch {
            Write-Warn "CodeQL download failed: $_"
            Write-Warn "CodeQL is optional. VRAgent works without it."
            Write-Warn "To install manually, see README.md"
        } finally {
            Pop-Location
        }
    }
} elseif ($SkipCodeQL) {
    Write-Header "Skipping CodeQL (--SkipCodeQL)"
    Write-Warn "CodeQL is optional but recommended for deep taint tracking."
} elseif ($Offline) {
    Write-Header "CodeQL (Offline Mode)"
    $codeqlBin = Join-Path $BACKEND "tools" "codeql" "codeql.exe"
    if (Test-Path $codeqlBin) {
        Write-Step "CodeQL found at: $codeqlBin"
    } else {
        Write-Warn "CodeQL not found. For offline install:"
        Write-Warn "  1. Download codeql-bundle-win64.tar.gz on an internet-connected machine"
        Write-Warn "  2. Extract to: backend\tools\codeql\"
        Write-Warn "  3. The binary should be at: backend\tools\codeql\codeql.exe"
    }
}

# ── Download jadx ──────────────────────────────────────────────────
if (-not $Offline) {
    Write-Header "Installing jadx (APK decompiler)"

    $jadxBin = Join-Path $BACKEND "tools" "jadx" "bin" "jadx.bat"
    if (Test-Path $jadxBin) {
        Write-Step "jadx already installed at: $jadxBin"
    } else {
        Write-Step "Downloading jadx..."
        Push-Location $BACKEND
        try {
            python -m scripts.download_jadx --output tools/jadx 2>&1 | ForEach-Object {
                if ($_ -match "Version:|installed|Binary:") { Write-Step $_ }
            }
        } catch {
            Write-Warn "jadx download failed: $_"
            Write-Warn "APK scanning will be unavailable without jadx."
            Write-Warn "Manual install: https://github.com/skylot/jadx/releases"
            Write-Warn "Extract to: backend\tools\jadx\ (needs Java 11+)"
        } finally {
            Pop-Location
        }
    }
} elseif ($Offline) {
    Write-Header "jadx (Offline Mode)"
    $jadxBin = Join-Path $BACKEND "tools" "jadx" "bin" "jadx.bat"
    if (Test-Path $jadxBin) {
        Write-Step "jadx found at: $jadxBin"
    } else {
        Write-Warn "jadx not found. For offline install:"
        Write-Warn "  1. Download jadx-<version>.zip on an internet-connected machine"
        Write-Warn "  2. Extract to: backend\tools\jadx\"
        Write-Warn "  3. Binary should be at: backend\tools\jadx\bin\jadx.bat"
        Write-Warn "  4. Requires Java 11+ at runtime"
    }
}

# ── Download offline data ───────────────────────────────────────────
if (-not $SkipData -and -not $Offline) {
    Write-Header "Downloading Offline Data"

    Push-Location $BACKEND
    try {
        # Check if Semgrep rules already exist
        $rulesDir = Join-Path $BACKEND "data" "semgrep-rules"
        $ruleCount = (Get-ChildItem -Path $rulesDir -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($ruleCount -gt 100) {
            Write-Step "Semgrep rules already present ($ruleCount rules)"
        } else {
            Write-Step "Downloading Semgrep rules..."
            try {
                python -m scripts.download_semgrep_rules --output data/semgrep-rules/ 2>&1 | Out-Null
                $newCount = (Get-ChildItem -Path $rulesDir -Filter "*.yaml" -Recurse | Measure-Object).Count
                Write-Step "Downloaded $newCount Semgrep rules"
            } catch {
                Write-Warn "Semgrep rules download failed. Using bundled rules."
            }
        }

        # Check if advisories already exist
        $advDir = Join-Path $BACKEND "data" "advisories"
        $manifest = Join-Path $advDir "manifest.json"
        if (Test-Path $manifest) {
            Write-Step "Advisory database already present"
        } else {
            Write-Step "Downloading OSV advisory database (~250MB)..."
            try {
                python -m scripts.sync_advisories --output data/advisories/ 2>&1 | Out-Null
                Write-Step "Advisory database downloaded"
            } catch {
                Write-Warn "Advisory database download failed."
                Write-Warn "Dependency scanning will be limited without it."
            }
        }

        # Icons
        $iconsDir = Join-Path $BACKEND "data" "icons"
        $iconCount = (Get-ChildItem -Path $iconsDir -Filter "*.svg" -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($iconCount -gt 50) {
            Write-Step "Technology icons already present ($iconCount icons)"
        } else {
            Write-Step "Downloading technology icons..."
            try {
                python -m scripts.download_icons --output data/icons/ 2>&1 | Out-Null
                Write-Step "Icons downloaded"
            } catch {
                Write-Warn "Icons download failed. Diagrams will work without custom icons."
            }
        }
    } finally {
        Pop-Location
    }
}

# ── Database setup ──────────────────────────────────────────────────
if (-not $SkipDB) {
    Write-Header "Setting Up Database"

    $connStr = "postgresql+asyncpg://${DBUser}:${DBPassword}@${DBHost}:${DBPort}/${DBName}"

    # Try to create database
    if (Test-Command "psql") {
        Write-Step "Creating database '$DBName' (if not exists)..."
        try {
            $env:PGPASSWORD = $DBPassword
            $dbExists = psql -h $DBHost -p $DBPort -U $DBUser -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DBName'" 2>$null
            if ($dbExists -ne "1") {
                psql -h $DBHost -p $DBPort -U postgres -c "CREATE USER $DBUser WITH PASSWORD '$DBPassword';" 2>$null
                psql -h $DBHost -p $DBPort -U postgres -c "CREATE DATABASE $DBName OWNER $DBUser;" 2>$null
                psql -h $DBHost -p $DBPort -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE $DBName TO $DBUser;" 2>$null
                Write-Step "Database created"
            } else {
                Write-Step "Database '$DBName' already exists"
            }
        } catch {
            Write-Warn "Could not auto-create database. Create it manually:"
            Write-Warn "  CREATE USER $DBUser WITH PASSWORD '$DBPassword';"
            Write-Warn "  CREATE DATABASE $DBName OWNER $DBUser;"
        } finally {
            Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        }
    } else {
        Write-Warn "psql not in PATH. Ensure the database exists:"
        Write-Warn "  CREATE USER $DBUser WITH PASSWORD '$DBPassword';"
        Write-Warn "  CREATE DATABASE $DBName OWNER $DBUser;"
    }

    # Run migrations
    Write-Step "Running database migrations..."
    Push-Location $BACKEND
    try {
        $env:VRAGENT_DATABASE_URL = $connStr
        alembic upgrade head 2>&1 | Out-Null
        Write-Step "Migrations complete"
    } catch {
        Write-Warn "Migration failed. Ensure PostgreSQL is running and the database exists."
        Write-Warn "Connection string: $connStr"
    } finally {
        Pop-Location
    }
}

# ── Summary ─────────────────────────────────────────────────────────
Write-Header "Installation Complete"

# Check what's installed
$checks = @(
    @{ Name = "Python backend"; Check = { Test-Path (Join-Path $BACKEND "app" "main.py") } },
    @{ Name = "Frontend node_modules"; Check = { Test-Path (Join-Path $FRONTEND "node_modules") } },
    @{ Name = "Semgrep"; Check = { Test-Command "semgrep" } },
    @{ Name = "Bandit"; Check = { Test-Command "bandit" } },
    @{ Name = "ESLint"; Check = { Test-Command "eslint" } },
    @{ Name = "CodeQL"; Check = { Test-Path (Join-Path $BACKEND "tools" "codeql" "codeql.exe") } },
    @{ Name = "jadx"; Check = { Test-Path (Join-Path $BACKEND "tools" "jadx" "bin" "jadx.bat") } },
    @{ Name = "Semgrep rules"; Check = { (Get-ChildItem -Path (Join-Path $BACKEND "data" "semgrep-rules") -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count -gt 100 } },
    @{ Name = "Advisory database"; Check = { Test-Path (Join-Path $BACKEND "data" "advisories" "manifest.json") } }
)

foreach ($c in $checks) {
    $ok = & $c.Check
    if ($ok) {
        Write-Step "$($c.Name)"
    } else {
        Write-Warn "$($c.Name) — not found"
    }
}

Write-Host ""
Write-Host "  To start VRAgent:" -ForegroundColor Cyan
Write-Host ""
Write-Host "    Terminal 1 (Backend):" -ForegroundColor White
Write-Host "      cd backend" -ForegroundColor DarkGray
Write-Host "      uvicorn app.main:app --host 0.0.0.0 --port 8000" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    Terminal 2 (Frontend):" -ForegroundColor White
Write-Host "      cd frontend" -ForegroundColor DarkGray
Write-Host "      npm run dev" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    Then open: http://localhost:3000" -ForegroundColor White
Write-Host ""
