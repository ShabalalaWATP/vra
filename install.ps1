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
    - SQLite database setup
    - Database migrations

    For air-gapped installs, run with -Offline and ensure offline packages
    are available (see README.md for preparation steps).

.PARAMETER Offline
    Skip all downloads. Install from local offline-packages/ only.

.PARAMETER SkipCodeQL
    Skip CodeQL download (it's optional but recommended).

.PARAMETER SkipDB
    Skip SQLite database initialization and migrations.

.PARAMETER SkipData
    Skip downloading Semgrep rules, advisories, and icons.

.PARAMETER DBPath
    SQLite database file path (default: backend\data\vragent.db)

.EXAMPLE
    # Full install (internet required)
    .\install.ps1

    # Air-gapped install (offline packages must be prepared in advance)
    .\install.ps1 -Offline

    # Install without CodeQL
    .\install.ps1 -SkipCodeQL

    # Custom database path
    .\install.ps1 -DBPath backend\data\custom.db
#>

param(
    [switch]$Offline,
    [switch]$SkipCodeQL,
    [switch]$SkipDB,
    [switch]$SkipData,
    [string]$DBPath = "backend\\data\\vragent.db"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ROOT = $PSScriptRoot
$BACKEND = Join-Path $ROOT "backend"
$FRONTEND = Join-Path $ROOT "frontend"
$OFFLINE_ROOT = Join-Path $ROOT "offline-packages"
$OFFLINE_PYTHON = Join-Path $OFFLINE_ROOT "python"
$OFFLINE_NODE = Join-Path $OFFLINE_ROOT "node_modules.tar.gz"
$OFFLINE_TOOLS = Join-Path $OFFLINE_ROOT "tools"
$LOCAL_SCANNERS = Join-Path $BACKEND "tools" "python_vendor"
$VENV_DIR = Join-Path $ROOT ".venv"
$VENV_PYTHON = Join-Path $VENV_DIR "Scripts\python.exe"
$MIN_NODE_MAJOR = 22
$MIN_NPM_MAJOR = 10

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

function Get-MajorVersion {
    param([string]$VersionText)
    if (-not $VersionText) {
        return 0
    }
    $token = (($VersionText.Trim() -replace "^v", "") -split "\.")[0]
    $major = 0
    if ([int]::TryParse($token, [ref]$major)) {
        return $major
    }
    return 0
}

function Find-Python312 {
    $candidates = @()

    if (Test-Command "py") {
        try {
            $launcherPath = (& py -3.12 -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            if ($launcherPath) {
                $candidates += $launcherPath
            }
        } catch {
            # Continue to other discovery paths.
        }
    }

    foreach ($name in @("python3.12", "python")) {
        if (Test-Command $name) {
            try {
                $candidatePath = (& $name -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
                if ($candidatePath) {
                    $candidates += $candidatePath
                }
            } catch {
                # Continue to other discovery paths.
            }
        }
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        try {
            $version = (& $candidate -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null | Select-Object -First 1)
            if ($version -eq "3.12") {
                return $candidate
            }
        } catch {
            # Continue checking candidates.
        }
    }

    return $null
}

function Get-SqliteUrl {
    param([string]$PathString)
    $fullPath = [System.IO.Path]::GetFullPath(
        $(if ([System.IO.Path]::IsPathRooted($PathString)) { $PathString } else { Join-Path $ROOT $PathString })
    )
    return "sqlite+aiosqlite:///" + ($fullPath -replace "\\", "/")
}

# ── Banner ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  VRAgent Installer" -ForegroundColor Cyan
Write-Host "  Offline AI-Assisted Static Vulnerability Research Platform" -ForegroundColor DarkCyan
Write-Host ""

# ── Check prerequisites ────────────────────────────────────────────
Write-Header "Checking Prerequisites"

# Python 3.12 is required because tree-sitter-languages 1.10.2 does not
# publish Windows wheels for Python 3.13 or 3.14.
$SYSTEM_PYTHON = Find-Python312
if (-not $SYSTEM_PYTHON) {
    Write-Err "Python 3.12 is required. Install Python 3.12 and ensure the py launcher or python3.12 is available."
    exit 1
}
$pyVer = & $SYSTEM_PYTHON --version 2>&1
Write-Step "Python for VRAgent: $pyVer ($SYSTEM_PYTHON)"

if ((Test-Path $VENV_PYTHON)) {
    $venvVersion = (& $VENV_PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null | Select-Object -First 1)
    if ($venvVersion -ne "3.12") {
        Write-Warn "Existing .venv uses Python $venvVersion; recreating it with Python 3.12."
        $resolvedVenv = (Resolve-Path $VENV_DIR).Path
        if ($resolvedVenv -eq (Join-Path $ROOT ".venv")) {
            Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
        } else {
            Write-Err "Refusing to remove unexpected venv path: $resolvedVenv"
            exit 1
        }
    }
}

if (-not (Test-Path $VENV_PYTHON)) {
    Write-Step "Creating local virtual environment: $VENV_DIR"
    & $SYSTEM_PYTHON -m venv $VENV_DIR
}

$PYTHON = $VENV_PYTHON
$PIP = @($PYTHON, "-m", "pip")
& $PYTHON -m pip install --upgrade pip setuptools wheel 2>&1 | Out-Null

# Node.js
if (Test-Command "node") {
    $nodeVer = node --version 2>&1
    $nodeMajor = Get-MajorVersion $nodeVer
    if ($nodeMajor -lt $MIN_NODE_MAJOR) {
        Write-Err "Node.js $MIN_NODE_MAJOR or newer is required. Current version: $nodeVer"
        Write-Err "Install Node.js 22.x LTS and add it to PATH."
        exit 1
    }
    Write-Step "Node.js: $nodeVer"
} else {
    Write-Err "Node.js not found. Install Node.js 22.x LTS and add it to PATH."
    exit 1
}

# npm
if (Test-Command "npm") {
    $npmVer = npm --version 2>&1
    $npmMajor = Get-MajorVersion $npmVer
    if ($npmMajor -lt $MIN_NPM_MAJOR) {
        Write-Err "npm $MIN_NPM_MAJOR or newer is required. Current version: $npmVer"
        Write-Err "Install the npm version bundled with Node.js 22.x LTS."
        exit 1
    }
    Write-Step "npm: $npmVer"
} else {
    Write-Err "npm not found. Should come with Node.js."
    exit 1
}
$NPM = if (Test-Command "npm.cmd") { (Get-Command "npm.cmd").Source } else { "npm" }

# ── Install Python backend ─────────────────────────────────────────
Write-Header "Installing Backend Dependencies"

Push-Location $BACKEND
try {
    if ($Offline) {
        if (Test-Path $OFFLINE_PYTHON) {
            Write-Step "Installing from offline packages: $OFFLINE_PYTHON"
            & $PYTHON -m pip install --no-index --find-links=$OFFLINE_PYTHON -e ".[dev]" 2>&1 | Out-Null
        } else {
            Write-Err "Offline packages not found at: $OFFLINE_PYTHON"
            Write-Err "Prepare offline packages first (see README.md)"
            exit 1
        }
    } else {
        Write-Step "Installing Python packages from PyPI..."
        & $PYTHON -m pip install -e ".[dev]" 2>&1 | Out-Null
    }
    Write-Step "Backend dependencies installed"

    # Bundle Semgrep + Bandit locally under backend/tools/
    $offlineScannerVendor = Join-Path $OFFLINE_TOOLS "python_vendor"
    if ($Offline -and (Test-Path $offlineScannerVendor)) {
        Write-Step "Restoring bundled Python scanners from offline bundle..."
        if (Test-Path $LOCAL_SCANNERS) {
            Remove-Item -Recurse -Force $LOCAL_SCANNERS
        }
        New-Item -ItemType Directory -Path (Split-Path $LOCAL_SCANNERS -Parent) -Force | Out-Null
        Copy-Item -Path $offlineScannerVendor -Destination $LOCAL_SCANNERS -Recurse -Force
    } else {
        Write-Step "Bundling project-local Python scanners..."
        $bundleArgs = @("-m", "scripts.bundle_python_scanners")
        if ($Offline) {
            if (-not (Test-Path $OFFLINE_PYTHON)) {
                Write-Err "Offline Python packages not found at: $OFFLINE_PYTHON"
                exit 1
            }
            $bundleArgs += @("--no-index", "--wheelhouse", $OFFLINE_PYTHON)
        }
        & $PYTHON @bundleArgs 2>&1 | Out-Null
    }

    $localSemgrep = Join-Path $BACKEND "tools" "bin" "run_semgrep.py"
    $localBandit = Join-Path $BACKEND "tools" "bin" "run_bandit.py"
    if ((Test-Path $localSemgrep) -and (Test-Path $LOCAL_SCANNERS)) {
        $semgrepVer = & $PYTHON $localSemgrep --version 2>$null | Select-Object -First 1
        Write-Step "Bundled Semgrep ready: $semgrepVer"
    } else {
        Write-Warn "Bundled Semgrep was not created successfully."
    }
    if ((Test-Path $localBandit) -and (Test-Path $LOCAL_SCANNERS)) {
        $banditVer = & $PYTHON $localBandit --version 2>$null | Select-Object -First 1
        Write-Step "Bundled Bandit ready: $banditVer"
    } else {
        Write-Warn "Bundled Bandit was not created successfully."
    }
} finally {
    Pop-Location
}

# ── Install Node.js frontend ───────────────────────────────────────
Write-Header "Installing Frontend Dependencies"

Push-Location $FRONTEND
try {
    if ($Offline) {
        if (Test-Path $OFFLINE_NODE) {
            Write-Step "Extracting offline node_modules..."
            tar xzf $OFFLINE_NODE
        } else {
            Write-Err "Offline node_modules not found at: $OFFLINE_NODE"
            exit 1
        }
    } else {
        [string[]]$npmInstallArgs = @(
            if (Test-Path (Join-Path $FRONTEND "package-lock.json")) { "ci" } else { "install" }
        )
        Write-Step "Running npm $($npmInstallArgs[0])..."
        & $NPM @npmInstallArgs
        if ($LASTEXITCODE -ne 0 -and $npmInstallArgs[0] -eq "ci") {
            Write-Warn "npm ci failed; falling back to npm install to refresh the lockfile."
            & $NPM install
        }
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Frontend dependency installation failed."
            exit 1
        }
    }
    Write-Step "Frontend dependencies installed"

    Write-Step "Building frontend..."
    & $NPM run build
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Frontend build failed."
        exit 1
    }
    Write-Step "Frontend build complete"

    # ESLint
    $localEslint = Join-Path $FRONTEND "node_modules" ".bin" "eslint.cmd"
    if (Test-Path $localEslint) {
        Write-Step "ESLint available locally: $localEslint"
    } else {
        Write-Warn "Local ESLint binary not found. VRAgent will bootstrap frontend dependencies on first ESLint scan."
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
            & $PYTHON -m scripts.download_codeql --output tools/codeql 2>&1 | ForEach-Object {
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
    $offlineCodeql = Join-Path $OFFLINE_TOOLS "codeql"
    $codeqlDir = Join-Path $BACKEND "tools" "codeql"
    $codeqlBin = Join-Path $BACKEND "tools" "codeql" "codeql.exe"
    if (-not (Test-Path $codeqlBin) -and (Test-Path $offlineCodeql)) {
        Write-Step "Restoring CodeQL from offline bundle..."
        New-Item -ItemType Directory -Path $codeqlDir -Force | Out-Null
        Copy-Item -Path (Join-Path $offlineCodeql "*") -Destination $codeqlDir -Recurse -Force
    }
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
            & $PYTHON -m scripts.download_jadx --output tools/jadx 2>&1 | ForEach-Object {
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
    $offlineJadx = Join-Path $OFFLINE_TOOLS "jadx"
    $jadxDir = Join-Path $BACKEND "tools" "jadx"
    $jadxBin = Join-Path $BACKEND "tools" "jadx" "bin" "jadx.bat"
    if (-not (Test-Path $jadxBin) -and (Test-Path $offlineJadx)) {
        Write-Step "Restoring jadx from offline bundle..."
        New-Item -ItemType Directory -Path $jadxDir -Force | Out-Null
        Copy-Item -Path (Join-Path $offlineJadx "*") -Destination $jadxDir -Recurse -Force
    }
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
                & $PYTHON -m scripts.download_semgrep_rules --output data/semgrep-rules/ 2>&1 | Out-Null
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
                & $PYTHON -m scripts.sync_advisories --output data/advisories/ 2>&1 | Out-Null
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
                & $PYTHON -m scripts.download_icons --output data/icons/ 2>&1 | Out-Null
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

    $dbFile = if ([System.IO.Path]::IsPathRooted($DBPath)) { $DBPath } else { Join-Path $ROOT $DBPath }
    $dbDir = Split-Path -Parent $dbFile
    if (-not (Test-Path $dbDir)) {
        New-Item -ItemType Directory -Path $dbDir -Force | Out-Null
    }
    $connStr = Get-SqliteUrl -PathString $DBPath
    Write-Step "Using SQLite database: $dbFile"

    # Run migrations
    Write-Step "Running database migrations..."
    Push-Location $BACKEND
    try {
        $env:VRAGENT_DATABASE_URL = $connStr
        & $PYTHON -m alembic upgrade head 2>&1 | Out-Null
        Write-Step "Migrations complete"
    } catch {
        Write-Warn "Migration failed for SQLite database: $dbFile"
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
    @{ Name = "Bundled Semgrep"; Check = { (Test-Path (Join-Path $BACKEND "tools" "bin" "run_semgrep.py")) -and (Test-Path (Join-Path $BACKEND "tools" "python_vendor")) } },
    @{ Name = "Bundled Bandit"; Check = { (Test-Path (Join-Path $BACKEND "tools" "bin" "run_bandit.py")) -and (Test-Path (Join-Path $BACKEND "tools" "python_vendor")) } },
    @{ Name = "ESLint"; Check = { Test-Path (Join-Path $FRONTEND "node_modules" ".bin" "eslint.cmd") } },
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
Write-Host "    Preferred runtime (single process, serves frontend/dist):" -ForegroundColor White
Write-Host "      .\\start.ps1" -ForegroundColor DarkGray
Write-Host "      Then open: http://localhost:8000" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    Development mode (two processes):" -ForegroundColor White
    Write-Host "      Terminal 1: cd backend ; ..\\.venv\\Scripts\\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000" -ForegroundColor DarkGray
Write-Host "      Terminal 2: cd frontend ; npm run dev" -ForegroundColor DarkGray
Write-Host "      Then open: http://localhost:3000" -ForegroundColor DarkGray
Write-Host ""
