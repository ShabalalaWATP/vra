param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$UvicornArgs
)

$ErrorActionPreference = "Stop"

$ROOT = $PSScriptRoot
$BACKEND = Join-Path $ROOT "backend"
$VENV_PYTHON = Join-Path (Join-Path $ROOT ".venv") "Scripts\python.exe"
$DIST = Join-Path (Join-Path (Join-Path $ROOT "frontend") "dist") "index.html"

if (-not (Test-Path $DIST)) {
    Write-Warning "frontend/dist/index.html is missing. Build the frontend before using start.ps1."
}

if (-not $env:VRAGENT_CORS_ORIGINS) {
    $env:VRAGENT_CORS_ORIGINS = "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://127.0.0.1:3000"
}

Push-Location $BACKEND
try {
    $argsToUse = @("app.main:app", "--host", "0.0.0.0", "--port", "8000")
    if ($UvicornArgs) {
        $argsToUse += $UvicornArgs
    }
    $python = if (Test-Path $VENV_PYTHON) { $VENV_PYTHON } else { "python" }
    $pyVersion = (& $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null | Select-Object -First 1)
    if ($pyVersion -ne "3.12") {
        throw "VRAgent requires Python 3.12 for the current tree-sitter-languages dependency. Found Python $pyVersion at $python. Run .\install.ps1 first."
    }
    & $python -m uvicorn @argsToUse
} finally {
    Pop-Location
}
