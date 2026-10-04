<#
  One-time setup for a Windows analyst machine (no Docker needed).

    powershell -ExecutionPolicy Bypass -File .\setup.ps1

  What it does, and nothing else:
    1. checks Python 3.10+                              (stops with an install hint if missing)
    2. creates backend\.venv and installs the dependencies
    3. creates backend\.env from the example if you have none (no keys are filled in for you)
    4. builds the web UI if Node.js is installed        (otherwise only the API runs; the script says so)
    5. runs the test suite unless -SkipTests

  Everything the app needs is in this repository. The script never touches mail, never contacts a threat-intelligence
  service and never uploads anything.
#>
param(
    [switch]$SkipTests,
    [switch]$SkipFrontend
)
# Native commands (git, npm, pip) write progress to stderr; with "Stop" Windows PowerShell 5.1 turns that into a fatal error.
# So errors are handled explicitly: every native call is followed by an exit-code check.
$ErrorActionPreference = "Continue"
$root = $PSScriptRoot
$backend = Join-Path $root "backend"

function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "ERROR: $text" -ForegroundColor Red; exit 1 }

# ---- 1. Python ---------------------------------------------------------------------------------------------------
Step "Checking Python"
$python = $null
foreach ($candidate in @("py", "python")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $probeArgs = if ($candidate -eq "py") { @("-3", "-c", "import sys; print('%d.%d' % sys.version_info[:2])") } else { @("-c", "import sys; print('%d.%d' % sys.version_info[:2])") }
        try { $version = (& $candidate @probeArgs 2>$null) | Select-Object -First 1 } catch { $version = $null }
        if ($version -match '^(\d+)\.(\d+)$' -and ([int]$Matches[1] -gt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 10))) {
            $python = $candidate; $pythonArgs = if ($candidate -eq "py") { @("-3") } else { @() }
            Write-Host "Using $candidate (Python $version)"
            break
        }
    }
}
if (-not $python) { Fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), then run this script again." }

# ---- 2. virtual environment ----------------------------------------------------------------------------------------
Step "Creating the virtual environment and installing dependencies"
$venvPython = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { & $python @pythonArgs -m venv (Join-Path $backend ".venv"); if ($LASTEXITCODE -ne 0) { Fail "could not create the virtual environment" } }
& $venvPython -m pip install --quiet --upgrade pip
& $venvPython -m pip install --quiet -r (Join-Path $backend "requirements.txt")
if ($LASTEXITCODE -ne 0) { Fail "pip install failed (check your internet connection / proxy)" }

# ---- 3. .env -------------------------------------------------------------------------------------------------------
Step "Configuration"
$envFile = Join-Path $backend ".env"
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $root "deploy\team-config.example\env.example") $envFile
    Write-Host "Created backend\.env from the example. Open it and add your own API keys (all optional)."
} else {
    Write-Host "backend\.env already exists (left as it is)"
}

# ---- 4. web UI -----------------------------------------------------------------------------------------------------
Step "Web UI"
$dist = Join-Path $root "frontend\dist\index.html"
if ($SkipFrontend) {
    Write-Host "Skipped (-SkipFrontend)"
} elseif ((Get-Command node -ErrorAction SilentlyContinue) -and (Get-Command npm -ErrorAction SilentlyContinue)) {
    Push-Location (Join-Path $root "frontend")
    try { npm ci --no-audit --no-fund --silent; if ($LASTEXITCODE -ne 0) { Fail "npm ci failed" }; npm run build --silent; if ($LASTEXITCODE -ne 0) { Fail "the UI build failed" } } finally { Pop-Location }
    Write-Host "UI built."
} elseif (Test-Path $dist) {
    Write-Host "Node.js not found, using the UI build that is already there."
} else {
    Write-Host "Node.js was not found, so the web UI was NOT built; only the API will run. Install Node 20+ from https://nodejs.org, or use Docker." -ForegroundColor Yellow
}

# ---- 5. tests ------------------------------------------------------------------------------------------------------
if (-not $SkipTests) {
    Step "Running the tests (offline, about half a minute)"
    Push-Location $backend
    try { & $venvPython -m pytest -q; if ($LASTEXITCODE -ne 0) { Fail "tests failed: do not use this install until that is understood" } } finally { Pop-Location }
}

Write-Host ""
Write-Host "Setup finished. Start the app with:   powershell -ExecutionPolicy Bypass -File .\run.ps1" -ForegroundColor Green
