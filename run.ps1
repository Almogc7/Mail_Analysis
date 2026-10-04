<#
  Start Mail Analysis on this machine (API + web UI in one process) and open it in the browser.

    powershell -ExecutionPolicy Bypass -File .\run.ps1            # http://localhost:8000
    powershell -ExecutionPolicy Bypass -File .\run.ps1 -Port 9000

  It listens on this machine only. The app has NO login, so do not change that until authentication exists.
  Stop it with Ctrl+C in this window.
#>
param(
    [int]$Port = 8000,
    [switch]$NoBrowser
)
# Native commands (git, npm, pip) write progress to stderr; with "Stop" Windows PowerShell 5.1 turns that into a fatal error.
# So errors are handled explicitly: every native call is followed by an exit-code check.
$ErrorActionPreference = "Continue"
$backend = Join-Path $PSScriptRoot "backend"
$venvPython = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "ERROR: not set up yet. Run:  powershell -ExecutionPolicy Bypass -File .\setup.ps1" -ForegroundColor Red
    exit 1
}
$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Write-Host "ERROR: port $Port is already in use (is Mail Analysis already running? try another port: -Port 9000)." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path (Join-Path $PSScriptRoot "frontend\dist\index.html"))) {
    Write-Host "Note: the web UI is not built, so only the API is served (http://localhost:$Port/docs). Run setup.ps1 with Node.js installed to build it." -ForegroundColor Yellow
}
if (-not $NoBrowser) { Start-Job -ScriptBlock { param($p) Start-Sleep -Seconds 3; Start-Process "http://localhost:$p" } -ArgumentList $Port | Out-Null }
Write-Host "Mail Analysis on http://localhost:$Port  (this machine only; Ctrl+C to stop)"
Set-Location $backend
& $venvPython -m uvicorn app.main:app --host 127.0.0.1 --port $Port
