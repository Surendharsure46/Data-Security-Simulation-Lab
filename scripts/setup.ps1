# One-time setup on Windows (PowerShell). Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "== Checking prerequisites" -ForegroundColor Cyan
$py = $null
try { $py = (& py -3.11 -c "import sys; print(sys.executable)") } catch { }
if (-not $py) { throw "Python 3.11+ not found. Install Python 3.11 from python.org (tick 'py launcher')." }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Node.js 20+ not found. Install the LTS release from nodejs.org." }
Write-Host "Python: $py"; Write-Host "Node:   $(node --version)"

Write-Host "== Backend virtual environment" -ForegroundColor Cyan
Push-Location "$root\backend"
if (-not (Test-Path .venv)) { & py -3.11 -m venv .venv }
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m app.cli validate-content
.\.venv\Scripts\python.exe -m app.cli init-db
Pop-Location

Write-Host "== Frontend dependencies" -ForegroundColor Cyan
Push-Location "$root\frontend"
npm ci
Pop-Location
Write-Host "Setup complete. Start with: powershell -ExecutionPolicy Bypass -File scripts\dev.ps1" -ForegroundColor Green
