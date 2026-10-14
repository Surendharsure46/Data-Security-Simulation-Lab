# One-time setup on Windows (PowerShell), from the repository root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Node.js 26.10+ not found. Install it from nodejs.org." }
Write-Host "Node: $(node --version)"
Push-Location $root
npm ci; if ($LASTEXITCODE) { exit 1 }
npm run build -w @threatready/contracts; if ($LASTEXITCODE) { exit 1 }
npm run build -w @threatready/api; if ($LASTEXITCODE) { exit 1 }
node apps\api\dist\cli.js validate-content; if ($LASTEXITCODE) { exit 1 }
node apps\api\dist\cli.js migrate; if ($LASTEXITCODE) { exit 1 }
Pop-Location
Write-Host "Setup complete. Start with: powershell -ExecutionPolicy Bypass -File scripts\dev.ps1" -ForegroundColor Green
