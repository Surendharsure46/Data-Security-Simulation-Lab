# Run every automated test suite. Pass -E2E to include the Playwright browser test.
param([switch]$E2E)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location "$root\backend"; .\.venv\Scripts\python.exe -m pytest; if ($LASTEXITCODE) { exit 1 }; Pop-Location
Push-Location "$root\frontend"
npm run typecheck; if ($LASTEXITCODE) { exit 1 }
npm test; if ($LASTEXITCODE) { exit 1 }
if ($E2E) { npx playwright test; if ($LASTEXITCODE) { exit 1 } }
Pop-Location
Write-Host "All requested test suites passed." -ForegroundColor Green
