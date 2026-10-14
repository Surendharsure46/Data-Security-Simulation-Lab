# Run every automated test suite. Pass -E2E to include the Playwright browser test.
param([switch]$E2E)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
npm run check:boundaries; if ($LASTEXITCODE) { exit 1 }
npm run typecheck; if ($LASTEXITCODE) { exit 1 }
npm test; if ($LASTEXITCODE) { exit 1 }
if ($E2E) { npm run e2e; if ($LASTEXITCODE) { exit 1 } }
Pop-Location
Write-Host "All requested test suites passed." -ForegroundColor Green
