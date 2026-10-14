# Start the API (http://127.0.0.1:8000, embedded PostgreSQL in apps/api/var/pgdata) and the web dev server
# (http://localhost:5173) in two windows.
$root = Split-Path -Parent $PSScriptRoot
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location $root; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location $root; npm run dev:web"
Write-Host "API:      http://127.0.0.1:8000/api/health"
Write-Host "Web app:  http://localhost:5173"
