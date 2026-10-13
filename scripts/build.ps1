# Production-style single process: build the UI and let FastAPI serve it on port 8000.
$root = Split-Path -Parent $PSScriptRoot
Push-Location "$root\frontend"; npm run build; Pop-Location
Push-Location "$root\backend"
$env:THREATREADY_ENV = "production"
.\.venv\Scripts\python.exe -m app.cli init-db
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
Pop-Location
