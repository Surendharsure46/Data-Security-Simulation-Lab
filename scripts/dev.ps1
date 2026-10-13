# Start backend (http://127.0.0.1:8000) and frontend dev server (http://localhost:5173) in two windows.
$root = Split-Path -Parent $PSScriptRoot
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\backend'; .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; npm run dev"
Write-Host "Backend:  http://127.0.0.1:8000/api/health"
Write-Host "Frontend: http://localhost:5173  (set `$env:PORT to use another port)"
