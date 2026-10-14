# Production-style single process: build everything and let the API serve the web app on port 8000.
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
npm run build; if ($LASTEXITCODE) { exit 1 }
node apps\api\dist\cli.js migrate; if ($LASTEXITCODE) { exit 1 }
Push-Location apps\api
node dist\main.js
Pop-Location
Pop-Location
