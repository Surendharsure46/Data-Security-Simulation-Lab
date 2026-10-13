# Deployment and operations

## Requirements

| Component | Version used for verification | Notes |
|---|---|---|
| Windows | 11 Pro 22631 | Linux/macOS work with equivalent commands (`.venv/bin/python`). |
| Python | 3.11.x (CPython) | 3.8 is **not** supported. The `py` launcher is used by the scripts. |
| Node.js / npm | Node 26.10, npm 11.19 | Node 20 LTS or newer expected to work. |
| RAM | < 500 MB for backend + Vite dev server | Suitable for an 8 GB laptop. |
| Docker | not required | Dockerfile/compose provided but **untested**. |

Backend Python dependencies are pinned in `backend/requirements.txt` (runtime) and `requirements-dev.txt` (tests). Frontend dependencies are pinned in `frontend/package.json` with a lockfile.

## Local development (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1   # venv, pip install, validate content, migrate, npm ci
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1     # backend :8000 + Vite :5173 (proxy /api → :8000)
```

Configuration is read from environment variables prefixed `THREATREADY_` or from `.env` in the repository root or `backend/` (see `.env.example`). Relative SQLite paths are resolved from the backend working directory.

### Database initialisation and migrations

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.cli init-db          # alembic upgrade head + default organisation (+ admin if configured)
.\.venv\Scripts\python.exe -m alembic revision --autogenerate -m "describe change"   # after model changes
.\.venv\Scripts\python.exe -m alembic upgrade head
```

Synthetic training data is not seeded globally: each scenario session provisions its own copy of the fictional company from `app/content/company.py`, and labs create their data on first use.

### Accounts

- Learners self-register (disable with `THREATREADY_ALLOW_SELF_REGISTRATION=false`).
- Admin: set `THREATREADY_BOOTSTRAP_ADMIN_PASSWORD` before `init-db`, or `python -m app.cli create-user alice --role admin` (prompts for the password).

## Single-process “production” mode

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

Builds `frontend/dist`, sets `THREATREADY_ENV=production` (hides `/api/docs`) and serves UI + API from `http://127.0.0.1:8000`. For anything beyond a single trusted machine put a TLS-terminating reverse proxy in front, bind uvicorn to localhost, and run one worker process (login rate limiting is in-memory).

## Containers (optional, untested)

```
docker compose up --build
```

The image builds the UI, runs `init-db` at start and stores the database and lab files in the `threatready-data` volume. Docker was not available on the build machine, so this path has not been executed.

## Backup and recovery

Stop the server, then copy `backend/var/threatready.db` (and `-wal`/`-shm` files if present) and `backend/var/labs/`. Restore by copying them back. Lab files are disposable and can be regenerated.

## Safe reset

- One scenario: **Simulation Workspace → Reset** (keeps submitted attempts).
- One lab: the lab page's **Reset** button.
- Everything (development only): stop the server, `python -m app.cli reset-data --yes`, then `python -m app.cli init-db`.

## Troubleshooting (Windows)

| Symptom | Fix |
|---|---|
| `py -3.11` not found | Install Python 3.11 from python.org with the “py launcher” option, reopen PowerShell. |
| Script blocked by execution policy | Use `powershell -ExecutionPolicy Bypass -File …` as shown. |
| Port 5173 already in use | `$env:PORT=5180; npm run dev` (Vite reads `PORT`). |
| UI shows “Cannot reach the Threatready server” | Start the backend on port 8000, or set `THREATREADY_BACKEND` for Vite's proxy. |
| `npm ci` warns that esbuild install scripts were not run | Harmless with npm 11: the platform binary ships as `@esbuild/win32-x64`. |
| Playwright cannot find a browser | `npx playwright install chromium`, or use installed Edge: `$env:PW_CHANNEL="msedge"`. |
| `database is locked` | Only one backend process should use the SQLite file; stop duplicates. |
