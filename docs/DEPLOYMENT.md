# Deployment and operations

## Requirements

| Component | Version used for verification | Notes |
|---|---|---|
| Node.js / npm | Node 26.10, npm 11 | Required: the database lab uses `node:sqlite` with `setAuthorizer`. No Python is needed any more. |
| PostgreSQL | 17 in production (RDS); embedded PGlite 0.5 locally and in tests | Same migrations on both. |
| Docker | optional | Image and compose file are provided; Docker was not installed on the build machine, so they are built in CI only. |
| OpenTofu | 1.10+ | Only to provision AWS. Nothing has been provisioned. |

All dependencies are pinned to exact versions in the workspace `package.json` files with one root `package-lock.json`.

## Repository layout

```
packages/contracts   Zod request schemas + policy language (shared by API and web)
apps/api             NestJS API + worker, Drizzle schema and SQL migrations, Vitest suite
apps/web             React SPA, Vitest component tests, Playwright e2e
infra/tofu           OpenTofu: network, RDS, S3, ECS Fargate (api, worker, migrate), ALB, EFS, Cloudflare, GitHub OIDC
.github/workflows    ci.yml (verify, e2e, PostgreSQL, image, infra validate) and deploy.yml (OIDC deploy)
scripts/             Windows setup/dev/test/build scripts and the module-boundary check
```

## Local development

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1   # npm ci, build, validate content, migrate
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1     # API :8000 + Vite :5173 (proxy /api -> :8000)
```

Without the scripts: `npm ci`, then `npm run dev` (builds and starts the API with the embedded database in `apps/api/var/pgdata`) and `npm run dev:web` in a second terminal.

Configuration comes from `THREATREADY_*` environment variables or a `.env` file in the repository root or `apps/api` (see `.env.example`). The API refuses to start in production without `THREATREADY_AUTH_SECRET`.

### Database and migrations

```powershell
npm run db:migrate                     # build + apply migrations (+ bootstrap admin if configured)
npm run db:generate                    # after changing apps/api/src/db/schema.ts: writes a new SQL migration
```

The API applies pending migrations at start-up unless `THREATREADY_MIGRATE_ON_START=false`. On AWS it is off and the one-off `threatready-migrate` ECS task runs them before services roll. CI fails if the schema changed without a committed migration. Row-level security policies live in the hand-written migration `0001_rls.sql`.

### Accounts

- Learners self-register with an email address (disable with `THREATREADY_ALLOW_SELF_REGISTRATION=false`).
- Bootstrap admin: set `THREATREADY_BOOTSTRAP_ADMIN_EMAIL` / `THREATREADY_BOOTSTRAP_ADMIN_PASSWORD` (12+ characters).
- Any role: `THREATREADY_NEW_USER_PASSWORD=... node apps/api/dist/cli.js create-user alice@example.com instructor "Alice"` (the password is never a command-line argument).
- Accounts from the previous Python release are **not** migrated: usernames became email addresses and PBKDF2 hashes are not compatible with Better Auth. Learners re-register.

## Single-process production mode (one machine)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

Builds everything, migrates and serves web app + API on port 8000 (role `all`: API and worker in one process). Use PostgreSQL (`THREATREADY_DATABASE_URL=postgres://…`), set `THREATREADY_ENV=production` and a real `THREATREADY_AUTH_SECRET`, and put TLS in front.

## Render (or any Node.js host)

| Setting | Value |
|---|---|
| Build Command | `npm ci && npm run build` |
| Start Command | `npm start` |
| Node version | 26.10 (from `.node-version` / `engines`) |
| Health check path | `/api/health` |

Environment variables:

| Variable | Value |
|---|---|
| `THREATREADY_ENV` | `production` |
| `THREATREADY_AUTH_SECRET` | 32+ random characters (required; Render's "Generate" button works) |
| `THREATREADY_DATABASE_URL` | the Internal Database URL of a Render PostgreSQL instance. Without it the embedded database lives on the service's disk and is lost on every deploy. |
| `THREATREADY_BOOTSTRAP_ADMIN_EMAIL` / `..._PASSWORD` | optional admin account |

Render's `PORT` and `RENDER_EXTERNAL_URL` are picked up automatically (listening address, cookie origin and trusted origin). Set `THREATREADY_PUBLIC_URL` when you use a custom domain. Migrations run at start-up (`THREATREADY_MIGRATE_ON_START`, default `true`). Do not set `NODE_ENV=production` for the build, or `npm ci` skips the build tools.

## Containers

```
THREATREADY_AUTH_SECRET=<64 hex chars> docker compose up --build
```

Starts PostgreSQL 17, runs migrations once, then the `api` (port 8000) and `worker` services from the same image.

## AWS (OpenTofu, not provisioned)

`infra/tofu` describes the target environment from the architecture decision document:

| Module | Resources |
|---|---|
| `network` | VPC, two public subnets (ALB, Fargate tasks), two private subnets with no internet route (RDS, EFS), VPC flow logs for rejected traffic. No NAT gateway. |
| `database` | RDS PostgreSQL 17 (gp3, encrypted, `rds.force_ssl`, 14-day backups, Performance Insights, deletion protection in production). RDS manages the master password in Secrets Manager; the `database-url` secret is derived from it. |
| `storage` | Private, versioned, KMS-encrypted S3 bucket with TLS-only policy (for the S3 StoragePort adapter). |
| `app` | ECR (immutable tags, scan on push), ECS cluster, Fargate ARM64 task definitions `api`, `worker`, `migrate`, the `api` service behind an ALB (TLS 1.3 policy, `/api/health` checks, circuit-breaker rollback), the `worker` service, EFS for lab files shared by all api tasks, generated auth secret, least-privilege task roles. |
| `edge` | Cloudflare proxied DNS record, strict TLS, always-HTTPS, ACM certificate validated through Cloudflare DNS; the ALB accepts only Cloudflare IP ranges. |
| `github_oidc` | GitHub OIDC provider and a deploy role limited to the `production` environment of one repository. |

First apply:

```
cd infra/tofu
cp backend.hcl.example backend.hcl            # state bucket
cp production.tfvars.example production.tfvars
tofu init -backend-config=backend.hcl
tofu apply -var-file=production.tfvars
```

Then copy the outputs (`AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `ECR_REPOSITORY`, `ECS_CLUSTER`, `ECS_NETWORK_CONFIGURATION`) into GitHub repository variables and create a `production` environment. `deploy.yml` builds the ARM64 image, pushes it, registers new task definitions, runs the migrate task and rolls both services. The task definitions start with a `:bootstrap` image tag, so the services stay unhealthy until the first deploy.

Known limits of the infrastructure code: it has not been planned or applied against a real account; `tofu validate` runs in CI. The S3 and SES adapters are stubs, so the app keeps using local storage (EFS) and console mail until they are implemented.

## Backup and recovery

- Production: RDS automated backups (14 days, point-in-time restore) and EFS. Lab files are disposable.
- Local: stop the API, copy `apps/api/var/pgdata` and `apps/api/var/labs`.

## Safe reset

- One scenario: **Simulation Workspace → Reset** (keeps submitted attempts). One lab: the lab page's **Reset** button.
- Everything (local only): stop the API and delete `apps/api/var`.

## Troubleshooting (Windows)

| Symptom | Fix |
|---|---|
| UI shows "Cannot reach the Threatready server" | Start the API on port 8000, or point Vite's proxy elsewhere with `THREATREADY_BACKEND`. The first start migrates the embedded database and takes a little longer. |
| `node:sqlite` errors or `setAuthorizer is not a function` | Upgrade Node.js to 26.10 or newer. |
| Port 5173 already in use | `$env:PORT=5180; npm run dev:web`. |
| Playwright cannot find a browser | `npx playwright install chromium`, or use installed Edge: `$env:PW_CHANNEL="msedge"`. |
| "Cross-origin request refused" | Add the page's origin to `THREATREADY_TRUSTED_ORIGINS`. |
