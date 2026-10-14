// Throw-away API for end-to-end tests: in-memory PostgreSQL (PGlite), a fresh lab directory and the bootstrap admin.
// Usage: node scripts/e2e-server.mjs [port]   (run `npm run build -w @threatready/api` first)
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const api = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = join(api, "var", "e2e");
rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });
Object.assign(process.env, {
  THREATREADY_ENV: "development",
  THREATREADY_ROLE: "api",
  THREATREADY_PORT: process.argv[2] ?? "8099",
  THREATREADY_DATABASE_URL: "pglite://memory",
  THREATREADY_LAB_DATA_DIR: join(dir, "labs"),
  THREATREADY_FRONTEND_DIST: join(dir, "no-dist"),
  THREATREADY_TRUSTED_ORIGINS: "http://127.0.0.1:5199,http://localhost:5199",
  THREATREADY_PUBLIC_URL: "http://127.0.0.1:5199",
});
await import("../dist/main.js");
