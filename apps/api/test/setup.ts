// Runs before every test file is imported: configuration comes from the environment, as in production.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import "reflect-metadata";

const tmp = mkdtempSync(join(tmpdir(), "threatready-tests-"));
process.env.THREATREADY_ENV = "test";
process.env.THREATREADY_DATABASE_URL = "pglite://memory";
process.env.THREATREADY_LAB_DATA_DIR = join(tmp, "labs");
process.env.THREATREADY_FRONTEND_DIST = join(tmp, "no-dist");
process.env.THREATREADY_LOGIN_RATE_LIMIT_PER_MINUTE = "1000";
process.env.THREATREADY_API_RATE_LIMIT_PER_MINUTE = "100000";
process.env.THREATREADY_AUTH_SECRET = "test-secret-test-secret-test-secret-0123456789";
