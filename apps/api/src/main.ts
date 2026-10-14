/**
 * Entry point. THREATREADY_ROLE selects what this process does:
 *   api     HTTP API (+ static web app when built)
 *   worker  background jobs (pg-boss)
 *   all     both (local development, single-container demos)
 * The same container image runs both roles on ECS (see infra/tofu).
 */
import "reflect-metadata";
import { Logger } from "@nestjs/common";
import * as Sentry from "@sentry/node";
import { getConfig, loadEnvFiles } from "./config.js";
import { createApp, ensureBootstrapAdmin, initPlatform } from "./server.js";
import { startWorker } from "./worker/jobs.js";

async function main(): Promise<void> {
  loadEnvFiles();
  const cfg = getConfig();
  if (cfg.sentryDsn) Sentry.init({ dsn: cfg.sentryDsn, environment: cfg.env, tracesSampleRate: 0 });
  const log = new Logger("Main");
  const database = await initPlatform();
  await ensureBootstrapAdmin();
  if (cfg.role === "worker" || cfg.role === "all") await startWorker(database);
  if (cfg.role === "api" || cfg.role === "all") {
    const app = await createApp();
    await app.listen(cfg.port, cfg.host);
    log.log(`Threatready API listening on http://${cfg.host}:${cfg.port} (${cfg.env}, ${database.driver}, role ${cfg.role})`);
  }
  const shutdown = async () => {
    await database.close().catch(() => undefined);
    process.exit(0);
  };
  process.once("SIGTERM", () => void shutdown());
  process.once("SIGINT", () => void shutdown());
}

main().catch((e: unknown) => {
  Sentry.captureException(e);
  console.error(e);
  process.exit(1);
});
