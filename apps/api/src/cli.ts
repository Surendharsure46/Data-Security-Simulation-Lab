/**
 * Operations CLI:
 *   node dist/cli.js migrate                        apply database migrations (and create the bootstrap admin if configured)
 *   node dist/cli.js validate-content               check scenario and career content
 *   node dist/cli.js create-user EMAIL ROLE NAME    password from THREATREADY_NEW_USER_PASSWORD (never a CLI argument)
 *   node dist/cli.js cleanup-labs                   remove orphaned lab directories
 */
import "reflect-metadata";
import { eq } from "drizzle-orm";
import { getConfig, loadEnvFiles } from "./config.js";
import { createDatabase } from "./db/client.js";
import { user } from "./db/schema.js";
import { getAuth } from "./platform/auth.js";
import { ensureBootstrapAdmin, initPlatform } from "./server.js";
import { cleanupLabFiles } from "./worker/jobs.js";

async function main(): Promise<void> {
  loadEnvFiles();
  const [cmd, ...args] = process.argv.slice(2);
  const cfg = getConfig();
  switch (cmd) {
    case "migrate": {
      const database = createDatabase(cfg.databaseUrl);
      await database.migrate();
      console.log("Migrations applied");
      await initPlatform({ database, migrate: false });
      await ensureBootstrapAdmin();
      await database.close();
      return;
    }
    case "validate-content": {
      const database = await initPlatform({ database: createDatabase("pglite://memory"), migrate: false });
      console.log("Content valid");
      await database.close();
      return;
    }
    case "create-user": {
      const [email, role, ...name] = args;
      const password = process.env.THREATREADY_NEW_USER_PASSWORD;
      if (!email || !["learner", "instructor", "admin"].includes(role) || !name.length || !password || password.length < 12) {
        throw new Error("Usage: create-user EMAIL learner|instructor|admin NAME, with THREATREADY_NEW_USER_PASSWORD set (12+ characters)");
      }
      const database = await initPlatform();
      await getAuth().api.signUpEmail({ body: { email: email.toLowerCase(), password, name: name.join(" ") } });
      await database.db.update(user).set({ role, emailVerified: true }).where(eq(user.email, email.toLowerCase()));
      console.log(`Created ${role} ${email.toLowerCase()}`);
      await database.close();
      return;
    }
    case "cleanup-labs": {
      const database = await initPlatform();
      console.log(await cleanupLabFiles(database));
      await database.close();
      return;
    }
    default:
      throw new Error("Commands: migrate | validate-content | create-user | cleanup-labs");
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
