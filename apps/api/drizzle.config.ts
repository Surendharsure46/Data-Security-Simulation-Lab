import { defineConfig } from "drizzle-kit";

// Migrations are generated SQL, reviewed in pull requests and applied by `node dist/cli.js migrate`
// (a one-off task before each deploy). Row-level security lives in a hand-written migration (rls).
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./migrations",
  strict: true,
});
