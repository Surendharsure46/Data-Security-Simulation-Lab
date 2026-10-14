import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Tests run against the tsc build in dist/ (tsc emits the decorator metadata NestJS needs), so `npm test` builds first.
// Test files import ../src/... for types; at runtime those imports resolve to the compiled dist/ files.
const dist = fileURLToPath(new URL("./dist/", import.meta.url));

export default defineConfig({
  resolve: { alias: [{ find: /^(?:\.\.\/)+src\//, replacement: dist }] },
  test: {
    include: ["test/**/*.test.ts"],
    setupFiles: ["test/setup.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    pool: "forks",
  },
});
