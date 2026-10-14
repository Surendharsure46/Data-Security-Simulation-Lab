// Copies non-TypeScript runtime assets into dist after `tsc` (scenario definitions, dblab worker data).
import { cpSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
mkdirSync(join(root, "dist", "content"), { recursive: true });
cpSync(join(root, "src", "content", "scenarios"), join(root, "dist", "content", "scenarios"), { recursive: true });
cpSync(join(root, "src", "content", "data"), join(root, "dist", "content", "data"), { recursive: true });
