// Enforces the modular-monolith dependency rules (architecture decision document, "boundaries"). Exit code 1 on violation.
//   domain/, labs/, content/  framework-free: no NestJS, no Express, no HTTP layer (modules/, platform/http)
//   content/                  depends on nothing but content/ and common/ (plus the lab registry it validates against)
//   packages/contracts        never imports an app
//   apps/web                  never imports apps/api (talks to it over HTTP, types come from @threatready/contracts)
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const files = (dir) => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (f === "node_modules" || f === "dist") return [];
  return statSync(p).isDirectory() ? files(p) : /\.(ts|tsx|mjs)$/.test(f) ? [p] : [];
});
const importsOf = (src) => [...src.matchAll(/(?:import|export)[^"'`]*?from\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1] ?? m[2]);

const rules = [
  { scope: "apps/api/src/domain", deny: [/^@nestjs\//, /^express$/, /\/modules\//, /platform\/http/] },
  { scope: "apps/api/src/labs", deny: [/^@nestjs\//, /^express$/, /\/modules\//, /platform\//] },
  { scope: "apps/api/src/content", deny: [/^@nestjs\//, /\/modules\//, /\/platform\//, /\/db\//], allow: [/labs\/registry/, /domain\/scenario-defs/] },
  { scope: "packages/contracts/src", deny: [/apps\//, /^@threatready\/api/, /^\.\.\/\.\.\//] },
  { scope: "apps/web/src", deny: [/apps\/api/, /^@threatready\/api/] },
];

const violations = [];
for (const rule of rules) {
  for (const file of files(join(root, rule.scope))) {
    for (const spec of importsOf(readFileSync(file, "utf8"))) {
      if (rule.allow?.some((a) => a.test(spec))) continue;
      if (rule.deny.some((d) => d.test(spec))) violations.push(`${relative(root, file).split(sep).join("/")} imports ${spec}`);
    }
  }
}
if (violations.length) {
  console.error(`Module boundary violations:\n  ${violations.join("\n  ")}`);
  process.exit(1);
}
console.log("Module boundaries OK");
