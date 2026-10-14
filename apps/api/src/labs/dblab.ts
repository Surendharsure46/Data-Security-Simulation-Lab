/**
 * Database Security Lab (REAL_LAB) on a disposable per-user SQLite database (node:sqlite).
 *
 * SQLite has no native users, roles or GRANT statements. This lab enforces application roles with SQLite's authorizer
 * callback (`DatabaseSync.setAuthorizer`), which is SQLite's real mechanism for statement-level access decisions. The lab
 * documentation says so explicitly; it does not pretend SQLite behaves like PostgreSQL or MySQL.
 *
 * Safety: learner SQL runs only against the learner's own lab file, one statement at a time, in a child process that is
 * killed after a 2 s budget, read-only for non-DBA roles, with ATTACH/DETACH/PRAGMA, recursive CTEs and internal tables denied, and a
 * row cap.
 */
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { backup as sqliteBackup, DatabaseSync } from "node:sqlite";
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { DomainError, iso, pad, Rng, sorted } from "../common/util.js";
import { luhnComplete, syntheticName, syntheticPhone } from "../content/company.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const ROLES: Record<string, string> = {
  support_agent: "Front-line support: should read masked customer data and cases only",
  analyst: "Analytics: masked customer data only",
  reporting_svc: "Reporting service: support cases only",
  dba: "Database administrator: full control",
};
const INITIAL_GRANTS: [string, string, string][] = [
  ["support_agent", "customers_masked", "SELECT"],
  ["support_agent", "support_cases", "SELECT"],
  ["support_agent", "customers", "SELECT"], // excessive: added during a 2024 migration, never removed
  ["analyst", "customers_masked", "SELECT"],
  ["reporting_svc", "support_cases", "SELECT"],
];
export const USER_TABLES = new Set(["customers", "support_cases", "customers_masked"]);
const MAX_ROWS = 200;
const TIME_BUDGET_MS = 2000;
export const MASK_EXPR: Record<string, string> = {
  card_number: "'**** **** **** ' || substr(card_number, -4)",
  email: "substr(email, 1, 1) || '***@' || substr(email, instr(email, '@') + 1)",
  dob: "substr(dob, 1, 4) || '-**-**'",
  phone: "'(***) ***-' || substr(phone, -4)",
};
export const PAN_RE = /\b\d{13,19}\b/;

export const dbPath = (d: string) => join(d, "kr_lab.sqlite");

function connect(path: string): DatabaseSync {
  return new DatabaseSync(path, { timeout: 5000 });
}

function withDb<T>(path: string, fn: (db: DatabaseSync) => T): T {
  const db = connect(path);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

function rebuildMaskedView(db: DatabaseSync): void {
  const enabled = new Set((db.prepare("SELECT column_name FROM _lab_masking WHERE enabled = 1").all() as Json[]).map((r) => r.column_name));
  const cols = ["id", "full_name"];
  for (const col of ["email", "phone", "dob", "card_number"]) cols.push(enabled.has(col) ? `${MASK_EXPR[col]} AS ${col}` : col);
  cols.push("segment");
  db.exec("DROP VIEW IF EXISTS customers_masked");
  db.exec(`CREATE VIEW customers_masked AS SELECT ${cols.join(", ")} FROM customers`);
}

/**
 * Build the lab database in a temporary file and swap it in atomically, so concurrent requests never observe a
 * half-initialised database. node:sqlite is synchronous, so the build itself cannot interleave within a process.
 */
export function initDb(d: string): Json {
  const path = dbPath(d);
  const tmp = `${path}.${randomUUID().replace(/-/g, "")}.tmp`;
  const rng = new Rng(4242);
  withDb(tmp, (db) => {
    db.exec(`
      CREATE TABLE customers (id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT, dob TEXT, card_number TEXT, segment TEXT);
      CREATE TABLE support_cases (id INTEGER PRIMARY KEY, customer_id INTEGER, opened TEXT, subject TEXT, status TEXT);
      CREATE TABLE _lab_grants (role TEXT, table_name TEXT, privilege TEXT, PRIMARY KEY (role, table_name, privilege));
      CREATE TABLE _lab_audit (id INTEGER PRIMARY KEY, ts TEXT, role TEXT, statement TEXT, rows_returned INTEGER, decision TEXT, source TEXT);
      CREATE TABLE _lab_masking (column_name TEXT PRIMARY KEY, enabled INTEGER);
    `);
    db.exec("BEGIN");
    const ins = db.prepare("INSERT INTO customers VALUES (?,?,?,?,?,?,?)");
    for (let i = 1; i <= 300; i++) {
      const [f, l] = syntheticName(rng);
      ins.run(i, `${f} ${l}`, `${f.toLowerCase()}.${l.toLowerCase()}${i}@example.com`, syntheticPhone(rng),
        `${rng.randint(1950, 2004)}-${pad(rng.randint(1, 12), 2)}-${pad(rng.randint(1, 28), 2)}`, luhnComplete("4", 16, rng),
        rng.choice(["retail", "premier", "small-business"]));
    }
    const insCase = db.prepare("INSERT INTO support_cases VALUES (?,?,?,?,?)");
    for (let i = 1; i <= 120; i++) {
      insCase.run(i, rng.randint(1, 300), `2026-03-${pad(rng.randint(1, 9), 2)}`,
        rng.choice(["Card declined", "Address change", "Fee dispute", "Statement copy"]), rng.choice(["open", "closed"]));
    }
    const insGrant = db.prepare("INSERT INTO _lab_grants VALUES (?,?,?)");
    for (const g of INITIAL_GRANTS) insGrant.run(...g);
    const insMask = db.prepare("INSERT INTO _lab_masking VALUES (?,?)");
    for (const c of Object.keys(MASK_EXPR)) insMask.run(c, 0);
    const history: [string, string, string, number][] = [
      ["2026-03-08T09:12:44Z", "support_agent", "SELECT * FROM customers_masked WHERE id = 118", 1],
      ["2026-03-08T09:40:02Z", "support_agent", "SELECT * FROM support_cases WHERE customer_id = 118", 3],
      ["2026-03-08T11:05:19Z", "analyst", "SELECT segment, count(*) FROM customers_masked GROUP BY segment", 3],
      ["2026-03-08T13:22:51Z", "reporting_svc", "SELECT status, count(*) FROM support_cases GROUP BY status", 2],
      ["2026-03-09T02:13:07Z", "support_agent", "SELECT * FROM customers", 300],
      ["2026-03-09T08:58:30Z", "support_agent", "SELECT * FROM customers_masked WHERE id = 42", 1],
    ];
    const insAudit = db.prepare("INSERT INTO _lab_audit (ts, role, statement, rows_returned, decision, source) VALUES (?,?,?,?,'ALLOWED','seeded-history')");
    for (const h of history) insAudit.run(...h);
    rebuildMaskedView(db);
    db.exec("COMMIT");
  });
  renameSync(tmp, path);
  return { path: "kr_lab.sqlite", customers: 300, support_cases: 120, provenance: "REAL_LAB" };
}

export function requireDb(d: string): string {
  const p = dbPath(d);
  if (!existsSync(p)) initDb(d);
  return p;
}

export function grants(d: string): Json[] {
  return withDb(requireDb(d), (db) => db.prepare("SELECT role, table_name, privilege FROM _lab_grants ORDER BY role, table_name").all().map((r) => ({ ...r })));
}

export function revoke(d: string, role: string, table: string): number {
  return withDb(requireDb(d), (db) => Number(db.prepare("DELETE FROM _lab_grants WHERE role = ? AND table_name = ?").run(role, table).changes));
}

export function grant(d: string, role: string, table: string): void {
  if (!Object.hasOwn(ROLES, role) || !USER_TABLES.has(table)) throw new DomainError("Unknown role or table");
  withDb(requireDb(d), (db) => db.prepare("INSERT OR IGNORE INTO _lab_grants VALUES (?,?, 'SELECT')").run(role, table));
}

function auditRow(path: string, role: string, sql: string, rows: number, decision: string): number {
  return withDb(path, (db) => Number(db.prepare(
    "INSERT INTO _lab_audit (ts, role, statement, rows_returned, decision, source) VALUES (?,?,?,?,?, 'learner')",
  ).run(iso(new Date()), role, sql.slice(0, 500), rows, decision).lastInsertRowid));
}

const WORKER_PATH = fileURLToPath(new URL(import.meta.url.endsWith(".ts") ? "./dblab-worker.ts" : "./dblab-worker.js", import.meta.url));
let activeWorkers = 0;
const MAX_WORKERS = 4;

interface WorkerResult { ok: boolean; columns?: string[]; rows?: unknown[][]; total?: number; error?: string }

/** Run one statement in a child process; the process is killed if it exceeds the time budget. */
function runInWorker(path: string, role: string, allowed: string[], sql: string, params: string[]): Promise<WorkerResult> {
  if (activeWorkers >= MAX_WORKERS) throw new DomainError("The database lab is busy; try again in a moment", 429);
  activeWorkers += 1;
  return new Promise((resolve) => {
    const child = fork(WORKER_PATH, [], { execArgv: ["--max-old-space-size=64", "--disable-warning=ExperimentalWarning"], stdio: ["ignore", "ignore", "ignore", "ipc"],
      serialization: "advanced" });
    let settled = false;
    const done = (r: WorkerResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      activeWorkers -= 1;
      if (child.exitCode === null) child.kill("SIGKILL");
      resolve(r);
    };
    // Hard stop: generous allowance for process start-up on slow CPUs, then the 2 s statement budget (+ margin) once the
    // child reports that the statement has started. Killing the process is the only way to stop SQLite mid-step.
    const interrupted = () => done({ ok: false, error: "interrupted: statement exceeded the 2 second lab time budget" });
    let timer = setTimeout(interrupted, TIME_BUDGET_MS + 8000);
    child.on("message", (m: WorkerResult & { started?: boolean }) => {
      if (m.started) {
        clearTimeout(timer);
        timer = setTimeout(interrupted, TIME_BUDGET_MS + 500);
      } else {
        done(m);
      }
    });
    child.once("error", (e) => done({ ok: false, error: e.message }));
    child.once("exit", () => done({ ok: false, error: "interrupted: query process exited" }));
    child.send({ path, role, allowed, sql, params, maxRows: MAX_ROWS, budgetMs: TIME_BUDGET_MS });
  });
}

export async function runQuery(d: string, role: string, rawSql: string): Promise<Json> {
  if (!Object.hasOwn(ROLES, role)) throw new DomainError(`Unknown role. Roles: ${Object.keys(ROLES).join(", ")}`);
  const sql = rawSql.trim().replace(/;+$/, "");
  if (!sql || sql.length > 2000) throw new DomainError("Provide one SQL statement (max 2000 characters)");
  const path = requireDb(d);
  const allowed = withDb(path, (db) => (db.prepare("SELECT table_name FROM _lab_grants WHERE role = ? AND privilege = 'SELECT'").all(role) as Json[])
    .map((r) => r.table_name as string));
  const r = await runInWorker(path, role, allowed, sql, []);
  let decision = "ALLOWED";
  let error: string | null = null;
  if (!r.ok) {
    error = r.error ?? "error";
    decision = error.includes("not authorized") || error.includes("prohibited") ? "DENIED" : "ERROR";
  }
  const total = r.ok ? r.total! : 0;
  const auditId = auditRow(path, role, sql, total, decision);
  return { role, decision, error, columns: r.ok ? r.columns : [], rows: r.ok ? r.rows : [], row_count: total, truncated: r.ok && total > MAX_ROWS,
    audit_id: auditId, allowed_objects: sorted(allowed), enforcement: "SQLite authorizer callback (SQLite has no native roles)",
    provenance: "REAL_LAB" };
}

/** Customer lookup as the support portal would implement it. */
export async function lookup(d: string, mode: string, email: string): Promise<Json> {
  if (mode !== "vulnerable" && mode !== "parameterized") throw new DomainError("mode must be vulnerable or parameterized");
  if (email.length > 200) throw new DomainError("Input too long");
  const path = requireDb(d);
  const sql = mode === "vulnerable"
    ? `SELECT id, full_name, email FROM customers WHERE email = '${email}'` // deliberately vulnerable (lab)
    : "SELECT id, full_name, email FROM customers WHERE email = ?";
  const r = await runInWorker(path, "portal", ["customers"], sql, mode === "parameterized" ? [email] : []);
  const rows = r.ok ? r.rows! : [];
  return { mode, executed_sql: sql, bound_parameters: mode === "parameterized" ? [email] : [], rows, row_count: rows.length,
    error: r.ok ? null : r.error, provenance: "REAL_LAB" };
}

export function masking(d: string): Record<string, boolean> {
  return withDb(requireDb(d), (db) => Object.fromEntries((db.prepare("SELECT column_name, enabled FROM _lab_masking").all() as Json[])
    .map((r) => [r.column_name, Boolean(r.enabled)])));
}

export function setMasking(d: string, column: string, enabled: boolean): Record<string, boolean> {
  if (!Object.hasOwn(MASK_EXPR, column)) throw new DomainError("Unknown column");
  withDb(requireDb(d), (db) => {
    db.prepare("UPDATE _lab_masking SET enabled = ? WHERE column_name = ?").run(enabled ? 1 : 0, column);
    rebuildMaskedView(db);
  });
  return masking(d);
}

export function maskedViewSql(d: string): string {
  return withDb(requireDb(d), (db) => (db.prepare("SELECT sql FROM sqlite_master WHERE name = 'customers_masked'").get() as Json).sql);
}

export function auditLog(d: string): Json[] {
  return withDb(requireDb(d), (db) => db.prepare("SELECT * FROM _lab_audit ORDER BY id DESC LIMIT 200").all().map((r) => ({ ...r })));
}

export function bulkAuditIds(d: string, threshold = 100): number[] {
  return withDb(requireDb(d), (db) => (db.prepare(
    "SELECT id FROM _lab_audit WHERE source = 'seeded-history' AND rows_returned >= ? AND role != 'dba'",
  ).all(threshold) as Json[]).map((r) => Number(r.id)));
}

export function customersChecksum(path: string): [number, string] {
  return withDb(path, (db) => {
    const st = db.prepare("SELECT * FROM customers ORDER BY id");
    st.setReturnArrays(true);
    const rows = st.all() as unknown as unknown[][];
    const h = createHash("sha256");
    for (const r of rows) h.update(JSON.stringify(r));
    return [rows.length, h.digest("hex")];
  });
}

function backupStamp(): string {
  const now = new Date();
  const ns = process.hrtime.bigint() % 1000n;
  return `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1, 2)}${pad(now.getUTCDate(), 2)}T${pad(now.getUTCHours(), 2)}${pad(now.getUTCMinutes(), 2)}`
    + `${pad(now.getUTCSeconds(), 2)}${pad(now.getUTCMilliseconds(), 3)}${pad(Number(ns), 3)}`;
}

export async function backup(d: string): Promise<Json> {
  const src = requireDb(d);
  const bdir = join(d, "backups");
  mkdirSync(bdir, { recursive: true });
  const name = `kr_lab_${backupStamp()}.sqlite`;
  const db = connect(src);
  try {
    await sqliteBackup(db, join(bdir, name));
  } finally {
    db.close();
  }
  const [count, digest] = customersChecksum(join(bdir, name));
  return { backup_id: name, customers_rows: count, customers_sha256: digest, provenance: "REAL_LAB" };
}

export function damage(d: string): Json {
  const deleted = withDb(requireDb(d), (db) => Number(db.prepare(
    "DELETE FROM customers WHERE id IN (SELECT id FROM customers ORDER BY id DESC LIMIT 25)",
  ).run().changes));
  const [count, digest] = customersChecksum(dbPath(d));
  return { deleted_rows: deleted, customers_rows: count, customers_sha256: digest,
    scenario: "Simulated incident: a faulty clean-up script deleted 25 customer rows from the lab database.", provenance: "REAL_LAB" };
}

function backupFile(d: string, backupId: string): string {
  if (!/^kr_lab_\d{8}T\d{12}\.sqlite$/.test(backupId)) throw new DomainError("Invalid backup id");
  const p = join(d, "backups", backupId);
  if (!existsSync(p)) throw new DomainError("Backup not found", 404);
  return p;
}

export async function restore(d: string, backupId: string): Promise<Json> {
  const src = backupFile(d, backupId);
  const db = connect(src);
  try {
    await sqliteBackup(db, dbPath(d));
  } finally {
    db.close();
  }
  const [count, digest] = customersChecksum(dbPath(d));
  return { restored_from: backupId, customers_rows: count, customers_sha256: digest, provenance: "REAL_LAB" };
}

export function verifyRestore(d: string, backupId: string): Json {
  const src = backupFile(d, backupId);
  const [bc, bd] = customersChecksum(src);
  const [lc, ld] = customersChecksum(dbPath(d));
  return { backup_rows: bc, live_rows: lc, backup_sha256: bd, live_sha256: ld, match: bc === lc && bd === ld, provenance: "REAL_LAB" };
}

export function backups(d: string): string[] {
  const bdir = join(d, "backups");
  return existsSync(bdir) ? sorted(readdirSync(bdir).filter((f) => /^kr_lab_.*\.sqlite$/.test(f))) : [];
}
