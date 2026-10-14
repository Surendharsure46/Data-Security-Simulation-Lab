/**
 * Runs one learner SQL statement for the Database Security Lab in a short-lived child process. A process (not a worker
 * thread) is used because SQLite cannot be interrupted from JavaScript while it is inside a single step: when the 2 s
 * budget is exceeded the parent kills the process, which ends the query and releases its locks immediately.
 * Self-contained (node: imports only, erasable TypeScript) so it runs from source under type stripping or from dist.
 */
import { constants as C, DatabaseSync } from "node:sqlite";

interface Job { path: string; role: string; allowed: string[]; sql: string; params: string[]; maxRows: number; budgetMs: number }

const LAB_WRITE_ACTIONS = new Set([C.SQLITE_INSERT, C.SQLITE_UPDATE, C.SQLITE_DELETE, C.SQLITE_DROP_TABLE, C.SQLITE_DROP_VIEW, C.SQLITE_CREATE_TABLE]);

function authorizer(role: string, allowed: Set<string>) {
  return (action: number, arg1: string | null, _arg2: string | null, _db: string | null, source: string | null): number => {
    if (action === C.SQLITE_RECURSIVE) return C.SQLITE_DENY; // unbounded recursive CTEs cannot be interrupted mid-step
    if (role === "dba") {
      if (action === C.SQLITE_ATTACH || action === C.SQLITE_DETACH || action === C.SQLITE_PRAGMA) return C.SQLITE_DENY;
      if (action === C.SQLITE_READ && arg1 && arg1.startsWith("_lab_")) return C.SQLITE_DENY;
      if (LAB_WRITE_ACTIONS.has(action) && arg1 && arg1.startsWith("_lab_")) return C.SQLITE_DENY;
      return C.SQLITE_OK;
    }
    if (action === C.SQLITE_SELECT || action === C.SQLITE_FUNCTION) return C.SQLITE_OK;
    if (action === C.SQLITE_READ) {
      // Reads through a view report the view name in `source`; the view grant then applies.
      const obj = source || arg1;
      return obj && allowed.has(obj) ? C.SQLITE_OK : C.SQLITE_DENY;
    }
    return C.SQLITE_DENY;
  };
}

/** True when the text contains a statement separator outside string literals and comments. */
function hasSecondStatement(sql: string): boolean {
  let quote: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"' || c === "`") {
      quote = c;
    } else if (c === "-" && sql[i + 1] === "-") {
      const nl = sql.indexOf(String.fromCharCode(10), i);
      if (nl < 0) return false;
      i = nl;
    } else if (c === "/" && sql[i + 1] === "*") {
      const end = sql.indexOf("*/", i + 2);
      if (end < 0) return false;
      i = end + 1;
    } else if (c === ";" && sql.slice(i + 1).trim()) {
      return true;
    }
  }
  return false;
}

function run(job: Job) {
  const deadline = Date.now() + job.budgetMs; // the budget covers the statement, not process start-up
  if (hasSecondStatement(job.sql)) return { ok: false, error: "You can only execute one statement at a time." };
  const db = new DatabaseSync(job.path, { timeout: 5000 });
  try {
    db.setAuthorizer(authorizer(job.role, new Set(job.allowed)));
    const st = db.prepare(job.sql);
    st.setReturnArrays(true);
    const columns = st.columns().map((c) => c.name);
    const rows: unknown[][] = [];
    let total = 0;
    for (const r of st.iterate(...job.params) as Iterable<unknown[]>) {
      total += 1;
      if (rows.length < job.maxRows) rows.push(r.map((v) => (typeof v === "bigint" ? Number(v) : v instanceof Uint8Array ? `<${v.length} bytes>` : v)));
      if (Date.now() > deadline) throw new Error("interrupted: statement exceeded the 2 second lab time budget");
    }
    return { ok: true, columns, rows, total };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  } finally {
    db.setAuthorizer(null);
    db.close();
  }
}

process.once("message", (job: Job) => {
  process.send!({ started: true }); // the parent starts its hard 2 s timer now that start-up is over
  const result = run(job);
  process.send!(result, () => process.exit(0));
});
