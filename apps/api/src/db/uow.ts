/**
 * Unit of work: an identity map with dirty tracking over Drizzle.
 *
 * Domain services load rows, mutate them and rely on a flush, the same way the original SQLAlchemy services did.
 * Rules: reassign JSON fields instead of mutating them in place (`g.members = [...g.members, k]`); inserts and deletes
 * are immediate; updates are flushed automatically before every query (autoflush) and at the end of the request.
 */
import { and, count, eq, getTableName, type SQL } from "drizzle-orm";
import type { PgColumn, PgTable } from "drizzle-orm/pg-core";
import type { Db } from "./client.js";

type AnyTable = PgTable & { id: PgColumn };
type Row<T extends AnyTable> = T["$inferSelect"];
type Insert<T extends AnyTable> = T["$inferInsert"];

interface Tracked {
  table: AnyTable;
  id: unknown;
  row: Record<string, unknown>;
  dirty: Set<string>;
  proxy: Record<string, unknown>;
}

export class UnitOfWork {
  private map = new Map<string, Tracked>();

  constructor(readonly db: Db) {}

  private key(table: AnyTable, id: unknown) {
    return `${getTableName(table)}:${String(id)}`;
  }

  /** Track a row loaded from the database; returns the canonical (possibly already modified) instance. */
  track<T extends AnyTable>(table: T, row: Row<T>): Row<T> {
    const raw = row as Record<string, unknown>;
    const k = this.key(table, raw.id);
    const existing = this.map.get(k);
    if (existing) return existing.proxy as Row<T>;
    const entry: Tracked = { table, id: raw.id, row: raw, dirty: new Set(), proxy: {} };
    entry.proxy = new Proxy(raw, {
      set: (target, prop, value) => {
        if (typeof prop === "string" && target[prop] !== value) entry.dirty.add(prop);
        target[prop as string] = value;
        return true;
      },
    });
    this.map.set(k, entry);
    return entry.proxy as Row<T>;
  }

  async flush(): Promise<void> {
    for (const entry of this.map.values()) {
      if (!entry.dirty.size) continue;
      const changes: Record<string, unknown> = {};
      for (const f of entry.dirty) changes[f] = entry.row[f];
      entry.dirty.clear();
      await this.db.update(entry.table).set(changes as never).where(eqId(entry.table, entry.id));
    }
  }

  async all<T extends AnyTable>(table: T, where?: SQL, orderBy: (PgColumn | SQL)[] = []): Promise<Row<T>[]> {
    await this.flush();
    let q = this.db.select().from(table as AnyTable).$dynamic();
    if (where) q = q.where(where);
    if (orderBy.length) q = q.orderBy(...orderBy);
    const rows = (await q) as Row<T>[];
    return rows.map((r) => this.track(table, r));
  }

  async one<T extends AnyTable>(table: T, where: SQL, orderBy: (PgColumn | SQL)[] = []): Promise<Row<T> | undefined> {
    await this.flush();
    let q = this.db.select().from(table as AnyTable).where(where).$dynamic();
    if (orderBy.length) q = q.orderBy(...orderBy);
    const rows = (await q.limit(1)) as Row<T>[];
    return rows[0] ? this.track(table, rows[0]) : undefined;
  }

  async get<T extends AnyTable>(table: T, id: unknown): Promise<Row<T> | undefined> {
    const cached = this.map.get(this.key(table, id));
    if (cached) return cached.proxy as Row<T>;
    return this.one(table, eqId(table, id));
  }

  async count(table: AnyTable, ...where: (SQL | undefined)[]): Promise<number> {
    await this.flush();
    const rows = await this.db.select({ n: count() }).from(table).where(and(...where));
    return Number(rows[0]?.n ?? 0);
  }

  async insert<T extends AnyTable>(table: T, values: Insert<T>): Promise<Row<T>> {
    await this.flush();
    const rows = (await this.db.insert(table).values(values as never).returning()) as Row<T>[];
    return this.track(table, rows[0]);
  }

  async insertMany<T extends AnyTable>(table: T, values: Insert<T>[]): Promise<void> {
    if (!values.length) return;
    await this.flush();
    await this.db.insert(table).values(values as never);
  }

  async delete(table: AnyTable, where: SQL): Promise<void> {
    await this.flush();
    await this.db.delete(table).where(where);
    const name = getTableName(table);
    for (const k of [...this.map.keys()]) if (k.startsWith(`${name}:`)) this.map.delete(k);
  }

  /** Drop cached instances (after bulk SQL that bypassed the identity map). */
  forget(table: AnyTable): void {
    const name = getTableName(table);
    for (const k of [...this.map.keys()]) if (k.startsWith(`${name}:`)) this.map.delete(k);
  }
}

function eqId(table: AnyTable, id: unknown): SQL {
  return eq(table.id, id as never);
}
