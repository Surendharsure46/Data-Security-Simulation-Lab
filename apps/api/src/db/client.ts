/**
 * Database client factory. One code path for both drivers:
 *   postgres://…        node-postgres Pool (AWS RDS in production)
 *   pglite://<dir>      embedded PostgreSQL (WASM) persisted in a directory — local development
 *   pglite://memory     embedded, in-memory — tests
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import type { PgDatabase } from "drizzle-orm/pg-core";
import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import { migrate as migratePg } from "drizzle-orm/node-postgres/migrator";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { migrate as migratePglite } from "drizzle-orm/pglite/migrator";
import pg from "pg";
import { API_DIR } from "../config.js";
import { schema } from "./schema.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Db = PgDatabase<any, typeof schema>;

export interface Database {
  db: Db;
  driver: "pg" | "pglite";
  /** Raw SQL for libraries that bring their own queries (pg-boss). */
  executeSql(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
  migrate(): Promise<void>;
  close(): Promise<void>;
}

export const MIGRATIONS_DIR = join(API_DIR, "migrations");

/** Wrap an existing PGlite instance (tests clone a migrated template per test). */
export function fromPglite(client: PGlite): Database {
  const db = drizzlePglite({ client, schema }) as unknown as Db;
  return {
    db,
    driver: "pglite",
    executeSql: async (text, values) => {
      // Parameterless scripts may contain several statements (pg-boss installs its schema that way); the extended
      // protocol behind query() accepts only one, so they go through exec() and return the last result.
      if (!values?.length) {
        const results = await client.exec(text);
        return { rows: results.length ? results[results.length - 1].rows : [] };
      }
      return { rows: (await client.query(text, values as unknown[])).rows };
    },
    migrate: () => migratePglite(db as never, { migrationsFolder: MIGRATIONS_DIR }),
    close: () => client.close(),
  };
}

export function createDatabase(url: string): Database {
  if (url.startsWith("pglite://")) {
    const location = url.slice("pglite://".length);
    if (location === "memory" || location === "") return fromPglite(new PGlite());
    mkdirSync(location, { recursive: true });
    return fromPglite(new PGlite(location));
  }
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  const db = drizzlePg({ client: pool, schema }) as unknown as Db;
  return {
    db,
    driver: "pg",
    executeSql: async (text, values) => ({ rows: (await pool.query(text, values as unknown[])).rows }),
    migrate: () => migratePg(db as never, { migrationsFolder: MIGRATIONS_DIR }),
    close: () => pool.end(),
  };
}
