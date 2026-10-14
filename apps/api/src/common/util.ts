/** Shared helpers: domain errors, UTC time formatting, deterministic random numbers and small value utilities. */

export class DomainError extends Error {
  constructor(message: string, readonly statusCode = 400) {
    super(message);
  }
}

/** UTC timestamp rendered as YYYY-MM-DDTHH:MM:SSZ (the format used in every API response). */
export function iso(d: Date | string | null | undefined): string | null {
  if (d === null || d === undefined) return null;
  const date = typeof d === "string" ? new Date(d) : d;
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function addSeconds(d: Date, s: number): Date {
  return new Date(d.getTime() + s * 1000);
}

export function addMinutes(d: Date, m: number): Date {
  return new Date(d.getTime() + m * 60_000);
}

export function addDays(d: Date, days: number): Date {
  return new Date(d.getTime() + days * 86_400_000);
}

export function dateOnly(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Round half away from zero to `n` decimals (stable, deterministic). */
export function round(x: number, n = 0): number {
  const f = 10 ** n;
  return Math.sign(x) * Math.round(Math.abs(x) * f + Number.EPSILON) / f;
}

export function fmtInt(n: number): string {
  return n.toLocaleString("en-US");
}

export function sorted<T>(xs: Iterable<T>, key?: (x: T) => string | number): T[] {
  const arr = [...xs];
  return arr.sort((a, b) => {
    const ka = key ? key(a) : (a as unknown as string | number);
    const kb = key ? key(b) : (b as unknown as string | number);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

export function uniqueSorted(xs: Iterable<string>): string[] {
  return sorted(new Set(xs));
}

/** Structural equality for JSON-like values (object key order ignored). */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    const bb = b as unknown[];
    return a.length === bb.length && a.every((x, i) => deepEqual(x, bb[i]));
  }
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  return ka.length === kb.length && ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

/** JSON with sorted keys (deterministic digests). */
export function stableStringify(v: unknown): string {
  return JSON.stringify(v, (_k, val) => {
    if (val && typeof val === "object" && !Array.isArray(val) && !(val instanceof Date)) {
      return Object.fromEntries(Object.keys(val).sort().map((k) => [k, (val as Record<string, unknown>)[k]]));
    }
    return val;
  });
}

/** Python-style repr used in deterministic explanations ('text', ['a'], True, None). */
export function pyRepr(v: unknown): string {
  if (v === null || v === undefined) return "None";
  if (typeof v === "boolean") return v ? "True" : "False";
  if (typeof v === "string") return `'${v}'`;
  if (Array.isArray(v)) return `[${v.map(pyRepr).join(", ")}]`;
  if (typeof v === "object") return `{${Object.entries(v).map(([k, x]) => `'${k}': ${pyRepr(x)}`).join(", ")}}`;
  return String(v);
}

/**
 * Deterministic pseudo-random generator (mulberry32) used for synthetic content, so every session starts from an
 * identical environment. Not for security purposes.
 */
export class Rng {
  private s: number;

  constructor(seed: number) {
    this.s = seed >>> 0;
  }

  random(): number {
    this.s = (this.s + 0x6d2b79f5) >>> 0;
    let t = this.s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** Inclusive integer range, like Python's random.randint. */
  randint(a: number, b: number): number {
    return a + Math.floor(this.random() * (b - a + 1));
  }

  choice<T>(xs: readonly T[]): T {
    return xs[Math.floor(this.random() * xs.length)];
  }

  shuffle<T>(xs: T[]): T[] {
    for (let i = xs.length - 1; i > 0; i--) {
      const j = Math.floor(this.random() * (i + 1));
      [xs[i], xs[j]] = [xs[j], xs[i]];
    }
    return xs;
  }
}

export function pad(n: number, width: number): string {
  return String(n).padStart(width, "0");
}

/** Python `datetime.isoformat()` for an aware UTC datetime (e.g. 2026-03-09T09:00:00+00:00). */
export function pyIso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "+00:00");
}
