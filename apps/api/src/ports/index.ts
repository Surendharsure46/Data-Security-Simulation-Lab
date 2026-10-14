/**
 * Ports for external capabilities. Domain code depends on these interfaces only; adapters are chosen by configuration.
 * This release ships development adapters (local disk, console mail, no-op LLM, static entitlements). The production
 * adapters (S3, SES, Anthropic, billing provider) are stubs that fail loudly until implemented and configured.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { Logger } from "@nestjs/common";
import { getConfig } from "../config.js";

// --------------------------------------------------------------------------- LLM

export interface LlmPort {
  /** Optional natural-language explanation. Returns null when no model is configured; callers keep deterministic text. */
  explain(input: { purpose: string; facts: Record<string, unknown> }): Promise<string | null>;
}

export class NoopLlm implements LlmPort {
  async explain(): Promise<string | null> {
    return null;
  }
}

// --------------------------------------------------------------------------- storage

export interface StoragePort {
  put(key: string, body: Buffer | string, contentType: string): Promise<void>;
  get(key: string): Promise<Buffer | null>;
  delete(key: string): Promise<void>;
}

export class LocalStorage implements StoragePort {
  constructor(private readonly root: string) {}

  private path(key: string): string {
    if (!/^[A-Za-z0-9/_.-]{1,300}$/.test(key) || key.includes("..")) throw new Error("Invalid storage key");
    const p = resolve(this.root, key);
    if (!p.startsWith(resolve(this.root) + sep)) throw new Error("Invalid storage key");
    return p;
  }

  async put(key: string, body: Buffer | string): Promise<void> {
    const p = this.path(key);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, body);
  }

  async get(key: string): Promise<Buffer | null> {
    try {
      return readFileSync(this.path(key));
    } catch {
      return null;
    }
  }

  async delete(key: string): Promise<void> {
    rmSync(this.path(key), { force: true });
  }
}

export class S3Storage implements StoragePort {
  async put(): Promise<void> { throw new Error("S3 storage adapter is not implemented in this release"); }
  async get(): Promise<Buffer | null> { throw new Error("S3 storage adapter is not implemented in this release"); }
  async delete(): Promise<void> { throw new Error("S3 storage adapter is not implemented in this release"); }
}

// --------------------------------------------------------------------------- mail

export interface MailMessage { to: string; subject: string; text: string }
export interface MailPort {
  send(msg: MailMessage): Promise<void>;
}

/** Development mail: logs the message instead of sending it. Never use in production. */
export class ConsoleMail implements MailPort {
  private readonly log = new Logger("ConsoleMail");
  readonly outbox: MailMessage[] = [];

  async send(msg: MailMessage): Promise<void> {
    this.outbox.push(msg);
    if (this.outbox.length > 100) this.outbox.shift();
    this.log.log(`to=${msg.to} subject=${JSON.stringify(msg.subject)}\n${msg.text}`);
  }
}

export class SesMail implements MailPort {
  async send(): Promise<void> {
    throw new Error("SES mail adapter is not implemented in this release");
  }
}

// --------------------------------------------------------------------------- payments / entitlements

export interface Entitlements { plan: string; features: string[] }
export interface PaymentPort {
  entitlements(orgId: number): Promise<Entitlements>;
}

/** Every organization is entitled to every module until billing exists. */
export class StaticEntitlements implements PaymentPort {
  async entitlements(): Promise<Entitlements> {
    return { plan: "training", features: ["*"] };
  }
}

// --------------------------------------------------------------------------- registry

export interface Ports { llm: LlmPort; storage: StoragePort; mail: MailPort; payment: PaymentPort }
let ports: Ports | null = null;

export function buildPorts(): Ports {
  const cfg = getConfig();
  if (cfg.production && cfg.mailDriver === "console") new Logger("Ports").warn("Console mail driver in production: emails are only logged");
  return {
    llm: new NoopLlm(),
    storage: cfg.storageDriver === "s3" ? new S3Storage() : new LocalStorage(join(cfg.labDataDir, "..", "storage")),
    mail: cfg.mailDriver === "ses" ? new SesMail() : new ConsoleMail(),
    payment: new StaticEntitlements(),
  };
}

export function getPorts(): Ports {
  ports ??= buildPorts();
  return ports;
}

export function setPorts(p: Ports | null): void {
  ports = p;
}
