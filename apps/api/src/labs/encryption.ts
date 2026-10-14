/**
 * Encryption Lab.
 *
 * REAL_LAB exercises use Node's built-in crypto (OpenSSL) on disposable synthetic files: AES-256-GCM with an
 * scrypt-derived key, SHA-256 / HMAC-SHA256, and envelope encryption with RFC 3394 AES key wrap (id-aes256-wrap).
 * No custom cryptography is implemented. The TLS metadata exercise and configuration review are SIMULATED.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scryptSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DomainError, pyRepr, sorted, stableStringify } from "../common/util.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const SCRYPT_N = 2 ** 15, SCRYPT_R = 8, SCRYPT_P = 1;
const MAGIC = Buffer.from("TRLAB1\n");
const WRAP_IV = Buffer.from("A6A6A6A6A6A6A6A6", "hex"); // RFC 3394 default initial value

export const SAMPLE_PLAINTEXT = Buffer.from(
  "customer_id,full_name,email,card_last4\n"
  + "KRC-10293847,Avery Castellano,avery.castellano@example.com,4821\n"
  + "KRC-55102938,Rowan Eastwood,rowan.eastwood@example.net,1177\n"
  + "KRC-77319201,Quinn Hollister,quinn.hollister@example.org,9034\n"
  + "# synthetic training data - Threatready encryption lab\n",
);

export const HASH_FILES: Record<string, string> = {
  "payroll_batch_A.csv": "employee_id,net_pay\nKR-E-100231,4210.55\nKR-E-100232,3988.10\nKR-E-100233,5120.00\n",
  "payroll_batch_B.csv": "employee_id,net_pay\nKR-E-100231,4210.55\nKR-E-100232,3988.10\nKR-E-100233,5120.00\n",
  "payroll_batch_C.csv": "employee_id,net_pay\nKR-E-100231,4210.55\nKR-E-100232,8988.10\nKR-E-100233,5120.00\n",
};

export const sha256Hex = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");

// The manifest published by Finance before transfer (hash of the original batch).
export const MANIFEST = { original_batch_sha256: sha256Hex(HASH_FILES["payroll_batch_A.csv"]) };
export const TAMPERED_FILE = "payroll_batch_C.csv";

// --------------------------------------------------------------------------- hashing

export function hashFile(name: string): Json {
  if (!Object.hasOwn(HASH_FILES, name)) throw new DomainError("Unknown lab file", 404);
  const data = Buffer.from(HASH_FILES[name]);
  return { file: name, sha256: sha256Hex(data), bytes: data.length };
}

export function hmacDemo(message: string, keyLabel: string): Json {
  const key = createHash("sha256").update(`threatready-lab-hmac-${keyLabel}`).digest();
  return { hmac_sha256: createHmac("sha256", key).update(message).digest("hex"), sha256: sha256Hex(message),
    note: "A plain hash can be recomputed by anyone; an HMAC requires the shared key, so it also proves origin." };
}

// --------------------------------------------------------------------------- file encryption

function derive(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 64 * 1024 * 1024 });
}

function gcmEncrypt(key: Buffer, nonce: Buffer, pt: Buffer, aad: Buffer): Buffer {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(aad);
  return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]); // ciphertext || 16-byte tag (same layout as AESGCM)
}

function gcmDecrypt(key: Buffer, nonce: Buffer, ct: Buffer, aad: Buffer): Buffer | null {
  if (ct.length < 16) return null;
  try {
    const d = createDecipheriv("aes-256-gcm", key, nonce);
    d.setAAD(aad);
    d.setAuthTag(ct.subarray(ct.length - 16));
    return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  } catch {
    return null;
  }
}

export function encryptSample(d: string, passphrase: string): Json {
  if (passphrase.length < 12) throw new DomainError("Use a passphrase of at least 12 characters");
  writeFileSync(join(d, "customer_sample.csv"), SAMPLE_PLAINTEXT);
  const salt = randomBytes(16), nonce = randomBytes(12);
  const header = { alg: "AES-256-GCM", kdf: "scrypt", n: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt: salt.toString("hex"), nonce: nonce.toString("hex") };
  const hdr = Buffer.from(stableStringify(header));
  const ct = gcmEncrypt(derive(passphrase, salt), nonce, SAMPLE_PLAINTEXT, hdr); // header authenticated as AAD
  const len = Buffer.alloc(2);
  len.writeUInt16BE(hdr.length);
  const blob = Buffer.concat([MAGIC, len, hdr, ct]);
  writeFileSync(join(d, "customer_sample.csv.enc"), blob);
  return { header, ciphertext_bytes: ct.length, ciphertext_prefix_hex: ct.subarray(0, 24).toString("hex"), file_sha256: sha256Hex(blob),
    plaintext_sha256: sha256Hex(SAMPLE_PLAINTEXT), plaintext_written: "customer_sample.csv", encrypted_written: "customer_sample.csv.enc",
    tag_bytes: 16, provenance: "REAL_LAB" };
}

function readBlob(d: string): [Json, Buffer, Buffer] {
  const p = join(d, "customer_sample.csv.enc");
  if (!existsSync(p)) throw new DomainError("Encrypt the sample file first", 409);
  const blob = readFileSync(p);
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) throw new DomainError("Unrecognised file format", 422);
  const n = blob.readUInt16BE(MAGIC.length);
  const hdr = blob.subarray(MAGIC.length + 2, MAGIC.length + 2 + n);
  return [JSON.parse(hdr.toString()), hdr, blob.subarray(MAGIC.length + 2 + n)];
}

/** The authenticated header of the encrypted sample (algorithm, KDF parameters, salt, nonce). */
export function readSampleHeader(d: string): Json {
  return readBlob(d)[0];
}

export function decryptSample(d: string, passphrase: string): Json {
  const [header, hdr, ct] = readBlob(d);
  const pt = gcmDecrypt(derive(passphrase, Buffer.from(header.salt, "hex")), Buffer.from(header.nonce, "hex"), ct, hdr);
  if (!pt) {
    return { success: false, error: "InvalidTag: authentication failed. Wrong key or modified ciphertext; no plaintext was released.", provenance: "REAL_LAB" };
  }
  return { success: true, plaintext_sha256: sha256Hex(pt), matches_original: pt.equals(SAMPLE_PLAINTEXT), preview: pt.toString().slice(0, 160),
    provenance: "REAL_LAB" };
}

export function tamperSample(d: string): Json {
  const p = join(d, "customer_sample.csv.enc");
  if (!existsSync(p)) throw new DomainError("Encrypt the sample file first", 409);
  const blob = readFileSync(p);
  const idx = blob.length - 20; // inside the ciphertext body, before the tag
  blob[idx] ^= 0x01;
  writeFileSync(p, blob);
  return { modified_byte_offset: idx, file_sha256: sha256Hex(blob), provenance: "REAL_LAB" };
}

// --------------------------------------------------------------------------- envelope encryption

const ENVELOPE_DATA = Buffer.concat([Buffer.from("payroll backup 2026-03 (synthetic)\n"),
  Buffer.from("KR-E-100231,DE89370400440532013000,4210.55\n".repeat(20))]);
const ENVELOPE_AAD = Buffer.from("backup_payroll.dat");

function keyWrap(kek: Buffer, key: Buffer): Buffer {
  const c = createCipheriv("id-aes256-wrap", kek, WRAP_IV);
  return Buffer.concat([c.update(key), c.final()]);
}

function keyUnwrap(kek: Buffer, wrapped: Buffer): Buffer | null {
  try {
    const d = createDecipheriv("id-aes256-wrap", kek, WRAP_IV);
    return Buffer.concat([d.update(wrapped), d.final()]);
  } catch {
    return null;
  }
}

const keyringPath = (d: string) => join(d, "lab_keyring.json");

export function envelopeInit(d: string): Json {
  const kek = randomBytes(32), dek = randomBytes(32), nonce = randomBytes(12);
  const ct = gcmEncrypt(dek, nonce, ENVELOPE_DATA, ENVELOPE_AAD);
  const data = Buffer.concat([nonce, ct]);
  writeFileSync(join(d, "backup_payroll.dat.enc"), data);
  const wrapped = keyWrap(kek, dek);
  const ring = { active: "kek-v1", keys: { "kek-v1": { material: kek.toString("hex"), status: "ACTIVE" } }, wrapped_dek: wrapped.toString("hex"),
    wrapped_by: "kek-v1" };
  writeFileSync(keyringPath(d), JSON.stringify(ring));
  return { kek_id: "kek-v1", wrapped_dek_hex: wrapped.toString("hex"), data_ciphertext_sha256: sha256Hex(data),
    note: "Lab keyring stored on disk for the exercise only. Production KEKs live in a KMS or HSM and never leave it.", provenance: "REAL_LAB" };
}

function ring(d: string): Json {
  const p = keyringPath(d);
  if (!existsSync(p)) throw new DomainError("Initialise envelope encryption first", 409);
  return JSON.parse(readFileSync(p, "utf8"));
}

export function envelopeRotate(d: string): Json {
  const r = ring(d);
  const oldId: string = r.active;
  const dek = keyUnwrap(Buffer.from(r.keys[oldId].material, "hex"), Buffer.from(r.wrapped_dek, "hex"));
  if (!dek) throw new DomainError("Keyring is inconsistent; re-initialise the exercise", 409);
  const newId = `kek-v${Object.keys(r.keys).length + 1}`;
  const kek = randomBytes(32);
  r.keys[oldId].status = "RETIRED";
  r.keys[newId] = { material: kek.toString("hex"), status: "ACTIVE" };
  r.active = newId;
  r.wrapped_dek = keyWrap(kek, dek).toString("hex");
  r.wrapped_by = newId;
  writeFileSync(keyringPath(d), JSON.stringify(r));
  const data = readFileSync(join(d, "backup_payroll.dat.enc"));
  return { retired: oldId, active: newId, wrapped_dek_hex: r.wrapped_dek, data_ciphertext_sha256: sha256Hex(data),
    note: "Only the wrapped DEK changed; the bulk data ciphertext is byte-for-byte identical.", provenance: "REAL_LAB" };
}

export function envelopeDecrypt(d: string, kekId?: string | null): Json {
  const r = ring(d);
  const kid: string = kekId || r.active;
  if (!Object.hasOwn(r.keys, kid)) throw new DomainError("Unknown key id", 404);
  const dek = keyUnwrap(Buffer.from(r.keys[kid].material, "hex"), Buffer.from(r.wrapped_dek, "hex"));
  if (!dek) {
    return { success: false, kek_id: kid, error: `InvalidUnwrap: ${kid} cannot unwrap the current DEK (it was re-wrapped).`, provenance: "REAL_LAB" };
  }
  const blob = readFileSync(join(d, "backup_payroll.dat.enc"));
  const pt = gcmDecrypt(dek, blob.subarray(0, 12), blob.subarray(12), ENVELOPE_AAD);
  if (!pt) throw new DomainError("Backup ciphertext failed authentication", 409);
  return { success: true, kek_id: kid, plaintext_sha256: sha256Hex(pt), matches_original: pt.equals(ENVELOPE_DATA), data_ciphertext_sha256: sha256Hex(blob),
    provenance: "REAL_LAB" };
}

// --------------------------------------------------------------------------- TLS metadata (simulated)

export const TLS_CAPTURE = {
  provenance: "SIMULATED",
  description: "Summary of a synthetic TLS 1.3 session from a lab laptop to portal.kestrelridge.example. Not a real capture.",
  records: [
    { t: "0.000", dir: "client→server", type: "TCP SYN", detail: "10.20.44.18:51544 → 203.0.113.40:443" },
    { t: "0.031", dir: "client→server", type: "ClientHello", detail: "SNI=portal.kestrelridge.example; supported_versions=TLS1.3,TLS1.2; ALPN=h2" },
    { t: "0.064", dir: "server→client", type: "ServerHello", detail: "selected TLS1.3; cipher TLS_AES_128_GCM_SHA256; key_share x25519" },
    { t: "0.065", dir: "server→client", type: "Encrypted handshake", detail: "EncryptedExtensions, Certificate, CertificateVerify, Finished (encrypted, 3,412 bytes)" },
    { t: "0.120", dir: "client→server", type: "Application data", detail: "encrypted record, 1,108 bytes" },
    { t: "0.233", dir: "server→client", type: "Application data", detail: "encrypted records, 48,880 bytes total" },
  ],
};
export const TLS_ITEMS: Record<string, boolean> = {
  destination_ip: true, sni_hostname: true, tls_version_and_cipher: true, packet_sizes_and_timing: true,
  url_path: false, http_cookies: false, form_field_values: false, server_certificate_tls13: false,
};
export const TLS_LABELS: Record<string, string> = {
  destination_ip: "Destination IP address and port", sni_hostname: "Server name (SNI)",
  tls_version_and_cipher: "Negotiated TLS version and cipher suite", packet_sizes_and_timing: "Packet sizes and timing",
  url_path: "Requested URL path", http_cookies: "HTTP cookies", form_field_values: "Submitted form field values",
  server_certificate_tls13: "Server certificate (TLS 1.3)",
};

export function gradeTls(visible: string[]): Json {
  const unknown = visible.filter((v) => !Object.hasOwn(TLS_ITEMS, v));
  if (unknown.length) throw new DomainError(`Unknown items: ${pyRepr(sorted(new Set(unknown)))}`);
  const chosen = new Set(visible);
  const correct = Object.fromEntries(Object.entries(TLS_ITEMS).map(([k, v]) => [k, chosen.has(k) === v]));
  const n = Object.values(correct).filter(Boolean).length;
  return { passed: n === Object.keys(TLS_ITEMS).length, correct_count: n, total: Object.keys(TLS_ITEMS).length, per_item: correct };
}

// --------------------------------------------------------------------------- configuration review (simulated)

export const WEAK_CONFIG = {
  service: "kr-backup-service (simulated)",
  tls_min_version: "TLS1.0",
  cipher_suites: ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
  verify_server_certificate: false,
  at_rest_algorithm: "AES-128-ECB",
  key_location: "same_volume",
  key_rotation_days: 0,
  backup_encryption: false,
  secret_storage: "plaintext_config",
};
export const CONFIG_OPTIONS: Record<string, string[]> = {
  tls_min_version: ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"],
  cipher_suites: ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
  at_rest_algorithm: ["AES-128-ECB", "AES-256-CBC", "AES-256-GCM", "ChaCha20-Poly1305", "DES"],
  key_location: ["same_volume", "config_file", "kms", "hsm"],
  secret_storage: ["plaintext_config", "environment_variable", "vault", "kms"],
};
const AEAD_SUITES = new Set(["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]);

/** Deterministic validator; each rule maps to a documented weakness. */
export function validateConfig(cfg: Json): Json[] {
  const f: Json[] = [];
  for (const [k, opts] of Object.entries(CONFIG_OPTIONS)) {
    const v = cfg[k];
    const vals = Array.isArray(v) ? v : [v];
    if (vals.some((x) => !opts.includes(x))) throw new DomainError(`Invalid value for ${k}`);
  }
  if (cfg.tls_min_version === "TLS1.0" || cfg.tls_min_version === "TLS1.1") {
    f.push({ id: "ENC-01", severity: "HIGH", finding: "Legacy TLS versions enabled", fix: "Set minimum version to TLS1.2 or TLS1.3." });
  }
  const weak = (cfg.cipher_suites as string[]).filter((s) => !AEAD_SUITES.has(s));
  if (weak.length) {
    f.push({ id: "ENC-02", severity: "HIGH", finding: `Non-AEAD or legacy cipher suites: ${weak.join(", ")}`, fix: "Allow only AEAD suites (GCM / ChaCha20-Poly1305)." });
  }
  if (!cfg.cipher_suites.length) f.push({ id: "ENC-02b", severity: "HIGH", finding: "No cipher suites configured", fix: "Enable at least one AEAD suite." });
  if (!cfg.verify_server_certificate) {
    f.push({ id: "ENC-03", severity: "CRITICAL", finding: "Server certificate validation disabled (interception possible)", fix: "Enable certificate validation." });
  }
  if (cfg.at_rest_algorithm !== "AES-256-GCM" && cfg.at_rest_algorithm !== "ChaCha20-Poly1305") {
    f.push({ id: "ENC-04", severity: "HIGH", finding: `At-rest algorithm ${cfg.at_rest_algorithm} is unauthenticated or weak`, fix: "Use AES-256-GCM or ChaCha20-Poly1305." });
  }
  if (cfg.key_location !== "kms" && cfg.key_location !== "hsm") {
    f.push({ id: "ENC-05", severity: "HIGH", finding: "Encryption key stored alongside the data or in configuration", fix: "Store keys in a KMS or HSM." });
  }
  const days = cfg.key_rotation_days;
  if (!Number.isInteger(days) || days <= 0 || days > 365) {
    f.push({ id: "ENC-06", severity: "MEDIUM", finding: "Key rotation disabled or longer than 365 days", fix: "Rotate keys at least annually (1-365 days)." });
  }
  if (!cfg.backup_encryption) f.push({ id: "ENC-07", severity: "HIGH", finding: "Backups are not encrypted", fix: "Enable backup encryption." });
  if (cfg.secret_storage !== "vault" && cfg.secret_storage !== "kms") {
    f.push({ id: "ENC-08", severity: "HIGH", finding: "Database password stored outside a secrets manager", fix: "Use a vault or KMS-backed secret store." });
  }
  return f;
}
