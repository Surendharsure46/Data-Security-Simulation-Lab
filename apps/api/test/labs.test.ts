/** Lab exercises: real cryptographic and SQLite operations plus simulated labs. */
import { describe, expect, it } from "vitest";
import { type Agent, api, useApp } from "./helpers.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const status = async (h: Agent, lab: string): Promise<Record<string, boolean>> => (await api(h, "GET", "/api/labs/status"))[lab].exercises;

describe("encryption lab (REAL_LAB)", () => {
  const t = useApp();

  it("hashing exercise", async () => {
    const h = await t.register("learner1");
    const files: string[] = (await api(h, "GET", "/api/labs/encryption")).files;
    expect((await h.post("/api/labs/encryption/hash/answer").send({ modified_file: "payroll_batch_C.csv" })).status).toBe(409); // hash first
    const digests: Record<string, string> = {};
    for (const f of files) digests[f] = (await api(h, "POST", "/api/labs/encryption/hash", { file: f })).sha256;
    const manifest = (await api(h, "GET", "/api/labs/encryption")).manifest.original_batch_sha256;
    const modified = Object.entries(digests).filter(([, d]) => d !== manifest).map(([f]) => f);
    expect(modified).toEqual(["payroll_batch_C.csv"]);
    expect((await api(h, "POST", "/api/labs/encryption/hash/answer", { modified_file: modified[0] })).correct).toBe(true);
    expect((await status(h, "encryption")).hashing).toBe(true);
  });

  it("real AES-256-GCM round trip, wrong key and tamper detection", async () => {
    const h = await t.register("learner1");
    const enc = await api(h, "POST", "/api/labs/encryption/file/encrypt", { passphrase: "Correct-Horse-42!" });
    expect(enc.header.alg).toBe("AES-256-GCM");
    expect(enc.provenance).toBe("REAL_LAB");
    const wrong = await api(h, "POST", "/api/labs/encryption/file/decrypt", { passphrase: "Wrong-Passphrase-1" });
    expect(wrong.success).toBe(false);
    expect(wrong.error).toContain("InvalidTag");
    const ok = await api(h, "POST", "/api/labs/encryption/file/decrypt", { passphrase: "Correct-Horse-42!" });
    expect(ok.success && ok.matches_original).toBe(true);
    await api(h, "POST", "/api/labs/encryption/file/tamper");
    const tampered = await api(h, "POST", "/api/labs/encryption/file/decrypt", { passphrase: "Correct-Horse-42!" });
    expect(tampered.success).toBe(false);
    expect(tampered.checks).toEqual({ wrong_key_rejected: true, correct_ok: true, tamper_rejected: true });
    expect((await status(h, "encryption")).file_roundtrip).toBe(true);
  });

  it("envelope rotation keeps the data ciphertext", async () => {
    const h = await t.register("learner1");
    const init = await api(h, "POST", "/api/labs/encryption/envelope/init");
    const rot = await api(h, "POST", "/api/labs/encryption/envelope/rotate");
    expect(rot.data_ciphertext_sha256).toBe(init.data_ciphertext_sha256);
    expect(rot.data_unchanged_since_init).toBe(true);
    expect(rot.wrapped_dek_hex).not.toBe(init.wrapped_dek_hex);
    const old = await api(h, "POST", "/api/labs/encryption/envelope/decrypt", { kek_id: "kek-v1" });
    expect(old.success).toBe(false);
    expect(old.error).toContain("InvalidUnwrap");
    const fresh = await api(h, "POST", "/api/labs/encryption/envelope/decrypt", {});
    expect(fresh.success && fresh.matches_original).toBe(true);
    expect((await status(h, "encryption")).envelope_rotation).toBe(true);
  });

  it("TLS metadata and configuration review", async () => {
    const h = await t.register("learner1");
    const wrong = await api(h, "POST", "/api/labs/encryption/tls/answer", { visible: ["url_path", "sni_hostname"] });
    expect(wrong.passed).toBe(false);
    expect(wrong).not.toHaveProperty("per_item");
    const right = await api(h, "POST", "/api/labs/encryption/tls/answer",
      { visible: ["destination_ip", "sni_hostname", "tls_version_and_cipher", "packet_sizes_and_timing"] });
    expect(right.passed).toBe(true);
    const ids = new Set((await api(h, "POST", "/api/labs/encryption/config/validate")).findings.map((f: Json) => f.id));
    for (const id of ["ENC-01", "ENC-02", "ENC-03", "ENC-04", "ENC-05", "ENC-06", "ENC-07", "ENC-08"]) expect(ids.has(id), id).toBe(true);
    const good = { tls_min_version: "TLS1.2", cipher_suites: ["TLS_AES_256_GCM_SHA384"], verify_server_certificate: true, at_rest_algorithm: "AES-256-GCM",
      key_location: "kms", key_rotation_days: 365, backup_encryption: true, secret_storage: "vault" };
    await api(h, "PUT", "/api/labs/encryption/config", good);
    expect((await api(h, "POST", "/api/labs/encryption/config/validate")).passed).toBe(true);
    expect((await h.put("/api/labs/encryption/config").send({ ...good, at_rest_algorithm: "ROT13" })).status).toBe(400);
    const st = await status(h, "encryption");
    expect(st.tls_metadata && st.config_review).toBe(true);
  });
});

describe("database lab (REAL_LAB)", () => {
  const t = useApp();
  const query = (h: Agent, role: string, sql: string) => api(h, "POST", "/api/labs/database/query", { role, sql });

  it("least privilege is enforced by the authorizer", async () => {
    const h = await t.register("learner1");
    await api(h, "POST", "/api/labs/database/reset");
    const before = await query(h, "support_agent", "SELECT * FROM customers");
    expect([before.decision, before.row_count, before.truncated]).toEqual(["ALLOWED", 300, true]);
    await api(h, "POST", "/api/labs/database/grants/revoke", { role: "support_agent", table: "customers" });
    expect((await query(h, "support_agent", "SELECT * FROM customers")).decision).toBe("DENIED");
    const ok = await query(h, "support_agent", "SELECT * FROM customers_masked LIMIT 5");
    expect([ok.decision, ok.row_count]).toEqual(["ALLOWED", 5]);
    expect((await status(h, "database")).least_privilege).toBe(true);
  });

  it("denies dangerous statements", async () => {
    const h = await t.register("learner1");
    for (const [role, sql] of [["support_agent", "DELETE FROM support_cases"], ["support_agent", "SELECT * FROM _lab_grants"],
      ["dba", "ATTACH DATABASE 'x.db' AS x"], ["dba", "PRAGMA table_info(customers)"], ["analyst", "SELECT * FROM support_cases"],
      ["dba", "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c"]]) {
      expect(["DENIED", "ERROR"], `${role}: ${sql}`).toContain((await query(h, role, sql)).decision);
    }
    expect((await query(h, "dba", "SELECT 1; DROP TABLE customers")).decision).toBe("ERROR");
    expect((await query(h, "dba", "SELECT count(*) FROM customers")).rows[0][0]).toBe(300);
  });

  it("stops a runaway query within the time budget", async () => {
    const h = await t.register("learner1");
    const started = Date.now();
    const r = await query(h, "dba", "SELECT count(*) FROM customers a, customers b, customers c, customers d");
    expect(r.decision).toBe("ERROR");
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it("SQL injection versus parameterized queries", async () => {
    const h = await t.register("learner1");
    const payload = "x' OR '1'='1";
    expect((await api(h, "POST", "/api/labs/database/lookup", { mode: "vulnerable", email: payload })).row_count).toBeGreaterThan(1);
    const safe = await api(h, "POST", "/api/labs/database/lookup", { mode: "parameterized", email: payload });
    expect(safe.row_count).toBe(0);
    expect(safe.bound_parameters).toEqual([payload]);
    const union = await api(h, "POST", "/api/labs/database/lookup", { mode: "vulnerable", email: "x' UNION SELECT role, table_name, privilege FROM _lab_grants --" });
    expect(union.row_count).toBe(0);
    expect(union.error).toMatch(/not authorized|prohibited/);
    expect((await status(h, "database")).injection).toBe(true);
  });

  it("masking, audit review and backup/restore", async () => {
    const h = await t.register("learner1");
    for (const column of ["card_number", "email", "dob"]) await api(h, "PUT", "/api/labs/database/masking", { column, enabled: true });
    const r = await query(h, "support_agent", "SELECT * FROM customers_masked LIMIT 3");
    expect(String(r.rows[0][r.columns.indexOf("card_number")]).startsWith("**** **** **** ")).toBe(true);
    expect((await status(h, "database")).masking).toBe(true);

    const entries: Json[] = (await api(h, "GET", "/api/labs/database/audit")).entries;
    const bulk = entries.find((e) => e.source === "seeded-history" && e.rows_returned === 300)!;
    const normal = entries.find((e) => e.source === "seeded-history" && e.rows_returned === 1)!;
    expect((await api(h, "POST", "/api/labs/database/audit/identify", { audit_id: normal.id })).correct).toBe(false);
    expect((await api(h, "POST", "/api/labs/database/audit/identify", { audit_id: bulk.id })).correct).toBe(true);

    const b = await api(h, "POST", "/api/labs/database/backup");
    expect((await api(h, "POST", "/api/labs/database/damage")).customers_rows).toBe(275);
    expect((await api(h, "POST", "/api/labs/database/verify", { backup_id: b.backup_id })).match).toBe(false);
    await api(h, "POST", "/api/labs/database/restore", { backup_id: b.backup_id });
    const v = await api(h, "POST", "/api/labs/database/verify", { backup_id: b.backup_id });
    expect(v.match).toBe(true);
    expect(v.live_rows).toBe(300);
    expect((await h.post("/api/labs/database/restore").send({ backup_id: "../../etc/passwd" })).status).toBe(400);
    const st = await status(h, "database");
    expect(st.audit && st.backup_restore).toBe(true);
  });

  it("isolates lab files per user", async () => {
    const h = await t.register("learner1");
    const other = await t.register("otheruser");
    await api(h, "POST", "/api/labs/database/grants/revoke", { role: "support_agent", table: "customers" });
    expect((await api(other, "GET", "/api/labs/database")).grants).toContainEqual({ role: "support_agent", table_name: "customers", privilege: "SELECT" });
  });
});

describe("simulated labs", () => {
  const t = useApp();

  it("cloud: assess and remediate without business disruption", async () => {
    const h = await t.register("learner1");
    const ov = await api(h, "GET", "/api/labs/cloud");
    expect(ov.provenance).toBe("SIMULATED");
    expect(ov.audit_events.every((e: Json) => e.provenance === "SIMULATED")).toBe(true);
    expect((await api(h, "POST", "/api/labs/cloud/assess")).buckets[0].bucket).toBe("kr-analytics-exports");
    expect((await api(h, "POST", "/api/labs/cloud/assess/answer", { bucket: "kr-analytics-exports" })).correct).toBe(true);
    // Over-remediation: making the marketing website private breaks a documented requirement.
    await api(h, "POST", "/api/labs/cloud/change", { bucket: "kr-marketing-site", field: "access", value: "RESTRICTED" });
    for (const [bucket, field, value] of [["kr-analytics-exports", "access", "RESTRICTED"], ["kr-analytics-exports", "encryption", true],
      ["kr-analytics-exports", "access_logging", true], ["kr-hr-scans", "remove_principal", "acct-helpwise-vendor"], ["kr-hr-scans", "access_logging", true]]) {
      await api(h, "POST", "/api/labs/cloud/change", { bucket, field, value });
    }
    await api(h, "POST", "/api/labs/cloud/assess");
    const res = await api(h, "POST", "/api/labs/cloud/verify");
    expect(res.passed).toBe(false);
    expect(res.reasons.some((r: string) => r.includes("marketing"))).toBe(true);
    await api(h, "POST", "/api/labs/cloud/change", { bucket: "kr-marketing-site", field: "access", value: "PUBLIC_READ" });
    expect((await api(h, "POST", "/api/labs/cloud/verify")).passed).toBe(false); // needs a re-assessment after the last change
    await api(h, "POST", "/api/labs/cloud/assess");
    expect((await api(h, "POST", "/api/labs/cloud/verify")).passed).toBe(true);
  });

  it("privacy: minimisation, retention and legal hold", async () => {
    const h = await t.register("learner1");
    const fields: string[] = (await api(h, "GET", "/api/labs/privacy")).fields;
    const decisions: Json = Object.fromEntries(fields.map((f) => [f, { decision: "KEEP", reason: "needed for purpose" }]));
    for (const f of ["national_id", "card_number", "date_of_birth"]) decisions[f] = { decision: "REMOVE", reason: "not needed for newsletters" };
    expect((await api(h, "PUT", "/api/labs/privacy/minimization", { decisions })).passed).toBe(true);
    // Ignoring legal hold deletes held records: critical failure.
    await api(h, "POST", "/api/labs/privacy/retention/evaluate", { inactive_days: 730, no_consent_days: 30, respect_legal_hold: false });
    expect((await h.post("/api/labs/privacy/retention/execute").send({ confirm: false })).status).toBe(409);
    const bad = await api(h, "POST", "/api/labs/privacy/retention/execute", { confirm: true });
    if (bad.legal_hold_deleted.length) expect(bad.passed).toBe(false);
    await api(h, "POST", "/api/labs/privacy/reset");
    await api(h, "PUT", "/api/labs/privacy/minimization", { decisions });
    expect((await api(h, "POST", "/api/labs/privacy/retention/evaluate", { inactive_days: 730, no_consent_days: 30, respect_legal_hold: true })).to_delete).toBeGreaterThan(0);
    const good = await api(h, "POST", "/api/labs/privacy/retention/execute", { confirm: true });
    expect(good.passed).toBe(true);
    expect(good.legal_hold_deleted).toEqual([]);
    const report = (await h.get("/api/labs/privacy/report")).text;
    expect(report).toContain("not legal advice");
    expect(report).toContain("Records deleted");
    const st = await status(h, "privacy");
    expect(st.minimization && st.retention && st.report).toBe(true);
  });

  it("AI: prompt gateway, RAG access control and logging", async () => {
    const h = await t.register("learner1");
    const ov = await api(h, "GET", "/api/labs/ai");
    expect((await api(h, "POST", "/api/labs/ai/gateway/evaluate")).passed).toBe(false);
    const policy = { ...structuredClone(ov.state.gateway_policy), outcome: "BLOCK", conditions: { match: "any", conditions: [
      { match: "all", conditions: [
        { field: "destination.sanctioned", op: "eq", value: false },
        { field: "content.detected_types", op: "contains_any", value: ["CREDIT_CARD", "SECRET_CREDENTIAL", "CONFIDENTIAL_MARKER", "CUSTOMER_ACCOUNT", "EMAIL_ADDRESS"] }] },
      { field: "content.detected_types", op: "contains_any", value: ["CREDIT_CARD", "IBAN", "US_SSN", "SECRET_CREDENTIAL"] }] } };
    const res = await api(h, "PUT", "/api/labs/ai/gateway", { policy });
    expect(res.passed, JSON.stringify(res.results.filter((r: Json) => !r.correct))).toBe(true);
    expect((await api(h, "POST", "/api/labs/ai/gateway/evaluate")).passed).toBe(true);

    const leak = await api(h, "POST", "/api/labs/ai/rag/query", { role: "support_agent", query: "what is rita silva salary" });
    expect(leak.results.some((d: Json) => ["D2", "D5"].includes(d.id))).toBe(true);
    expect((await api(h, "POST", "/api/labs/ai/rag/tests")).passed).toBe(false);
    await api(h, "PUT", "/api/labs/ai/rag", { enforce_acl: true, index_restricted_docs: true });
    expect((await api(h, "POST", "/api/labs/ai/rag/tests")).passed).toBe(true);

    const findings = await api(h, "PUT", "/api/labs/ai/logging", { prompt_logging: "full", retention_days: 3650, log_access: "all_staff", vendor_training_opt_in: true });
    expect(findings.findings).toHaveLength(4);
    expect((await api(h, "PUT", "/api/labs/ai/logging", { prompt_logging: "redacted", retention_days: 30, log_access: "security_only",
      vendor_training_opt_in: false })).passed).toBe(true);
    expect(Object.values(await status(h, "ai")).every(Boolean)).toBe(true);
  });

  it("grades knowledge checks on the server", async () => {
    const h = await t.register("learner1");
    expect(JSON.stringify(await api(h, "GET", "/api/curriculum/quiz/M01-L1"))).not.toContain("answer");
    expect((await api(h, "POST", "/api/curriculum/quiz/M01-L1", { answers: [0, 0, 0, 0] })).passed).toBe(false);
    expect((await api(h, "POST", "/api/curriculum/quiz/M01-L1", { answers: [1, 1, 1, 1] })).passed).toBe(true);
    const cur = await api(h, "GET", "/api/curriculum");
    expect(cur.lessons.find((x: Json) => x.id === "M01-L1").completed).toBe(true);
    expect(cur.modules.find((m: Json) => m.id === "M10").status).toBe("PLANNED");
    expect((await h.get("/api/curriculum/quiz/constructor")).status).toBe(404);
  });

  it("a specialist pathway unlocks its lessons", async () => {
    const h = await t.register("learner1");
    let cur = await api(h, "GET", "/api/curriculum");
    expect(cur.lessons.find((x: Json) => x.id === "M08-L1").available).toBe(false);
    await api(h, "PUT", "/api/curriculum/pathway", { pathway: "dlp-engineer" });
    cur = await api(h, "GET", "/api/curriculum");
    expect(cur.lessons.find((x: Json) => x.id === "M08-L1").available).toBe(true);
    expect(cur.lessons.find((x: Json) => x.id === "M06-L1").available).toBe(false);
    const dash = await api(h, "GET", "/api/dashboard");
    expect(dash.pathway.id).toBe("dlp-engineer");
    expect(dash.next_lesson).toBeTruthy();
  });

  it("integrations are reported honestly", async () => {
    const h = await t.register("learner1");
    const ints: Json[] = await api(h, "GET", "/api/integrations");
    const purview = ints.find((i) => i.key === "microsoft-purview")!;
    expect([purview.status, purview.enabled, purview.tested]).toEqual(["NOT_IMPLEMENTED", false, false]);
    expect(ints.every((i) => ["IMPLEMENTED", "NOT_IMPLEMENTED", "GUIDE_ONLY"].includes(i.status))).toBe(true);
  });
});
