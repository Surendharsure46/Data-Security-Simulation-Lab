/** Hands-on lab endpoints. Every response states its provenance (REAL_LAB or SIMULATED). */
import { createHmac, scryptSync, timingSafeEqual } from "node:crypto";
import { Controller, Get, Put } from "@nestjs/common";
import {
  AiLogIn, AnswerFileIn, BackupIn, BucketAnswerIn, CloudChangeIn, ConfirmIn, EncConfigIn, EnvDecIn, GatewayIn, GrantIn, HashIn, HmacIn, IdentifyIn,
  LookupIn, MaskIn, MinimizationIn, PassIn, QueryIn, RagCfgIn, RagQueryIn, RetentionIn, TlsIn,
} from "@threatready/contracts";
import { z } from "zod";
import { DomainError, sorted } from "../common/util.js";
import type { Principal } from "../db/context.js";
import * as dblab from "../labs/dblab.js";
import * as enc from "../labs/encryption.js";
import { getState, labDir, type LabStateRow, passedExercises, recordResult, setState } from "../labs/common.js";
import { LAB_EXERCISES } from "../labs/registry.js";
import * as sim from "../labs/simlabs.js";
import { CurrentPrincipal, Permission, PERMISSIONS, PostOk, RawResponse, ZBody } from "../platform/http.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type In<T extends z.ZodType> = z.infer<T>;

async function passOnce(userId: string, lab: string, exercise: string, provenance: string, detail: Json): Promise<boolean> {
  if ((await passedExercises(userId, lab)).has(exercise)) return false;
  await recordResult(userId, lab, exercise, true, provenance, detail);
  return true;
}

const ENC_DEFAULT = (): Json => ({ hashed: [], file: {}, envelope: {}, config: null });
const DB_DEFAULT = (): Json => ({ denied_after_revoke: false, masked_ok_after_revoke: false, vuln_demo: null, param_safe: false, backup_id: null,
  damaged: false, restored: false });

const encState = (userId: string) => getState(userId, "encryption", ENC_DEFAULT());
const dbState = (userId: string) => getState(userId, "database", DB_DEFAULT());
const cloudState = (userId: string) => getState(userId, "cloud", sim.cloudInitial());
const privacyState = (userId: string) => getState(userId, "privacy", sim.privacyInitial());
const aiState = (userId: string) => getState(userId, "ai", sim.aiInitial());
const replace = (st: LabStateRow, state: Json) => { st.state = state; st.updated_at = new Date(); };

/** Proof-of-knowledge for the lab passphrase (HMAC under the scrypt-derived key), so the passphrase itself is never stored. */
function verifier(passphrase: string, saltHex: string): string {
  const key = scryptSync(passphrase, Buffer.from(saltHex, "hex"), 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return createHmac("sha256", key).update("threatready-verifier").digest("hex");
}

const REFS_CUSTOMERS = /\bcustomers\b(?!_masked)/i;
const REFS_MASKED = /\bcustomers_masked\b/i;

@Controller("api/labs")
@Permission(PERMISSIONS.SELF)
export class LabsController {
  @Get("status")
  async status(@CurrentPrincipal() p: Principal) {
    const out: Json = {};
    for (const [lab, v] of Object.entries(LAB_EXERCISES)) {
      const passed = await passedExercises(p.userId, lab);
      out[lab] = { mode: v.mode, exercises: Object.fromEntries(v.exercises.map((e) => [e, passed.has(e)])) };
    }
    return out;
  }

  // =========================================================================== encryption

  @Get("encryption")
  async encOverview(@CurrentPrincipal() p: Principal) {
    const st = await encState(p.userId);
    const { file, ...rest } = st.state;
    const { verifier: _v, ...fileOut } = file ?? {};
    return { files: sorted(Object.keys(enc.HASH_FILES)), manifest: enc.MANIFEST, state: { ...rest, file: fileOut },
      passed: sorted(await passedExercises(p.userId, "encryption")), tls: { capture: enc.TLS_CAPTURE, items: enc.TLS_LABELS },
      config_options: enc.CONFIG_OPTIONS, config: st.state.config ?? enc.WEAK_CONFIG };
  }

  @PostOk("encryption/hash")
  async encHash(@CurrentPrincipal() p: Principal, @ZBody(HashIn) body: In<typeof HashIn>) {
    const res = enc.hashFile(body.file);
    const st = await encState(p.userId);
    setState(st, { hashed: sorted(new Set([...(st.state.hashed ?? []), body.file])) });
    return { ...res, provenance: "REAL_LAB" };
  }

  @PostOk("encryption/hash/answer")
  async encHashAnswer(@CurrentPrincipal() p: Principal, @ZBody(AnswerFileIn) body: In<typeof AnswerFileIn>) {
    const st = await encState(p.userId);
    const hashed = new Set<string>(st.state.hashed ?? []);
    const all = Object.keys(enc.HASH_FILES);
    if (hashed.size !== all.length || !all.every((f) => hashed.has(f))) {
      throw new DomainError("Hash all three files and compare them with the manifest before answering", 409);
    }
    const ok = body.modified_file === enc.TAMPERED_FILE;
    if (ok) await passOnce(p.userId, "encryption", "hashing", "REAL_LAB", { answer: body.modified_file });
    return { correct: ok, explanation: ok ? "Its SHA-256 differs from the manifest; a single changed digit changes the whole digest."
      : "That file's digest matches the manifest. Compare every digest with the published value." };
  }

  @PostOk("encryption/hmac")
  encHmac(@ZBody(HmacIn) body: In<typeof HmacIn>) {
    return { ...enc.hmacDemo(body.message, body.key_label), provenance: "REAL_LAB" };
  }

  @PostOk("encryption/file/encrypt")
  async encEncrypt(@CurrentPrincipal() p: Principal, @ZBody(PassIn) body: In<typeof PassIn>) {
    const res = enc.encryptSample(labDir(p.userId, "crypto"), body.passphrase);
    const st = await encState(p.userId);
    setState(st, { file: { encrypted: true, tampered: false, wrong_key_rejected: false, correct_ok: false, tamper_rejected: false,
      verifier: verifier(body.passphrase, res.header.salt) } });
    return res;
  }

  @PostOk("encryption/file/decrypt")
  async encDecrypt(@CurrentPrincipal() p: Principal, @ZBody(PassIn) body: In<typeof PassIn>) {
    const d = labDir(p.userId, "crypto");
    const st = await encState(p.userId);
    const f: Json = { ...(st.state.file ?? {}) };
    if (!f.encrypted) throw new DomainError("Encrypt the sample file first", 409);
    const res = enc.decryptSample(d, body.passphrase);
    const header = enc.readSampleHeader(d);
    const a = Buffer.from(verifier(body.passphrase, header.salt), "hex");
    const b = Buffer.from(String(f.verifier ?? ""), "hex");
    const correctPass = a.length === b.length && timingSafeEqual(a, b);
    if (!res.success && !correctPass && !f.tampered) f.wrong_key_rejected = true;
    if (res.success && res.matches_original) f.correct_ok = true;
    if (!res.success && correctPass && f.tampered) f.tamper_rejected = true;
    setState(st, { file: f });
    const keys = ["wrong_key_rejected", "correct_ok", "tamper_rejected"];
    if (keys.every((k) => f[k])) await passOnce(p.userId, "encryption", "file_roundtrip", "REAL_LAB", Object.fromEntries(keys.map((k) => [k, f[k]])));
    return { ...res, checks: Object.fromEntries(keys.map((k) => [k, f[k] ?? false])) };
  }

  @PostOk("encryption/file/tamper")
  async encTamper(@CurrentPrincipal() p: Principal) {
    const res = enc.tamperSample(labDir(p.userId, "crypto"));
    const st = await encState(p.userId);
    setState(st, { file: { ...(st.state.file ?? {}), tampered: true } });
    return res;
  }

  @PostOk("encryption/envelope/init")
  async envInit(@CurrentPrincipal() p: Principal) {
    const res = enc.envelopeInit(labDir(p.userId, "crypto"));
    const st = await encState(p.userId);
    setState(st, { envelope: { initial_data_sha256: res.data_ciphertext_sha256, rotated: false, decrypted_after_rotation: false, data_unchanged: null } });
    return res;
  }

  @PostOk("encryption/envelope/rotate")
  async envRotate(@CurrentPrincipal() p: Principal) {
    const res = enc.envelopeRotate(labDir(p.userId, "crypto"));
    const st = await encState(p.userId);
    const e: Json = { ...(st.state.envelope ?? {}) };
    e.rotated = true;
    e.data_unchanged = res.data_ciphertext_sha256 === e.initial_data_sha256;
    setState(st, { envelope: e });
    return { ...res, data_unchanged_since_init: e.data_unchanged };
  }

  @PostOk("encryption/envelope/decrypt")
  async envDecrypt(@CurrentPrincipal() p: Principal, @ZBody(EnvDecIn) body: In<typeof EnvDecIn>) {
    const res = enc.envelopeDecrypt(labDir(p.userId, "crypto"), body.kek_id);
    const st = await encState(p.userId);
    const e: Json = { ...(st.state.envelope ?? {}) };
    if (res.success && res.matches_original && e.rotated) e.decrypted_after_rotation = true;
    setState(st, { envelope: e });
    if (e.rotated && e.data_unchanged && e.decrypted_after_rotation) await passOnce(p.userId, "encryption", "envelope_rotation", "REAL_LAB", e);
    return res;
  }

  @PostOk("encryption/tls/answer")
  async tlsAnswer(@CurrentPrincipal() p: Principal, @ZBody(TlsIn) body: In<typeof TlsIn>) {
    const { per_item: _per, ...res } = enc.gradeTls(body.visible);
    if (res.passed) await passOnce(p.userId, "encryption", "tls_metadata", "SIMULATED", { answer: sorted(body.visible) });
    return { ...res, provenance: "SIMULATED" };
  }

  @Put("encryption/config")
  async putConfig(@CurrentPrincipal() p: Principal, @ZBody(EncConfigIn) body: In<typeof EncConfigIn>) {
    const cfg = { service: enc.WEAK_CONFIG.service, ...body };
    const findings = enc.validateConfig(cfg); // validates allowed values
    const st = await encState(p.userId);
    setState(st, { config: cfg });
    return { config: cfg, findings_preview: findings.length };
  }

  @PostOk("encryption/config/validate")
  async validateConfig(@CurrentPrincipal() p: Principal) {
    const st = await encState(p.userId);
    const cfg = st.state.config ?? enc.WEAK_CONFIG;
    const findings = enc.validateConfig(cfg);
    if (!findings.length) await passOnce(p.userId, "encryption", "config_review", "SIMULATED", { config: cfg });
    return { findings, passed: !findings.length, provenance: "SIMULATED" };
  }

  @PostOk("encryption/config/reset")
  async resetConfig(@CurrentPrincipal() p: Principal) {
    setState(await encState(p.userId), { config: null });
    return { config: enc.WEAK_CONFIG };
  }

  // =========================================================================== database

  @Get("database")
  async dbOverview(@CurrentPrincipal() p: Principal) {
    const d = labDir(p.userId, "database");
    const st = await dbState(p.userId);
    return { roles: dblab.ROLES, grants: dblab.grants(d), masking: dblab.masking(d), masked_view_sql: dblab.maskedViewSql(d), backups: dblab.backups(d),
      state: st.state, passed: sorted(await passedExercises(p.userId, "database")), tables: sorted(dblab.USER_TABLES),
      enforcement: "SQLite authorizer callback (SQLite has no native roles or GRANT)", provenance: "REAL_LAB" };
  }

  @PostOk("database/reset")
  async dbReset(@CurrentPrincipal() p: Principal) {
    const res = dblab.initDb(labDir(p.userId, "database"));
    replace(await dbState(p.userId), DB_DEFAULT());
    return res;
  }

  @PostOk("database/query")
  async dbQuery(@CurrentPrincipal() p: Principal, @ZBody(QueryIn) body: In<typeof QueryIn>) {
    const d = labDir(p.userId, "database");
    const res = await dblab.runQuery(d, body.role, body.sql);
    const st = await dbState(p.userId);
    const s: Json = { ...st.state };
    const revoked = !dblab.grants(d).some((g) => g.role === "support_agent" && g.table_name === "customers");
    if (body.role === "support_agent" && revoked) {
      if (res.decision === "DENIED" && REFS_CUSTOMERS.test(body.sql)) s.denied_after_revoke = true;
      if (res.decision === "ALLOWED" && REFS_MASKED.test(body.sql) && res.row_count > 0) s.masked_ok_after_revoke = true;
    }
    replace(st, s);
    if (revoked && s.denied_after_revoke && s.masked_ok_after_revoke) {
      await passOnce(p.userId, "database", "least_privilege", "REAL_LAB", { denied_after_revoke: true, masked_ok: true });
    }
    const m = dblab.masking(d);
    if (body.role === "support_agent" && res.decision === "ALLOWED" && REFS_MASKED.test(body.sql) && res.row_count > 0
      && ["card_number", "email", "dob"].every((c) => m[c]) && res.columns.includes("card_number")) {
      const flat = (res.rows as unknown[][]).flat().map(String).join(" ");
      if (!dblab.PAN_RE.test(flat) && !/\b[a-z]{2,}\.[a-z]+\d*@/.test(flat)) {
        await passOnce(p.userId, "database", "masking", "REAL_LAB", { columns_masked: Object.entries(m).filter(([, v]) => v).map(([c]) => c) });
      }
    }
    return res;
  }

  @PostOk("database/grants/revoke")
  dbRevoke(@CurrentPrincipal() p: Principal, @ZBody(GrantIn) body: In<typeof GrantIn>) {
    const d = labDir(p.userId, "database");
    const n = dblab.revoke(d, body.role, body.table);
    if (n === 0) throw new DomainError("No such grant", 404);
    return { revoked: n, grants: dblab.grants(d), provenance: "REAL_LAB" };
  }

  @PostOk("database/grants/grant")
  dbGrant(@CurrentPrincipal() p: Principal, @ZBody(GrantIn) body: In<typeof GrantIn>) {
    const d = labDir(p.userId, "database");
    dblab.grant(d, body.role, body.table);
    return { grants: dblab.grants(d), provenance: "REAL_LAB" };
  }

  @PostOk("database/lookup")
  async dbLookup(@CurrentPrincipal() p: Principal, @ZBody(LookupIn) body: In<typeof LookupIn>) {
    const res = await dblab.lookup(labDir(p.userId, "database"), body.mode, body.email);
    const st = await dbState(p.userId);
    const s: Json = { ...st.state };
    const injected = body.email.includes("'");
    if (body.mode === "vulnerable" && injected && res.row_count > 1) s.vuln_demo = body.email;
    if (body.mode === "parameterized" && injected && res.row_count === 0 && s.vuln_demo === body.email) s.param_safe = true;
    replace(st, s);
    if (s.vuln_demo && s.param_safe) await passOnce(p.userId, "database", "injection", "REAL_LAB", { payload: s.vuln_demo });
    return res;
  }

  @Put("database/masking")
  dbMask(@CurrentPrincipal() p: Principal, @ZBody(MaskIn) body: In<typeof MaskIn>) {
    const d = labDir(p.userId, "database");
    return { masking: dblab.setMasking(d, body.column, body.enabled), masked_view_sql: dblab.maskedViewSql(d), provenance: "REAL_LAB" };
  }

  @Get("database/audit")
  dbAudit(@CurrentPrincipal() p: Principal) {
    return { entries: dblab.auditLog(labDir(p.userId, "database")), provenance: "REAL_LAB",
      note: "Entries with source 'seeded-history' are pre-loaded synthetic history; 'learner' entries record your real queries." };
  }

  @PostOk("database/audit/identify")
  async dbIdentify(@CurrentPrincipal() p: Principal, @ZBody(IdentifyIn) body: In<typeof IdentifyIn>) {
    const ok = dblab.bulkAuditIds(labDir(p.userId, "database")).includes(body.audit_id);
    if (ok) await passOnce(p.userId, "database", "audit", "REAL_LAB", { audit_id: body.audit_id });
    return { correct: ok, explanation: ok ? "A support role read every customer row at 02:13 — bulk, after hours, from the unmasked table."
      : "That entry is consistent with the role's normal single-record work. Look at rows returned, time and object." };
  }

  @PostOk("database/backup")
  async dbBackup(@CurrentPrincipal() p: Principal) {
    const res = await dblab.backup(labDir(p.userId, "database"));
    const st = await dbState(p.userId);
    replace(st, { ...st.state, backup_id: res.backup_id, damaged: false, restored: false });
    return res;
  }

  @PostOk("database/damage")
  async dbDamage(@CurrentPrincipal() p: Principal) {
    const res = dblab.damage(labDir(p.userId, "database"));
    const st = await dbState(p.userId);
    replace(st, { ...st.state, damaged: Boolean(st.state.backup_id) });
    return res;
  }

  @PostOk("database/restore")
  async dbRestore(@CurrentPrincipal() p: Principal, @ZBody(BackupIn) body: In<typeof BackupIn>) {
    const res = await dblab.restore(labDir(p.userId, "database"), body.backup_id);
    const st = await dbState(p.userId);
    replace(st, { ...st.state, restored: Boolean(st.state.damaged) && body.backup_id === st.state.backup_id });
    return res;
  }

  @PostOk("database/verify")
  async dbVerify(@CurrentPrincipal() p: Principal, @ZBody(BackupIn) body: In<typeof BackupIn>) {
    const res = dblab.verifyRestore(labDir(p.userId, "database"), body.backup_id);
    const st = await dbState(p.userId);
    if (res.match && st.state.restored && body.backup_id === st.state.backup_id) await passOnce(p.userId, "database", "backup_restore", "REAL_LAB", res);
    return res;
  }

  // =========================================================================== cloud (simulated)

  @Get("cloud")
  async cloudOverview(@CurrentPrincipal() p: Principal) {
    const st = await cloudState(p.userId);
    return { buckets: st.state.buckets, access_options: sim.CLOUD_ACCESS_OPTIONS, target: sim.CLOUD_TARGET, audit_events: sim.cloudAuditEvents(st.state),
      assessments_run: st.state.assessments,
      risk_model: "exposure = sensitivity(0-3) × access breadth (public/all-authenticated 3, cross-account 2, org-wide 1, restricted 0) "
        + "+ 1 per missing control (encryption, access logging) when sensitivity ≥ Confidential",
      passed: sorted(await passedExercises(p.userId, "cloud")), provenance: "SIMULATED",
      note: "Simulated object storage. Events are synthetic and are not AWS, Azure or Google Cloud telemetry." };
  }

  @PostOk("cloud/assess")
  async cloudAssess(@CurrentPrincipal() p: Principal) {
    const st = await cloudState(p.userId);
    const s: Json = { ...st.state, assessments: st.state.assessments + 1, last_assessment_seq: st.state.seq };
    replace(st, s);
    return sim.cloudAssess(s);
  }

  @PostOk("cloud/assess/answer")
  async cloudAnswer(@CurrentPrincipal() p: Principal, @ZBody(BucketAnswerIn) body: In<typeof BucketAnswerIn>) {
    const st = await cloudState(p.userId);
    if (st.state.assessments < 1) throw new DomainError("Run an assessment first", 409);
    const top = sim.cloudAssess(sim.cloudInitial()).buckets[0].bucket;
    const ok = body.bucket === top;
    if (ok) await passOnce(p.userId, "cloud", "assess", "SIMULATED", { bucket: body.bucket });
    return { correct: ok };
  }

  @PostOk("cloud/change")
  async cloudChange(@CurrentPrincipal() p: Principal, @ZBody(CloudChangeIn) body: In<typeof CloudChangeIn>) {
    const st = await cloudState(p.userId);
    replace(st, sim.cloudChange(st.state, body.bucket, body.field, body.value));
    return { buckets: st.state.buckets, audit_events: sim.cloudAuditEvents(st.state) };
  }

  @PostOk("cloud/verify")
  async cloudVerify(@CurrentPrincipal() p: Principal) {
    const res = sim.cloudRemediationResult((await cloudState(p.userId)).state);
    if (res.passed) await passOnce(p.userId, "cloud", "remediate", "SIMULATED", { total: res.assessment.total_exposure_non_public });
    return res;
  }

  @PostOk("cloud/reset")
  async cloudReset(@CurrentPrincipal() p: Principal) {
    replace(await cloudState(p.userId), sim.cloudInitial());
    return { ok: true };
  }

  // =========================================================================== privacy (simulated)

  @Get("privacy")
  async privacyOverview(@CurrentPrincipal() p: Principal) {
    const st = await privacyState(p.userId);
    return { purpose: sim.PRIVACY_PURPOSE, retention_standard: sim.RETENTION_STANDARD, fields: sim.LEAD_FIELDS, lab_today: "2026-03-09", state: st.state,
      passed: sorted(await passedExercises(p.userId, "privacy")), provenance: "SIMULATED",
      note: "Disposable synthetic records. Deletion here permanently removes records from your lab copy only; reset restores them." };
  }

  @Put("privacy/minimization")
  async privacyMin(@CurrentPrincipal() p: Principal, @ZBody(MinimizationIn) body: In<typeof MinimizationIn>) {
    const res = sim.privacyGradeMinimization(body.decisions);
    const st = await privacyState(p.userId);
    replace(st, { ...st.state, field_decisions: body.decisions, minimization_result: res });
    if (res.passed) await passOnce(p.userId, "privacy", "minimization", "SIMULATED", res);
    return res;
  }

  @PostOk("privacy/retention/evaluate")
  async privacyEval(@CurrentPrincipal() p: Principal, @ZBody(RetentionIn) body: In<typeof RetentionIn>) {
    const st = await privacyState(p.userId);
    const preview = sim.privacyEvaluate(st.state, body);
    replace(st, { ...st.state, retention: body, evaluations: (st.state.evaluations ?? 0) + 1 });
    return { rule: body, matches: preview, to_delete: preview.filter((x) => x.action === "DELETE").length };
  }

  @PostOk("privacy/retention/execute")
  async privacyExec(@CurrentPrincipal() p: Principal, @ZBody(ConfirmIn) body: In<typeof ConfirmIn>) {
    if (!body.confirm) throw new DomainError("Deletion is irreversible for this lab copy. Resubmit with confirm=true.", 409);
    const st = await privacyState(p.userId);
    const rule = st.state.retention;
    if (!rule) throw new DomainError("Evaluate a retention rule first", 409);
    const expected = sim.privacyExpectedDeletions(st.state);
    const deleteIds = new Set(sim.privacyEvaluate(st.state, rule).filter((x) => x.action === "DELETE").map((x) => x.lead_id as string));
    const heldDeleted = sorted([...deleteIds].filter((i) => (st.state.leads as Json[]).find((x) => x.lead_id === i)!.legal_hold));
    const s: Json = { ...st.state };
    s.leads = (s.leads as Json[]).filter((x) => !deleteIds.has(x.lead_id));
    s.deleted = sorted(new Set([...(s.deleted ?? []), ...deleteIds]));
    if (heldDeleted.length) s.critical = `Records under legal hold were deleted: ${heldDeleted.join(", ")}`;
    replace(st, s);
    const passed = !heldDeleted.length && deleteIds.size === expected.size && [...deleteIds].every((i) => expected.has(i)) && !s.critical;
    if (passed) await passOnce(p.userId, "privacy", "retention", "SIMULATED", { deleted: sorted(deleteIds) });
    return { deleted: sorted(deleteIds), remaining: s.leads.length, legal_hold_deleted: heldDeleted, passed,
      verification: `Remaining records re-checked: ${(s.leads as Json[]).filter((x) => deleteIds.has(x.lead_id)).length} deleted IDs still present.`,
      feedback: passed ? null : heldDeleted.length ? "Critical: legal hold must override deletion. Reset the lab to retry."
        : "The deleted set does not match the records standard. Reset the lab and compare your rule to the standard." };
  }

  @Get("privacy/report")
  async privacyReport(@CurrentPrincipal() p: Principal) {
    const st = await privacyState(p.userId);
    const passed = await passedExercises(p.userId, "privacy");
    const md = sim.privacyReport(st.state, st.state.minimization_result ?? null);
    if (passed.has("minimization") && passed.has("retention")) await passOnce(p.userId, "privacy", "report", "SIMULATED", {});
    return new RawResponse(md, "text/markdown; charset=utf-8");
  }

  @PostOk("privacy/reset")
  async privacyReset(@CurrentPrincipal() p: Principal) {
    replace(await privacyState(p.userId), sim.privacyInitial());
    return { ok: true };
  }

  // =========================================================================== AI data security (simulated)

  @Get("ai")
  async aiOverview(@CurrentPrincipal() p: Principal) {
    const st = await aiState(p.userId);
    return { state: st.state,
      prompts: sim.AI_PROMPTS.map(({ should_block, ...rest }) => ({ ...rest, expected: should_block ? "BLOCK" : "ALLOW" })),
      destinations: sim.AI_DESTINATIONS, documents: sim.RAG_DOCS, roles: sim.RAG_ROLES, rag_tests: sim.RAG_TESTS, logging_options: sim.AI_LOG_OPTIONS,
      passed: sorted(await passedExercises(p.userId, "ai")), provenance: "SIMULATED",
      note: "No prompt is sent to any AI model. Retrieval is a deterministic keyword ranker used to test access control." };
  }

  @Put("ai/gateway")
  async aiGateway(@CurrentPrincipal() p: Principal, @ZBody(GatewayIn) body: In<typeof GatewayIn>) {
    const res = sim.aiEvaluatePrompts(body.policy); // validates
    const st = await aiState(p.userId);
    replace(st, { ...st.state, gateway_policy: body.policy });
    return res;
  }

  @PostOk("ai/gateway/evaluate")
  async aiGatewayEval(@CurrentPrincipal() p: Principal) {
    const res = sim.aiEvaluatePrompts((await aiState(p.userId)).state.gateway_policy);
    if (res.passed) await passOnce(p.userId, "ai", "prompt_gateway", "SIMULATED", { correct: res.correct });
    return res;
  }

  @Put("ai/rag")
  async aiRagCfg(@CurrentPrincipal() p: Principal, @ZBody(RagCfgIn) body: In<typeof RagCfgIn>) {
    const st = await aiState(p.userId);
    replace(st, { ...st.state, rag: body });
    return body;
  }

  @PostOk("ai/rag/query")
  async aiRagQuery(@CurrentPrincipal() p: Principal, @ZBody(RagQueryIn) body: In<typeof RagQueryIn>) {
    const st = await aiState(p.userId);
    return { results: sim.ragRetrieve(st.state.rag, body.role, body.query), config: st.state.rag, provenance: "SIMULATED" };
  }

  @PostOk("ai/rag/tests")
  async aiRagTests(@CurrentPrincipal() p: Principal) {
    const st = await aiState(p.userId);
    const res = sim.ragRunTests(st.state.rag);
    if (res.passed) await passOnce(p.userId, "ai", "rag_acl", "SIMULATED", { config: st.state.rag });
    return res;
  }

  @Put("ai/logging")
  async aiLogging(@CurrentPrincipal() p: Principal, @ZBody(AiLogIn) body: In<typeof AiLogIn>) {
    const findings = sim.aiLoggingFindings(body);
    const st = await aiState(p.userId);
    replace(st, { ...st.state, logging: body });
    if (!findings.length) await passOnce(p.userId, "ai", "retention", "SIMULATED", body);
    return { findings, passed: !findings.length, provenance: "SIMULATED" };
  }

  @PostOk("ai/reset")
  async aiReset(@CurrentPrincipal() p: Principal) {
    replace(await aiState(p.userId), sim.aiInitial());
    return { ok: true };
  }
}
