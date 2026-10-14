/**
 * SIMULATED labs: Cloud DSPM, Privacy & Governance and AI Data Security.
 *
 * State lives in `lab_states` per user. All cloud events are synthetic and labelled as such; they are not AWS, Azure or
 * Google Cloud telemetry. The AI lab performs no model calls: retrieval is a deterministic keyword-overlap ranker so that
 * the access-control behaviour can be tested exactly.
 */
import { addDays, DomainError, pad, pyRepr, Rng, sorted } from "../common/util.js";
import { syntheticName } from "../content/company.js";
import { maxConfidence, scanText } from "../domain/detection.js";
import { decide, evaluatePolicy } from "../domain/policy-engine.js";
import { PolicyDefinitionSchema } from "@threatready/contracts";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

// =========================================================================== Cloud DSPM

export const ACCESS_BREADTH: Record<string, number> = { PUBLIC_READ: 3, ALL_AUTHENTICATED_USERS: 3, CROSS_ACCOUNT: 2, ORG_WIDE: 1, RESTRICTED: 0 };
const SENSITIVITY: Record<string, number> = { public: 0, internal: 1, confidential: 2, restricted: 3 };

const CLOUD_INITIAL = {
  buckets: [
    { name: "kr-analytics-exports", data_label: "restricted", objects: 3, records: 46990, access: "ALL_AUTHENTICATED_USERS",
      cross_account_principals: [] as string[], encryption: false, access_logging: false, purpose: "Analytics team extracts", business_requirement: null },
    { name: "kr-marketing-site", data_label: "public", objects: 212, records: 0, access: "PUBLIC_READ", cross_account_principals: [],
      encryption: true, access_logging: true, purpose: "Static website for product pages",
      business_requirement: "Must remain publicly readable: serves www.kestrelridge.example" },
    { name: "kr-hr-scans", data_label: "restricted", objects: 1840, records: 1840, access: "CROSS_ACCOUNT",
      cross_account_principals: ["acct-helpwise-vendor"], encryption: true, access_logging: false, purpose: "Scanned HR onboarding forms",
      business_requirement: null },
    { name: "kr-app-logs", data_label: "confidential", objects: 9000, records: 0, access: "ORG_WIDE", cross_account_principals: [],
      encryption: true, access_logging: true, purpose: "Application logs (contain customer emails)", business_requirement: null },
    { name: "kr-db-backups", data_label: "restricted", objects: 30, records: 48210, access: "RESTRICTED", cross_account_principals: [],
      encryption: true, access_logging: true, purpose: "Nightly database backups", business_requirement: null },
    { name: "kr-dev-sandbox", data_label: "internal", objects: 57, records: 0, access: "PUBLIC_READ", cross_account_principals: [],
      encryption: false, access_logging: false, purpose: "Developer experiments", business_requirement: null },
  ],
  assessments: 0,
  last_change_seq: 0,
  last_assessment_seq: 0,
  seq: 0,
  change_log: [] as Json[],
};
export const CLOUD_TARGET = 10; // total exposure of non-public data must be <= target

export function cloudInitial(): Json {
  return structuredClone(CLOUD_INITIAL);
}

export function exposure(b: Json): Json {
  const s = SENSITIVITY[b.data_label];
  const breadth = ACCESS_BREADTH[b.access];
  const extra = s >= 2 ? (b.encryption ? 0 : 1) + (b.access_logging ? 0 : 1) : 0;
  return { score: s * breadth + extra, sensitivity: s, breadth, missing_controls: extra,
    formula: "sensitivity(0-3) × access breadth(0-3) + 1 per missing control (encryption, logging) when sensitivity ≥ 2" };
}

export function cloudAssess(state: Json): Json {
  const rows: Json[] = (state.buckets as Json[]).map((b) => ({ bucket: b.name, ...exposure(b), access: b.access, data_label: b.data_label }));
  rows.sort((a, b) => b.score - a.score || (a.bucket < b.bucket ? -1 : a.bucket > b.bucket ? 1 : 0));
  const total = rows.filter((r) => r.sensitivity > 0).reduce((n, r) => n + r.score, 0);
  return { buckets: rows, total_exposure_non_public: total, target: CLOUD_TARGET, provenance: "SIMULATED" };
}

/** Deterministic synthetic audit events reflecting the *current* configuration. */
export function cloudAuditEvents(state: Json): Json[] {
  const rng = new Rng(7);
  const out: Json[] = [];
  for (const b of state.buckets as Json[]) {
    if (b.access === "PUBLIC_READ" || b.access === "ALL_AUTHENTICATED_USERS") {
      for (let i = 0; i < 3; i++) {
        out.push({ time: `2026-03-0${i + 3}T0${rng.randint(1, 9)}:${rng.randint(10, 59)}:00Z`, bucket: b.name,
          principal: b.access === "PUBLIC_READ" ? "anonymous" : `external-account-${rng.randint(1000, 9999)}`,
          operation: "GetObject", source_ip: `198.51.100.${rng.randint(2, 250)}`, result: "Success" });
      }
    }
    for (const p of b.cross_account_principals) {
      out.push({ time: "2026-03-05T14:02:00Z", bucket: b.name, principal: p, operation: "ListObjects", source_ip: "203.0.113.77", result: "Success" });
    }
  }
  for (const c of state.change_log ?? []) {
    out.push({ time: "lab-time", bucket: c.bucket, principal: "learner", operation: `PutBucketConfig:${c.field}`, source_ip: "10.20.0.1", result: "Success" });
  }
  for (const e of out) {
    e.provenance = "SIMULATED";
    e.note = "Synthetic cloud audit event; not vendor telemetry.";
  }
  return out;
}

export const CLOUD_ACCESS_OPTIONS = Object.keys(ACCESS_BREADTH);

export function cloudChange(state: Json, bucket: string, field: string, value: unknown): Json {
  const st = structuredClone(state);
  const b = (st.buckets as Json[]).find((x) => x.name === bucket);
  if (!b) throw new DomainError("Unknown bucket", 404);
  if (field === "access") {
    if (typeof value !== "string" || !CLOUD_ACCESS_OPTIONS.includes(value)) throw new DomainError(`access must be one of ${pyRepr(CLOUD_ACCESS_OPTIONS)}`);
    b.access = value;
    if (value !== "CROSS_ACCOUNT") b.cross_account_principals = [];
  } else if (field === "encryption" || field === "access_logging") {
    if (typeof value !== "boolean") throw new DomainError(`${field} must be true or false`);
    b[field] = value;
  } else if (field === "remove_principal") {
    if (!b.cross_account_principals.includes(value)) throw new DomainError("Principal not present");
    b.cross_account_principals = b.cross_account_principals.filter((p: string) => p !== value);
    if (!b.cross_account_principals.length && b.access === "CROSS_ACCOUNT") b.access = "RESTRICTED";
  } else {
    throw new DomainError("Unsupported change");
  }
  st.seq += 1;
  st.last_change_seq = st.seq;
  st.change_log.push({ seq: st.seq, bucket, field, value });
  return st;
}

export function cloudRemediationResult(state: Json): Json {
  const a = cloudAssess(state);
  const site = (state.buckets as Json[]).find((b) => b.name === "kr-marketing-site")!;
  const disrupted = site.access !== "PUBLIC_READ";
  const reassessed = state.last_assessment_seq >= state.last_change_seq && state.last_change_seq > 0;
  const reasons: string[] = [];
  if (a.total_exposure_non_public > CLOUD_TARGET) reasons.push(`Total exposure ${a.total_exposure_non_public} is above the target ${CLOUD_TARGET}.`);
  if (disrupted) reasons.push("kr-marketing-site must remain publicly readable (documented business requirement).");
  if (!reassessed) reasons.push("Run a re-assessment after your last change to verify the result.");
  return { passed: a.total_exposure_non_public <= CLOUD_TARGET && !disrupted && reassessed, reasons, assessment: a };
}

// =========================================================================== Privacy & governance

export const PRIVACY_PURPOSE = "Send product newsletters to people who explicitly opted in, and measure engagement. "
  + "No credit decisions, identity verification or payments are performed with this dataset.";
export const RETENTION_STANDARD = "Kestrel Ridge records standard (fictional): inactive marketing leads are deleted after 24 months (730 days) "
  + "without activity; leads without valid marketing consent are deleted within 30 days of creation; "
  + "records under legal hold are never deleted until the hold is lifted.";
export const LEAD_FIELDS = ["lead_id", "full_name", "email", "phone", "date_of_birth", "national_id", "card_number", "city",
  "consent_marketing", "consent_date", "created_at", "last_activity", "legal_hold"];
const REQUIRED_KEEP = new Set(["lead_id", "email", "consent_marketing", "consent_date", "last_activity", "created_at", "legal_hold"]);
const REQUIRED_REMOVE = new Set(["national_id", "card_number", "date_of_birth"]);
const LAB_TODAY = new Date(Date.UTC(2026, 2, 9));
const isoDate = (d: Date) => d.toISOString().slice(0, 10);
const daysBetween = (a: Date, b: Date) => Math.round((a.getTime() - b.getTime()) / 86_400_000);
const parseDate = (s: string) => new Date(`${s}T00:00:00Z`);

export function privacyInitial(): Json {
  const rng = new Rng(99);
  const leads: Json[] = [];
  for (let i = 1; i <= 30; i++) {
    const [f, l] = syntheticName(rng);
    const created = addDays(LAB_TODAY, -rng.choice([10, 20, 45, 200, 400, 800, 900, 1200]));
    const last = addDays(created, rng.randint(0, Math.max(1, daysBetween(LAB_TODAY, created))));
    const consent = rng.random() > 0.25;
    leads.push({
      lead_id: `LD-${1000 + i}`, full_name: `${f} ${l}`, email: `${f.toLowerCase()}.${l.toLowerCase()}@example.org`,
      phone: `(312) 555-01${pad(rng.randint(0, 99), 2)}`, date_of_birth: `${rng.randint(1960, 2003)}-0${rng.randint(1, 9)}-1${rng.randint(0, 9)}`,
      national_id: `${pad(rng.randint(100, 665), 3)}-${rng.randint(10, 99)}-${rng.randint(1000, 9999)}`,
      card_number: "", city: rng.choice(["Austin", "Chicago", "Boston", "Denver"]),
      consent_marketing: consent, consent_date: consent ? isoDate(created) : null,
      created_at: isoDate(created), last_activity: isoDate(last), legal_hold: i === 4 || i === 17,
    });
  }
  for (const ld of leads.slice(0, 6)) {
    let n = "4";
    for (let j = 0; j < 15; j++) n += String(rng.randint(0, 9));
    ld.card_number = n;
  }
  return { leads, field_decisions: {}, retention: null, deleted: [], critical: null, evaluations: 0 };
}

export function privacyGradeMinimization(decisions: Record<string, Json>): Json {
  const unknown = Object.keys(decisions).filter((f) => !LEAD_FIELDS.includes(f));
  if (unknown.length) throw new DomainError(`Unknown fields: ${pyRepr(sorted(unknown))}`);
  if (Object.keys(decisions).length !== LEAD_FIELDS.length) throw new DomainError("Decide KEEP or REMOVE for every field");
  for (const [f, d] of Object.entries(decisions)) {
    if (!["KEEP", "REMOVE"].includes(d?.decision) || String(d?.reason ?? "").trim().length < 5) {
      throw new DomainError(`Field ${f}: decision must be KEEP or REMOVE with a reason (5+ characters)`);
    }
  }
  const removed = new Set(Object.entries(decisions).filter(([, d]) => d.decision === "REMOVE").map(([f]) => f));
  const missingRemovals = sorted([...REQUIRED_REMOVE].filter((f) => !removed.has(f)));
  const wronglyRemoved = sorted([...REQUIRED_KEEP].filter((f) => removed.has(f)));
  return { passed: !missingRemovals.length && !wronglyRemoved.length, missing_removals: missingRemovals, wrongly_removed: wronglyRemoved,
    note: "phone, full_name and city are judgement calls for this purpose; either decision is accepted with a reason." };
}

export function privacyEvaluate(state: Json, rule: Json): Json[] {
  const inactiveDays = Math.trunc(Number(rule.inactive_days));
  const noConsentDays = Math.trunc(Number(rule.no_consent_days));
  const out: Json[] = [];
  for (const ld of state.leads as Json[]) {
    const reasons: string[] = [];
    if (daysBetween(LAB_TODAY, parseDate(ld.last_activity)) > inactiveDays) reasons.push(`inactive > ${inactiveDays} days`);
    if (!ld.consent_marketing && daysBetween(LAB_TODAY, parseDate(ld.created_at)) > noConsentDays) reasons.push(`no consent after ${noConsentDays} days`);
    if (reasons.length) {
      const held = ld.legal_hold && rule.respect_legal_hold;
      out.push({ lead_id: ld.lead_id, reasons, legal_hold: ld.legal_hold, action: held ? "RETAIN (legal hold)" : "DELETE" });
    }
  }
  return out;
}

export function privacyExpectedDeletions(state: Json): Set<string> {
  const ideal = { inactive_days: 730, no_consent_days: 30, respect_legal_hold: true };
  return new Set(privacyEvaluate(state, ideal).filter((r) => r.action === "DELETE").map((r) => r.lead_id));
}

const pyBool = (v: unknown) => (v === true ? "True" : v === false ? "False" : String(v));

export function privacyReport(state: Json, minimization: Json | null): string {
  const lines = ["# Privacy controls findings report (SIMULATED lab)", "",
    "> Synthetic dataset. This report records platform exercise results and is not legal advice. "
    + "Confirm obligations with Legal / the Privacy Office.", "",
    `**Documented purpose:** ${PRIVACY_PURPOSE}`, "", `**Retention standard applied:** ${RETENTION_STANDARD}`, "",
    "## Data minimisation decisions", "", "| Field | Decision | Reason |", "|---|---|---|"];
  for (const f of LEAD_FIELDS) {
    const d = state.field_decisions?.[f] ?? {};
    lines.push(`| ${f} | ${d.decision ?? "-"} | ${String(d.reason ?? "-").replace(/\|/g, "/")} |`);
  }
  if (minimization) lines.push("", `Minimisation check: ${minimization.passed ? "PASSED" : "NOT PASSED"}.`);
  const r = state.retention ?? {};
  lines.push("", "## Retention and deletion", "",
    `Rule: inactive > ${r.inactive_days ?? "-"} days; no consent after ${r.no_consent_days ?? "-"} days; `
    + `legal hold respected: ${r.respect_legal_hold === undefined ? "-" : pyBool(r.respect_legal_hold)}.`,
    `Records deleted from the disposable dataset: ${state.deleted.length} (${state.deleted.join(", ") || "none"}).`,
    `Records remaining: ${state.leads.length}. Legal-hold records remaining: ${state.leads.filter((x: Json) => x.legal_hold).length}.`);
  if (state.critical) lines.push("", `**Critical issue:** ${state.critical}`);
  lines.push("", "## Open items for Legal / Privacy Office", "",
    "- Confirm the retention periods against applicable law for each jurisdiction where leads reside.",
    "- Confirm the lawful basis and consent wording for newsletter processing.",
    "- Decide whether historical copies in backups require separate deletion handling.");
  return lines.join("\n");
}

// =========================================================================== AI data security

export const AI_DESTINATIONS: Record<string, Json> = {
  "ai-unapproved": { id: "ai-unapproved", kind: "AI_SERVICE", category: "UNSANCTIONED", sanctioned: false, internal: false, domain: "chat.genie.example" },
  "ai-approved": { id: "ai-approved", kind: "AI_SERVICE", category: "INTERNAL", sanctioned: true, internal: true, domain: "ai.kestrelridge.example" },
};
export const AI_PROMPTS = [
  { id: "P1", actor_dept: "Customer Operations", destination: "ai-unapproved", should_block: true,
    text: "Summarise these complaints: KRC-10293847 avery.castellano@example.com card 4532015112830366 disputed fee" },
  { id: "P2", actor_dept: "IT", destination: "ai-unapproved", should_block: true,
    text: "Why does this config fail? CRM_CLIENT_SECRET=krsim-SYNTHETIC-9f8e7d6c5b4a3921" },
  { id: "P3", actor_dept: "Marketing", destination: "ai-unapproved", should_block: false,
    text: "Write three subject lines for a newsletter about our no-annual-fee card" },
  { id: "P4", actor_dept: "Customer Operations", destination: "ai-approved", should_block: false,
    text: "Draft a polite reply to customer KRC-55102938 about a statement copy request" },
  { id: "P5", actor_dept: "Finance", destination: "ai-approved", should_block: true,
    text: "Reconcile payroll: KR-E-100231 DE89370400440532013000 net 4210.55" },
  { id: "P6", actor_dept: "Legal", destination: "ai-unapproved", should_block: true,
    text: "STRICTLY CONFIDENTIAL draft settlement terms with PayBridge - rewrite more formally" },
  { id: "P7", actor_dept: "IT", destination: "ai-approved", should_block: false,
    text: "Explain the difference between TLS 1.2 and TLS 1.3 in plain language" },
  { id: "P8", actor_dept: "Customer Operations", destination: "ai-unapproved", should_block: false,
    text: "How do I politely decline a refund request? Give a generic template." },
];
export const AI_DEFAULT_POLICY = {
  name: "AI prompt gateway (initial)",
  description: "Initial rule: only payment cards to unapproved AI are monitored.",
  kind: "DLP", priority: 100, applies_to_actions: ["AI_PROMPT"],
  conditions: { match: "all", conditions: [
    { field: "destination.sanctioned", op: "eq", value: false },
    { field: "content.detected_types", op: "contains_any", value: ["CREDIT_CARD"] },
  ] },
  outcome: "MONITOR", severity: "MEDIUM", alert: true,
};

export const RAG_DOCS = [
  { id: "D1", title: "Support macro: card replacement", acl: ["grp-all-staff"], text: "card replacement verify identity two factors reissue" },
  { id: "D2", title: "HR salary bands 2026", acl: ["grp-hr"], text: "salary bands compensation pay grade support agent rita silva salary" },
  { id: "D3", title: "Escalation notes for premier customers", acl: ["grp-support-leads"], text: "premier customer escalation notes refund approval" },
  { id: "D4", title: "Refund policy", acl: ["grp-all-staff"], text: "refund policy fee dispute approval decline template" },
  { id: "D5", title: "Disciplinary case file (HR)", acl: ["grp-hr"], text: "disciplinary case rita silva warning performance" },
  { id: "D6", title: "Product FAQ", acl: ["grp-all-staff"], text: "no annual fee cashback groceries product card" },
];
export const RAG_ROLES: Record<string, string[]> = {
  support_agent: ["grp-all-staff", "grp-support-agents"], support_lead: ["grp-all-staff", "grp-support-leads"], hr_partner: ["grp-all-staff", "grp-hr"],
};
export const RAG_TESTS = [
  { id: "Q1", role: "support_agent", query: "what is rita silva salary", forbidden: ["D2", "D5"], expected_any: [] as string[] },
  { id: "Q2", role: "support_agent", query: "card replacement verify identity", forbidden: [] as string[], expected_any: ["D1"] },
  { id: "Q3", role: "support_agent", query: "premier customer escalation refund", forbidden: ["D3"], expected_any: ["D4"] },
  { id: "Q4", role: "hr_partner", query: "salary bands pay grade", forbidden: [] as string[], expected_any: ["D2"] },
];
export const AI_LOG_DEFAULT = { prompt_logging: "full", retention_days: 3650, log_access: "all_staff", vendor_training_opt_in: true };
export const AI_LOG_OPTIONS: Record<string, string[]> = {
  prompt_logging: ["full", "redacted", "metadata_only", "none"], log_access: ["all_staff", "it_admins", "security_only"],
};

export function aiInitial(): Json {
  return { gateway_policy: structuredClone(AI_DEFAULT_POLICY), rag: { enforce_acl: false, index_restricted_docs: true },
    logging: structuredClone(AI_LOG_DEFAULT) };
}

export function aiEvaluatePrompts(policyRaw: unknown): Json {
  const parsed = PolicyDefinitionSchema.safeParse(policyRaw);
  if (!parsed.success) {
    throw new DomainError(`Invalid gateway policy: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).slice(0, 8).join("; ")}`, 422);
  }
  const pol = parsed.data;
  if (pol.kind !== "DLP") throw new DomainError("Gateway policy must be a DLP policy");
  const ranks = { public: 0, internal: 1, confidential: 2, restricted: 3 };
  const results = AI_PROMPTS.map((p) => {
    const scan = scanText(p.text);
    const ctx = {
      action: { type: "AI_PROMPT" }, actor: { department: p.actor_dept },
      content: { detected_types: sorted(Object.keys(scan)), match_count: Object.values(scan).reduce((n, r) => n + r.match_count, 0),
        max_confidence: maxConfidence(scan) },
      destination: AI_DESTINATIONS[p.destination], _label_ranks: ranks,
    };
    const decision = decide([evaluatePolicy("AI-GATEWAY", 1, "ENABLED", pol, ctx)]);
    const blocked = decision.outcome === "BLOCK";
    return { id: p.id, text: p.text, destination: p.destination, detected_types: sorted(Object.keys(scan)), outcome: decision.outcome,
      should_block: p.should_block, correct: blocked === p.should_block };
  });
  return { results, passed: results.every((r) => r.correct), correct: results.filter((r) => r.correct).length, total: results.length,
    provenance: "SIMULATED" };
}

const tokens = (s: string) => new Set(s.toLowerCase().match(/[a-z0-9]+/g) ?? []);

export function ragRetrieve(cfg: Json, role: string, query: string, k = 2): Json[] {
  if (!Object.hasOwn(RAG_ROLES, role)) throw new DomainError("Unknown role");
  const groups = new Set(RAG_ROLES[role]);
  let docs = RAG_DOCS.filter((d) => cfg.index_restricted_docs || !d.acl.includes("grp-hr"));
  if (cfg.enforce_acl) docs = docs.filter((d) => d.acl.some((a) => groups.has(a)));
  const q = tokens(query);
  const scored = docs.map((d) => {
    const t = tokens(`${d.text} ${d.title}`);
    return { s: [...q].filter((x) => t.has(x)).length, d };
  }).sort((a, b) => b.s - a.s || (a.d.id < b.d.id ? -1 : 1));
  return scored.filter((x) => x.s > 0).slice(0, k).map(({ s, d }) => ({ id: d.id, title: d.title, score: s, acl: d.acl }));
}

export function ragRunTests(cfg: Json): Json {
  const out = RAG_TESTS.map((t) => {
    const got = ragRetrieve(cfg, t.role, t.query).map((d) => d.id as string);
    const leaked = sorted(got.filter((g) => t.forbidden.includes(g)));
    const missing = t.expected_any.length > 0 && !got.some((g) => t.expected_any.includes(g));
    return { ...t, retrieved: got, leaked, missing_expected: missing, passed: !leaked.length && !missing };
  });
  return { results: out, passed: out.every((r) => r.passed), provenance: "SIMULATED" };
}

export function aiLoggingFindings(cfg: Json): Json[] {
  for (const [k, opts] of Object.entries(AI_LOG_OPTIONS)) if (!opts.includes(cfg[k])) throw new DomainError(`Invalid value for ${k}`);
  const days = cfg.retention_days;
  if (!Number.isInteger(days) || days < 0) throw new DomainError("retention_days must be a non-negative integer");
  const f: Json[] = [];
  if (cfg.prompt_logging === "full") f.push({ id: "AI-01", finding: "Full prompts are logged, copying any sensitive data users paste.", fix: "Log redacted prompts or metadata only." });
  if (days > 90) f.push({ id: "AI-02", finding: `Prompt logs kept for ${days} days.`, fix: "Keep prompt logs 90 days or less unless a documented need exists." });
  if (cfg.log_access === "all_staff") f.push({ id: "AI-03", finding: "All staff can read prompt logs.", fix: "Restrict log access to Security." });
  if (cfg.vendor_training_opt_in) f.push({ id: "AI-04", finding: "Prompts are shared with the vendor for model training.", fix: "Opt out of vendor training." });
  return f;
}

