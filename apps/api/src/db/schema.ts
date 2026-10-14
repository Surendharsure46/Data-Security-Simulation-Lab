/**
 * Drizzle schema (PostgreSQL).
 *
 * Identity tables (user, session, account, verification, twoFactor) follow Better Auth's model; the users and
 * password hashes live in our database. Domain tables keep snake_case property names so API responses match the
 * documented field names exactly. Simulation tables are scoped to a scenario session: every session receives its
 * own copy of the synthetic enterprise. Row-level security policies (migration 0001_rls.sql) are a backstop on
 * every user-owned and session-owned table.
 */
import { sql } from "drizzle-orm";
import {
  boolean, doublePrecision, index, integer, jsonb, pgTable, serial, text, timestamp, uniqueIndex, varchar,
} from "drizzle-orm/pg-core";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });
const created = () => ts("created_at").notNull().defaultNow();
const json = <T = Json>(name: string, dflt: unknown = {}) => jsonb(name).$type<T>().notNull().default(sql.raw(`'${JSON.stringify(dflt)}'::jsonb`));

// --------------------------------------------------------------------------- platform

export const organizations = pgTable("organizations", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 200 }).notNull(),
  slug: varchar("slug", { length: 100 }).notNull().unique(),
  created_at: created(),
});

// Better Auth core tables (field names are Better Auth's; extra fields are declared as additionalFields).
export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
  twoFactorEnabled: boolean("two_factor_enabled").default(false),
  role: varchar("role", { length: 20 }).notNull().default("learner"), // learner | instructor | admin
  org_id: integer("org_id").references(() => organizations.id),
  is_active: boolean("is_active").notNull().default(true),
});

export const session = pgTable("session", {
  id: text("id").primaryKey(),
  expiresAt: ts("expires_at").notNull(),
  token: text("token").notNull().unique(),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
}, (t) => [index("session_user_idx").on(t.userId)]);

export const account = pgTable("account", {
  id: text("id").primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: ts("access_token_expires_at"),
  refreshTokenExpiresAt: ts("refresh_token_expires_at"),
  scope: text("scope"),
  password: text("password"),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
}, (t) => [index("account_user_idx").on(t.userId)]);

export const verification = pgTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: ts("expires_at").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

export const twoFactor = pgTable("two_factor", {
  id: text("id").primaryKey(),
  secret: text("secret").notNull(),
  backupCodes: text("backup_codes").notNull(),
  userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  verified: boolean("verified").default(true),
  failedVerificationCount: integer("failed_verification_count").default(0),
  lockedUntil: ts("locked_until"),
}, (t) => [index("two_factor_user_idx").on(t.userId), index("two_factor_secret_idx").on(t.secret)]);

export const audit_records = pgTable("audit_records", {
  id: serial("id").primaryKey(),
  org_id: integer("org_id").references(() => organizations.id),
  user_id: text("user_id"),
  action: varchar("action", { length: 80 }).notNull(),
  target_type: varchar("target_type", { length: 60 }),
  target_id: varchar("target_id", { length: 80 }),
  detail: json("detail"),
  created_at: created(),
});

export const integration_configs = pgTable("integration_configs", {
  id: serial("id").primaryKey(),
  org_id: integer("org_id").notNull().references(() => organizations.id),
  connector: varchar("connector", { length: 60 }).notNull(),
  enabled: boolean("enabled").notNull().default(false),
  settings: json("settings"), // never holds secrets
  updated_at: ts("updated_at").notNull().defaultNow(),
}, (t) => [uniqueIndex("integration_org_connector").on(t.org_id, t.connector)]);

// --------------------------------------------------------------------------- scenario sessions

export const scenario_sessions = pgTable("scenario_sessions", {
  id: serial("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  org_id: integer("org_id").notNull().references(() => organizations.id),
  scenario_id: varchar("scenario_id", { length: 80 }).notNull(),
  scenario_version: varchar("scenario_version", { length: 20 }).notNull(),
  variant: varchar("variant", { length: 20 }).notNull(),
  mode: varchar("mode", { length: 20 }).notNull(), // GUIDED | ASSESSMENT
  status: varchar("status", { length: 20 }).notNull().default("ACTIVE"), // ACTIVE | PAUSED | SUBMITTED
  attempt_number: integer("attempt_number").notNull().default(1),
  sim_clock: ts("sim_clock").notNull(),
  run_count: integer("run_count").notNull().default(0),
  event_seq: integer("event_seq").notNull().default(0),
  hints_used: json("hints_used"),
  flags: json("flags"),
  created_at: created(),
  updated_at: ts("updated_at").notNull().defaultNow(),
}, (t) => [index("scenario_sessions_user_idx").on(t.user_id)]);

const sid = () => integer("session_id").notNull().references(() => scenario_sessions.id, { onDelete: "cascade" });

export const scenario_actions = pgTable("scenario_actions", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  seq: integer("seq").notNull(),
  action_type: varchar("action_type", { length: 60 }).notNull(),
  params: json("params"),
  result: json("result"),
  provenance: varchar("provenance", { length: 20 }).notNull().default("SIMULATED"),
  sim_time: ts("sim_time").notNull(),
  created_at: created(),
}, (t) => [index("scenario_actions_session_idx").on(t.session_id)]);

export const sim_identities = pgTable("sim_identities", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  display_name: varchar("display_name", { length: 120 }).notNull(),
  email: varchar("email", { length: 160 }).notNull(),
  department: varchar("department", { length: 60 }).notNull(),
  title: varchar("title", { length: 120 }).notNull(),
  enterprise_role: varchar("enterprise_role", { length: 60 }).notNull(),
  employment_type: varchar("employment_type", { length: 30 }).notNull(),
  manager_key: varchar("manager_key", { length: 60 }),
  status: varchar("status", { length: 20 }).notNull().default("ACTIVE"),
  sessions_revoked_at: ts("sessions_revoked_at"),
  attributes: json("attributes"),
}, (t) => [uniqueIndex("sim_identities_session_key").on(t.session_id, t.key)]);

export const sim_groups = pgTable("sim_groups", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  name: varchar("name", { length: 120 }).notNull(),
  description: text("description").notNull().default(""),
  members: json<string[]>("members", []),
}, (t) => [uniqueIndex("sim_groups_session_key").on(t.session_id, t.key)]);

export const data_assets = pgTable("data_assets", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  name: varchar("name", { length: 200 }).notNull(),
  asset_type: varchar("asset_type", { length: 40 }).notNull(),
  data_structure: varchar("data_structure", { length: 20 }).notNull(),
  system: varchar("system", { length: 80 }).notNull(),
  location: varchar("location", { length: 300 }).notNull(),
  department: varchar("department", { length: 60 }).notNull(),
  owner_key: varchar("owner_key", { length: 60 }),
  label_key: varchar("label_key", { length: 40 }),
  record_count: integer("record_count").notNull().default(0),
  size_bytes: integer("size_bytes").notNull().default(0),
  description: text("description").notNull().default(""),
  content_sample: text("content_sample").notNull().default(""),
  handling_notes: text("handling_notes").notNull().default(""),
  exception_note: text("exception_note").notNull().default(""),
  quarantined: boolean("quarantined").notNull().default(false),
  attributes: json("attributes"),
}, (t) => [uniqueIndex("data_assets_session_key").on(t.session_id, t.key)]);

export const access_grants = pgTable("access_grants", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  asset_key: varchar("asset_key", { length: 60 }).notNull(),
  principal_type: varchar("principal_type", { length: 20 }).notNull(),
  principal_key: varchar("principal_key", { length: 60 }).notNull(),
  permission: varchar("permission", { length: 20 }).notNull(),
  justification: text("justification").notNull().default(""),
  status: varchar("status", { length: 20 }).notNull().default("ACTIVE"),
  review_decision: varchar("review_decision", { length: 20 }),
  review_note: text("review_note").notNull().default(""),
  revoked_at: ts("revoked_at"),
}, (t) => [index("access_grants_session_idx").on(t.session_id)]);

export const destinations = pgTable("destinations", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  name: varchar("name", { length: 160 }).notNull(),
  kind: varchar("kind", { length: 30 }).notNull(),
  domain: varchar("domain", { length: 160 }).notNull().default(""),
  category: varchar("category", { length: 30 }).notNull(),
  sanctioned: boolean("sanctioned").notNull().default(false),
  internal: boolean("internal").notNull().default(false),
  blocked: boolean("blocked").notNull().default(false),
}, (t) => [uniqueIndex("destinations_session_key").on(t.session_id, t.key)]);

export const classification_labels = pgTable("classification_labels", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 40 }).notNull(),
  name: varchar("name", { length: 80 }).notNull(),
  rank: integer("rank").notNull(),
  description: text("description").notNull().default(""),
  handling: text("handling").notNull().default(""),
}, (t) => [uniqueIndex("classification_labels_session_key").on(t.session_id, t.key)]);

export const classification_rules = pgTable("classification_rules", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  name: varchar("name", { length: 160 }).notNull(),
  detectors: json<string[]>("detectors", []),
  min_matches: integer("min_matches").notNull().default(1),
  min_confidence: varchar("min_confidence", { length: 10 }).notNull().default("MEDIUM"),
  recommended_label: varchar("recommended_label", { length: 40 }).notNull(),
  enabled: boolean("enabled").notNull().default(true),
  version: integer("version").notNull().default(1),
}, (t) => [uniqueIndex("classification_rules_session_key").on(t.session_id, t.key)]);

export const discovery_scans = pgTable("discovery_scans", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  scan_number: integer("scan_number").notNull(),
  assets_scanned: integer("assets_scanned").notNull().default(0),
  findings_count: integer("findings_count").notNull().default(0),
  rule_snapshot: json<Json[]>("rule_snapshot", []),
  sim_time: ts("sim_time").notNull(),
  created_at: created(),
});

export const classification_findings = pgTable("classification_findings", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  scan_id: integer("scan_id").notNull().references(() => discovery_scans.id, { onDelete: "cascade" }),
  asset_key: varchar("asset_key", { length: 60 }).notNull(),
  detector: varchar("detector", { length: 40 }).notNull(),
  match_count: integer("match_count").notNull(),
  confidence: varchar("confidence", { length: 10 }).notNull(),
  evidence: json<Json[]>("evidence", []),
  recommended_label: varchar("recommended_label", { length: 40 }),
  rule_keys: json<string[]>("rule_keys", []),
});

export const classification_assignments = pgTable("classification_assignments", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  asset_key: varchar("asset_key", { length: 60 }).notNull(),
  label_key: varchar("label_key", { length: 40 }).notNull(),
  previous_label_key: varchar("previous_label_key", { length: 40 }),
  owner_key: varchar("owner_key", { length: 60 }),
  justification: text("justification").notNull(),
  handling_notes: text("handling_notes").notNull().default(""),
  exception_note: text("exception_note").notNull().default(""),
  assigned_by: text("assigned_by").notNull(),
  sim_time: ts("sim_time").notNull(),
  created_at: created(),
});

// --------------------------------------------------------------------------- policies

export const policies = pgTable("policies", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  key: varchar("key", { length: 60 }).notNull(),
  kind: varchar("kind", { length: 20 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("ENABLED"),
  current_version: integer("current_version").notNull().default(1),
  baseline: boolean("baseline").notNull().default(false),
  created_at: created(),
}, (t) => [uniqueIndex("policies_session_key").on(t.session_id, t.key)]);

export const policy_versions = pgTable("policy_versions", {
  id: serial("id").primaryKey(),
  policy_id: integer("policy_id").notNull().references(() => policies.id, { onDelete: "cascade" }),
  version: integer("version").notNull(),
  definition: json("definition"),
  change_note: text("change_note").notNull().default(""),
  author: varchar("author", { length: 254 }).notNull(),
  created_at: created(),
}, (t) => [uniqueIndex("policy_versions_policy_version").on(t.policy_id, t.version)]);

export const policy_evaluations = pgTable("policy_evaluations", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  transaction_id: varchar("transaction_id", { length: 40 }).notNull(),
  dry_run: boolean("dry_run").notNull().default(false),
  context: json("context"),
  trace: json<Json[]>("trace", []),
  final_outcome: varchar("final_outcome", { length: 20 }).notNull(),
  decisive_policy: varchar("decisive_policy", { length: 60 }),
  created_at: created(),
});

export const policy_test_runs = pgTable("policy_test_runs", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  run_number: integer("run_number").notNull(),
  policy_snapshot: json("policy_snapshot"),
  results: json<Json[]>("results", []),
  metrics: json("metrics"),
  created_at: created(),
});

export const change_records = pgTable("change_records", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  policy_key: varchar("policy_key", { length: 60 }).notNull(),
  from_version: integer("from_version").notNull(),
  to_version: integer("to_version").notNull(),
  reason: text("reason").notNull(),
  expected_impact: text("expected_impact").notNull().default(""),
  rollback_plan: text("rollback_plan").notNull().default(""),
  test_run_id: integer("test_run_id").references(() => policy_test_runs.id),
  created_at: created(),
});

// --------------------------------------------------------------------------- events and investigation

export const security_events = pgTable("security_events", {
  id: serial("id").primaryKey(),
  event_id: varchar("event_id", { length: 40 }).notNull().unique(),
  session_id: sid(),
  organization_id: integer("organization_id"),
  scenario_id: varchar("scenario_id", { length: 80 }).notNull(),
  seq: integer("seq").notNull(),
  run_number: integer("run_number").notNull().default(0),
  timestamp: ts("timestamp").notNull(),
  actor_id: varchar("actor_id", { length: 60 }),
  resource_id: varchar("resource_id", { length: 60 }),
  action: varchar("action", { length: 40 }).notNull(),
  result: varchar("result", { length: 30 }).notNull(),
  data_classification: varchar("data_classification", { length: 40 }),
  source_type: varchar("source_type", { length: 30 }).notNull(),
  source_system: varchar("source_system", { length: 80 }).notNull(),
  provenance: varchar("provenance", { length: 20 }).notNull(),
  policy_id: varchar("policy_id", { length: 60 }),
  policy_version: integer("policy_version"),
  destination: varchar("destination", { length: 60 }),
  transaction_id: varchar("transaction_id", { length: 40 }),
  related_event_ids: json<string[]>("related_event_ids", []),
  evidence_refs: json<string[]>("evidence_refs", []),
  summary: text("summary").notNull().default(""),
  extension: json("extension"),
  step_key: varchar("step_key", { length: 60 }), // internal; never serialized
}, (t) => [index("security_events_session_idx").on(t.session_id, t.run_number)]);

export const alerts = pgTable("alerts", {
  id: serial("id").primaryKey(),
  alert_id: varchar("alert_id", { length: 40 }).notNull().unique(),
  session_id: sid(),
  run_number: integer("run_number").notNull().default(0),
  title: varchar("title", { length: 200 }).notNull(),
  severity: varchar("severity", { length: 20 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("NEW"),
  disposition: varchar("disposition", { length: 30 }),
  disposition_note: text("disposition_note").notNull().default(""),
  policy_id: varchar("policy_id", { length: 60 }).notNull(),
  policy_version: integer("policy_version").notNull(),
  triggering_event_id: varchar("triggering_event_id", { length: 40 }).notNull(),
  event_ids: json<string[]>("event_ids", []),
  actor_id: varchar("actor_id", { length: 60 }),
  resource_id: varchar("resource_id", { length: 60 }),
  explanation: text("explanation").notNull().default(""),
  timestamp: ts("timestamp").notNull(),
  step_key: varchar("step_key", { length: 60 }), // internal; never serialized
}, (t) => [index("alerts_session_idx").on(t.session_id)]);

export const investigation_cases = pgTable("investigation_cases", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  title: varchar("title", { length: 200 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("OPEN"),
  alert_ids: json<string[]>("alert_ids", []),
  hypothesis: text("hypothesis").notNull().default(""),
  severity: varchar("severity", { length: 20 }),
  determination: varchar("determination", { length: 40 }),
  subject_identities: json<string[]>("subject_identities", []),
  affected_asset_keys: json<string[]>("affected_asset_keys", []),
  exposure_status: varchar("exposure_status", { length: 30 }),
  records_potentially_exposed: integer("records_potentially_exposed"),
  root_causes: json<string[]>("root_causes", []),
  summary: text("summary").notNull().default(""),
  root_cause_narrative: text("root_cause_narrative").notNull().default(""),
  residual_risk: text("residual_risk").notNull().default(""),
  lessons_learned: text("lessons_learned").notNull().default(""),
  created_at: created(),
  updated_at: ts("updated_at").notNull().defaultNow(),
});

export const case_notes = pgTable("case_notes", {
  id: serial("id").primaryKey(),
  case_id: integer("case_id").notNull().references(() => investigation_cases.id, { onDelete: "cascade" }),
  kind: varchar("kind", { length: 20 }).notNull(),
  text: text("text").notNull(),
  evidence_ids: json<number[]>("evidence_ids", []),
  created_at: created(),
});

export const evidence_references = pgTable("evidence_references", {
  id: serial("id").primaryKey(),
  case_id: integer("case_id").notNull().references(() => investigation_cases.id, { onDelete: "cascade" }),
  ref_type: varchar("ref_type", { length: 30 }).notNull(),
  ref_id: varchar("ref_id", { length: 80 }).notNull(),
  label: varchar("label", { length: 300 }).notNull(),
  note: text("note").notNull().default(""),
  created_at: created(),
}, (t) => [uniqueIndex("evidence_case_ref").on(t.case_id, t.ref_type, t.ref_id)]);

export const remediation_actions = pgTable("remediation_actions", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  case_id: integer("case_id").references(() => investigation_cases.id, { onDelete: "set null" }),
  seq: integer("seq").notNull(),
  action_type: varchar("action_type", { length: 40 }).notNull(),
  target_key: varchar("target_key", { length: 80 }).notNull(),
  justification: text("justification").notNull().default(""),
  status: varchar("status", { length: 20 }).notNull(),
  before_state: json("before_state"),
  after_state: json("after_state"),
  verification: json("verification"),
  provenance: varchar("provenance", { length: 20 }).notNull().default("SIMULATED"),
  sim_time: ts("sim_time").notNull(),
  created_at: created(),
});

// --------------------------------------------------------------------------- assessment, labs, journey

export const assessment_attempts = pgTable("assessment_attempts", {
  id: serial("id").primaryKey(),
  session_id: sid(),
  user_id: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  scenario_id: varchar("scenario_id", { length: 80 }).notNull(),
  rubric_version: varchar("rubric_version", { length: 20 }).notNull(),
  mode: varchar("mode", { length: 20 }).notNull(),
  total_score: doublePrecision("total_score").notNull(),
  passed: boolean("passed").notNull(),
  category_scores: json("category_scores"),
  criteria: json<Json[]>("criteria", []),
  critical_failures: json<Json[]>("critical_failures", []),
  missing_tasks: json<string[]>("missing_tasks", []),
  recommendations: json<Json[]>("recommendations", []),
  inputs_digest: varchar("inputs_digest", { length: 64 }).notNull(),
  attempt_number: integer("attempt_number").notNull().default(1),
  variant: varchar("variant", { length: 20 }).notNull().default(""),
  report_snapshot: text("report_snapshot").notNull().default(""),
  submitted_at: ts("submitted_at").notNull().defaultNow(),
});

export const lab_exercise_results = pgTable("lab_exercise_results", {
  id: serial("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  lab: varchar("lab", { length: 40 }).notNull(),
  exercise: varchar("exercise", { length: 60 }).notNull(),
  passed: boolean("passed").notNull(),
  provenance: varchar("provenance", { length: 20 }).notNull(),
  detail: json("detail"),
  created_at: created(),
}, (t) => [index("lab_results_user_idx").on(t.user_id)]);

export const lab_states = pgTable("lab_states", {
  id: serial("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  lab: varchar("lab", { length: 40 }).notNull(),
  state: json("state"),
  updated_at: ts("updated_at").notNull().defaultNow(),
}, (t) => [uniqueIndex("lab_states_user_lab").on(t.user_id, t.lab)]);

export const learner_profiles = pgTable("learner_profiles", {
  id: serial("id").primaryKey(),
  user_id: text("user_id").notNull().unique().references(() => user.id, { onDelete: "cascade" }),
  onboarding_step: varchar("onboarding_step", { length: 20 }).notNull().default("ROLE"), // ROLE | DONE
  onboarding: json("onboarding"), // fundamentals read, demo-lab progress
  desired_role: varchar("desired_role", { length: 40 }),
  career_level: integer("career_level").notNull().default(0), // highest unlocked level 0..5
  role_title: varchar("role_title", { length: 120 }),
  joined_at: ts("joined_at"),
  pending_promotion: integer("pending_promotion"), // unlocked level (6 = journey complete) awaiting the popup
  created_at: created(),
  updated_at: ts("updated_at").notNull().defaultNow(),
});

export const mission_attempts = pgTable("mission_attempts", {
  id: serial("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  mission_id: varchar("mission_id", { length: 20 }).notNull(),
  attempt_number: integer("attempt_number").notNull().default(1),
  strategy: varchar("strategy", { length: 20 }).notNull().default("ASSIGNED"),
  counts: boolean("counts").notNull().default(true),
  status: varchar("status", { length: 20 }).notNull().default("IN_PROGRESS"),
  session_id: integer("session_id").references(() => scenario_sessions.id, { onDelete: "set null" }),
  understanding: json("understanding"),
  explanation: text("explanation").notNull().default(""),
  cited_evidence: json<Json[]>("cited_evidence", []),
  assessment_attempt_id: integer("assessment_attempt_id").references(() => assessment_attempts.id),
  score: doublePrecision("score"),
  outcome: json("outcome"),
  started_at: ts("started_at").notNull().defaultNow(),
  submitted_at: ts("submitted_at"),
}, (t) => [index("mission_attempts_user_idx").on(t.user_id)]);

export const skill_records = pgTable("skill_records", {
  id: serial("id").primaryKey(),
  user_id: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
  skill_key: varchar("skill_key", { length: 40 }).notNull(),
  proficiency: integer("proficiency").notNull(),
  mission_id: varchar("mission_id", { length: 20 }).notNull(),
  mission_attempt_id: integer("mission_attempt_id").notNull().references(() => mission_attempts.id, { onDelete: "cascade" }),
  evidence: json("evidence"),
  recorded_at: ts("recorded_at").notNull().defaultNow(),
}, (t) => [index("skill_records_user_idx").on(t.user_id)]);

export type Tables = typeof schema;
export const schema = {
  organizations, user, session, account, verification, twoFactor, audit_records, integration_configs,
  scenario_sessions, scenario_actions, sim_identities, sim_groups, data_assets, access_grants, destinations,
  classification_labels, classification_rules, discovery_scans, classification_findings, classification_assignments,
  policies, policy_versions, policy_evaluations, policy_test_runs, change_records, security_events, alerts,
  investigation_cases, case_notes, evidence_references, remediation_actions, assessment_attempts, lab_exercise_results,
  lab_states, learner_profiles, mission_attempts, skill_records,
};
