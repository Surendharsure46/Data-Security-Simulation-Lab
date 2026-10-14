/**
 * @threatready/contracts — request schemas shared by the API (validation and OpenAPI generation)
 * and the web app (types). Responses are documented in OpenAPI as objects; their exact shapes
 * follow the API serializers.
 */
import { z } from "zod";

export * from "./policy.js";
import { PolicyDefinitionSchema } from "./policy.js";

const str = (max: number, min = 0) => z.string().min(min).max(max);

// --------------------------------------------------------------------------- auth

export const PASSWORD_RULE = "At least 10 characters with upper- and lower-case letters and a digit.";

export const RegisterIn = z.object({
  email: z.email().max(254).transform((v) => v.toLowerCase()),
  display_name: str(80, 1),
  password: str(128, 10).refine((v) => v.toLowerCase() !== v && v.toUpperCase() !== v && /\d/.test(v), {
    message: "Password needs upper- and lower-case letters and a digit",
  }),
});
export const LoginIn = z.object({ email: str(254, 1).transform((v) => v.toLowerCase()), password: str(128, 1) });

// --------------------------------------------------------------------------- sessions

export const StartSessionIn = z.object({
  scenario_id: z.string(),
  mode: z.enum(["GUIDED", "ASSESSMENT"]).default("GUIDED"),
  variant: str(10).nullable().optional(),
});
export const ResetIn = z.object({ new_variant: z.boolean().default(true), confirm: z.boolean().default(false) });
export const ConfirmIn = z.object({ confirm: z.boolean().default(false) });
export const RunIn = z.object({ mode: z.enum(["standard", "validation"]).default("standard") });
export const ActivityIn = z.object({
  actor: str(60),
  action: z.enum(["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT", "SIGN_IN"]),
  resource: str(60).nullable().optional(),
  destination: str(60).nullable().optional(),
  record_count: z.number().int().min(0).max(10_000_000).nullable().optional(),
  business_justification: str(300).nullable().optional(),
  ticket_id: str(40).nullable().optional(),
});
export const ReportQuery = z.object({
  format: z.enum(["md", "html", "json", "csv"]).default("md"),
  download: z.enum(["true", "false"]).optional(),
});

// --------------------------------------------------------------------------- environment, discovery, classification

export const AssetsQuery = z.object({
  q: str(100).optional(),
  label: z.string().optional(),
  department: z.string().optional(),
  unlabeled: z.enum(["true", "false"]).optional(),
  no_owner: z.enum(["true", "false"]).optional(),
});
export const ReviewIn = z.object({ decision: z.enum(["KEEP", "REVOKE"]), note: str(1000, 5) });
export const RuleIn = z.object({
  enabled: z.boolean(),
  min_matches: z.number().int().min(1).max(10_000),
  min_confidence: z.enum(["LOW", "MEDIUM", "HIGH"]),
  recommended_label: str(40),
  detectors: z.array(z.string()).min(1).max(10),
});
export const AssignIn = z.object({
  asset_key: str(60),
  label_key: str(40),
  justification: str(2000, 10),
  owner_key: str(60).nullable().optional(),
  handling_notes: str(2000).default(""),
  exception_note: str(2000).default(""),
});

// --------------------------------------------------------------------------- policies and engineering

export const PolicyIn = z.object({ key: str(44), definition: z.record(z.string(), z.unknown()), change_note: str(500).default("") });
export const PolicyUpdateIn = z.object({ definition: z.record(z.string(), z.unknown()), change_note: str(500, 3) });
export const PolicyStatusIn = z.object({ status: z.string() });
export const RollbackIn = z.object({ to_version: z.number().int().min(1) });
export const PolicyTestIn = z.object({
  actor: str(60),
  action: str(20),
  resource: str(60),
  destination: str(60).nullable().optional(),
  record_count: z.number().int().min(0).max(10_000_000).nullable().optional(),
  hour: z.number().int().min(0).max(23).default(12),
  context: z.record(z.string(), z.unknown()).default({}),
  draft: z.object({ key: z.string().optional(), definition: z.record(z.string(), z.unknown()) }).nullable().optional(),
});
export const ChangeRecordIn = z.object({
  policy_key: z.string(),
  from_version: z.number().int(),
  to_version: z.number().int(),
  reason: str(2000, 10),
  expected_impact: str(2000).default(""),
  rollback_plan: str(2000).default(""),
  test_run_id: z.number().int().nullable().optional(),
});

// --------------------------------------------------------------------------- investigation

export const DISPOSITIONS = ["TRUE_POSITIVE", "BENIGN_POSITIVE", "FALSE_POSITIVE", "UNDETERMINED"] as const;
export const EVIDENCE_TYPES = ["EVENT", "ALERT", "ASSET", "IDENTITY", "GRANT", "POLICY_VERSION", "FINDING"] as const;
export const NOTE_KINDS = ["OBSERVATION", "INFERENCE", "UNKNOWN", "HYPOTHESIS"] as const;

export const EventsQuery = z.object({
  q: str(100).optional(),
  actor: z.string().optional(),
  resource: z.string().optional(),
  source_type: z.string().optional(),
  result: z.string().optional(),
  run: z.coerce.number().int().optional(),
  transaction: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(2000).default(500),
});
export const AlertsQuery = z.object({
  status: z.string().optional(),
  run: z.coerce.number().int().optional(),
  undispositioned: z.enum(["true", "false"]).optional(),
});
export const DispositionIn = z.object({ disposition: z.enum(DISPOSITIONS), note: str(2000, 10) });
export const CaseIn = z.object({ title: str(200, 3), alert_ids: z.array(z.string()).max(50).default([]), hypothesis: str(2000).default("") });
export const CasePatch = z.object({
  title: str(200, 3).optional(),
  status: z.enum(["OPEN", "CONTAINED", "CLOSED"]).optional(),
  hypothesis: str(4000).optional(),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).nullable().optional(),
  determination: z.string().nullable().optional(),
  subject_identities: z.array(z.string()).max(20).optional(),
  affected_asset_keys: z.array(z.string()).max(50).optional(),
  exposure_status: z.string().nullable().optional(),
  records_potentially_exposed: z.number().int().min(0).max(100_000_000).nullable().optional(),
  root_causes: z.array(z.string()).max(10).optional(),
  alert_ids: z.array(z.string()).max(50).optional(),
  summary: str(8000).optional(),
  root_cause_narrative: str(8000).optional(),
  residual_risk: str(8000).optional(),
  lessons_learned: str(8000).optional(),
});
export const NoteIn = z.object({ kind: z.enum(NOTE_KINDS), text: str(4000, 5), evidence_ids: z.array(z.number().int()).max(20).default([]) });
export const EvidenceIn = z.object({ ref_type: z.enum(EVIDENCE_TYPES), ref_id: str(80, 1), note: str(1000).default("") });
export const RemediationIn = z.object({
  action_type: str(40),
  target_key: str(80),
  justification: str(2000, 10),
  case_id: z.number().int().nullable().optional(),
  confirm_destructive: z.boolean().default(false),
});
export const RiskIn = z.object({
  label: z.string().nullable().optional(),
  records: z.number().int().min(0).max(100_000_000),
  destination_external: z.boolean(),
  data_left_org: z.enum(["YES", "NO", "UNKNOWN"]),
});

// --------------------------------------------------------------------------- curriculum and learning journey

export const PathwayIn = z.object({ pathway: z.string() });
export const AnswersIn = z.object({ answers: z.array(z.number().int()).max(20) });
export const RoleChoiceIn = z.object({ role: str(40) });
export const DemoScanIn = z.object({ text: str(5000).nullable().optional() });
export const DemoClassifyIn = z.object({ label: str(40) });
export const DemoTransferIn = z.object({ destination: str(60) });
export const MissionSubmitIn = z.object({ explanation: str(6000), cited_evidence: z.array(z.number().int()).max(50).default([]) });
export const RetryIn = z.object({ strategy: z.enum(["PRACTICE", "NEW_VARIANT"]) });

// --------------------------------------------------------------------------- labs

export const HashIn = z.object({ file: str(60) });
export const AnswerFileIn = z.object({ modified_file: str(60) });
export const PassIn = z.object({ passphrase: str(200, 1) });
export const HmacIn = z.object({ message: str(2000), key_label: str(40).default("lab-key") });
export const EnvDecIn = z.object({ kek_id: str(20).nullable().optional() });
export const TlsIn = z.object({ visible: z.array(z.string()).max(20) });
export const EncConfigIn = z.object({
  tls_min_version: z.string(),
  cipher_suites: z.array(z.string()).max(10),
  verify_server_certificate: z.boolean(),
  at_rest_algorithm: z.string(),
  key_location: z.string(),
  key_rotation_days: z.number().int().min(0).max(3650),
  backup_encryption: z.boolean(),
  secret_storage: z.string(),
});
export const QueryIn = z.object({ role: str(30), sql: str(2000, 1) });
export const GrantIn = z.object({ role: str(30), table: str(40) });
export const LookupIn = z.object({ mode: z.enum(["vulnerable", "parameterized"]), email: str(200) });
export const MaskIn = z.object({ column: str(30), enabled: z.boolean() });
export const IdentifyIn = z.object({ audit_id: z.number().int() });
export const BackupIn = z.object({ backup_id: str(60) });
export const BucketAnswerIn = z.object({ bucket: str(60) });
export const CloudChangeIn = z.object({
  bucket: str(60),
  field: z.enum(["access", "encryption", "access_logging", "remove_principal"]),
  value: z.unknown(),
});
export const MinimizationIn = z.object({
  decisions: z.record(z.string(), z.object({ decision: z.enum(["KEEP", "REMOVE"]), reason: str(500) })),
});
export const RetentionIn = z.object({
  inactive_days: z.number().int().min(1).max(10000),
  no_consent_days: z.number().int().min(1).max(10000),
  respect_legal_hold: z.boolean(),
});
export const GatewayIn = z.object({ policy: z.record(z.string(), z.unknown()) });
export const RagCfgIn = z.object({ enforce_acl: z.boolean(), index_restricted_docs: z.boolean() });
export const RagQueryIn = z.object({ role: str(30), query: str(300, 1) });
export const AiLogIn = z.object({
  prompt_logging: z.string(),
  retention_days: z.number().int().min(0).max(36500),
  log_access: z.string(),
  vendor_training_opt_in: z.boolean(),
});

// --------------------------------------------------------------------------- admin

export const IntegrationToggleIn = z.object({ enabled: z.boolean() });
export const UserUpdateIn = z.object({ role: z.enum(["learner", "instructor", "admin"]).nullable().optional(), is_active: z.boolean().nullable().optional() });

export { PolicyDefinitionSchema as PolicyDefinitionIn };
export type RegisterBody = z.input<typeof RegisterIn>;
export type LoginBody = z.input<typeof LoginIn>;
