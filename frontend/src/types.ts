export interface User {
  id: number;
  username: string;
  display_name: string;
  role: "learner" | "instructor" | "admin";
  org_id: number;
}

export interface Task {
  key: string;
  stage: string;
  title: string;
  description: string;
  done: boolean;
  hints_available: number;
  hints_revealed: number;
}

export interface SessionSummary {
  id: number;
  scenario_id: string;
  scenario_title: string;
  mode: "GUIDED" | "ASSESSMENT";
  status: "ACTIVE" | "PAUSED" | "SUBMITTED";
  attempt_number: number;
  sim_clock: string;
  run_count: number;
  updated_at: string;
  user_id: number;
}

export interface SessionDetail extends SessionSummary {
  progress: Task[];
  progress_percent: number;
  scenario: ScenarioPublic;
  runs: { run_number: number; mode: string; sim_day: string }[];
  counts: Record<string, number>;
  hints_enabled: boolean;
  hints_used: Record<string, number[]>;
  latest_attempt: Attempt | null;
}

export interface ScenarioPublic {
  id: string;
  version: string;
  title: string;
  summary: string;
  briefing: string;
  level: string;
  difficulty: string;
  modules: string[];
  estimated_minutes: number;
  objectives: string[];
  variant_count: number;
  tasks: { key: string; stage: string; title: string; description: string }[];
  remediation_catalog: RemediationType[];
  rubric: {
    pass_threshold: number;
    categories: Record<string, { name: string; weight: number }>;
    criteria: { key: string; category: string; points: number; description: string }[];
    critical_conditions: { key: string; description: string }[];
  };
}

export interface RemediationType {
  type: string;
  category: string;
  target_type: "IDENTITY" | "DESTINATION" | "ASSET" | "GRANT" | "PARTY";
  title: string;
  description: string;
  destructive: boolean;
}

export interface Asset {
  key: string;
  name: string;
  asset_type: string;
  data_structure: string;
  system: string;
  location: string;
  department: string;
  owner_key: string | null;
  label_key: string | null;
  record_count: number;
  size_bytes: number;
  quarantined: boolean;
  detectors?: string[];
  recommended_label?: string | null;
  scanned?: boolean;
}

export interface Identity {
  key: string;
  display_name: string;
  email: string;
  department: string;
  title: string;
  enterprise_role: string;
  employment_type: string;
  status: string;
  groups: string[];
  attributes: Record<string, unknown>;
}

export interface Label {
  key: string;
  name: string;
  rank: number;
  description: string;
  handling: string;
}

export interface Destination {
  key: string;
  name: string;
  kind: string;
  domain: string;
  category: string;
  sanctioned: boolean;
  internal: boolean;
  blocked: boolean;
}

export interface SecEvent {
  event_id: string;
  timestamp: string;
  run_number: number;
  actor_id: string | null;
  resource_id: string | null;
  action: string;
  result: string;
  data_classification: string | null;
  source_type: string;
  source_system: string;
  provenance: string;
  policy_id: string | null;
  policy_version: number | null;
  destination: string | null;
  transaction_id: string | null;
  related_event_ids: string[];
  evidence_refs: string[];
  summary: string;
  extension: Record<string, any>;
}

export interface Alert {
  alert_id: string;
  run_number: number;
  title: string;
  severity: string;
  status: string;
  disposition: string | null;
  disposition_note: string;
  policy_id: string;
  policy_version: number;
  triggering_event_id: string;
  event_ids: string[];
  actor_id: string | null;
  resource_id: string | null;
  explanation: string;
  timestamp: string;
}

export interface Attempt {
  id: number;
  session_id: number;
  attempt_number: number;
  mode: string;
  total_score: number;
  passed: boolean;
  category_scores: Record<string, { name: string; weight: number; percent: number; weighted: number }>;
  criteria: { key: string; category: string; description: string; points: number; earned: number; explanation: string; lessons: string[] }[];
  critical_failures: { key: string; description: string; detail: string }[];
  missing_tasks: string[];
  recommendations: { lesson_id: string; because: string[] }[];
  inputs_digest: string;
  submitted_at: string;
  label: string;
  disclaimer: string;
}

export interface Policy {
  key: string;
  kind: "DLP" | "DETECTION";
  status: "ENABLED" | "DISABLED";
  baseline: boolean;
  current_version: number;
  definition: PolicyDefinition;
  versions: { version: number; author: string; change_note: string; created_at: string }[];
  version_definitions?: Record<string, PolicyDefinition>;
}

export interface Condition {
  field: string;
  op: string;
  value?: unknown;
}

export interface ConditionGroup {
  match: "all" | "any";
  conditions: (Condition | ConditionGroup)[];
}

export interface PolicyException {
  id: string;
  description: string;
  when: ConditionGroup;
  outcome: "ALLOW" | "MONITOR";
  keep_alert?: boolean;
}

export interface PolicyDefinition {
  name: string;
  description: string;
  kind: "DLP" | "DETECTION";
  priority: number;
  applies_to_actions: string[];
  conditions: ConditionGroup;
  outcome: "ALLOW" | "MONITOR" | "WARN" | "BLOCK";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  alert: boolean;
  escalate: boolean;
  alert_title: string;
  exceptions: PolicyException[];
  test_cases: unknown[];
}

export interface TraceEntry {
  policy_key: string;
  policy_version: number;
  name: string;
  kind: string;
  status: string;
  priority: number;
  configured_outcome: string;
  severity: string;
  matched: boolean;
  exception: { id: string; description: string } | null;
  effective_outcome: string | null;
  alert: boolean;
  skipped_reason?: string;
  condition_trace?: TraceNode;
  explanation: string;
}

export interface TraceNode {
  group?: "all" | "any";
  result: boolean;
  children?: TraceNode[];
  field?: string;
  op?: string;
  value?: unknown;
  actual?: unknown;
  missing?: boolean;
  error?: string;
}

export interface Decision {
  outcome: string;
  decisive_policy: string | null;
  decisive_version: number | null;
  reason: string;
}

export function isGroup(c: Condition | ConditionGroup): c is ConditionGroup {
  return (c as ConditionGroup).conditions !== undefined;
}
