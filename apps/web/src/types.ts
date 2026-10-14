export interface User {
  id: string;
  email: string;
  display_name: string;
  role: "learner" | "instructor" | "admin";
  org_id: number;
  mfa_enabled: boolean;
}

export interface Task {
  key: string;
  stage: string;
  phase?: string;
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
  user_id: string;
  mission?: { attempt_id: number; mission_id: string; status: string } | null;
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

// ----------------------------------------------------------------------------- learning journey (roles, levels 0-5, labs)

export type PhaseKey = "UNDERSTAND" | "INSPECT" | "ACT" | "OBSERVE" | "VALIDATE" | "SUBMIT";

export interface Role {
  key: string;
  title: string;
  icon: string;
  summary: string;
  focus: string[];
}

export interface CareerProfile {
  onboarding_complete: boolean;
  desired_role: string | null;
  role: Role | null;
  career_level: number;
  role_title: string | null;
  joined_at: string | null;
  pending_promotion: number | null;
  level: { level: number; title: string; summary: string } | null;
  top_level: number;
}

export interface PublicContent {
  welcome: {
    title: string; tagline: string; intro: string;
    sections: { title: string; points: string[] }[];
    motivation: { title: string; text: string }[];
  };
  platform: { title: string; summary: string; loop: { title: string; text: string }[]; safety: string[] };
  roles: Role[];
  phases: { key: PhaseKey; title: string; summary: string }[];
  levels: { level: number; title: string; summary: string; icon: string; labs: number; lessons: number }[];
}

export interface MissionQuestion {
  q: string;
  options: string[];
}

export interface DemoContent {
  title: string; intro: string; record_name: string; record: string;
  labels: { key: string; name: string; rank: number; description: string }[];
  destinations: { key: string; name: string; category: string }[];
}

export interface MissionPublic {
  id: string;
  kind: "SCENARIO" | "LAB" | "DEMO";
  level: number;
  level_title: string;
  title: string;
  assigned_by: string;
  business_problem: { statement: string; stakes: string[]; success_looks_like: string[]; questions: MissionQuestion[] };
  required: { key: string; label: string; requirement: string }[];
  min_score: number;
  min_explanation: number;
  scenario_id?: string;
  scenario_title?: string;
  briefing?: string;
  mode?: "GUIDED" | "ASSESSMENT";
  estimated_minutes?: number;
  hints?: boolean;
  lab?: string;
  route?: string;
  exercises?: { exercise: string; phase: PhaseKey; title: string; steps: string[] }[];
  demo?: DemoContent;
}

export interface PhaseItem {
  key: string;
  kind: "check" | "task" | "lab_exercise" | "demo_step" | "submission";
  title: string;
  description: string;
  done: boolean;
  route?: string;
  steps?: string[];
  hints_available?: number;
}

export interface MissionPhase {
  key: PhaseKey;
  title: string;
  summary: string;
  items: PhaseItem[];
  done: boolean | null;
  note: string | null;
}

export interface SkillScore {
  skill: string;
  name: string;
  proficiency: number;
  criteria?: string[];
  because?: string[];
}

export interface RemedialLesson {
  id: string;
  title: string;
  module: string;
  body: string;
  practice: string;
  has_quiz: boolean;
}

export interface NextInfo {
  more_missions?: boolean;
  next_mission?: { id: string; title: string };
  level_completed?: number;
  level_unlocked?: number;
  new_title?: string;
  journey_complete?: boolean;
  practice_only?: boolean;
}

export interface MissionOutcome {
  kind: "SCENARIO" | "LAB" | "DEMO";
  score: number;
  min_score: number;
  score_ok: boolean;
  passed: boolean;
  critical_failures: { key: string; description: string; detail: string }[];
  required: { key: string; label: string; requirement: string; met: boolean; actual: string; explanation: string }[];
  skills: SkillScore[];
  skill_gaps: SkillScore[];
  remedial_lessons: RemedialLesson[];
  skills_recorded?: { skill: string; name: string; proficiency: number }[];
  next?: NextInfo;
  category_scores?: Record<string, { name: string; weight: number; percent: number; weighted: number }>;
  criteria?: Attempt["criteria"];
  missing_tasks?: string[];
  mode_label?: string;
  assessment_attempt_id?: number;
}

export interface MissionAttempt {
  id: number;
  mission: MissionPublic;
  attempt_number: number;
  strategy: "ASSIGNED" | "PRACTICE" | "NEW_VARIANT";
  counts: boolean;
  status: "IN_PROGRESS" | "PASSED" | "NOT_PASSED" | "PRACTICE_PASSED" | "ABANDONED";
  started_at: string;
  submitted_at: string | null;
  understanding: { passed: boolean; score: number | null; correct: boolean[] | null; carried_over_from: number | null };
  phases: MissionPhase[];
  readiness: { understanding_passed: boolean; work_done: number; work_total: number; session_status: string | null };
  explanation: string;
  cited_evidence: Record<string, unknown>[];
  score: number | null;
  outcome: MissionOutcome | null;
  retry_options: ("PRACTICE" | "NEW_VARIANT")[];
  session: { id: number; mode: string; status: string; attempt_number: number; run_count: number } | null;
  observations: { runs: { run_number: number; mode: string; sim_day: string; events: number; prevented_events: number; alerts: number }[] } | null;
  evidence_options: { case_id: number | null; case_title: string | null; items: { id: number; ref_type: string; ref_id: string; label: string }[] } | null;
  practice_note?: string;
}

export interface LevelStep {
  type: "learn" | "check" | "mission";
  key: string;
  title: string;
  done: boolean;
  status: "DONE" | "CURRENT" | "OPEN" | "LOCKED";  // OPEN = available, but not the recommended next step
  kind?: "SCENARIO" | "LAB" | "DEMO";
  lab?: string | null;
  mode?: string | null;
  latest_attempt?: { id: number; status: string; score: number | null } | null;
}

export interface FundamentalItem {
  type: "lesson" | "briefing" | "text";
  key: string;
  title: string;
  body?: string;
  module?: string;
  practice?: string;
  organization?: {
    company: { name: string; industry: string; employees: number; description: string };
    mission_statement: string;
    crown_jewels: { name: string; where: string; why: string }[];
    departments: { name: string; note: string }[];
    team: { name: string; role: string; note: string }[];
    current_concerns: string[];
    disclaimer: string;
  };
}

export interface LevelDetail {
  level: number;
  title: string;
  summary: string;
  icon: string;
  before_you_start: string[];
  responsibilities: string[];
  challenge: string;
  rank_title: string;
  status: "COMPLETED" | "CURRENT" | "LOCKED";
  unlocked: boolean;
  fundamentals: FundamentalItem[];
  steps: LevelStep[];
  progress: { done: number; total: number };
  next_step: LevelStep | null;
  check: { passed: boolean; pass_mark: number; questions: MissionQuestion[] };
}

export interface LevelSummary {
  level: number;
  title: string;
  summary: string;
  icon: string;
  status: "COMPLETED" | "CURRENT" | "LOCKED";
  unlocked: boolean;
  progress: { done: number; total: number };
  rank_title: string;
  next_step: LevelStep | null;
  labs: number;
}

export interface Promotion {
  journey_complete: boolean;
  level: number | null;
  completed_level: number;
  completed_title?: string;
  title: string;
  new_title: string | null;
  summary: string;
  responsibilities: string[];
  challenge: string;
  missions: { id: string; title: string; kind: string }[];
}

export interface Journey {
  profile: CareerProfile;
  levels: LevelSummary[];
  current_level: LevelSummary;
  next_step: (LevelStep & { level: number; active_attempt_id: number | null }) | null;
  overall_progress: { done: number; total: number };
  journey_complete: boolean;
  skills: { skill: string; name: string; description: string; proficiency: number | null; mission_id: string | null; recorded_at: string | null }[];
  recent_outcomes: { attempt_id: number; mission_id: string; title: string; level: number; status: string; score: number | null; submitted_at: string }[];
  pending_promotion: Promotion | null;
  organization: { name: string; team: { name: string; role: string; note: string }[] };
}
