CREATE TABLE "access_grants" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"asset_key" varchar(60) NOT NULL,
	"principal_type" varchar(20) NOT NULL,
	"principal_key" varchar(60) NOT NULL,
	"permission" varchar(20) NOT NULL,
	"justification" text DEFAULT '' NOT NULL,
	"status" varchar(20) DEFAULT 'ACTIVE' NOT NULL,
	"review_decision" varchar(20),
	"review_note" text DEFAULT '' NOT NULL,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "account" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"provider_id" text NOT NULL,
	"user_id" text NOT NULL,
	"access_token" text,
	"refresh_token" text,
	"id_token" text,
	"access_token_expires_at" timestamp with time zone,
	"refresh_token_expires_at" timestamp with time zone,
	"scope" text,
	"password" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "alerts" (
	"id" serial PRIMARY KEY NOT NULL,
	"alert_id" varchar(40) NOT NULL,
	"session_id" integer NOT NULL,
	"run_number" integer DEFAULT 0 NOT NULL,
	"title" varchar(200) NOT NULL,
	"severity" varchar(20) NOT NULL,
	"status" varchar(20) DEFAULT 'NEW' NOT NULL,
	"disposition" varchar(30),
	"disposition_note" text DEFAULT '' NOT NULL,
	"policy_id" varchar(60) NOT NULL,
	"policy_version" integer NOT NULL,
	"triggering_event_id" varchar(40) NOT NULL,
	"event_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"actor_id" varchar(60),
	"resource_id" varchar(60),
	"explanation" text DEFAULT '' NOT NULL,
	"timestamp" timestamp with time zone NOT NULL,
	"step_key" varchar(60),
	CONSTRAINT "alerts_alert_id_unique" UNIQUE("alert_id")
);
--> statement-breakpoint
CREATE TABLE "assessment_attempts" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"user_id" text NOT NULL,
	"scenario_id" varchar(80) NOT NULL,
	"rubric_version" varchar(20) NOT NULL,
	"mode" varchar(20) NOT NULL,
	"total_score" double precision NOT NULL,
	"passed" boolean NOT NULL,
	"category_scores" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"criteria" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"critical_failures" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"missing_tasks" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"recommendations" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"inputs_digest" varchar(64) NOT NULL,
	"attempt_number" integer DEFAULT 1 NOT NULL,
	"variant" varchar(20) DEFAULT '' NOT NULL,
	"report_snapshot" text DEFAULT '' NOT NULL,
	"submitted_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_records" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" integer,
	"user_id" text,
	"action" varchar(80) NOT NULL,
	"target_type" varchar(60),
	"target_id" varchar(80),
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "case_notes" (
	"id" serial PRIMARY KEY NOT NULL,
	"case_id" integer NOT NULL,
	"kind" varchar(20) NOT NULL,
	"text" text NOT NULL,
	"evidence_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "change_records" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"policy_key" varchar(60) NOT NULL,
	"from_version" integer NOT NULL,
	"to_version" integer NOT NULL,
	"reason" text NOT NULL,
	"expected_impact" text DEFAULT '' NOT NULL,
	"rollback_plan" text DEFAULT '' NOT NULL,
	"test_run_id" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "classification_assignments" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"asset_key" varchar(60) NOT NULL,
	"label_key" varchar(40) NOT NULL,
	"previous_label_key" varchar(40),
	"owner_key" varchar(60),
	"justification" text NOT NULL,
	"handling_notes" text DEFAULT '' NOT NULL,
	"exception_note" text DEFAULT '' NOT NULL,
	"assigned_by" text NOT NULL,
	"sim_time" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "classification_findings" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"scan_id" integer NOT NULL,
	"asset_key" varchar(60) NOT NULL,
	"detector" varchar(40) NOT NULL,
	"match_count" integer NOT NULL,
	"confidence" varchar(10) NOT NULL,
	"evidence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"recommended_label" varchar(40),
	"rule_keys" jsonb DEFAULT '[]'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "classification_labels" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(40) NOT NULL,
	"name" varchar(80) NOT NULL,
	"rank" integer NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"handling" text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE TABLE "classification_rules" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"name" varchar(160) NOT NULL,
	"detectors" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"min_matches" integer DEFAULT 1 NOT NULL,
	"min_confidence" varchar(10) DEFAULT 'MEDIUM' NOT NULL,
	"recommended_label" varchar(40) NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"version" integer DEFAULT 1 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "data_assets" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"name" varchar(200) NOT NULL,
	"asset_type" varchar(40) NOT NULL,
	"data_structure" varchar(20) NOT NULL,
	"system" varchar(80) NOT NULL,
	"location" varchar(300) NOT NULL,
	"department" varchar(60) NOT NULL,
	"owner_key" varchar(60),
	"label_key" varchar(40),
	"record_count" integer DEFAULT 0 NOT NULL,
	"size_bytes" integer DEFAULT 0 NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"content_sample" text DEFAULT '' NOT NULL,
	"handling_notes" text DEFAULT '' NOT NULL,
	"exception_note" text DEFAULT '' NOT NULL,
	"quarantined" boolean DEFAULT false NOT NULL,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "destinations" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"name" varchar(160) NOT NULL,
	"kind" varchar(30) NOT NULL,
	"domain" varchar(160) DEFAULT '' NOT NULL,
	"category" varchar(30) NOT NULL,
	"sanctioned" boolean DEFAULT false NOT NULL,
	"internal" boolean DEFAULT false NOT NULL,
	"blocked" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "discovery_scans" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"scan_number" integer NOT NULL,
	"assets_scanned" integer DEFAULT 0 NOT NULL,
	"findings_count" integer DEFAULT 0 NOT NULL,
	"rule_snapshot" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"sim_time" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "evidence_references" (
	"id" serial PRIMARY KEY NOT NULL,
	"case_id" integer NOT NULL,
	"ref_type" varchar(30) NOT NULL,
	"ref_id" varchar(80) NOT NULL,
	"label" varchar(300) NOT NULL,
	"note" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "integration_configs" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" integer NOT NULL,
	"connector" varchar(60) NOT NULL,
	"enabled" boolean DEFAULT false NOT NULL,
	"settings" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "investigation_cases" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"title" varchar(200) NOT NULL,
	"status" varchar(20) DEFAULT 'OPEN' NOT NULL,
	"alert_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"hypothesis" text DEFAULT '' NOT NULL,
	"severity" varchar(20),
	"determination" varchar(40),
	"subject_identities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"affected_asset_keys" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"exposure_status" varchar(30),
	"records_potentially_exposed" integer,
	"root_causes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"root_cause_narrative" text DEFAULT '' NOT NULL,
	"residual_risk" text DEFAULT '' NOT NULL,
	"lessons_learned" text DEFAULT '' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "lab_exercise_results" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"lab" varchar(40) NOT NULL,
	"exercise" varchar(60) NOT NULL,
	"passed" boolean NOT NULL,
	"provenance" varchar(20) NOT NULL,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "lab_states" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"lab" varchar(40) NOT NULL,
	"state" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "learner_profiles" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"onboarding_step" varchar(20) DEFAULT 'ROLE' NOT NULL,
	"onboarding" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"desired_role" varchar(40),
	"career_level" integer DEFAULT 0 NOT NULL,
	"role_title" varchar(120),
	"joined_at" timestamp with time zone,
	"pending_promotion" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "learner_profiles_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE TABLE "mission_attempts" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"mission_id" varchar(20) NOT NULL,
	"attempt_number" integer DEFAULT 1 NOT NULL,
	"strategy" varchar(20) DEFAULT 'ASSIGNED' NOT NULL,
	"counts" boolean DEFAULT true NOT NULL,
	"status" varchar(20) DEFAULT 'IN_PROGRESS' NOT NULL,
	"session_id" integer,
	"understanding" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"explanation" text DEFAULT '' NOT NULL,
	"cited_evidence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"assessment_attempt_id" integer,
	"score" double precision,
	"outcome" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"submitted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" varchar(200) NOT NULL,
	"slug" varchar(100) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organizations_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "policies" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"kind" varchar(20) NOT NULL,
	"status" varchar(20) DEFAULT 'ENABLED' NOT NULL,
	"current_version" integer DEFAULT 1 NOT NULL,
	"baseline" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policy_evaluations" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"transaction_id" varchar(40) NOT NULL,
	"dry_run" boolean DEFAULT false NOT NULL,
	"context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"trace" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"final_outcome" varchar(20) NOT NULL,
	"decisive_policy" varchar(60),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policy_test_runs" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"run_number" integer NOT NULL,
	"policy_snapshot" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"results" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"metrics" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policy_versions" (
	"id" serial PRIMARY KEY NOT NULL,
	"policy_id" integer NOT NULL,
	"version" integer NOT NULL,
	"definition" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"change_note" text DEFAULT '' NOT NULL,
	"author" varchar(254) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "remediation_actions" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"case_id" integer,
	"seq" integer NOT NULL,
	"action_type" varchar(40) NOT NULL,
	"target_key" varchar(80) NOT NULL,
	"justification" text DEFAULT '' NOT NULL,
	"status" varchar(20) NOT NULL,
	"before_state" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"after_state" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"verification" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"provenance" varchar(20) DEFAULT 'SIMULATED' NOT NULL,
	"sim_time" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scenario_actions" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"seq" integer NOT NULL,
	"action_type" varchar(60) NOT NULL,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"provenance" varchar(20) DEFAULT 'SIMULATED' NOT NULL,
	"sim_time" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scenario_sessions" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"org_id" integer NOT NULL,
	"scenario_id" varchar(80) NOT NULL,
	"scenario_version" varchar(20) NOT NULL,
	"variant" varchar(20) NOT NULL,
	"mode" varchar(20) NOT NULL,
	"status" varchar(20) DEFAULT 'ACTIVE' NOT NULL,
	"attempt_number" integer DEFAULT 1 NOT NULL,
	"sim_clock" timestamp with time zone NOT NULL,
	"run_count" integer DEFAULT 0 NOT NULL,
	"event_seq" integer DEFAULT 0 NOT NULL,
	"hints_used" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"flags" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"event_id" varchar(40) NOT NULL,
	"session_id" integer NOT NULL,
	"organization_id" integer,
	"scenario_id" varchar(80) NOT NULL,
	"seq" integer NOT NULL,
	"run_number" integer DEFAULT 0 NOT NULL,
	"timestamp" timestamp with time zone NOT NULL,
	"actor_id" varchar(60),
	"resource_id" varchar(60),
	"action" varchar(40) NOT NULL,
	"result" varchar(30) NOT NULL,
	"data_classification" varchar(40),
	"source_type" varchar(30) NOT NULL,
	"source_system" varchar(80) NOT NULL,
	"provenance" varchar(20) NOT NULL,
	"policy_id" varchar(60),
	"policy_version" integer,
	"destination" varchar(60),
	"transaction_id" varchar(40),
	"related_event_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"extension" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"step_key" varchar(60),
	CONSTRAINT "security_events_event_id_unique" UNIQUE("event_id")
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" text PRIMARY KEY NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"token" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL,
	CONSTRAINT "session_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "sim_groups" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"name" varchar(120) NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"members" jsonb DEFAULT '[]'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sim_identities" (
	"id" serial PRIMARY KEY NOT NULL,
	"session_id" integer NOT NULL,
	"key" varchar(60) NOT NULL,
	"display_name" varchar(120) NOT NULL,
	"email" varchar(160) NOT NULL,
	"department" varchar(60) NOT NULL,
	"title" varchar(120) NOT NULL,
	"enterprise_role" varchar(60) NOT NULL,
	"employment_type" varchar(30) NOT NULL,
	"manager_key" varchar(60),
	"status" varchar(20) DEFAULT 'ACTIVE' NOT NULL,
	"sessions_revoked_at" timestamp with time zone,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "skill_records" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"skill_key" varchar(40) NOT NULL,
	"proficiency" integer NOT NULL,
	"mission_id" varchar(20) NOT NULL,
	"mission_attempt_id" integer NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"recorded_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "two_factor" (
	"id" text PRIMARY KEY NOT NULL,
	"secret" text NOT NULL,
	"backup_codes" text NOT NULL,
	"user_id" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"email" text NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"two_factor_enabled" boolean DEFAULT false,
	"role" varchar(20) DEFAULT 'learner' NOT NULL,
	"org_id" integer,
	"is_active" boolean DEFAULT true NOT NULL,
	CONSTRAINT "user_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "verification" (
	"id" text PRIMARY KEY NOT NULL,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "access_grants" ADD CONSTRAINT "access_grants_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_attempts" ADD CONSTRAINT "assessment_attempts_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assessment_attempts" ADD CONSTRAINT "assessment_attempts_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_records" ADD CONSTRAINT "audit_records_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "case_notes" ADD CONSTRAINT "case_notes_case_id_investigation_cases_id_fk" FOREIGN KEY ("case_id") REFERENCES "public"."investigation_cases"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "change_records" ADD CONSTRAINT "change_records_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "change_records" ADD CONSTRAINT "change_records_test_run_id_policy_test_runs_id_fk" FOREIGN KEY ("test_run_id") REFERENCES "public"."policy_test_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "classification_assignments" ADD CONSTRAINT "classification_assignments_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "classification_findings" ADD CONSTRAINT "classification_findings_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "classification_findings" ADD CONSTRAINT "classification_findings_scan_id_discovery_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."discovery_scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "classification_labels" ADD CONSTRAINT "classification_labels_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "classification_rules" ADD CONSTRAINT "classification_rules_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "data_assets" ADD CONSTRAINT "data_assets_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "destinations" ADD CONSTRAINT "destinations_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "discovery_scans" ADD CONSTRAINT "discovery_scans_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_references" ADD CONSTRAINT "evidence_references_case_id_investigation_cases_id_fk" FOREIGN KEY ("case_id") REFERENCES "public"."investigation_cases"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_configs" ADD CONSTRAINT "integration_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lab_exercise_results" ADD CONSTRAINT "lab_exercise_results_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "lab_states" ADD CONSTRAINT "lab_states_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "learner_profiles" ADD CONSTRAINT "learner_profiles_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mission_attempts" ADD CONSTRAINT "mission_attempts_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mission_attempts" ADD CONSTRAINT "mission_attempts_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mission_attempts" ADD CONSTRAINT "mission_attempts_assessment_attempt_id_assessment_attempts_id_fk" FOREIGN KEY ("assessment_attempt_id") REFERENCES "public"."assessment_attempts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_evaluations" ADD CONSTRAINT "policy_evaluations_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_test_runs" ADD CONSTRAINT "policy_test_runs_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_policy_id_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "remediation_actions" ADD CONSTRAINT "remediation_actions_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "remediation_actions" ADD CONSTRAINT "remediation_actions_case_id_investigation_cases_id_fk" FOREIGN KEY ("case_id") REFERENCES "public"."investigation_cases"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scenario_actions" ADD CONSTRAINT "scenario_actions_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scenario_sessions" ADD CONSTRAINT "scenario_sessions_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scenario_sessions" ADD CONSTRAINT "scenario_sessions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sim_groups" ADD CONSTRAINT "sim_groups_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sim_identities" ADD CONSTRAINT "sim_identities_session_id_scenario_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."scenario_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "skill_records" ADD CONSTRAINT "skill_records_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "skill_records" ADD CONSTRAINT "skill_records_mission_attempt_id_mission_attempts_id_fk" FOREIGN KEY ("mission_attempt_id") REFERENCES "public"."mission_attempts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "two_factor" ADD CONSTRAINT "two_factor_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user" ADD CONSTRAINT "user_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "access_grants_session_idx" ON "access_grants" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "account_user_idx" ON "account" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "alerts_session_idx" ON "alerts" USING btree ("session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "classification_labels_session_key" ON "classification_labels" USING btree ("session_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "classification_rules_session_key" ON "classification_rules" USING btree ("session_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "data_assets_session_key" ON "data_assets" USING btree ("session_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "destinations_session_key" ON "destinations" USING btree ("session_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "evidence_case_ref" ON "evidence_references" USING btree ("case_id","ref_type","ref_id");--> statement-breakpoint
CREATE UNIQUE INDEX "integration_org_connector" ON "integration_configs" USING btree ("org_id","connector");--> statement-breakpoint
CREATE INDEX "lab_results_user_idx" ON "lab_exercise_results" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "lab_states_user_lab" ON "lab_states" USING btree ("user_id","lab");--> statement-breakpoint
CREATE INDEX "mission_attempts_user_idx" ON "mission_attempts" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "policies_session_key" ON "policies" USING btree ("session_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "policy_versions_policy_version" ON "policy_versions" USING btree ("policy_id","version");--> statement-breakpoint
CREATE INDEX "scenario_actions_session_idx" ON "scenario_actions" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "scenario_sessions_user_idx" ON "scenario_sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "security_events_session_idx" ON "security_events" USING btree ("session_id","run_number");--> statement-breakpoint
CREATE INDEX "session_user_idx" ON "session" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "sim_groups_session_key" ON "sim_groups" USING btree ("session_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "sim_identities_session_key" ON "sim_identities" USING btree ("session_id","key");--> statement-breakpoint
CREATE INDEX "skill_records_user_idx" ON "skill_records" USING btree ("user_id");