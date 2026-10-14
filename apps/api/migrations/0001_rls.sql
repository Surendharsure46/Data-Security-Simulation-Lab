-- Row-level security backstop (architecture decision L7).
-- API requests run each transaction as the NOLOGIN role threatready_app with app.user_id / app.org_id / app.staff
-- set per transaction (see src/db/request-context.ts). The table owner (migrations, background worker) is not
-- subject to these policies. Application guards remain the primary authorization layer; these policies make a
-- missed WHERE clause return nothing instead of another user's rows.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'threatready_app') THEN
    CREATE ROLE threatready_app NOLOGIN;
  END IF;
END $$;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public TO threatready_app;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO threatready_app;
--> statement-breakpoint
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO threatready_app;
--> statement-breakpoint
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO threatready_app;
--> statement-breakpoint
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO threatready_app;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app_user_id() RETURNS text LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.user_id', true), '') $$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app_org_id() RETURNS integer LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.org_id', true), '')::integer $$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app_is_staff() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT coalesce(current_setting('app.staff', true) = 'true', false) $$;
--> statement-breakpoint
-- Own rows, or (staff only) rows of users in the same organisation.
CREATE OR REPLACE FUNCTION app_can_see_user(uid text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
$$ SELECT uid = app_user_id() OR (app_is_staff() AND EXISTS (SELECT 1 FROM "user" u WHERE u.id = uid AND u.org_id = app_org_id())) $$;
--> statement-breakpoint
ALTER TABLE scenario_sessions ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY scenario_sessions_access ON scenario_sessions USING (app_can_see_user(user_id)) WITH CHECK (user_id = app_user_id());
--> statement-breakpoint
DO $$
DECLARE t text;
BEGIN
  -- Tables owned by a scenario session: visible when the session is visible, writable only in the caller's own sessions.
  FOREACH t IN ARRAY ARRAY['scenario_actions', 'sim_identities', 'sim_groups', 'data_assets', 'access_grants', 'destinations',
    'classification_labels', 'classification_rules', 'discovery_scans', 'classification_findings', 'classification_assignments',
    'policies', 'policy_evaluations', 'policy_test_runs', 'change_records', 'security_events', 'alerts', 'investigation_cases',
    'remediation_actions']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON %I USING (session_id IN (SELECT id FROM scenario_sessions)) '
                   'WITH CHECK (session_id IN (SELECT id FROM scenario_sessions WHERE user_id = app_user_id()))', t || '_access', t);
  END LOOP;
  -- Tables owned by a user.
  FOREACH t IN ARRAY ARRAY['assessment_attempts', 'lab_exercise_results', 'lab_states', 'learner_profiles', 'mission_attempts', 'skill_records']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON %I USING (app_can_see_user(user_id)) WITH CHECK (user_id = app_user_id())', t || '_access', t);
  END LOOP;
END $$;
--> statement-breakpoint
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY policy_versions_access ON policy_versions USING (policy_id IN (SELECT id FROM policies)) WITH CHECK (policy_id IN (SELECT id FROM policies));
--> statement-breakpoint
ALTER TABLE case_notes ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY case_notes_access ON case_notes USING (case_id IN (SELECT id FROM investigation_cases)) WITH CHECK (case_id IN (SELECT id FROM investigation_cases));
--> statement-breakpoint
ALTER TABLE evidence_references ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY evidence_references_access ON evidence_references USING (case_id IN (SELECT id FROM investigation_cases)) WITH CHECK (case_id IN (SELECT id FROM investigation_cases));
