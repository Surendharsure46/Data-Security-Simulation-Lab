/** Reusable learner journeys driven only through the public API. */
import { expect } from "vitest";
import { type Agent, api } from "./helpers.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export const GOOD_LABELS: Record<string, [string, string | null]> = {
  "ast-cust-export-q1": ["restricted", "u-hpatel"],
  "ast-crm-customers": ["restricted", null],
  "ast-support-tickets": ["confidential", null],
  "ast-employee-directory": ["internal", null],
  "ast-cust-sample-masked": ["internal", null],
  "ast-qa-test-cards": ["internal", null],
  "ast-api-config": ["restricted", "u-tbrandt"],
  "ast-vendor-contract": ["confidential", null],
  "ast-cloud-customers-2025": ["restricted", "u-hpatel"],
};

export const BLOCK_POLICY = {
  name: "Block sensitive customer data to personal or unsanctioned destinations",
  description: "Blocks transfers of Confidential+ data, or content with regulated identifiers, to unsanctioned destinations.",
  kind: "DLP",
  priority: 10,
  applies_to_actions: ["UPLOAD", "EMAIL", "COPY_TO_USB", "AI_PROMPT", "PRINT"],
  conditions: { match: "all", conditions: [
    { field: "destination.sanctioned", op: "eq", value: false },
    { match: "any", conditions: [
      { field: "content.label", op: "label_at_least", value: "confidential" },
      { field: "content.detected_types", op: "contains_any", value: ["CREDIT_CARD", "US_SSN", "IBAN", "SECRET_CREDENTIAL"] },
    ] },
  ] },
  outcome: "BLOCK",
  severity: "HIGH",
  alert: true,
  alert_title: "Blocked sensitive transfer to unsanctioned destination",
};

export async function prepareAndRunBaseline(h: Agent, sid: number): Promise<Json> {
  const base = `/api/sessions/${sid}`;
  await api(h, "POST", `${base}/discovery/scan`);
  await api(h, "GET", `${base}/assets/ast-cust-export-q1`);
  for (const [key, [label, owner]] of Object.entries(GOOD_LABELS)) {
    const body: Json = { asset_key: key, label_key: label, justification: `Classified as ${label} based on scan evidence and context` };
    if (owner) body.owner_key = owner;
    await api(h, "POST", `${base}/classification/assign`, body);
  }
  return api(h, "POST", `${base}/timeline/run`, { mode: "standard" });
}

export async function goodInvestigation(h: Agent, sid: number, culprit = "u-jokafor", ambiguous = "u-rsilva", exfilAction = "UPLOAD"): Promise<number> {
  const base = `/api/sessions/${sid}`;
  const alerts: Json[] = await api(h, "GET", `${base}/alerts?run=1`);
  const culpritAlerts = alerts.filter((a) => a.actor_id === culprit);
  for (const a of alerts) {
    const disposition = a.actor_id === culprit ? "TRUE_POSITIVE" : a.actor_id === ambiguous ? "UNDETERMINED" : "BENIGN_POSITIVE";
    await api(h, "POST", `${base}/alerts/${a.alert_id}/disposition`, { disposition, note: "Assessed against linked evidence" });
  }
  const cs = await api(h, "POST", `${base}/cases`, { title: "Customer export leaves company", alert_ids: culpritAlerts.map((a) => a.alert_id) });
  const cid = cs.id as number;
  const events: Json[] = await api(h, "GET", `${base}/events?actor=${culprit}&run=1&resource=ast-cust-export-q1`);
  const download = events.find((e) => e.action === "DOWNLOAD")!;
  const transfer = events.find((e) => ["PROXY", "EMAIL_GATEWAY"].includes(e.source_type) && e.action === exfilAction)!;
  expect(download && transfer, "download and transfer events exist").toBeTruthy();
  const ev1 = await api(h, "POST", `${base}/cases/${cid}/evidence`, { ref_type: "EVENT", ref_id: download.event_id });
  await api(h, "POST", `${base}/cases/${cid}/evidence`, { ref_type: "EVENT", ref_id: transfer.event_id });
  await api(h, "POST", `${base}/cases/${cid}/evidence`, { ref_type: "GRANT", ref_id: "g-02" });
  await api(h, "POST", `${base}/cases/${cid}/notes`, { kind: "OBSERVATION", text: "Bulk download of 48,210 records followed by an allowed transfer", evidence_ids: [ev1.id] });
  await api(h, "POST", `${base}/cases/${cid}/notes`, { kind: "INFERENCE", text: "The export left the company through a personal channel" });
  await api(h, "POST", `${base}/cases/${cid}/notes`, { kind: "UNKNOWN", text: "Whether the external copy was further shared is unknown" });
  const risk = await api(h, "POST", `${base}/risk-score`, { label: "restricted", records: 48210, destination_external: true, data_left_org: "YES" });
  await api(h, "PATCH", `${base}/cases/${cid}`, {
    severity: risk.severity, determination: "CONFIRMED_DATA_EXFILTRATION", subject_identities: [culprit], affected_asset_keys: ["ast-cust-export-q1"],
    exposure_status: "CONFIRMED_EXFILTRATION", records_potentially_exposed: 48210,
    root_causes: ["EXCESSIVE_PERMISSION", "MISSING_CLASSIFICATION", "MONITOR_ONLY_POLICY"],
  });
  return cid;
}

export async function goodRemediation(h: Agent, sid: number, cid: number, culprit = "u-jokafor"): Promise<void> {
  const base = `/api/sessions/${sid}`;
  for (const [action, target] of [["PRESERVE_EVIDENCE", culprit], ["DISABLE_ACCOUNT", culprit], ["ESCALATE", "PRIVACY_OFFICE"]]) {
    const r = await api(h, "POST", `${base}/remediation`, { action_type: action, target_key: target, case_id: cid, justification: "Containment per incident procedure" });
    expect(["VERIFIED", "RECORDED"]).toContain(r.status);
  }
  await api(h, "POST", `${base}/access/g-02/review`, { decision: "REVOKE", note: "Agents do not need bulk extracts" });
  await api(h, "POST", `${base}/policies`, { key: "POL-DLP-CUSTOMER", definition: BLOCK_POLICY, change_note: "Close exfiltration path" });
  const email = (await api(h, "GET", `${base}/policies/POL-DLP-EMAIL`)).definition;
  email.exceptions = [{ id: "EX-PAYROLL", description: "Payroll submissions to the contracted payroll provider",
    when: { match: "all", conditions: [
      { field: "destination.id", op: "eq", value: "dst-paybridge-email" },
      { field: "actor.department", op: "eq", value: "Finance" }] } }];
  await api(h, "PUT", `${base}/policies/POL-DLP-EMAIL`, { definition: email, change_note: "Tune payroll false positive" });
  await api(h, "POST", `${base}/policies/test`, { actor: culprit, action: "UPLOAD", resource: "ast-cust-export-q1", destination: "dst-personal-cloud" });
  await api(h, "POST", `${base}/policies/test`, { actor: "u-emorales", action: "UPLOAD", resource: "ast-product-brochure", destination: "dst-personal-cloud" });
  await api(h, "POST", `${base}/timeline/run`, { mode: "validation" });
  await api(h, "PATCH", `${base}/cases/${cid}`, {
    summary: "A support identity downloaded the full customer export and transferred it to a personal destination.",
    root_cause_narrative: "Support agents inherited read access to nightly exports; the export was unlabeled and DLP was monitor-only.",
    residual_risk: "The external copy cannot be recalled; other inherited folder permissions remain unreviewed.",
    lessons_learned: "Review export locations, label bulk extracts at creation and pilot DLP to enforcement with tuning.",
  });
}
