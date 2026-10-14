/**
 * Report generation. Every report is derived from persisted session state; nothing is invented.
 *
 * Reports are built as a neutral structure (title + sections) and rendered to Markdown, HTML (fully escaped), JSON or
 * CSV (tabular reports only).
 */
import { and, asc, desc, eq, inArray, isNotNull } from "drizzle-orm";
import { DomainError, iso } from "../common/util.js";
import { uow } from "../db/context.js";
import {
  access_grants, alerts, assessment_attempts, case_notes, classification_assignments, classification_findings, data_assets,
  evidence_references, policy_evaluations, policy_test_runs, remediation_actions, security_events, user,
} from "../db/schema.js";
import { primaryCase, type CaseRow, type RemediationRow } from "./investigation.js";
import { definitionFor, type EventRow, type SessionRow } from "./simulation.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Body = { kind: "text"; content: string } | { kind: "list"; items: string[] } | { kind: "table"; columns: string[]; rows: unknown[][] };
interface Section { heading: string; body: Body }
export interface Report extends Json { title: string; report_type: string; sections: Section[] }

export const REPORT_TYPES: Record<string, string> = {
  inventory: "Data inventory",
  "classification-register": "Classification register",
  "policy-tests": "Policy test report",
  "incident-timeline": "Incident timeline",
  "case-report": "Investigation case report",
  "remediation-verification": "Remediation verification report",
  assessment: "Competency assessment report",
};
const TABULAR = new Set(["inventory", "classification-register", "policy-tests", "incident-timeline", "remediation-verification"]);
const MODE_STATEMENT = "Execution mode: SIMULATED. All data, identities and events are synthetic and were produced by "
  + "the Threatready simulation engine; no real system was affected.";

const now = () => iso(new Date())!;
const table = (columns: string[], rows: unknown[][]): Body => ({ kind: "table", columns, rows: rows.map((r) => r.map((v) => (v === null || v === undefined ? "" : v))) });
const text = (content: string): Body => ({ kind: "text", content });
const list = (items: string[]): Body => ({ kind: "list", items });

/** Python str() for table cells (booleans render as True/False). */
function str(v: unknown): string {
  if (typeof v === "boolean") return v ? "True" : "False";
  if (v === null || v === undefined) return "None";
  return String(v);
}

const assetsOf = (s: SessionRow) => uow().all(data_assets, eq(data_assets.session_id, s.id), [asc(data_assets.key)]);

export async function build(s: SessionRow, reportType: string): Promise<Report> {
  if (!Object.hasOwn(REPORT_TYPES, reportType)) throw new DomainError(`Unknown report type. Available: ${Object.keys(REPORT_TYPES).join(", ")}`, 404);
  const d = definitionFor(s);
  const learner = await uow().one(user, eq(user.id, s.user_id));
  const sections: Section[] = [];
  await BUILDERS[reportType](s, sections);
  return {
    title: `${REPORT_TYPES[reportType]} — ${d.title}`, report_type: reportType, scenario: `${d.id} v${d.version}`, session_id: s.id,
    attempt: s.attempt_number, mode: s.mode, learner: learner?.name ?? "", generated_at: now(), execution_mode: "SIMULATED",
    timezone: "All timestamps are UTC.", statement: MODE_STATEMENT, sections,
  };
}

async function caseEvents(s: SessionRow, cs: CaseRow | undefined): Promise<EventRow[]> {
  const ids = new Set<string>();
  const u = uow();
  if (cs) {
    for (const e of await u.all(evidence_references, and(eq(evidence_references.case_id, cs.id), eq(evidence_references.ref_type, "EVENT"))!)) ids.add(e.ref_id);
    if (cs.alert_ids?.length) for (const al of await u.all(alerts, inArray(alerts.alert_id, cs.alert_ids))) for (const x of al.event_ids ?? []) ids.add(x);
  }
  if (!ids.size) return [];
  return u.all(security_events, and(eq(security_events.session_id, s.id), inArray(security_events.event_id, [...ids])),
    [asc(security_events.timestamp), asc(security_events.seq)]);
}

/** Per-activity outcome of a run, derived only from the recorded events (no ground truth). */
export async function runOutcomes(s: SessionRow, runNumber: number): Promise<Json[]> {
  const txs = new Map<string, EventRow[]>();
  const evs = await uow().all(security_events, and(eq(security_events.session_id, s.id), eq(security_events.run_number, runNumber)), [asc(security_events.seq)]);
  for (const e of evs) {
    const k = e.transaction_id || e.event_id;
    if (!txs.has(k)) txs.set(k, []);
    txs.get(k)!.push(e);
  }
  return [...txs.values()].map((group) => {
    const first = group[0];
    const prevented = group.filter((e) => ["BLOCKED", "DENIED", "FAILURE"].includes(e.result));
    return {
      timestamp: iso(first.timestamp), actor: first.actor_id,
      action: group.find((e) => ["DLP", "EMAIL_GATEWAY", "PROXY", "ENDPOINT"].includes(e.source_type))?.action ?? first.action,
      resource: first.resource_id, destination: group.find((e) => e.destination)?.destination ?? null,
      outcome: prevented.length ? "PREVENTED" : "COMPLETED",
      prevented_by: prevented.length ? `${prevented[0].source_system}${prevented[0].policy_id ? " / " + prevented[0].policy_id : ""}` : null,
      event_ids: group.map((e) => e.event_id),
    };
  });
}

const remediationsOf = (s: SessionRow) => uow().all(remediation_actions, eq(remediation_actions.session_id, s.id), [asc(remediation_actions.seq)]);

async function verificationLines(s: SessionRow): Promise<string[]> {
  const lines: string[] = [];
  for (const r of (s.flags ?? {}).runs ?? []) {
    const outcomes = await runOutcomes(s, r.run_number);
    const prevented = outcomes.filter((o) => o.outcome === "PREVENTED");
    const label = r.mode === "validation" ? "Control-validation replay" : "Business-day run";
    lines.push(`Run ${r.run_number} (${label}, ${r.sim_day}): ${outcomes.length} activities, ${prevented.length} prevented.`);
    for (const o of prevented) {
      lines.push(`  Prevented: ${o.actor} ${o.action} ${o.resource || ""}${o.destination ? " -> " + o.destination : ""} (${o.prevented_by})`);
    }
  }
  for (const r of await remediationsOf(s)) {
    const v = r.verification ?? {};
    let line = `${r.action_type} ${r.target_key}: ${r.status} — ${v.check ?? ""}`;
    if (v.caveat) line += ` (caveat: ${v.caveat})`;
    lines.push(line);
  }
  return lines.length ? lines : ["No runs or remediation actions recorded."];
}

const BUILDERS: Record<string, (s: SessionRow, sections: Section[]) => Promise<void>> = {
  inventory: async (s, sections) => {
    const u = uow();
    const findings = new Map<string, (typeof classification_findings.$inferSelect)[]>();
    const latest = await u.one(classification_findings, eq(classification_findings.session_id, s.id), [desc(classification_findings.scan_id)]);
    const latestScan = latest?.scan_id;
    if (latestScan) {
      for (const f of await u.all(classification_findings, eq(classification_findings.scan_id, latestScan))) {
        if (!findings.has(f.asset_key)) findings.set(f.asset_key, []);
        findings.get(f.asset_key)!.push(f);
      }
    }
    const rows = (await assetsOf(s)).map((a) => {
      const det = (findings.get(a.key) ?? []).map((f) => `${f.detector}×${f.match_count} (${f.confidence})`).join("; ");
      return [a.key, a.name, a.asset_type, a.data_structure, a.system, a.location, a.department, a.owner_key || "MISSING", a.label_key || "UNLABELED",
        a.record_count, det || (latestScan ? "none" : "not scanned")];
    });
    sections.push({ heading: "Inventory", body: table(
      ["asset_key", "name", "type", "structure", "system", "location", "department", "owner", "label", "records", "detector_findings"], rows) });
    const gaps = rows.filter((r) => r[7] === "MISSING" || r[8] === "UNLABELED").map((r) => `${r[1]}: owner ${r[7]}, label ${r[8]}`);
    sections.push({ heading: "Coverage gaps", body: list(gaps.length ? gaps : ["No unlabeled or unowned assets."]) });
  },
  "classification-register": async (s, sections) => {
    const rows = (await assetsOf(s)).map((a) => [a.key, a.name, a.label_key || "UNLABELED", a.owner_key || "MISSING", a.handling_notes, a.exception_note]);
    sections.push({ heading: "Current register", body: table(["asset_key", "name", "label", "owner", "handling", "exception"], rows) });
    const hist = await uow().all(classification_assignments, eq(classification_assignments.session_id, s.id), [asc(classification_assignments.id)]);
    sections.push({ heading: "Change history", body: table(["sim_time", "asset_key", "previous", "new", "owner", "justification"],
      hist.map((h) => [iso(h.sim_time), h.asset_key, h.previous_label_key || "UNLABELED", h.label_key, h.owner_key, h.justification])) });
  },
  "policy-tests": async (s, sections) => {
    const u = uow();
    const runs = await u.all(policy_test_runs, eq(policy_test_runs.session_id, s.id), [asc(policy_test_runs.run_number)]);
    if (runs.length) {
      const last = runs[runs.length - 1];
      const m = last.metrics;
      sections.push({ heading: `Latest test-suite run (#${last.run_number})`, body: text(
        `Cases: ${m.total}. TP ${m.tp}, FP ${m.fp}, TN ${m.tn}, FN ${m.fn}. Precision ${str(m.precision)}, recall ${str(m.recall)}. ${m.scope_note}`) });
      sections.push({ heading: "Case results", body: table(["case", "description", "expected", "outcome", "decisive_policy", "correct"],
        last.results.map((r) => [r.id, r.description, r.should_prevent ? "PREVENT" : "ALLOW", r.outcome, r.decisive_policy, r.correct])) });
      sections.push({ heading: "Run history", body: table(["run", "precision", "recall", "fp", "fn", "policies"],
        runs.map((r) => [r.run_number, r.metrics.precision, r.metrics.recall, r.metrics.fp, r.metrics.fn,
          Object.entries(r.policy_snapshot).map(([k, v]) => `${k} v${(v as Json).version} ${(v as Json).status}`).join(", ")])) });
    } else {
      sections.push({ heading: "Test-suite runs", body: text("No test-suite run has been executed.") });
    }
    const dry = await u.all(policy_evaluations, and(eq(policy_evaluations.session_id, s.id), eq(policy_evaluations.dry_run, true)), [asc(policy_evaluations.id)]);
    sections.push({ heading: "Ad-hoc policy tests (dry runs)", body: table(["#", "actor", "action", "resource", "destination", "outcome", "decisive_policy"],
      dry.map((e, i) => [i + 1, e.context.actor?.id, e.context.action?.type, e.context.resource?.id, e.context.destination?.id, e.final_outcome,
        e.decisive_policy])) });
  },
  "incident-timeline": async (s, sections) => {
    const cs = await primaryCase(s);
    const evs = await caseEvents(s, cs);
    if (!cs || !evs.length) {
      sections.push({ heading: "Timeline", body: text("No case with linked events or alerts exists yet.") });
      return;
    }
    sections.push({ heading: `Timeline for case #${cs.id}: ${cs.title}`, body: table(
      ["timestamp_utc", "event_id", "source", "actor", "action", "resource", "destination", "result", "provenance", "summary"],
      evs.map((e) => [iso(e.timestamp), e.event_id, e.source_system, e.actor_id, e.action, e.resource_id, e.destination, e.result, e.provenance, e.summary])) });
  },
  "case-report": async (s, sections) => {
    const cs = await primaryCase(s);
    if (!cs) {
      sections.push({ heading: "Case", body: text("No investigation case has been opened in this session.") });
      return;
    }
    const u = uow();
    const notes = await u.all(case_notes, eq(case_notes.case_id, cs.id), [asc(case_notes.id)]);
    const ev = await u.all(evidence_references, eq(evidence_references.case_id, cs.id), [asc(evidence_references.id)]);
    const evLabel = new Map(ev.map((e, i) => [e.id, `E${i + 1}`]));
    const assets = new Map((await assetsOf(s)).map((a) => [a.key, a]));
    const rems = await remediationsOf(s);
    const notesOf = (kind: string) => {
      const out = notes.filter((n) => n.kind === kind).map((n) => n.text
        + (n.evidence_ids?.length ? ` [evidence: ${n.evidence_ids.map((i) => evLabel.get(i) ?? "?").join(", ")}]` : ""));
      return out.length ? out : ["None recorded."];
    };
    sections.push({ heading: "1. Incident summary", body: text(cs.summary || "Not yet written.") });
    sections.push({ heading: "2. Scope and objective", body: text(
      `Case #${cs.id} '${cs.title}'. Alerts in scope: ${(cs.alert_ids ?? []).join(", ") || "none"}. `
      + `Determination: ${cs.determination || "not recorded"}. Subject identities: ${(cs.subject_identities ?? []).join(", ") || "none recorded"}. `
      + `Hypothesis: ${cs.hypothesis || "not recorded"}.`) });
    const evs = await caseEvents(s, cs);
    sections.push({ heading: "3. Relevant timeline", body: table(["timestamp_utc", "event_id", "actor", "action", "resource", "destination", "result"],
      evs.map((e) => [iso(e.timestamp), e.event_id, e.actor_id, e.action, e.resource_id, e.destination, e.result])) });
    sections.push({ heading: "4. Affected assets and data classifications", body: table(["asset_key", "name", "current_label", "records"],
      (cs.affected_asset_keys ?? []).map((k) => {
        const a = assets.get(k);
        return [k, a ? a.name : "?", a ? a.label_key : "?", a ? a.record_count : ""];
      })) });
    sections.push({ heading: "   Exposure", body: text(
      `Exposure status: ${cs.exposure_status || "not recorded"}. Records potentially exposed: `
      + `${cs.records_potentially_exposed !== null ? cs.records_potentially_exposed : "not recorded"}. Severity: ${cs.severity || "not recorded"}.`) });
    sections.push({ heading: "5. Evidence references", body: table(["ref", "type", "id", "label", "note"],
      ev.map((e) => [evLabel.get(e.id), e.ref_type, e.ref_id, e.label, e.note])) });
    sections.push({ heading: "6. Confirmed observations", body: list(notesOf("OBSERVATION")) });
    sections.push({ heading: "7. Inferences and uncertainties", body: list([
      ...notesOf("INFERENCE").map((t) => `Inference: ${t}`), ...notesOf("UNKNOWN").map((t) => `Unknown: ${t}`),
      ...notesOf("HYPOTHESIS").filter((t) => t !== "None recorded.").map((t) => `Hypothesis: ${t}`)]) });
    sections.push({ heading: "8. Root cause", body: text(
      (cs.root_cause_narrative || "Not established.") + (cs.root_causes?.length ? ` Categories: ${cs.root_causes.join(", ")}.` : "")) });
    const cat = new Map(definitionFor(s).remediation_catalog.map((r) => [r.type, r.category]));
    const contain = rems.filter((r) => ["CONTAINMENT", "PRESERVATION"].includes(cat.get(r.action_type) ?? ""));
    const other = rems.filter((r) => !contain.includes(r));
    const remCols = ["#", "sim_time", "action", "target", "status", "verification", "justification"];
    const remRows = (rs: RemediationRow[]) => rs.map((r) => [r.seq, iso(r.sim_time), r.action_type, r.target_key, r.status, r.verification?.check ?? "", r.justification]);
    sections.push({ heading: "9. Containment decisions", body: table(remCols, remRows(contain)) });
    sections.push({ heading: "10. Remediation actions", body: table(remCols, remRows(other)) });
    sections.push({ heading: "11. Verification results", body: list(await verificationLines(s)) });
    sections.push({ heading: "12. Residual risk", body: text(cs.residual_risk || "Not recorded.") });
    sections.push({ heading: "13. Lessons learned", body: text(cs.lessons_learned || "Not recorded.") });
    sections.push({ heading: "14. Generation details", body: text(`Generated ${now()} from session ${s.id}, attempt ${s.attempt_number}. ${MODE_STATEMENT}`) });
  },
  "remediation-verification": async (s, sections) => {
    const rems = await remediationsOf(s);
    sections.push({ heading: "Remediation actions", body: table(["#", "sim_time", "action", "target", "status", "before", "after", "verification"],
      rems.map((r) => [r.seq, iso(r.sim_time), r.action_type, r.target_key, r.status, JSON.stringify(r.before_state), JSON.stringify(r.after_state),
        JSON.stringify(r.verification)])) });
    const grants = await uow().all(access_grants, and(eq(access_grants.session_id, s.id), isNotNull(access_grants.review_decision)));
    sections.push({ heading: "Access review decisions", body: table(["grant", "asset", "principal", "permission", "decision", "status", "note"],
      grants.map((g) => [g.key, g.asset_key, g.principal_key, g.permission, g.review_decision, g.status, g.review_note])) });
    sections.push({ heading: "Replay verification", body: list(await verificationLines(s)) });
  },
  assessment: async (s, sections) => {
    const attempt = await uow().one(assessment_attempts, eq(assessment_attempts.session_id, s.id), [desc(assessment_attempts.id)]);
    if (!attempt) {
      // No score preview before submission: previews would let learners probe hidden answers.
      sections.push({ heading: "Status", body: text("Not yet submitted. Scores are calculated on the server only when the session is submitted.") });
      return;
    }
    sections.push({ heading: "Status", body: text(
      `Submitted ${iso(attempt.submitted_at)} (attempt ${attempt.attempt_number}, ${attempt.mode} mode). Inputs digest ${attempt.inputs_digest.slice(0, 16)}…`) });
    sections.push({ heading: "Result", body: text(
      `Score ${attempt.total_score}/100 — ${attempt.passed ? "PASS" : "NOT PASSED"}. This is a Threatready platform assessment outcome for the `
      + "tasks listed below. It is not a professional certification and reports only what this scenario assessed.") });
    sections.push({ heading: "Category scores", body: table(["category", "weight", "percent", "weighted"],
      Object.values(attempt.category_scores).map((v: Json) => [v.name, v.weight, v.percent, v.weighted])) });
    sections.push({ heading: "Criteria", body: table(["criterion", "category", "earned", "points", "explanation"],
      attempt.criteria.map((c) => [c.description, c.category, c.earned, c.points, c.explanation])) });
    sections.push({ heading: "Critical failures", body: list(attempt.critical_failures.length
      ? attempt.critical_failures.map((c) => `${c.description} ${c.detail}`) : ["None."]) });
    sections.push({ heading: "Missing tasks", body: list(attempt.missing_tasks.length ? attempt.missing_tasks : ["None."]) });
    sections.push({ heading: "Recommended learning", body: list(attempt.recommendations.length
      ? attempt.recommendations.map((r) => `${r.lesson_id}: ${r.because.join("; ")}`) : ["None."]) });
  },
};

// --------------------------------------------------------------------------- renderers

export function toMarkdown(rep: Report): string {
  const out = [`# ${rep.title}`, "", `> ${rep.statement}`, "",
    `- Scenario: ${rep.scenario} (session ${rep.session_id}, attempt ${rep.attempt}, ${rep.mode} mode)`,
    `- Learner: ${rep.learner}`, `- Generated: ${rep.generated_at} — ${rep.timezone}`, ""];
  const cell = (v: unknown) => str(v).replace(/\|/g, "\\|").replace(/\n/g, " ");
  for (const sec of rep.sections) {
    out.push(`## ${sec.heading.trim()}`, "");
    const b = sec.body;
    if (b.kind === "text") out.push(b.content, "");
    else if (b.kind === "list") out.push(...b.items.map((i) => `- ${i}`), "");
    else if (!b.rows.length) out.push("_No records._", "");
    else {
      out.push("| " + b.columns.join(" | ") + " |", "|" + "---|".repeat(b.columns.length));
      out.push(...b.rows.map((r) => "| " + r.map(cell).join(" | ") + " |"), "");
    }
  }
  return out.join("\n");
}

const esc = (v: unknown) => str(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

export function toHtml(rep: Report): string {
  const parts = [
    "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
    `<title>${esc(rep.title)}</title>`,
    "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#1b2430;max-width:1200px}"
    + "h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.6rem;border-bottom:1px solid #d5dbe3;padding-bottom:.3rem}"
    + "table{border-collapse:collapse;width:100%;font-size:.85rem}th,td{border:1px solid #d5dbe3;padding:.35rem .5rem;text-align:left;vertical-align:top}"
    + "th{background:#eef2f7}.banner{background:#fff7e0;border:1px solid #e6c870;padding:.6rem .8rem;border-radius:6px}</style></head><body>",
    `<h1>${esc(rep.title)}</h1>`,
    `<p class='banner'>${esc(rep.statement)}</p>`,
    `<p>Scenario ${esc(rep.scenario)} · session ${rep.session_id} · attempt ${rep.attempt} · ${esc(rep.mode)} mode · `
    + `learner ${esc(rep.learner)} · generated ${esc(rep.generated_at)} (${esc(rep.timezone)})</p>`,
  ];
  for (const sec of rep.sections) {
    parts.push(`<h2>${esc(sec.heading.trim())}</h2>`);
    const b = sec.body;
    if (b.kind === "text") parts.push(`<p>${esc(b.content)}</p>`);
    else if (b.kind === "list") parts.push("<ul>" + b.items.map((i) => `<li>${esc(i)}</li>`).join("") + "</ul>");
    else if (!b.rows.length) parts.push("<p><em>No records.</em></p>");
    else {
      parts.push("<table><thead><tr>" + b.columns.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr></thead><tbody>");
      parts.push(...b.rows.map((r) => "<tr>" + r.map((v) => `<td>${esc(v)}</td>`).join("") + "</tr>"));
      parts.push("</tbody></table>");
    }
  }
  parts.push("</body></html>");
  return parts.join("");
}

function csvField(v: unknown): string {
  const s = str(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(rep: Report): string {
  if (!TABULAR.has(rep.report_type)) throw new DomainError("CSV export is available for tabular reports only");
  const t = rep.sections.find((sec) => sec.body.kind === "table")!.body as Extract<Body, { kind: "table" }>;
  const lines = [t.columns.map(csvField).join(",")];
  for (const r of t.rows) {
    // Neutralise spreadsheet formula injection.
    lines.push(r.map((v) => (typeof v === "string" && /^[=+\-@]/.test(v) ? "'" + v : v)).map(csvField).join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
