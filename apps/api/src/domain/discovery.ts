/** Discovery scanning, classification register and access review. */
import { and, asc, desc, eq } from "drizzle-orm";
import { DomainError, pyRepr, sorted } from "../common/util.js";
import { uow } from "../db/context.js";
import {
  access_grants, classification_assignments, classification_findings, classification_labels, classification_rules, data_assets,
  discovery_scans,
} from "../db/schema.js";
import { CONFIDENCE_ORDER, DETECTORS, scanText, type DetectorResult } from "./detection.js";
import { applyRemediation } from "./investigation.js";
import { advanceClock, getAsset, getIdentity, labelRanks, recordAction, type AssetRow, type SessionRow } from "./simulation.js";

type RuleRow = typeof classification_rules.$inferSelect;

export async function rules(s: SessionRow): Promise<RuleRow[]> {
  return uow().all(classification_rules, eq(classification_rules.session_id, s.id), [asc(classification_rules.key)]);
}

/** Highest-ranked label among enabled rules whose detector, count and confidence thresholds are met. */
export function recommend(scan: Record<string, DetectorResult>, ruleList: RuleRow[], ranks: Record<string, number>): [string | null, string[]] {
  const hits: [number, string, string][] = [];
  for (const r of ruleList) {
    if (!r.enabled) continue;
    for (const det of r.detectors) {
      const res = scan[det];
      if (res && res.match_count >= r.min_matches && CONFIDENCE_ORDER[res.confidence] >= CONFIDENCE_ORDER[r.min_confidence]) {
        hits.push([ranks[r.recommended_label] ?? -1, r.recommended_label, r.key]);
        break;
      }
    }
  }
  if (!hits.length) return [null, []];
  // Python max() over tuples: rank, then label, then rule key.
  const best = hits.reduce((a, b) => (b[0] > a[0] || (b[0] === a[0] && (b[1] > a[1] || (b[1] === a[1] && b[2] > a[2]))) ? b : a));
  return [best[1], sorted(new Set(hits.map((h) => h[2])))];
}

export async function runScan(s: SessionRow) {
  advanceClock(s);
  const u = uow();
  const ruleList = await rules(s);
  const ranks = await labelRanks(s);
  const n = (await u.count(discovery_scans, eq(discovery_scans.session_id, s.id))) + 1;
  const scan = await u.insert(discovery_scans, {
    session_id: s.id, scan_number: n, sim_time: s.sim_clock,
    rule_snapshot: ruleList.map((r) => ({ key: r.key, detectors: r.detectors, min_matches: r.min_matches, min_confidence: r.min_confidence,
      label: r.recommended_label, enabled: r.enabled, version: r.version })),
  });
  let count = 0;
  const assets = await u.all(data_assets, eq(data_assets.session_id, s.id), [asc(data_assets.key)]);
  const findings: (typeof classification_findings.$inferInsert)[] = [];
  for (const a of assets) {
    const res = scanText(a.content_sample);
    const [label, ruleKeys] = recommend(res, ruleList, ranks);
    for (const [det, r] of Object.entries(res)) {
      findings.push({
        session_id: s.id, scan_id: scan.id, asset_key: a.key, detector: det, match_count: r.match_count, confidence: r.confidence,
        evidence: r.evidence, recommended_label: label,
        rule_keys: ruleKeys.filter((k) => ruleList.find((x) => x.key === k)!.detectors.includes(det)),
      });
      count += 1;
    }
  }
  await u.insertMany(classification_findings, findings);
  scan.assets_scanned = assets.length;
  scan.findings_count = count;
  await recordAction(s, "DISCOVERY_SCAN", { scan_number: n }, { findings: count });
  return scan;
}

export async function latestFindings(s: SessionRow) {
  const u = uow();
  const scan = await u.one(discovery_scans, eq(discovery_scans.session_id, s.id), [desc(discovery_scans.scan_number)]);
  if (!scan) return { scan: undefined, findings: [] as (typeof classification_findings.$inferSelect)[] };
  const findings = await u.all(classification_findings, eq(classification_findings.scan_id, scan.id),
    [asc(classification_findings.asset_key), asc(classification_findings.detector)]);
  return { scan, findings };
}

export async function assignLabel(s: SessionRow, userId: string, a: {
  asset_key: string; label_key: string; justification: string; owner_key: string | null; handling_notes: string; exception_note: string;
}) {
  const asset = await getAsset(s, a.asset_key);
  if (!Object.hasOwn(await labelRanks(s), a.label_key)) throw new DomainError(`Unknown label '${a.label_key}'`);
  if (a.owner_key) {
    const owner = await getIdentity(s, a.owner_key);
    if (owner.employment_type === "SERVICE" || owner.employment_type === "TEST") {
      throw new DomainError("A data owner must be an accountable person, not a service or test identity");
    }
  }
  advanceClock(s);
  const rec = await uow().insert(classification_assignments, {
    session_id: s.id, asset_key: asset.key, label_key: a.label_key, previous_label_key: asset.label_key,
    owner_key: a.owner_key || asset.owner_key, justification: a.justification, handling_notes: a.handling_notes,
    exception_note: a.exception_note, assigned_by: userId, sim_time: s.sim_clock,
  });
  asset.label_key = a.label_key;
  if (a.owner_key) asset.owner_key = a.owner_key;
  asset.handling_notes = a.handling_notes;
  asset.exception_note = a.exception_note;
  await recordAction(s, "CLASSIFY", { asset: asset.key, label: a.label_key, owner: asset.owner_key }, { previous: rec.previous_label_key });
  return rec;
}

export async function updateRule(s: SessionRow, key: string, a: {
  enabled: boolean; min_matches: number; min_confidence: string; recommended_label: string; detectors: string[];
}) {
  const r = await uow().one(classification_rules, and(eq(classification_rules.session_id, s.id), eq(classification_rules.key, key))!);
  if (!r) throw new DomainError("Unknown classification rule", 404);
  if (!Object.hasOwn(await labelRanks(s), a.recommended_label)) throw new DomainError(`Unknown label '${a.recommended_label}'`);
  const unknown = a.detectors.filter((d) => !Object.hasOwn(DETECTORS, d));
  if (unknown.length || !a.detectors.length) throw new DomainError(`Unknown or empty detector list: ${pyRepr(unknown)}`);
  if (!Object.hasOwn(CONFIDENCE_ORDER, a.min_confidence)) throw new DomainError("min_confidence must be LOW, MEDIUM or HIGH");
  const before = { enabled: r.enabled, min_matches: r.min_matches, min_confidence: r.min_confidence, recommended_label: r.recommended_label,
    detectors: r.detectors };
  r.enabled = a.enabled;
  r.min_matches = a.min_matches;
  r.min_confidence = a.min_confidence;
  r.recommended_label = a.recommended_label;
  r.detectors = [...a.detectors];
  r.version += 1;
  await recordAction(s, "CLASSIFICATION_RULE_UPDATE", { rule: key, before, version: r.version });
  return r;
}

export async function reviewGrant(s: SessionRow, a: { grant_key: string; decision: string; note: string }) {
  const g = await uow().one(access_grants, and(eq(access_grants.session_id, s.id), eq(access_grants.key, a.grant_key))!);
  if (!g) throw new DomainError("Unknown grant", 404);
  if (a.decision !== "KEEP" && a.decision !== "REVOKE") throw new DomainError("decision must be KEEP or REVOKE");
  if (a.decision === "REVOKE" && g.status === "ACTIVE") {
    await applyRemediation(s, { action_type: "REVOKE_GRANT", target_key: g.key, justification: a.note || "Access review", case_id: null,
      confirm_destructive: false });
    await recordAction(s, "GRANT_REVIEW_REVOKE", { grant: g.key, note: a.note });
  } else {
    await recordAction(s, a.decision === "KEEP" ? "GRANT_REVIEW_KEEP" : "GRANT_REVIEW_REVOKE", { grant: g.key, note: a.note });
  }
  g.review_decision = a.decision;
  g.review_note = a.note;
  return g;
}

export async function labels(s: SessionRow) {
  return uow().all(classification_labels, eq(classification_labels.session_id, s.id), [asc(classification_labels.rank)]);
}

export function assetSummary(a: AssetRow) {
  return { key: a.key, name: a.name, asset_type: a.asset_type, data_structure: a.data_structure, system: a.system, location: a.location,
    department: a.department, owner_key: a.owner_key, label_key: a.label_key, record_count: a.record_count, size_bytes: a.size_bytes,
    quarantined: a.quarantined };
}
