/** Synthetic enterprise inventory, discovery scanning, classification and access review. */
import { Controller, Get, Param, Put } from "@nestjs/common";
import { AssetsQuery, AssignIn, ReviewIn, RuleIn } from "@threatready/contracts";
import { and, asc, eq } from "drizzle-orm";
import { z } from "zod";
import { iso, sorted } from "../common/util.js";
import { COMPANY } from "../content/company.js";
import { type Principal, uow } from "../db/context.js";
import { access_grants, classification_assignments, data_assets, sim_groups, sim_identities } from "../db/schema.js";
import { CONFIDENCE_ORDER, detectorCatalog } from "../domain/detection.js";
import * as discovery from "../domain/discovery.js";
import { destinationList } from "../domain/investigation.js";
import { loadSession } from "../domain/session-lifecycle.js";
import { accessPath, getAsset, getIdentity, groupsOf, type IdentityRow } from "../domain/simulation.js";
import { CurrentPrincipal, IdParam, Permission, PERMISSIONS, PostOk, ZBody, ZQuery } from "../platform/http.js";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const read = (id: number, p: Principal) => loadSession(id, p, { write: false });
const write = (id: number, p: Principal) => loadSession(id, p, { write: true });

function identityOut(i: IdentityRow, groups: string[]): Json {
  return { key: i.key, display_name: i.display_name, email: i.email, department: i.department, title: i.title, enterprise_role: i.enterprise_role,
    employment_type: i.employment_type, manager_key: i.manager_key, status: i.status, sessions_revoked_at: iso(i.sessions_revoked_at),
    attributes: { ...(i.attributes ?? {}) }, groups };
}

const AccessQuery = z.object({ asset: z.string().max(60).optional() });
const FindingsQuery = z.object({ detector: z.string().max(40).optional(), min_confidence: z.string().max(10).optional() });

@Controller("api/sessions/:sessionId")
@Permission(PERMISSIONS.SELF)
export class EnvironmentController {
  @Get("company")
  async company(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    await read(id, p);
    return { ...COMPANY, provenance: "SIMULATED", note: "Fictional organisation. All data is synthetic." };
  }

  @Get("identities")
  async identities(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const groups = await uow().all(sim_groups, eq(sim_groups.session_id, s.id));
    return (await uow().all(sim_identities, eq(sim_identities.session_id, s.id), [asc(sim_identities.key)]))
      .map((i) => identityOut(i, sorted(groups.filter((g) => g.members.includes(i.key)).map((g) => g.key))));
  }

  @Get("groups")
  async groups(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await uow().all(sim_groups, eq(sim_groups.session_id, s.id), [asc(sim_groups.key)]))
      .map((g) => ({ key: g.key, name: g.name, description: g.description, members: g.members }));
  }

  @Get("destinations")
  async destinations(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await destinationList(s)).map((d) => ({ key: d.key, name: d.name, kind: d.kind, domain: d.domain, category: d.category,
      sanctioned: d.sanctioned, internal: d.internal, blocked: d.blocked }));
  }

  @Get("labels")
  async labels(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await discovery.labels(s)).map((l) => ({ key: l.key, name: l.name, rank: l.rank, description: l.description, handling: l.handling }));
  }

  @Get("assets")
  async assets(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZQuery(AssetsQuery) q: z.infer<typeof AssetsQuery>) {
    const s = await read(id, p);
    const { scan, findings } = await discovery.latestFindings(s);
    const byAsset = new Map<string, typeof findings>();
    for (const f of findings) {
      if (!byAsset.has(f.asset_key)) byAsset.set(f.asset_key, []);
      byAsset.get(f.asset_key)!.push(f);
    }
    const out: Json[] = [];
    for (const a of await uow().all(data_assets, eq(data_assets.session_id, s.id), [asc(data_assets.key)])) {
      if (q.q && !`${a.name} ${a.location} ${a.description} ${a.key}`.toLowerCase().includes(q.q.toLowerCase())) continue;
      if (q.label && a.label_key !== q.label) continue;
      if (q.department && a.department !== q.department) continue;
      if (q.unlabeled === "true" && a.label_key) continue;
      if (q.no_owner === "true" && a.owner_key) continue;
      const fs = byAsset.get(a.key) ?? [];
      out.push({ ...discovery.assetSummary(a), detectors: sorted(new Set(fs.map((f) => f.detector))), recommended_label: fs[0]?.recommended_label ?? null,
        scanned: scan !== undefined });
    }
    return out;
  }

  @Get("assets/:assetKey")
  async assetDetail(@IdParam("sessionId") id: number, @Param("assetKey") assetKey: string, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const u = uow();
    const a = await getAsset(s, assetKey);
    if (s.user_id === p.userId && s.status === "ACTIVE") {
      const viewed: string[] = [...((s.flags ?? {}).viewed_assets ?? [])];
      if (!viewed.includes(a.key)) s.flags = { ...(s.flags ?? {}), viewed_assets: [...viewed, a.key] };
    }
    const { findings } = await discovery.latestFindings(s);
    const grants = await u.all(access_grants, and(eq(access_grants.session_id, s.id), eq(access_grants.asset_key, a.key)), [asc(access_grants.key)]);
    const groupMap = new Map((await u.all(sim_groups, eq(sim_groups.session_id, s.id))).map((g) => [g.key, g]));
    const effective: Json[] = [];
    for (const i of await u.all(sim_identities, eq(sim_identities.session_id, s.id), [asc(sim_identities.key)])) {
      const path = await accessPath(s, i, a);
      if (path.allowed) effective.push({ identity: i.key, display_name: i.display_name, employment_type: i.employment_type, department: i.department,
        via: path.via, permission: path.permission });
    }
    const history = await u.all(classification_assignments, and(eq(classification_assignments.session_id, s.id),
      eq(classification_assignments.asset_key, a.key)), [asc(classification_assignments.id)]);
    return {
      ...discovery.assetSummary(a), description: a.description, content_sample: a.content_sample, handling_notes: a.handling_notes,
      exception_note: a.exception_note, provenance: "SIMULATED",
      findings: findings.filter((f) => f.asset_key === a.key).map((f) => ({ detector: f.detector, match_count: f.match_count, confidence: f.confidence,
        evidence: f.evidence, recommended_label: f.recommended_label, rule_keys: f.rule_keys })),
      grants: grants.map((g) => {
        const grp = groupMap.get(g.principal_key);
        return { key: g.key, principal_type: g.principal_type, principal_key: g.principal_key, principal_name: grp ? grp.name : g.principal_key,
          members: grp ? grp.members : [g.principal_key], permission: g.permission, justification: g.justification, status: g.status,
          review_decision: g.review_decision, review_note: g.review_note };
      }),
      effective_access: effective,
      classification_history: history.map((h) => ({ label: h.label_key, previous: h.previous_label_key, owner: h.owner_key, justification: h.justification,
        sim_time: iso(h.sim_time) })),
    };
  }

  @Get("access")
  async access(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZQuery(AccessQuery) q: z.infer<typeof AccessQuery>) {
    const s = await read(id, p);
    const where = q.asset ? and(eq(access_grants.session_id, s.id), eq(access_grants.asset_key, q.asset)) : eq(access_grants.session_id, s.id);
    return (await uow().all(access_grants, where, [asc(access_grants.key)])).map((g) => ({ key: g.key, asset_key: g.asset_key,
      principal_type: g.principal_type, principal_key: g.principal_key, permission: g.permission, justification: g.justification, status: g.status,
      review_decision: g.review_decision, review_note: g.review_note, revoked_at: iso(g.revoked_at) }));
  }

  @Get("identities/:identityKey/access")
  async identityAccess(@IdParam("sessionId") id: number, @Param("identityKey") identityKey: string, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const i = await getIdentity(s, identityKey);
    const out: Json[] = [];
    for (const a of await uow().all(data_assets, eq(data_assets.session_id, s.id), [asc(data_assets.key)])) {
      const path = await accessPath(s, i, a);
      if (path.allowed) out.push({ asset_key: a.key, name: a.name, label_key: a.label_key, via: path.via, permission: path.permission });
    }
    return { identity: identityKey, groups: await groupsOf(s, identityKey), access: out };
  }

  @PostOk("access/:grantKey/review")
  async review(@IdParam("sessionId") id: number, @Param("grantKey") grantKey: string, @CurrentPrincipal() p: Principal,
    @ZBody(ReviewIn) body: z.infer<typeof ReviewIn>) {
    const s = await write(id, p);
    const g = await discovery.reviewGrant(s, { grant_key: grantKey, decision: body.decision, note: body.note });
    return { key: g.key, status: g.status, review_decision: g.review_decision, review_note: g.review_note };
  }

  // ------------------------------------------------------------------------- discovery & classification

  @Get("discovery/detectors")
  async detectors(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    await read(id, p);
    return detectorCatalog();
  }

  @PostOk("discovery/scan")
  async scan(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await write(id, p);
    const sc = await discovery.runScan(s);
    return { scan_number: sc.scan_number, assets_scanned: sc.assets_scanned, findings: sc.findings_count, sim_time: iso(sc.sim_time),
      provenance: "SIMULATED", scope: "Each synthetic asset's stored content sample was inspected by the enabled detectors." };
  }

  @Get("discovery/findings")
  async findings(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZQuery(FindingsQuery) q: z.infer<typeof FindingsQuery>) {
    const s = await read(id, p);
    const { scan, findings } = await discovery.latestFindings(s);
    const minRank = q.min_confidence ? CONFIDENCE_ORDER[q.min_confidence] ?? 0 : 0;
    return {
      scan: scan ? { scan_number: scan.scan_number, sim_time: iso(scan.sim_time), assets_scanned: scan.assets_scanned, rule_snapshot: scan.rule_snapshot } : null,
      findings: findings.filter((f) => (!q.detector || f.detector === q.detector) && (!q.min_confidence || CONFIDENCE_ORDER[f.confidence] >= minRank))
        .map((f) => ({ asset_key: f.asset_key, detector: f.detector, match_count: f.match_count, confidence: f.confidence, evidence: f.evidence,
          recommended_label: f.recommended_label, rule_keys: f.rule_keys })),
    };
  }

  @Get("classification/rules")
  async rules(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    return (await discovery.rules(s)).map((r) => ({ key: r.key, name: r.name, detectors: r.detectors, min_matches: r.min_matches,
      min_confidence: r.min_confidence, recommended_label: r.recommended_label, enabled: r.enabled, version: r.version }));
  }

  @Put("classification/rules/:ruleKey")
  async putRule(@IdParam("sessionId") id: number, @Param("ruleKey") ruleKey: string, @CurrentPrincipal() p: Principal,
    @ZBody(RuleIn) body: z.infer<typeof RuleIn>) {
    const s = await write(id, p);
    const r = await discovery.updateRule(s, ruleKey, body);
    return { key: r.key, version: r.version };
  }

  @PostOk("classification/assign")
  async assign(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal, @ZBody(AssignIn) body: z.infer<typeof AssignIn>) {
    const s = await write(id, p);
    const rec = await discovery.assignLabel(s, p.userId, { ...body, owner_key: body.owner_key ?? null });
    return { asset_key: rec.asset_key, label_key: rec.label_key, previous_label_key: rec.previous_label_key, owner_key: rec.owner_key,
      sim_time: iso(rec.sim_time) };
  }

  @Get("classification/register")
  async register(@IdParam("sessionId") id: number, @CurrentPrincipal() p: Principal) {
    const s = await read(id, p);
    const u = uow();
    const hist = await u.all(classification_assignments, eq(classification_assignments.session_id, s.id), [asc(classification_assignments.id)]);
    return {
      assets: (await u.all(data_assets, eq(data_assets.session_id, s.id), [asc(data_assets.key)]))
        .map((a) => ({ ...discovery.assetSummary(a), handling_notes: a.handling_notes, exception_note: a.exception_note })),
      history: hist.map((h) => ({ asset_key: h.asset_key, label: h.label_key, previous: h.previous_label_key, owner: h.owner_key,
        justification: h.justification, handling_notes: h.handling_notes, exception_note: h.exception_note, sim_time: iso(h.sim_time) })),
    };
  }
}
