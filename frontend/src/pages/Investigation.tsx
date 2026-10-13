import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import {
  ActionButton, Badge, Banner, Card, Empty, ErrorBanner, Field, KV, LabelBadge, Loading, NeedSession, PageHead, ReadOnlyNotice, Status, Tabs, fmtNum,
  fmtTime, useToast,
} from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Alert, Asset, Destination, Identity, Label, RemediationType, SecEvent } from "../types";

// ----------------------------------------------------------------------------- alert queue

function AlertDetail({ sid, id, onChanged, onOpenCase }: { sid: number; id: string; onChanged: () => void; onOpenCase: (caseId: number) => void }) {
  const { canWrite, refresh } = useSession();
  const toast = useToast();
  const vocab = useLoad(() => api.get(`/api/sessions/${sid}/investigation/vocabulary`), [sid]);
  const a = useLoad(() => api.get(`/api/sessions/${sid}/alerts/${id}`), [sid, id]);
  const [disp, setDisp] = useState("");
  const [note, setNote] = useState("");
  const [title, setTitle] = useState("");
  useEffect(() => {
    if (a.data) {
      setDisp(a.data.disposition ?? "");
      setNote(a.data.disposition_note ?? "");
      setTitle(`Investigation: ${a.data.title}`.slice(0, 190));
    }
  }, [a.data]);
  if (a.loading) return <Card><Loading /></Card>;
  if (a.error) return <ErrorBanner error={a.error} />;
  const al = a.data;
  return (
    <Card title={al.title} actions={<><Status value={al.severity} /><Status value={al.status} /></>}>
      <KV items={[["Alert", <span className="mono">{al.alert_id}</span>], ["Time", fmtTime(al.timestamp)], ["Run", al.run_number],
        ["Policy", `${al.policy_id} v${al.policy_version}`], ["Actor", al.actor_id], ["Resource", al.resource_id],
        ["Triggering event", <span className="mono">{al.triggering_event_id}</span>], ["Cases", al.case_ids.length ? al.case_ids.map((c: number) => `#${c}`).join(", ") : "none"]]} />
      <h3 style={{ marginTop: 10 }}>Why the rule fired (deterministic explanation)</h3>
      <p className="small mono">{al.explanation}</p>
      <h3>Correlated events</h3>
      <p className="small muted">{al.correlation_method}</p>
      <ul className="timeline">
        {al.correlated.map((c: any) => (
          <li key={c.event_id} className={["BLOCKED", "DENIED"].includes(c.event.result) ? "bad" : c.strength === "strong" ? "linked" : ""}>
            <span className="small">{fmtTime(c.event.timestamp)}</span> <Badge>{c.event.source_type}</Badge> <Status value={c.event.result} /> {c.event.summary}
            <div className="small muted">{c.reasons.join(" · ")} · {c.strength} · {c.minutes_from_trigger >= 0 ? "+" : ""}{c.minutes_from_trigger} min · <span className="mono">{c.event_id}</span></div>
          </li>
        ))}
      </ul>
      <hr />
      <h3>Disposition</h3>
      <div className="grid two">
        <Field label="Disposition">
          <select value={disp} onChange={(e) => setDisp(e.target.value)} aria-label="Disposition">
            <option value="">— choose —</option>
            {vocab.data?.dispositions.map((d: string) => <option key={d} value={d}>{d.replace(/_/g, " ")}</option>)}
          </select>
        </Field>
        <Field label="Justification (min 10 chars)"><input value={note} onChange={(e) => setNote(e.target.value)} aria-label="Disposition justification" /></Field>
      </div>
      <p className="small muted">True positive: real problem. Benign positive: rule matched correctly but the activity is legitimate. False positive: the rule matched something it should not. Undetermined: the evidence cannot settle it.</p>
      <ActionButton className="primary" disabled={!canWrite || !disp || note.trim().length < 10} onClick={async () => {
        await api.post(`/api/sessions/${sid}/alerts/${id}/disposition`, { disposition: disp, note });
        toast(`${id}: ${disp}`);
        a.reload();
        onChanged();
        await refresh();
      }}>Save disposition</ActionButton>
      <hr />
      <h3>Open an investigation case</h3>
      <div className="row">
        <input value={title} onChange={(e) => setTitle(e.target.value)} style={{ flex: 1, minWidth: 220 }} aria-label="Case title" />
        <ActionButton disabled={!canWrite || title.trim().length < 3} onClick={async () => {
          const c = await api.post(`/api/sessions/${sid}/cases`, { title, alert_ids: [id] });
          toast(`Case #${c.id} opened`);
          await refresh();
          onOpenCase(c.id);
        }}>Open case from this alert</ActionButton>
      </div>
    </Card>
  );
}

function AlertQueue({ sid, onOpenCase }: { sid: number; onOpenCase: (id: number) => void }) {
  const [filter, setFilter] = useState<"all" | "open">("all");
  const alerts = useLoad(() => api.get<Alert[]>(`/api/sessions/${sid}/alerts${filter === "open" ? "?undispositioned=true" : ""}`), [sid, filter]);
  const [sel, setSel] = useState<string | null>(null);
  return (
    <div className="grid side">
      <Card title="Alert queue" actions={<select value={filter} onChange={(e) => setFilter(e.target.value as "all" | "open")} aria-label="Alert filter"><option value="all">All alerts</option><option value="open">Untriaged only</option></select>}>
        {alerts.loading ? <Loading /> : !alerts.data?.length ? <Empty title="No alerts"><p>Run the business day from the <Link to="/workspace">Simulation Workspace</Link>.</p></Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Run</th><th>Disposition</th></tr></thead>
            <tbody>{alerts.data.map((a) => (
              <tr key={a.alert_id} className={`selectable ${sel === a.alert_id ? "selected" : ""}`} tabIndex={0}
                onClick={() => setSel(a.alert_id)} onKeyDown={(e) => e.key === "Enter" && setSel(a.alert_id)}>
                <td className="small">{fmtTime(a.timestamp)}</td><td><Status value={a.severity} /></td>
                <td>{a.title}<div className="small muted">{a.policy_id} v{a.policy_version}</div></td><td>{a.run_number}</td>
                <td>{a.disposition ? <Status value={a.disposition} /> : <Badge tone="warn">untriaged</Badge>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
      <div>{sel ? <AlertDetail sid={sid} id={sel} onChanged={alerts.reload} onOpenCase={onOpenCase} /> : <Card><Empty title="Select an alert"><p>Review the rule explanation and correlated evidence, then record a disposition.</p></Empty></Card>}</div>
    </div>
  );
}

// ----------------------------------------------------------------------------- case workspace

function RiskCalculator({ sid, labels, onUse }: { sid: number; labels: Label[]; onUse: (sev: string) => void }) {
  const [f, setF] = useState({ label: "restricted", records: "0", destination_external: true, data_left_org: "UNKNOWN" });
  const [r, setR] = useState<any>(null);
  return (
    <div className="card tight">
      <h3>Risk model calculator</h3>
      <div className="grid four">
        <Field label="Data label"><select value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })}>{labels.map((l) => <option key={l.key} value={l.key}>{l.name}</option>)}</select></Field>
        <Field label="Records"><input inputMode="numeric" value={f.records} onChange={(e) => setF({ ...f, records: e.target.value.replace(/\D/g, "") })} /></Field>
        <Field label="External destination"><select value={String(f.destination_external)} onChange={(e) => setF({ ...f, destination_external: e.target.value === "true" })}><option value="true">yes</option><option value="false">no</option></select></Field>
        <Field label="Data left the organisation"><select value={f.data_left_org} onChange={(e) => setF({ ...f, data_left_org: e.target.value })}><option>YES</option><option>NO</option><option>UNKNOWN</option></select></Field>
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <ActionButton className="small" onClick={async () => setR(await api.post(`/api/sessions/${sid}/risk-score`, { ...f, records: Number(f.records || 0) }))}>Calculate</ActionButton>
        {r && <><span>Score {r.score} → <Status value={r.severity} /></span><button className="small" onClick={() => onUse(r.severity)}>Use as case severity</button></>}
      </div>
      {r && <p className="small muted">{r.model}. Components: {JSON.stringify(r.components)}</p>}
    </div>
  );
}

function CaseWorkspace({ sid, caseId }: { sid: number; caseId: number }) {
  const { canWrite, refresh, session } = useSession();
  const toast = useToast();
  const c = useLoad(() => api.get(`/api/sessions/${sid}/cases/${caseId}`), [sid, caseId]);
  const timeline = useLoad(() => api.get<(SecEvent & { linked_as_evidence: boolean })[]>(`/api/sessions/${sid}/cases/${caseId}/timeline`), [sid, caseId]);
  const vocab = useLoad(() => api.get(`/api/sessions/${sid}/investigation/vocabulary`), [sid]);
  const assets = useLoad(() => api.get<Asset[]>(`/api/sessions/${sid}/assets`), [sid]);
  const ids = useLoad(() => api.get<Identity[]>(`/api/sessions/${sid}/identities`), [sid]);
  const dests = useLoad(() => api.get<Destination[]>(`/api/sessions/${sid}/destinations`), [sid]);
  const grants = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/access`), [sid]);
  const labels = useLoad(() => api.get<Label[]>(`/api/sessions/${sid}/labels`), [sid]);
  const rems = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/remediation`), [sid]);
  const [form, setForm] = useState<any>(null);
  const [note, setNote] = useState({ kind: "OBSERVATION", text: "", evidence_ids: [] as number[] });
  const [ev, setEv] = useState({ ref_type: "ASSET", ref_id: "" });
  const [rem, setRem] = useState({ action_type: "", target_key: "", justification: "", confirm: false });
  const [tab, setTab] = useState<"evidence" | "scope" | "remediate" | "report">("evidence");

  useEffect(() => { if (c.data) setForm(c.data); }, [c.data]);
  if (!c.data || !form) return <Card><Loading /></Card>;
  if (c.error) return <ErrorBanner error={c.error} />;
  const data = c.data;
  const catalog: RemediationType[] = session?.scenario.remediation_catalog ?? [];
  const spec = catalog.find((x) => x.type === rem.action_type);
  const reloadAll = () => { c.reload(); timeline.reload(); rems.reload(); void refresh(); };
  const save = async (patch: Record<string, unknown>, msg = "Case updated") => {
    await api.patch(`/api/sessions/${sid}/cases/${caseId}`, patch);
    toast(msg);
    reloadAll();
  };
  const linkEvidence = async (ref_type: string, ref_id: string) => {
    await api.post(`/api/sessions/${sid}/cases/${caseId}/evidence`, { ref_type, ref_id });
    toast(`Linked ${ref_type} ${ref_id}`);
    reloadAll();
  };
  const targetOptions = (): [string, string][] => {
    switch (spec?.target_type) {
      case "IDENTITY": return (ids.data ?? []).filter((i) => i.employment_type !== "TEST").map((i) => [i.key, `${i.display_name} (${i.key})`]);
      case "DESTINATION": return (dests.data ?? []).filter((d) => !d.internal).map((d) => [d.key, d.name]);
      case "ASSET": return (assets.data ?? []).map((a) => [a.key, a.name]);
      case "GRANT": return (grants.data ?? []).filter((g) => g.status === "ACTIVE").map((g) => [g.key, `${g.key}: ${g.principal_key} ${g.permission} on ${g.asset_key}`]);
      case "PARTY": return (vocab.data?.escalation_parties ?? []).map((p: string) => [p, p.replace(/_/g, " ")]);
      default: return [];
    }
  };
  const evOptions = (): [string, string][] => {
    switch (ev.ref_type) {
      case "ASSET": return (assets.data ?? []).map((a) => [a.key, a.name]);
      case "IDENTITY": return (ids.data ?? []).map((i) => [i.key, i.display_name]);
      case "GRANT": return (grants.data ?? []).map((g) => [g.key, `${g.key} ${g.principal_key} → ${g.asset_key}`]);
      default: return [];
    }
  };
  return (
    <Card title={<div className="row"><h2>Case #{data.id}: {data.title}</h2><Status value={data.status} /></div>} actions={
      <select value={data.status} disabled={!canWrite} onChange={(e) => void save({ status: e.target.value }, `Case status: ${e.target.value}`)} aria-label="Case status">
        {["OPEN", "CONTAINED", "CLOSED"].map((s) => <option key={s}>{s}</option>)}
      </select>
    }>
      <Field label="Working hypothesis">
        <textarea value={form.hypothesis} onChange={(e) => setForm({ ...form, hypothesis: e.target.value })} onBlur={() => form.hypothesis !== data.hypothesis && canWrite && void save({ hypothesis: form.hypothesis }, "Hypothesis saved")} />
      </Field>
      <Tabs tabs={[["evidence", `Timeline & evidence (${data.evidence.length})`], ["scope", "Scope & severity"], ["remediate", "Containment & remediation"], ["report", "Report"]]} value={tab} onChange={setTab} />

      {tab === "evidence" && (
        <div className="grid two">
          <div>
            <h3>Case timeline</h3>
            <p className="small muted">Events from the case's alerts and linked evidence, in time order (UTC). Link events to cite them in observations.</p>
            <ul className="timeline">
              {timeline.data?.map((e) => (
                <li key={e.event_id} className={e.linked_as_evidence ? "linked" : ["BLOCKED", "DENIED"].includes(e.result) ? "bad" : ""}>
                  <span className="small">{fmtTime(e.timestamp)}</span> <Badge>{e.source_type}</Badge> <Status value={e.result} /> {e.summary}
                  <div className="row small"><span className="mono muted">{e.event_id}</span>
                    {e.linked_as_evidence ? <Badge tone="info">evidence</Badge> : <ActionButton className="small" disabled={!canWrite} onClick={() => linkEvidence("EVENT", e.event_id)}>Link as evidence</ActionButton>}</div>
                </li>
              ))}
            </ul>
            <p className="small">Need events outside the alert? Use the <Link to="/events">Security Event Explorer</Link> and link them to this case.</p>
          </div>
          <div>
            <h3>Evidence references</h3>
            {data.evidence.length === 0 ? <p className="muted small">No evidence yet.</p> : (
              <ul className="small">{data.evidence.map((e: any) => (
                <li key={e.id}><Badge>E{e.id}</Badge> <strong>{e.ref_type}</strong> {e.label}{" "}
                  <ActionButton className="small ghost" disabled={!canWrite} onClick={async () => { await api.del(`/api/sessions/${sid}/cases/${caseId}/evidence/${e.id}`); reloadAll(); }}>remove</ActionButton></li>
              ))}</ul>
            )}
            <div className="row">
              <select value={ev.ref_type} onChange={(e) => setEv({ ref_type: e.target.value, ref_id: "" })} aria-label="Evidence type">
                {["ASSET", "IDENTITY", "GRANT"].map((t) => <option key={t}>{t}</option>)}
              </select>
              <select value={ev.ref_id} onChange={(e) => setEv({ ...ev, ref_id: e.target.value })} aria-label="Evidence item" style={{ maxWidth: 260 }}>
                <option value="">— choose —</option>
                {evOptions().map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <ActionButton className="small" disabled={!canWrite || !ev.ref_id} onClick={() => linkEvidence(ev.ref_type, ev.ref_id)}>Link</ActionButton>
            </div>
            <hr />
            <h3>Analytic notes</h3>
            {["OBSERVATION", "INFERENCE", "UNKNOWN", "HYPOTHESIS"].map((k) => {
              const ns = data.notes.filter((n: any) => n.kind === k);
              return ns.length ? (
                <div key={k}><strong className="small">{k}</strong><ul className="small">{ns.map((n: any) => (
                  <li key={n.id}>{n.text} {n.evidence_ids.length > 0 && <span className="muted">[{n.evidence_ids.map((i: number) => `E${i}`).join(", ")}]</span>}</li>
                ))}</ul></div>
              ) : null;
            })}
            <div className="stack">
              <div className="row">
                <select value={note.kind} onChange={(e) => { const kind = e.target.value; setNote((n) => ({ ...n, kind })); }} aria-label="Note kind">
                  {["OBSERVATION", "INFERENCE", "UNKNOWN", "HYPOTHESIS"].map((k) => <option key={k}>{k}</option>)}
                </select>
                <span className="small muted">{note.kind === "OBSERVATION" ? "Must cite linked evidence." : note.kind === "UNKNOWN" ? "What the evidence cannot tell you." : "A conclusion drawn from observations."}</span>
              </div>
              <textarea value={note.text} onChange={(e) => { const text = e.target.value; setNote((n) => ({ ...n, text })); }} aria-label="Note text" />
              <div className="row small">
                Cite: {data.evidence.map((e: any) => (
                  <label key={e.id} className="inline-check"><input type="checkbox" checked={note.evidence_ids.includes(e.id)}
                    onChange={(x) => { const on = x.target.checked; setNote((n) => ({ ...n, evidence_ids: on ? [...n.evidence_ids.filter((i) => i !== e.id), e.id] : n.evidence_ids.filter((i) => i !== e.id) })); }} />E{e.id}</label>
                ))}
              </div>
              <ActionButton className="small primary" disabled={!canWrite || note.text.trim().length < 5} onClick={async () => {
                const submitted = note;
                await api.post(`/api/sessions/${sid}/cases/${caseId}/notes`, submitted);
                // Only clear if the learner has not started typing the next note meanwhile.
                setNote((n) => (n.text === submitted.text ? { kind: n.kind, text: "", evidence_ids: [] } : n));
                reloadAll();
              }}>Add note</ActionButton>
            </div>
          </div>
        </div>
      )}

      {tab === "scope" && (
        <div className="stack">
          <div className="grid two">
            <Field label="Determination">
              <select value={form.determination ?? ""} onChange={(e) => setForm({ ...form, determination: e.target.value || null })} aria-label="Determination">
                <option value="">— not determined —</option>{vocab.data?.determinations.map((d: string) => <option key={d}>{d}</option>)}
              </select>
            </Field>
            <Field label="Exposure status">
              <select value={form.exposure_status ?? ""} onChange={(e) => setForm({ ...form, exposure_status: e.target.value || null })} aria-label="Exposure status">
                <option value="">— not recorded —</option>{vocab.data?.exposure_statuses.map((d: string) => <option key={d}>{d}</option>)}
              </select>
            </Field>
            <Field label="Records potentially exposed"><input inputMode="numeric" value={form.records_potentially_exposed ?? ""} aria-label="Records potentially exposed"
              onChange={(e) => setForm({ ...form, records_potentially_exposed: e.target.value === "" ? null : Number(e.target.value.replace(/\D/g, "")) })} /></Field>
            <Field label="Severity">
              <select value={form.severity ?? ""} onChange={(e) => setForm({ ...form, severity: e.target.value || null })} aria-label="Severity">
                <option value="">— not assessed —</option>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </Field>
          </div>
          <RiskCalculator sid={sid} labels={labels.data ?? []} onUse={(sev) => setForm({ ...form, severity: sev })} />
          <fieldset style={{ border: "1px solid var(--border)", borderRadius: 6 }}>
            <legend className="small">Affected assets</legend>
            <div className="grid three">{assets.data?.map((a) => (
              <label key={a.key} className="inline-check small"><input type="checkbox" checked={form.affected_asset_keys.includes(a.key)}
                onChange={(e) => setForm({ ...form, affected_asset_keys: e.target.checked ? [...form.affected_asset_keys, a.key] : form.affected_asset_keys.filter((k: string) => k !== a.key) })} />
                {a.name} <LabelBadge label={a.label_key} /> <span className="muted">{fmtNum(a.record_count)}</span></label>
            ))}</div>
          </fieldset>
          <fieldset style={{ border: "1px solid var(--border)", borderRadius: 6 }}>
            <legend className="small">Subject identities (only those the evidence implicates)</legend>
            <div className="grid three">{ids.data?.filter((i) => i.employment_type !== "TEST").map((i) => (
              <label key={i.key} className="inline-check small"><input type="checkbox" checked={form.subject_identities.includes(i.key)}
                onChange={(e) => setForm({ ...form, subject_identities: e.target.checked ? [...form.subject_identities, i.key] : form.subject_identities.filter((k: string) => k !== i.key) })} />
                {i.display_name}</label>
            ))}</div>
          </fieldset>
          <fieldset style={{ border: "1px solid var(--border)", borderRadius: 6 }}>
            <legend className="small">Root causes established by evidence</legend>
            <div className="grid three">{vocab.data?.root_causes.map((r: string) => (
              <label key={r} className="inline-check small"><input type="checkbox" checked={form.root_causes.includes(r)}
                onChange={(e) => setForm({ ...form, root_causes: e.target.checked ? [...form.root_causes, r] : form.root_causes.filter((k: string) => k !== r) })} />{r.replace(/_/g, " ")}</label>
            ))}</div>
          </fieldset>
          <ActionButton className="primary" disabled={!canWrite} onClick={() => save({
            determination: form.determination, exposure_status: form.exposure_status, records_potentially_exposed: form.records_potentially_exposed,
            severity: form.severity, affected_asset_keys: form.affected_asset_keys, subject_identities: form.subject_identities, root_causes: form.root_causes,
          }, "Scope and severity saved")}>Save scope & severity</ActionButton>
        </div>
      )}

      {tab === "remediate" && (
        <div className="stack">
          <Banner tone="info">Actions change the simulated environment immediately and are verified against its state. Some actions destroy evidence or disrupt legitimate users — check the trade-offs. The incident procedure asset describes the required order.</Banner>
          <div className="grid three">
            <Field label="Action">
              <select value={rem.action_type} onChange={(e) => setRem({ ...rem, action_type: e.target.value, target_key: "", confirm: false })} aria-label="Remediation action">
                <option value="">— choose —</option>
                {catalog.map((x) => <option key={x.type} value={x.type}>{x.title} ({x.category.toLowerCase()})</option>)}
              </select>
            </Field>
            <Field label="Target">
              <select value={rem.target_key} disabled={!spec} onChange={(e) => setRem({ ...rem, target_key: e.target.value })} aria-label="Remediation target">
                <option value="">— choose —</option>
                {targetOptions().map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </Field>
            <Field label="Justification"><input value={rem.justification} onChange={(e) => setRem({ ...rem, justification: e.target.value })} aria-label="Remediation justification" /></Field>
          </div>
          {spec && <p className="small">{spec.description}</p>}
          {spec?.destructive && (
            <Banner tone="danger">
              <label className="inline-check"><input type="checkbox" checked={rem.confirm} onChange={(e) => setRem({ ...rem, confirm: e.target.checked })} />
                I understand this action is destructive and cannot be undone in this attempt.</label>
            </Banner>
          )}
          <ActionButton className="primary" disabled={!canWrite || !rem.action_type || !rem.target_key || rem.justification.trim().length < 10 || (spec?.destructive && !rem.confirm)}
            onClick={async () => {
              const r = await api.post(`/api/sessions/${sid}/remediation`, { action_type: rem.action_type, target_key: rem.target_key, justification: rem.justification, case_id: caseId, confirm_destructive: rem.confirm });
              toast(`${r.action_type} → ${r.status}`, r.status === "VERIFICATION_FAILED" ? "danger" : "ok");
              setRem({ action_type: "", target_key: "", justification: "", confirm: false });
              reloadAll();
            }}>Apply action</ActionButton>
          <h3>Applied actions (whole session)</h3>
          {!rems.data?.length ? <p className="muted small">None yet.</p> : (
            <div className="table-wrap"><table>
              <thead><tr><th>#</th><th>Sim time</th><th>Action</th><th>Target</th><th>Status</th><th>Verification</th><th /></tr></thead>
              <tbody>{rems.data.map((r) => (
                <tr key={r.id}><td>{r.seq}</td><td className="small">{fmtTime(r.sim_time)}</td><td>{r.action_type}</td><td className="small">{r.target_key}</td>
                  <td><Status value={r.status} /></td>
                  <td className="small">{r.verification.check}{r.verification.caveat && <div className="muted">Caveat: {r.verification.caveat}</div>}
                    {r.verification.former_members_with_other_access?.length > 0 && <div className="muted">Still has access via other grants: {r.verification.former_members_with_other_access.map((x: any) => x.identity).join(", ")}</div>}
                    {r.verification.local_evidence && <div>{r.verification.local_evidence}</div>}</td>
                  <td><ActionButton className="small" disabled={!canWrite} onClick={async () => { await api.post(`/api/sessions/${sid}/remediation/${r.id}/verify`); rems.reload(); }}>Re-verify</ActionButton></td></tr>
              ))}</tbody>
            </table></div>
          )}
          <p className="small">Fixing the root cause (permissions, labels, policies) is done in the <Link to="/classification?tab=access">Classification Studio</Link> and <Link to="/policies">DLP Policy Studio</Link>; prove it with a control-validation replay in the <Link to="/workspace">Simulation Workspace</Link>.</p>
        </div>
      )}

      {tab === "report" && (
        <div className="stack">
          {(["summary", "root_cause_narrative", "residual_risk", "lessons_learned"] as const).map((k) => (
            <Field key={k} label={k.replace(/_/g, " ").replace(/^./, (x) => x.toUpperCase())}>
              <textarea value={form[k] ?? ""} onChange={(e) => setForm({ ...form, [k]: e.target.value })} aria-label={k} />
            </Field>
          ))}
          <div className="row">
            <ActionButton className="primary" disabled={!canWrite} onClick={() => save({ summary: form.summary, root_cause_narrative: form.root_cause_narrative, residual_risk: form.residual_risk, lessons_learned: form.lessons_learned }, "Report sections saved")}>Save report sections</ActionButton>
            <Link className="btn" to="/assessment">Preview generated reports</Link>
          </div>
          <p className="small muted">Generated reports combine these sections with the recorded evidence, notes, timeline, remediation and verification results. Nothing is invented.</p>
        </div>
      )}
    </Card>
  );
}

function Cases({ sid, selected, setSelected }: { sid: number; selected: number | null; setSelected: (n: number | null) => void }) {
  const cases = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/cases`), [sid, selected]);
  return (
    <div className="grid side" style={{ gridTemplateColumns: "minmax(0, .7fr) minmax(0, 2.3fr)" }}>
      <Card title="Cases">
        {cases.loading ? <Loading /> : !cases.data?.length ? <p className="muted small">No cases. Open one from an alert.</p> : (
          <div className="table-wrap"><table><tbody>{cases.data.map((c) => (
            <tr key={c.id} className={`selectable ${selected === c.id ? "selected" : ""}`} onClick={() => setSelected(c.id)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setSelected(c.id)}>
              <td>#{c.id} {c.title}<div className="row small"><Status value={c.status} />{c.severity && <Status value={c.severity} />}</div></td>
            </tr>
          ))}</tbody></table></div>
        )}
      </Card>
      <div>{selected ? <CaseWorkspace sid={sid} caseId={selected} /> : <Card><Empty title="Select a case" /></Card>}</div>
    </div>
  );
}

function Inner({ sid }: { sid: number }) {
  const [tab, setTab] = useState<"alerts" | "cases">("alerts");
  const [caseId, setCaseId] = useState<number | null>(null);
  return (
    <>
      <PageHead title="Incident Investigation" crumbs="Incident Investigation" mode="SIMULATED">
        <p>Triage alerts, correlate evidence with explicit relationships, separate observations from inferences and unknowns, contain proportionately and verify every state change.</p>
      </PageHead>
      <ReadOnlyNotice />
      <Tabs tabs={[["alerts", "Alert queue"], ["cases", "Cases"]]} value={tab} onChange={setTab} />
      {tab === "alerts" ? <AlertQueue sid={sid} onOpenCase={(id) => { setCaseId(id); setTab("cases"); }} /> : <Cases sid={sid} selected={caseId} setSelected={setCaseId} />}
    </>
  );
}

export default function Investigation() {
  return <NeedSession>{(sid) => <Inner sid={sid} />}</NeedSession>;
}
