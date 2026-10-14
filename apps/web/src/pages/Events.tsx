import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, download } from "../api";
import { ActionButton, Badge, Card, Empty, ErrorBanner, Field, KV, Loading, NeedSession, PageHead, Provenance, Status, fmtTime, useToast } from "../components/ui";
import { useLoad, useSession } from "../state";
import type { SecEvent } from "../types";

const SOURCES = ["", "IDENTITY", "FILE_ACCESS", "DATABASE", "CLOUD_STORAGE", "DLP", "DETECTION", "EMAIL_GATEWAY", "PROXY", "ENDPOINT"];
const RESULTS = ["", "ALLOWED", "ALLOWED_WITH_WARNING", "BLOCKED", "DENIED", "SUCCESS", "FAILURE", "DETECTED"];

function EventDetail({ sid, id, onClose }: { sid: number; id: string; onClose: () => void }) {
  const { canWrite } = useSession();
  const toast = useToast();
  const ev = useLoad(() => api.get(`/api/sessions/${sid}/events/${id}`), [sid, id]);
  const cases = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/cases`), [sid]);
  const [caseId, setCaseId] = useState<string>("");
  if (ev.loading) return <Card><Loading /></Card>;
  if (ev.error) return <ErrorBanner error={ev.error} />;
  const e = ev.data;
  return (
    <Card title={<span className="mono">{e.event_id}</span>} actions={<button className="small ghost" onClick={onClose}>Close</button>}>
      <p>{e.summary}</p>
      <KV items={[
        ["Timestamp", fmtTime(e.timestamp)], ["Provenance", <Provenance mode={e.provenance} />], ["Source", `${e.source_type} · ${e.source_system}`],
        ["Actor", e.actor_id], ["Resource", e.resource_id], ["Action", e.action], ["Result", <Status value={e.result} />],
        ["Classification at time", e.data_classification ?? "unlabeled"], ["Destination", e.destination],
        ["Policy", e.policy_id ? `${e.policy_id} v${e.policy_version}` : null], ["Transaction", <span className="mono small">{e.transaction_id}</span>],
        ["Run", e.run_number === 0 ? "learner activity / probe" : e.run_number], ["Evidence refs", e.evidence_refs.join(", ") || "—"],
      ]} />
      <h3 style={{ marginTop: 10 }}>Source-specific extension</h3>
      <pre>{JSON.stringify(e.extension, null, 2)}</pre>
      <h3>Related events ({e.related.length})</h3>
      <ul className="small">{e.related.map((r: SecEvent) => <li key={r.event_id}><span className="mono">{r.event_id}</span> {r.source_type} <Status value={r.result} /> {r.summary}</li>)}</ul>
      {e.alerts.length > 0 && <><h3>Alerts referencing this event</h3><ul className="small">{e.alerts.map((a: any) => <li key={a.alert_id}>{a.alert_id}: {a.title}</li>)}</ul></>}
      <hr />
      <div className="row">
        <Field label="Link to case">
          <select value={caseId} onChange={(x) => setCaseId(x.target.value)} aria-label="Case">
            <option value="">— choose case —</option>
            {cases.data?.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
          </select>
        </Field>
        <ActionButton disabled={!canWrite || !caseId} onClick={async () => {
          await api.post(`/api/sessions/${sid}/cases/${caseId}/evidence`, { ref_type: "EVENT", ref_id: e.event_id });
          toast(`Linked ${e.event_id} to case #${caseId}`);
          ev.reload();
        }}>Link as evidence</ActionButton>
      </div>
    </Card>
  );
}

function Inner({ sid }: { sid: number }) {
  const [params] = useSearchParams();
  const [f, setF] = useState({ q: "", actor: "", resource: "", source_type: "", result: "", run: params.get("run") ?? "" });
  const [sel, setSel] = useState<string | null>(null);
  const qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v) as [string, string][]);
  const events = useLoad(() => api.get<SecEvent[]>(`/api/sessions/${sid}/events?${qs}`), [sid, qs.toString()]);
  return (
    <>
      <PageHead title="Security Event Explorer" crumbs="Security Event Explorer" mode="SIMULATED" actions={
        <ActionButton onClick={() => download(`/api/sessions/${sid}/export/events`, `threatready-session${sid}-events.jsonl`)}>Export JSON Lines</ActionButton>
      }>
        <p>Every event follows the common schema and records its provenance. Source systems prefixed <code>kr-sim-</code> are simulation components, not vendor products. Times are UTC.</p>
      </PageHead>
      <Card>
        <div className="grid four">
          <Field label="Search"><input value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} placeholder="text, id, actor, resource" /></Field>
          <Field label="Actor"><input value={f.actor} onChange={(e) => setF({ ...f, actor: e.target.value })} placeholder="e.g. u-mchen" /></Field>
          <Field label="Resource"><input value={f.resource} onChange={(e) => setF({ ...f, resource: e.target.value })} placeholder="e.g. ast-payroll-mar" /></Field>
          <Field label="Run"><input value={f.run} onChange={(e) => setF({ ...f, run: e.target.value.replace(/\D/g, "") })} placeholder="0 = ad-hoc" /></Field>
          <Field label="Source type"><select value={f.source_type} onChange={(e) => setF({ ...f, source_type: e.target.value })}>{SOURCES.map((s) => <option key={s} value={s}>{s || "any"}</option>)}</select></Field>
          <Field label="Result"><select value={f.result} onChange={(e) => setF({ ...f, result: e.target.value })}>{RESULTS.map((s) => <option key={s} value={s}>{s || "any"}</option>)}</select></Field>
        </div>
      </Card>
      <div className="grid side">
        <Card title={`Events (${events.data?.length ?? 0})`}>
          <ErrorBanner error={events.error} />
          {events.loading ? <Loading /> : events.data?.length === 0 ? <Empty title="No events match"><p>Run the business day or execute an activity in the Simulation Workspace.</p></Empty> : (
            <div className="table-wrap" style={{ maxHeight: 640, overflowY: "auto" }}><table>
              <thead><tr><th>Time (UTC)</th><th>Run</th><th>Source</th><th>Actor</th><th>Action</th><th>Resource</th><th>Result</th><th>Policy</th></tr></thead>
              <tbody>{events.data?.map((e) => (
                <tr key={e.event_id} className={`selectable ${sel === e.event_id ? "selected" : ""}`} tabIndex={0}
                  onClick={() => setSel(e.event_id)} onKeyDown={(k) => k.key === "Enter" && setSel(e.event_id)}>
                  <td className="small">{e.timestamp.slice(5, 19).replace("T", " ")}</td><td>{e.run_number}</td><td><Badge>{e.source_type}</Badge></td>
                  <td className="small">{e.actor_id ?? "—"}</td><td>{e.action}</td><td className="small">{e.resource_id ?? "—"}</td>
                  <td><Status value={e.result} /></td><td className="small">{e.policy_id ? `${e.policy_id} v${e.policy_version}` : ""}</td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
        <div>{sel ? <EventDetail sid={sid} id={sel} onClose={() => setSel(null)} /> : <Card><Empty title="Select an event"><p>Inspect fields, the source-specific extension, related events and linked alerts.</p></Empty></Card>}</div>
      </div>
    </>
  );
}

export default function Events() {
  return <NeedSession>{(sid) => <Inner sid={sid} />}</NeedSession>;
}
