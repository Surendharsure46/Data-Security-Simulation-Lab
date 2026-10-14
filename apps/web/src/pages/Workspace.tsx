import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { TraceList } from "../components/Trace";
import {
  ActionButton, Badge, Bar, Banner, Card, Empty, ErrorBanner, Field, KV, Loading, PageHead, Provenance, Status, fmtTime, useToast,
} from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Alert, Asset, Destination, Identity, Policy, ScenarioPublic, SecEvent, SessionSummary } from "../types";

function Launcher() {
  const { setSessionId } = useSession();
  const toast = useToast();
  const scen = useLoad(() => api.get<ScenarioPublic[]>("/api/scenarios"), []);
  const sess = useLoad(() => api.get<SessionSummary[]>("/api/sessions"), []);
  if (scen.loading || sess.loading) return <Loading />;
  return (
    <>
      <ErrorBanner error={scen.error || sess.error} />
      {scen.data?.map((s) => (
        <Card key={s.id} title={s.title} actions={<><Badge tone="info">{s.level} · {s.difficulty}</Badge><Badge>{s.estimated_minutes} min</Badge><Provenance mode="SIMULATED" /></>}>
          <p>{s.summary}</p>
          <details>
            <summary>Learning objectives and assessment rubric</summary>
            <ul>{s.objectives.map((o) => <li key={o}>{o}</li>)}</ul>
            <p className="small">Pass mark {s.rubric.pass_threshold}/100 with no critical failures. Critical conditions: {s.rubric.critical_conditions.map((c) => c.description).join(" ")}</p>
          </details>
          <div className="row" style={{ marginTop: 10 }}>
            <ActionButton className="primary" onClick={async () => {
              const r = await api.post("/api/sessions", { scenario_id: s.id, mode: "GUIDED" });
              setSessionId(r.id);
              toast("Guided session started");
            }}>Start guided practice</ActionButton>
            <ActionButton onClick={async () => {
              const r = await api.post("/api/sessions", { scenario_id: s.id, mode: "ASSESSMENT" });
              setSessionId(r.id);
              toast("Independent assessment started (no hints, random variant)");
            }}>Start independent assessment</ActionButton>
            <span className="small muted">{s.variant_count} variants · guided mode offers hints; assessment mode does not.</span>
          </div>
        </Card>
      ))}
      <Card title="Your sessions">
        {sess.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Session</th><th>Mode</th><th>Status</th><th>Runs</th><th>Updated</th><th /></tr></thead>
              <tbody>
                {sess.data.map((s) => (
                  <tr key={s.id}>
                    <td>#{s.id} {s.scenario_title} · attempt {s.attempt_number} {s.mission && <Badge tone="info">{s.mission.mission_id}</Badge>}</td>
                    <td>{s.mode}</td><td><Status value={s.status} /></td><td>{s.run_count}</td>
                    <td className="small">{fmtTime(s.updated_at)}</td>
                    <td><button className="small" onClick={() => setSessionId(s.id)}>Open</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="muted">No sessions yet.</p>}
      </Card>
    </>
  );
}

function Hints({ sid, taskKey, enabled, available, revealed, onReveal }: {
  sid: number; taskKey: string; enabled: boolean; available: number; revealed: string[]; onReveal: () => void;
}) {
  if (available === 0) return null;
  return (
    <div className="small">
      {revealed.map((h, i) => <div key={i} className="banner info" style={{ margin: "4px 0", padding: "4px 8px" }}>Hint {i + 1}: {h}</div>)}
      {enabled && revealed.length < available && (
        <ActionButton className="small ghost" onClick={async () => { await api.post(`/api/sessions/${sid}/hints/${taskKey}`); onReveal(); }}>
          Reveal hint ({available - revealed.length} left)
        </ActionButton>
      )}
    </div>
  );
}
const ACTIONS = ["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT", "SIGN_IN"];

function ActivitySimulator({ sid, canWrite, onDone }: { sid: number; canWrite: boolean; onDone: () => void }) {
  const ids = useLoad(() => api.get<Identity[]>(`/api/sessions/${sid}/identities`), [sid]);
  const assets = useLoad(() => api.get<Asset[]>(`/api/sessions/${sid}/assets`), [sid]);
  const dests = useLoad(() => api.get<Destination[]>(`/api/sessions/${sid}/destinations`), [sid]);
  const [form, setForm] = useState({ actor: "u-jokafor", action: "UPLOAD", resource: "ast-cust-export-q1", destination: "dst-personal-cloud", record_count: "", business_justification: "", ticket_id: "" });
  const [result, setResult] = useState<any>(null);
  const needsDest = !["DOWNLOAD", "SIGN_IN"].includes(form.action);
  return (
    <Card title="Activity generator" actions={<span className="small muted">Runs one synthetic activity through identity, access, egress and DLP controls. Generates real events and alerts in this session.</span>}>
      <div className="grid four">
        <Field label="Actor">
          <select value={form.actor} onChange={(e) => setForm({ ...form, actor: e.target.value })}>
            {ids.data?.map((i) => <option key={i.key} value={i.key}>{i.display_name} ({i.key})</option>)}
          </select>
        </Field>
        <Field label="Action">
          <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })}>
            {ACTIONS.map((a) => <option key={a}>{a}</option>)}
          </select>
        </Field>
        <Field label="Resource">
          <select value={form.resource} disabled={form.action === "SIGN_IN"} onChange={(e) => setForm({ ...form, resource: e.target.value })}>
            {assets.data?.map((a) => <option key={a.key} value={a.key}>{a.name}</option>)}
          </select>
        </Field>
        <Field label="Destination">
          <select value={form.destination} disabled={!needsDest} onChange={(e) => setForm({ ...form, destination: e.target.value })}>
            {dests.data?.map((d) => <option key={d.key} value={d.key}>{d.name}</option>)}
          </select>
        </Field>
        <Field label="Records (optional)"><input inputMode="numeric" value={form.record_count} onChange={(e) => setForm({ ...form, record_count: e.target.value.replace(/\D/g, "") })} /></Field>
        <Field label="Business justification"><input value={form.business_justification} onChange={(e) => setForm({ ...form, business_justification: e.target.value })} /></Field>
        <Field label="Ticket ID"><input value={form.ticket_id} onChange={(e) => setForm({ ...form, ticket_id: e.target.value })} /></Field>
        <div className="row" style={{ alignItems: "flex-end" }}>
          <ActionButton className="primary" disabled={!canWrite} onClick={async () => {
            const body: Record<string, unknown> = { actor: form.actor, action: form.action };
            if (form.action !== "SIGN_IN") body.resource = form.resource;
            if (needsDest) body.destination = form.destination;
            if (form.record_count) body.record_count = Number(form.record_count);
            if (form.business_justification) body.business_justification = form.business_justification;
            if (form.ticket_id) body.ticket_id = form.ticket_id;
            setResult(await api.post(`/api/sessions/${sid}/activities`, body));
            onDone();
          }}>Execute activity</ActionButton>
        </div>
      </div>
      {result && (
        <div style={{ marginTop: 12 }}>
          <div className="row"><strong>Outcome:</strong> <Status value={result.outcome} /> <span className="small">{result.reason}</span></div>
          <h3 style={{ marginTop: 10 }}>Generated events ({result.events.length})</h3>
          <ul className="timeline">
            {result.events.map((e: SecEvent) => (
              <li key={e.event_id} className={["BLOCKED", "DENIED", "FAILURE"].includes(e.result) ? "bad" : "good"}>
                <span className="mono small">{e.event_id}</span> <Badge>{e.source_type}</Badge> <Status value={e.result} /> {e.summary}
              </li>
            ))}
          </ul>
          {result.alerts.length > 0 && <Banner tone="warn">{result.alerts.length} alert(s) raised: {result.alerts.map((a: Alert) => a.title).join("; ")}</Banner>}
          {result.policy_trace?.length > 0 && <details><summary>Policy evaluation trace</summary><TraceList entries={result.policy_trace} /></details>}
        </div>
      )}
    </Card>
  );
}

export default function Workspace() {
  const { session, sessionId, setSessionId, refresh, canWrite } = useSession();
  const toast = useToast();
  const sid = session?.id;
  const policies = useLoad(() => (sid ? api.get<Policy[]>(`/api/sessions/${sid}/policies`) : Promise.resolve([])), [sid, session?.updated_at]);
  const alerts = useLoad(() => (sid ? api.get<Alert[]>(`/api/sessions/${sid}/alerts`) : Promise.resolve([])), [sid, session?.updated_at]);
  const hints = useLoad(() => (sid ? api.get<Record<string, string[]>>(`/api/sessions/${sid}/hints`) : Promise.resolve({} as Record<string, string[]>)), [sid, session?.attempt_number]);
  const [newVariant, setNewVariant] = useState(true);

  if (sessionId && !session) return <Loading label="Loading session…" />;
  if (!session) {
    return (
      <>
        <PageHead title="Simulation Workspace" crumbs="Simulation Workspace" mode="SIMULATED">
          <p>Each session provisions a private copy of the synthetic company Kestrel Ridge Financial. Nothing you do here affects other learners or any real system.</p>
        </PageHead>
        <Banner tone="info">Assessed work happens in your <Link to="/mission">assigned mission</Link>, which opens its own workspace. Sessions started here are a free practice sandbox: they are graded but do not complete missions or record skills.</Banner>
        <Launcher />
      </>
    );
  }
  const sc = session.scenario;
  const stages = Array.from(new Set(session.progress.map((t) => t.stage)));
  return (
    <>
      <PageHead title={sc.title} crumbs="Simulation Workspace" mode="SIMULATED" actions={
        <>
          {session.status === "ACTIVE" && <ActionButton onClick={async () => { await api.post(`/api/sessions/${sid}/pause`); await refresh(); }}>Pause</ActionButton>}
          {session.status === "PAUSED" && <ActionButton className="primary" onClick={async () => { await api.post(`/api/sessions/${sid}/resume`); await refresh(); }}>Resume</ActionButton>}
          {session.mission ? <Link className="btn primary" to={`/missions/${session.mission.attempt_id}`}>Back to mission {session.mission.mission_id}</Link> : <>
          <label className="inline-check small"><input type="checkbox" checked={newVariant} onChange={(e) => setNewVariant(e.target.checked)} /> new variant on reset</label>
          <ActionButton confirm="Reset discards all work in this session and starts a new attempt. Submitted results are kept. Continue?" onClick={async () => {
            await api.post(`/api/sessions/${sid}/reset`, { confirm: true, new_variant: newVariant });
            toast("Session reset to the initial state");
            await refresh();
          }}>Reset</ActionButton></>}
          <button className="ghost" onClick={() => setSessionId(null)}>Switch scenario</button>
        </>
      }>
        <p>Session #{session.id} · attempt {session.attempt_number} · {session.mode === "GUIDED" ? "guided practice (hints available)" : "independent assessment (no hints)"} · sim clock {fmtTime(session.sim_clock)}</p>
      </PageHead>
      {session.mission && (
        <Banner tone="info">This workspace belongs to mission <strong>{session.mission.mission_id}</strong>. Submit your evidence and explanation from the <Link to={`/missions/${session.mission.attempt_id}`}>mission view</Link>; to start over use <em>Retry with practice or new variant</em> there.</Banner>
      )}
      {session.status === "SUBMITTED" && !session.mission && (
        <Banner tone="info">Submitted. Score {session.latest_attempt?.total_score}/100 — {session.latest_attempt?.passed ? "PASS" : "NOT PASSED"}. <Link to="/assessment">View results and reports</Link>. Reset to start a new attempt.</Banner>
      )}
      {session.status === "PAUSED" && <Banner tone="warn">Paused. All change operations are refused by the server until you resume.</Banner>}
      <div className="grid side">
        <div>
          <Card title="Briefing">
            <p>{sc.briefing}</p>
            <details><summary>Objectives</summary><ul>{sc.objectives.map((o) => <li key={o}>{o}</li>)}</ul></details>
          </Card>
          <Card title="Execute the business day" actions={<Provenance mode="SIMULATED" />}>
            <p className="small">The scripted business day replays employee activity through your <em>current</em> controls. A <strong>control-validation replay</strong> repeats the day the next sim-day, substituting a test identity cloned from the original actor's role so that the fix — not just an account lockout — is verified.</p>
            <div className="row">
              <ActionButton className="primary" disabled={!canWrite} onClick={async () => {
                const r = await api.post(`/api/sessions/${sid}/timeline/run`, { mode: "standard" });
                toast(`Run ${r.run_number}: ${r.events_generated} events, ${r.alerts_generated} alerts, ${r.blocked_or_denied} prevented`);
                await refresh();
              }}>Run business day</ActionButton>
              <ActionButton disabled={!canWrite || session.run_count < 1} onClick={async () => {
                const r = await api.post(`/api/sessions/${sid}/timeline/run`, { mode: "validation" });
                toast(`Validation run ${r.run_number}: ${r.blocked_or_denied} activities prevented, ${r.alerts_generated} alerts`);
                await refresh();
              }}>Run control-validation replay</ActionButton>
            </div>
            {session.runs.length > 0 && (
              <div className="table-wrap" style={{ marginTop: 10 }}>
                <table>
                  <thead><tr><th>Run</th><th>Type</th><th>Sim day</th><th /></tr></thead>
                  <tbody>{session.runs.map((r) => (
                    <tr key={r.run_number}><td>{r.run_number}</td><td>{r.mode === "validation" ? "Control-validation replay" : "Business day"}</td><td>{r.sim_day}</td>
                      <td><Link className="btn small" to={`/events?run=${r.run_number}`}>Events</Link></td></tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </Card>
          <ActivitySimulator sid={session.id} canWrite={canWrite} onDone={() => void refresh()} />
          <Card title="Active policies" actions={<Link className="btn small" to="/policies">Open DLP Policy Studio</Link>}>
            {policies.loading ? <Loading /> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Policy</th><th>Kind</th><th>Status</th><th>Outcome</th><th>Version</th></tr></thead>
                <tbody>{policies.data?.map((p) => (
                  <tr key={p.key}><td>{p.key}<div className="small muted">{p.definition.name}</div></td><td>{p.kind}</td><td><Status value={p.status} /></td>
                    <td><Status value={p.definition.outcome} /></td><td>v{p.current_version}</td></tr>
                ))}</tbody>
              </table></div>
            )}
          </Card>
        </div>
        <div>
          <Card title="Progress">
            <Bar value={session.progress_percent} label="Scenario progress" />
            <p className="small muted">{session.progress_percent}% of tasks complete. Completion shows that a task was done, not whether it was done correctly — correctness is assessed on submission.</p>
            {stages.map((stage) => (
              <div key={stage}>
                <div className="nav-group" style={{ color: "var(--text-3)", padding: 0 }}>{stage}</div>
                <ul className="tasklist">
                  {session.progress.filter((t) => t.stage === stage).map((t) => (
                    <li key={t.key}>
                      <span className={`check ${t.done ? "done" : ""}`} aria-label={t.done ? "done" : "not done"}>{t.done ? "✓" : ""}</span>
                      <div>
                        <div><strong>{t.title}</strong></div>
                        <div className="small muted">{t.description}</div>
                        <Hints sid={session.id} taskKey={t.key} enabled={session.hints_enabled && canWrite} available={t.hints_available}
                          revealed={hints.data?.[t.key] ?? []} onReveal={hints.reload} />
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            <hr />
            {session.mission ? <Link className="btn primary" to={`/missions/${session.mission.attempt_id}`}>Go to mission submission</Link>
              : <Link className="btn primary" to="/assessment">Submit for assessment</Link>}
          </Card>
          <Card title="Environment state">
            <KV items={[
              ["Events", session.counts.events], ["Alerts (open)", `${session.counts.alerts} (${session.counts.open_alerts} untriaged)`],
              ["Cases", session.counts.cases], ["Policies", session.counts.policies], ["Unlabeled assets", session.counts.unlabeled_assets],
              ["Remediation actions", session.counts.remediations],
            ]} />
          </Card>
          <Card title="Recent alerts" actions={<Link className="btn small" to="/investigation">Investigate</Link>}>
            {alerts.data?.length ? (
              <ul className="timeline">{alerts.data.slice(-6).reverse().map((a) => (
                <li key={a.alert_id} className={a.disposition ? "good" : "bad"}>
                  <Status value={a.severity} /> {a.title} <div className="small muted">{fmtTime(a.timestamp)} · {a.disposition ?? "untriaged"}</div>
                </li>
              ))}</ul>
            ) : <Empty title="No alerts yet"><p className="small">Run the business day or execute an activity.</p></Empty>}
          </Card>
        </div>
      </div>
    </>
  );
}
