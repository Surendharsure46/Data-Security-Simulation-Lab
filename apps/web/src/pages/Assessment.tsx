import { useState } from "react";
import { Link } from "react-router-dom";
import { api, download } from "../api";
import { ActionButton, Badge, Banner, Card, Empty, Loading, PageHead, Provenance, Status, fmtTime, useToast } from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Attempt } from "../types";

function AttemptView({ a }: { a: Attempt }) {
  return (
    <Card title={`${a.label} — attempt ${a.attempt_number}`} actions={<span className="small muted">submitted {fmtTime(a.submitted_at)}</span>}>
      <div className="row" style={{ marginBottom: 8 }}>
        <span className="stat">{a.total_score}/100</span>
        {a.passed ? <Badge tone="ok">PASS</Badge> : <Badge tone="danger">NOT PASSED</Badge>}
        <span className="small muted">digest {a.inputs_digest.slice(0, 12)}…</span>
      </div>
      <Banner tone="info">{a.disclaimer}</Banner>
      {a.critical_failures.length > 0 && (
        <Banner tone="danger"><strong>Critical failures (cannot be offset by other scores):</strong>
          <ul>{a.critical_failures.map((c) => <li key={c.key}>{c.description} {c.detail}</li>)}</ul></Banner>
      )}
      <div className="grid four" style={{ marginBottom: 12 }}>
        {Object.values(a.category_scores).map((c) => (
          <div key={c.name} className="card tight" style={{ marginBottom: 0 }}>
            <div className="stat-label">{c.name} ({c.weight}%)</div>
            <div className="stat">{c.percent}%</div>
            <div className="small muted">{c.weighted} weighted points</div>
          </div>
        ))}
      </div>
      <div className="table-wrap"><table>
        <thead><tr><th>Criterion</th><th>Category</th><th>Score</th><th>Explanation</th></tr></thead>
        <tbody>{a.criteria.map((c) => (
          <tr key={c.key}><td>{c.description}</td><td className="small">{c.category}</td>
            <td>{c.earned}/{c.points} {c.earned < c.points && <Badge tone={c.earned === 0 ? "danger" : "warn"}>−{(c.points - c.earned).toFixed(1)}</Badge>}</td>
            <td className="small">{c.explanation}</td></tr>
        ))}</tbody>
      </table></div>
      <div className="grid two" style={{ marginTop: 12 }}>
        <div><h3>Missing tasks</h3>{a.missing_tasks.length ? <ul>{a.missing_tasks.map((t) => <li key={t}>{t}</li>)}</ul> : <p className="muted">None.</p>}</div>
        <div><h3>Targeted learning</h3>{a.recommendations.length ? <ul>{a.recommendations.map((r) => <li key={r.lesson_id}><Link to="/learning">{r.lesson_id}</Link>: {r.because.join("; ")}</li>)}</ul> : <p className="muted">None.</p>}</div>
      </div>
    </Card>
  );
}

function ReportViewer({ sid }: { sid: number }) {
  const types = useLoad(() => api.get<{ type: string; title: string; formats: string[] }[]>(`/api/sessions/${sid}/reports`), [sid]);
  const [open, setOpen] = useState<string | null>(null);
  const body = useLoad(() => (open ? api.text(`/api/sessions/${sid}/reports/${open}?format=md`) : Promise.resolve("")), [sid, open]);
  return (
    <Card title="Reports" actions={<Provenance mode="SIMULATED" />}>
      <p className="small muted">Generated from recorded session state at request time. Markdown, HTML (escaped) and JSON for all; CSV for tabular reports.</p>
      <div className="table-wrap"><table>
        <thead><tr><th>Report</th><th>View</th><th>Download</th></tr></thead>
        <tbody>{types.data?.map((t) => (
          <tr key={t.type}><td>{t.title}</td>
            <td><button className="small" onClick={() => setOpen(open === t.type ? null : t.type)}>{open === t.type ? "Hide" : "View"}</button></td>
            <td className="row">{t.formats.map((f) => (
              <ActionButton key={f} className="small" onClick={() => download(`/api/sessions/${sid}/reports/${t.type}?format=${f}&download=true`, `threatready-${t.type}-session${sid}.${f}`)}>{f.toUpperCase()}</ActionButton>
            ))}</td></tr>
        ))}</tbody>
      </table></div>
      {open && (body.loading ? <Loading /> : <pre style={{ maxHeight: 600, marginTop: 12 }} data-testid="report-body">{body.data}</pre>)}
    </Card>
  );
}

export default function Assessment() {
  const { session, canWrite, refresh } = useSession();
  const toast = useToast();
  const all = useLoad(() => api.get<Attempt[]>("/api/attempts"), [session?.status, session?.attempt_number]);
  const sid = session?.id;
  return (
    <>
      <PageHead title="Assessment & Reports" crumbs="Assessment & Reports">
        <p>Scores are computed only on the server from recorded session state, using the documented rubric. Results describe what this scenario assessed; they are not a professional certification.</p>
      </PageHead>
      {!session ? (
        <Card><Empty title="No active workspace"><p>Select a session to submit it or view its reports.</p><Link className="btn primary" to="/workspace">Simulation Workspace</Link></Empty></Card>
      ) : (
        <>
          <Card title={`Session #${session.id}: ${session.scenario.title}`} actions={<Status value={session.status} />}>
            <div className="grid two">
              <div>
                <h3>Rubric (configurable default weights)</h3>
                <ul className="small">{Object.values(session.scenario.rubric.categories).map((c) => <li key={c.name}>{c.name}: {c.weight}%</li>)}</ul>
                <p className="small">Pass mark {session.scenario.rubric.pass_threshold}/100 and no critical failure:</p>
                <ul className="small">{session.scenario.rubric.critical_conditions.map((c) => <li key={c.key}>{c.description}</li>)}</ul>
              </div>
              <div>
                <h3>Before you submit</h3>
                <p className="small">{session.progress.filter((t) => !t.done).length} of {session.progress.length} tasks are not yet complete. Submitting locks the session; reset afterwards to try again with a new variant.</p>
                {session.mission ? (
                  <Banner tone="info">This session belongs to mission {session.mission.mission_id}. <Link to={`/missions/${session.mission.attempt_id}`}>Submit your evidence and explanation in the mission view</Link>.</Banner>
                ) : <ActionButton className="primary" disabled={!canWrite} confirm="Submit this session for grading? It becomes read-only." onClick={async () => {
                  const a = await api.post<Attempt>(`/api/sessions/${sid}/submit`, { confirm: true });
                  toast(`Submitted: ${a.total_score}/100 ${a.passed ? "PASS" : "NOT PASSED"}`, a.passed ? "ok" : "info");
                  await refresh();
                  all.reload();
                }}>Submit for assessment</ActionButton>}
              </div>
            </div>
          </Card>
          {session.latest_attempt && <AttemptView a={session.latest_attempt} />}
          <ReportViewer sid={session.id} />
        </>
      )}
      <Card title="All submitted attempts">
        {all.loading ? <Loading /> : !all.data?.length ? <p className="muted">None yet.</p> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Attempt</th><th>Session</th><th>Mode</th><th>Score</th><th>Result</th><th>Submitted</th><th>Report snapshot</th></tr></thead>
            <tbody>{all.data.map((a) => (
              <tr key={a.id}><td>#{a.id} (attempt {a.attempt_number})</td><td>{a.session_id}</td><td>{a.mode}</td><td>{a.total_score}</td>
                <td>{a.passed ? <Badge tone="ok">PASS</Badge> : <Badge tone="danger">NOT PASSED</Badge>}</td><td className="small">{fmtTime(a.submitted_at)}</td>
                <td><ActionButton className="small" onClick={() => download(`/api/attempts/${a.id}/report`, `threatready-attempt${a.id}-case-report.md`)}>Download</ActionButton></td></tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
    </>
  );
}
