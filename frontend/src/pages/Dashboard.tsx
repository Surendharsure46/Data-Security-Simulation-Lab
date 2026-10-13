import { Link } from "react-router-dom";
import { api } from "../api";
import { Badge, Bar, Card, Empty, ErrorBanner, Loading, PageHead, Provenance, Status, fmtTime } from "../components/ui";
import { useLoad, useSession } from "../state";

interface Dash {
  user: { display_name: string };
  pathway: { id: string; title: string; completed: number; total: number; lessons: string[] };
  levels: { id: string; title: string; unlocked: boolean; lessons_total: number; lessons_completed: number }[];
  next_lesson: { id: string; title: string; practice: string; module: string; has_quiz: boolean } | null;
  proficiency: { module: string; title: string; completed: number; total: number; percent: number }[];
  latest_assessment_categories: Record<string, { name: string; percent: number }>;
  recommendations: { lesson_id: string; because: string[] }[];
  unverified_remediations: number;
  recent_sessions: { id: number; scenario_id: string; status: string; mode: string; attempt_number: number; updated_at: string }[];
  recent_attempts: { id: number; session_id: number; score: number; passed: boolean; mode: string; submitted_at: string }[];
  recent_labs: { lab: string; exercise: string; passed: boolean; provenance: string; created_at: string }[];
}

const MODULE_ROUTES: Record<string, string> = {
  M01: "/discovery", M02: "/policies", M03: "/labs/encryption", M04: "/labs/database", M05: "/labs/privacy",
  M06: "/labs/cloud", M07: "/investigation", M08: "/engineering", M09: "/labs/ai", M10: "/learning",
};

export default function Dashboard() {
  const { data, error, loading } = useLoad(() => api.get<Dash>("/api/dashboard"), []);
  const { setSessionId } = useSession();
  if (loading) return <Loading />;
  if (error || !data) return <ErrorBanner error={error} />;
  const p = data.pathway;
  return (
    <>
      <PageHead title={`Welcome, ${data.user.display_name}`}>
        <p>Understand → Discover → Classify → Configure → Execute → Detect → Investigate → Remediate → Verify → Document.</p>
      </PageHead>
      <div className="grid three">
        <Card title="Current learning path" actions={<Link to="/learning" className="btn small">Change</Link>}>
          <h3>{p.title}</h3>
          <Bar value={(100 * p.completed) / p.total} label="Pathway progress" />
          <p className="small muted">{p.completed} of {p.total} lessons completed with verified practical evidence.</p>
        </Card>
        <Card title="Recommended next task">
          {data.next_lesson ? (
            <>
              <h3>{data.next_lesson.id} · {data.next_lesson.title}</h3>
              <p className="small">{data.next_lesson.practice}</p>
              <Link className="btn primary small" to={data.next_lesson.has_quiz ? "/learning" : MODULE_ROUTES[data.next_lesson.module] ?? "/learning"}>Go to practice</Link>
            </>
          ) : (
            <p>All available lessons are complete.</p>
          )}
        </Card>
        <Card title="Outstanding work">
          <p><span className="stat">{data.recommendations.length}</span> <span className="muted">remedial lessons from your latest assessment</span></p>
          <p><span className="stat">{data.unverified_remediations}</span> <span className="muted">remediation actions that failed verification</span></p>
        </Card>
      </div>
      <div className="grid two">
        <Card title="Skill proficiency by module" actions={<span className="small muted">Share of lessons completed with verified evidence</span>}>
          <div className="stack">
            {data.proficiency.map((m) => (
              <div key={m.module}>
                <div className="row between small">
                  <span>{m.module} {m.title}</span>
                  <span className="muted">{m.completed}/{m.total}</span>
                </div>
                <Bar value={m.percent} label={`${m.title} proficiency`} />
              </div>
            ))}
          </div>
        </Card>
        <div>
          <Card title="Levels">
            <div className="table-wrap">
              <table>
                <thead><tr><th>Level</th><th>Status</th><th>Lessons</th></tr></thead>
                <tbody>
                  {data.levels.map((l) => (
                    <tr key={l.id}>
                      <td>{l.id} · {l.title}</td>
                      <td>{l.unlocked ? <Badge tone="ok">Unlocked</Badge> : <Badge>Locked</Badge>}</td>
                      <td>{l.lessons_completed}/{l.lessons_total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title="Recent scenarios">
            {data.recent_sessions.length === 0 ? (
              <Empty title="No scenario sessions yet"><Link className="btn primary" to="/workspace">Start the reference scenario</Link></Empty>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Session</th><th>Mode</th><th>Status</th><th>Updated</th><th /></tr></thead>
                  <tbody>
                    {data.recent_sessions.map((s) => (
                      <tr key={s.id}>
                        <td>#{s.id} {s.scenario_id} (attempt {s.attempt_number})</td>
                        <td>{s.mode}</td>
                        <td><Status value={s.status} /></td>
                        <td className="small">{fmtTime(s.updated_at)}</td>
                        <td><Link to="/workspace" className="btn small" onClick={() => setSessionId(s.id)}>Open</Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      </div>
      <div className="grid two">
        <Card title="Saved assessment reports">
          {data.recent_attempts.length === 0 ? <p className="muted">No submitted assessments yet.</p> : (
            <ul>
              {data.recent_attempts.map((a) => (
                <li key={a.id}>
                  Attempt #{a.id} (session {a.session_id}, {a.mode.toLowerCase()}): {a.score}/100 {a.passed ? <Badge tone="ok">PASS</Badge> : <Badge tone="danger">NOT PASSED</Badge>}{" "}
                  <Link to="/assessment">view</Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Recent lab results">
          {data.recent_labs.length === 0 ? <p className="muted">No lab exercises yet.</p> : (
            <ul>
              {data.recent_labs.map((r, i) => (
                <li key={i}>{r.lab} / {r.exercise}: {r.passed ? "passed" : "attempted"} <Provenance mode={r.provenance} /></li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
