import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ActionButton, Badge, Bar, Card, ErrorBanner, Loading, PageHead, Provenance, useToast } from "../components/ui";
import { useLoad } from "../state";

interface Lesson {
  id: string; module: string; level: string; title: string; body: string; practice: string;
  completed: boolean; available: boolean; check_type: string; in_pathway: boolean; has_quiz: boolean;
}
interface Curriculum {
  levels: any[];
  modules: { id: string; title: string; route: string; status: string; mode: string; summary: string; lessons_total: number; lessons_completed: number }[];
  lessons: Lesson[];
  pathways: { id: string; title: string; audience: string; completed: number; total: number; selected: boolean }[];
}

function Quiz({ lessonId, onDone }: { lessonId: string; onDone: () => void }) {
  const { data, error, loading } = useLoad(() => api.get(`/api/curriculum/quiz/${lessonId}`), [lessonId]);
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [result, setResult] = useState<{ score: number; passed: boolean; correct: boolean[] } | null>(null);
  if (loading) return <Loading />;
  if (error) return <ErrorBanner error={error} />;
  return (
    <div className="stack">
      {data.questions.map((q: { q: string; options: string[] }, i: number) => (
        <fieldset key={i} style={{ border: "1px solid var(--border)", borderRadius: 6 }}>
          <legend>{i + 1}. {q.q} {result && (result.correct[i] ? <Badge tone="ok">correct</Badge> : <Badge tone="danger">incorrect</Badge>)}</legend>
          {q.options.map((o, j) => (
            <label key={j} className="inline-check" style={{ display: "flex" }}>
              <input type="radio" name={`q${i}`} checked={answers[i] === j} onChange={() => setAnswers({ ...answers, [i]: j })} /> {o}
            </label>
          ))}
        </fieldset>
      ))}
      <ActionButton className="primary" disabled={Object.keys(answers).length !== data.questions.length} onClick={async () => {
        const r = await api.post(`/api/curriculum/quiz/${lessonId}`, { answers: data.questions.map((_: unknown, i: number) => answers[i]) });
        setResult(r);
        if (r.passed) onDone();
      }}>Submit answers</ActionButton>
      {result && <p>Score {Math.round(result.score * 100)}% — {result.passed ? "passed (graded on the server)." : "not passed; review the lesson and retry (75% required)."}</p>}
    </div>
  );
}

export default function Learning() {
  const { data, error, loading, reload } = useLoad(() => api.get<Curriculum>("/api/curriculum"), []);
  const [open, setOpen] = useState<string | null>(null);
  const toast = useToast();
  if (loading) return <Loading />;
  if (error || !data) return <ErrorBanner error={error} />;
  const moduleById = Object.fromEntries(data.modules.map((m) => [m.id, m]));
  return (
    <>
      <PageHead title="Learning Paths" crumbs="Learning Paths">
        <p>Lessons are completed only by server-verified practical work — a scenario task, a lab exercise or a graded knowledge check. Reading never completes a lesson.</p>
      </PageHead>
      <Card title="Pathways" actions={<span className="small muted">Specialist pathways unlock their own lessons without requiring unrelated modules.</span>}>
        <div className="grid four">
          {data.pathways.map((p) => (
            <div key={p.id} className="card tight" style={{ marginBottom: 0, borderColor: p.selected ? "var(--primary)" : undefined }}>
              <h3>{p.title}</h3>
              <p className="small muted">{p.audience}</p>
              <Bar value={(100 * p.completed) / p.total} label={`${p.title} progress`} />
              <div className="row between small" style={{ marginTop: 6 }}>
                <span>{p.completed}/{p.total}</span>
                {p.selected ? <Badge tone="info">Selected</Badge> : (
                  <ActionButton className="small" onClick={async () => { await api.put("/api/curriculum/pathway", { pathway: p.id }); toast(`Pathway set: ${p.title}`); reload(); }}>Select</ActionButton>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>
      {data.levels.map((lv) => (
        <Card key={lv.id} title={`${lv.id} — ${lv.title}`} actions={lv.unlocked ? <Badge tone="ok">Unlocked</Badge> : <Badge>Locked: complete {lv.unlock.min_lessons_in_previous} lessons in {lv.unlock.requires.join(", ")}</Badge>}>
          <details>
            <summary className="small">Level definition: objectives, evidence, rubric and critical failures</summary>
            <div className="grid two small" style={{ marginTop: 8 }}>
              <div><strong>Objectives</strong><ul>{lv.objectives.map((o: string) => <li key={o}>{o}</li>)}</ul>
                <strong>Practical tasks</strong><ul>{lv.practical_tasks.map((o: string) => <li key={o}>{o}</li>)}</ul>
                <strong>Scenario variations</strong><ul>{lv.scenario_variations.map((o: string) => <li key={o}>{o}</li>)}</ul></div>
              <div><strong>Required evidence</strong><ul>{lv.required_evidence.map((o: string) => <li key={o}>{o}</li>)}</ul>
                <strong>Scoring</strong><p>{lv.rubric}</p>
                <strong>Critical failures</strong><ul>{lv.critical_failures.map((o: string) => <li key={o}>{o}</li>)}</ul>
                <strong>Remediation</strong><ul>{lv.remediation.map((o: string) => <li key={o}>{o}</li>)}</ul></div>
            </div>
          </details>
          <div className="table-wrap" style={{ marginTop: 8 }}>
            <table>
              <thead><tr><th>Lesson</th><th>Module</th><th>Practical activity</th><th>Status</th><th /></tr></thead>
              <tbody>
                {data.lessons.filter((l) => l.level === lv.id).map((l) => {
                  const m = moduleById[l.module];
                  return (
                    <Fragment key={l.id}>
                      <tr>
                        <td><strong>{l.id}</strong> {l.title} {l.in_pathway && <Badge tone="info">pathway</Badge>}</td>
                        <td className="small">{m.title} <Provenance mode={m.mode} /> {m.status === "PLANNED" && <Badge tone="warn">PLANNED</Badge>}</td>
                        <td className="small">{l.practice}</td>
                        <td>{l.completed ? <Badge tone="ok">Completed</Badge> : l.available ? <Badge tone="neutral">Available</Badge> : <Badge>Locked</Badge>}</td>
                        <td><button className="small" onClick={() => setOpen(open === l.id ? null : l.id)} aria-expanded={open === l.id}>{open === l.id ? "Close" : "Open"}</button></td>
                      </tr>
                      {open === l.id && (
                        <tr>
                          <td colSpan={5}>
                            <p>{l.body}</p>
                            {!l.available && <p className="muted">This lesson is locked at your current level. You can still read it; completion requires the level or a pathway that includes it.</p>}
                            {l.has_quiz ? <Quiz lessonId={l.id} onDone={reload} /> : m.status !== "PLANNED" && <Link className="btn primary small" to={m.route}>Go to {m.title}</Link>}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      ))}
    </>
  );
}
