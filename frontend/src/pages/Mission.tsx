import { useEffect, useState, type ComponentType, type ReactNode } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { DemoLab } from "../components/DemoLab";
import {
  ActionButton, Badge, Banner, Card, Empty, ErrorBanner, Field, Loading, Provenance, Status, fmtTime, useToast,
} from "../components/ui";
import { useCareer, useLoad, useSession } from "../state";
import type { Journey, MissionAttempt, MissionOutcome, MissionPhase, PhaseItem, RemedialLesson } from "../types";
import AiLab from "./AiLab";
import CloudLab from "./CloudLab";
import DatabaseLab from "./DatabaseLab";
import EncryptionLab, { type LabViewProps } from "./EncryptionLab";
import { stepRoute } from "./journey/nav";
import PrivacyLab from "./PrivacyLab";

const LABS: Record<string, ComponentType<LabViewProps>> = {
  encryption: EncryptionLab, database: DatabaseLab, privacy: PrivacyLab, cloud: CloudLab, ai: AiLab,
};

// Where each reference-scenario task is performed.
const TASK_ROUTES: Record<string, [string, string]> = {
  discover: ["/discovery", "Data Discovery"], inspect: ["/discovery", "Data Discovery"],
  classify: ["/classification", "Classification Studio"], access_review: ["/classification", "Classification Studio"],
  policy: ["/policies", "DLP Policy Studio"], policy_test: ["/policies", "DLP Policy Studio"],
  run_day: ["/workspace", "Simulation Workspace"], triage: ["/investigation", "Incident Investigation"],
  case: ["/investigation", "Incident Investigation"], analysis: ["/investigation", "Incident Investigation"],
  scope: ["/investigation", "Incident Investigation"], contain: ["/investigation", "Incident Investigation"],
  fix: ["/policies", "DLP Policy Studio"], verify: ["/workspace", "Simulation Workspace"],
  report: ["/investigation", "Incident Investigation"],
};

function modeLabel(m: MissionAttempt["mission"]) {
  if (m.kind === "DEMO") return "Interactive lab";
  if (m.kind === "LAB") return `Hands-on lab · ${m.lab}`;
  return m.mode === "ASSESSMENT" ? "Simulation lab · independent (no hints)" : "Simulation lab · guided (hints available)";
}

// ----------------------------------------------------------------------------- /mission: open the current next step

export function CurrentMission() {
  const navigate = useNavigate();
  const j = useLoad(() => api.get<Journey>("/api/career/journey"), []);
  const [err, setErr] = useState<string | null>(null);
  const ns = j.data?.next_step;
  useEffect(() => {
    if (!ns) return;
    stepRoute(ns.level, ns).then((to) => navigate(to, { replace: true })).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [ns, navigate]);
  if (j.loading) return <Loading />;
  if (j.error || err) return <ErrorBanner error={j.error ?? err} />;
  if (!ns) return <Navigate to="/" replace />;
  return <Loading label="Opening your next step…" />;
}

// ----------------------------------------------------------------------------- shared pieces

function Understand({ a, onChange }: { a: MissionAttempt; onChange: () => void }) {
  const toast = useToast();
  const m = a.mission;
  const bp = m.business_problem;
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [result, setResult] = useState<{ score: number; passed: boolean; correct: boolean[] } | null>(null);
  const correct = result?.correct ?? a.understanding.correct;
  return (
    <>
      <p className="lead">{bp.statement}</p>
      <div className="grid two">
        <div><h3>What is at stake</h3><ul className="small">{bp.stakes.map((s) => <li key={s}>{s}</li>)}</ul></div>
        <div><h3>What success looks like</h3><ul className="small">{bp.success_looks_like.map((s) => <li key={s}>{s}</li>)}</ul></div>
      </div>
      {m.briefing && <details><summary className="small">Full scenario briefing</summary><p className="small">{m.briefing}</p></details>}
      <hr />
      <h3>Check your understanding</h3>
      {a.understanding.passed ? (
        <Banner tone="ok">Understood{a.understanding.carried_over_from ? ` (carried over from attempt ${a.understanding.carried_over_from})` : ""}. Move on to the hands-on work.</Banner>
      ) : a.status !== "IN_PROGRESS" ? <p className="muted">Not answered.</p> : (
        <div className="stack">
          {bp.questions.map((q, i) => (
            <fieldset key={i} className="question">
              <legend>{i + 1}. {q.q} {correct && (correct[i] ? <Badge tone="ok">correct</Badge> : <Badge tone="danger">incorrect</Badge>)}</legend>
              {q.options.map((o, j) => (
                <label key={j} className="option">
                  <input type="radio" name={`mq${i}`} checked={answers[i] === j} onChange={() => setAnswers({ ...answers, [i]: j })} /> {o}
                </label>
              ))}
            </fieldset>
          ))}
          <ActionButton className="primary" disabled={Object.keys(answers).length !== bp.questions.length} onClick={async () => {
            const r = await api.post<{ score: number; passed: boolean; correct: boolean[] }>(`/api/career/attempts/${a.id}/understand`,
              { answers: bp.questions.map((_, i) => answers[i]) });
            setResult(r);
            toast(r.passed ? "Understanding confirmed — the lab is open" : "Not quite — reread the problem and try again", r.passed ? "ok" : "info");
            if (r.passed) onChange();
          }}>Check answers</ActionButton>
        </div>
      )}
    </>
  );
}

function SubmitForm({ a, onDone, compact = false }: { a: MissionAttempt; onDone: (a: MissionAttempt) => void; compact?: boolean }) {
  const toast = useToast();
  const [explanation, setExplanation] = useState(a.explanation);
  const [cited, setCited] = useState<number[]>([]);
  const ev = a.evidence_options;
  const isScenario = a.mission.kind === "SCENARIO";
  const r = a.readiness;
  const min = a.mission.min_explanation;
  const ready = r.understanding_passed && explanation.trim().length >= min && (!isScenario || (cited.length > 0 && r.session_status === "ACTIVE"));
  return (
    <div className="stack">
      {!compact && (
        <ul className="small">
          <li>Practical work recorded: {r.work_done}/{r.work_total}. Completion shows work was done, not that it was right — correctness is assessed on submission.</li>
          {isScenario && r.session_status !== "ACTIVE" && <li><Badge tone="warn">workspace {r.session_status?.toLowerCase()}</Badge> resume it before submitting.</li>}
        </ul>
      )}
      {r.work_done < r.work_total && <Banner tone="warn">{r.work_total - r.work_done} step(s) are not complete yet. You can still submit to see your skill gaps.</Banner>}
      <Field label="Your explanation" hint={`What you found, what you did and how you verified it (${explanation.trim().length}/${min}+ characters).`}>
        <textarea name="explanation" rows={compact ? 5 : 6} value={explanation} onChange={(e) => setExplanation(e.target.value)} maxLength={6000} />
      </Field>
      {isScenario && (
        <fieldset className="question">
          <legend className="small">Cite evidence from your case {ev?.case_title ? `“${ev.case_title}”` : ""}</legend>
          {!ev?.items.length ? <p className="small muted">Link evidence to an investigation case first (Incident Investigation).</p> : ev.items.map((e) => (
            <label key={e.id} className="option">
              <input type="checkbox" checked={cited.includes(e.id)} onChange={(x) => setCited(x.target.checked ? [...cited, e.id] : cited.filter((i) => i !== e.id))} />
              <span><Badge>{e.ref_type}</Badge> <span className="mono small">{e.ref_id}</span> {e.label}</span>
            </label>
          ))}
        </fieldset>
      )}
      {!isScenario && <p className="small muted">The lab's server-verified results are attached as evidence automatically.</p>}
      <ActionButton className="primary cta" disabled={!ready} confirm="Submit for server-side assessment?" onClick={async () => {
        const res = await api.post<MissionAttempt>(`/api/career/attempts/${a.id}/submit`, { explanation, cited_evidence: cited });
        toast(res.status === "PASSED" ? "Lab passed" : res.status === "PRACTICE_PASSED" ? "Practice passed" : "Required criteria not met yet", res.status === "NOT_PASSED" ? "info" : "ok");
        onDone(res);
      }}>Submit for assessment</ActionButton>
    </div>
  );
}

function Lesson({ l, open }: { l: RemedialLesson; open: boolean }) {
  return (
    <details open={open} className="lesson-body" style={{ marginBottom: 8 }}>
      <summary><strong>{l.id}</strong> {l.title}</summary>
      <p className="small">{l.body}</p>
      <p className="small"><strong>Practice:</strong> {l.practice}</p>
      <Link className="btn small" to="/learning">{l.has_quiz ? "Take the knowledge check" : "Open in Learning Library"}</Link>
    </details>
  );
}

function Outcome({ a, o, onRetry }: { a: MissionAttempt; o: MissionOutcome; onRetry: (s: "PRACTICE" | "NEW_VARIANT") => Promise<void> }) {
  const navigate = useNavigate();
  const { refresh: refreshCareer } = useCareer();
  const passed = a.status === "PASSED";
  const practice = a.status === "PRACTICE_PASSED";
  const level = a.mission.level;
  const levelUp = passed && (o.next?.level_unlocked !== undefined || o.next?.journey_complete);
  useEffect(() => {
    if (levelUp) void refreshCareer(); // opens the congratulations popup
  }, [levelUp, refreshCareer]);
  return (
    <Card title={passed ? "Lab passed ✓" : practice ? "Practice passed" : "Not passed yet"} className={passed || practice ? "outcome-pass" : "outcome-fail"}
      actions={<>{o.mode_label && <Badge>{o.mode_label}</Badge>}<Status value={a.status} /></>}>
      <div className="row" style={{ marginBottom: 8 }}>
        <span className="stat">{o.score}/100</span>
        <span className="small muted">pass mark {o.min_score}{o.kind === "SCENARIO" ? " with no critical failure and every required criterion" : " — every step verified"}</span>
      </div>
      {o.critical_failures.length > 0 && (
        <Banner tone="danger"><strong>Critical failures (cannot be offset):</strong>
          <ul>{o.critical_failures.map((c) => <li key={c.key}>{c.description} {c.detail}</li>)}</ul></Banner>
      )}
      <h3>Required criteria</h3>
      <ul className="criteria">
        {o.required.map((r) => (
          <li key={r.key} className={r.met ? "met" : "unmet"}>
            <span aria-hidden>{r.met ? "✓" : "✗"}</span>
            <div><strong>{r.label}</strong> <span className="small muted">({r.requirement}; {r.actual})</span><div className="small">{r.explanation}</div></div>
          </li>
        ))}
      </ul>

      {passed && (
        <>
          <h3>Skills recorded</h3>
          <div className="row">{o.skills_recorded?.map((s) => <Badge key={s.skill} tone="ok">{s.name} · {s.proficiency}%</Badge>)}</div>
          <div className="next-box">
            {o.next?.more_missions && o.next.next_mission && (
              <><span>Next lab in Level {level}: <strong>{o.next.next_mission.title}</strong></span>
                <ActionButton className="primary cta" onClick={async () => {
                  const n = await api.post<MissionAttempt>(`/api/career/missions/${o.next!.next_mission!.id}/start`);
                  navigate(`/missions/${n.id}`);
                }}>Start next lab →</ActionButton></>
            )}
            {o.next?.level_unlocked !== undefined && <span>🎉 Level {o.next.level_completed} complete — Level {o.next.level_unlocked} is unlocked.</span>}
            {o.next?.journey_complete && <span>🏆 You have completed all six levels.</span>}
            {!o.next?.more_missions && <Link className="btn" to={`/levels/${o.next?.level_unlocked ?? level}`}>{o.next?.level_unlocked !== undefined ? `Go to Level ${o.next.level_unlocked}` : `Back to Level ${level}`}</Link>}
          </div>
        </>
      )}

      {practice && (
        <Banner tone="info">
          Practice passed. Practice attempts show you are ready but do not complete an independent lab.
          <div className="row" style={{ marginTop: 6 }}>
            {a.retry_options.includes("NEW_VARIANT") && <ActionButton className="primary" onClick={() => onRetry("NEW_VARIANT")}>Take the assessed lab with a new variant</ActionButton>}
          </div>
        </Banner>
      )}

      {!passed && !practice && (
        <>
          <h3>Skill gaps</h3>
          {o.skill_gaps.length === 0 ? <p className="small muted">No skill below the threshold; check the required criteria above.</p> : (
            <ul>{o.skill_gaps.map((g) => (
              <li key={g.skill}><strong>{g.name}</strong> ({g.proficiency}%)<ul className="small">{g.because?.map((b) => <li key={b}>{b}</li>)}</ul></li>
            ))}</ul>
          )}
          {o.remedial_lessons.length > 0 && <h3>Remedial lesson{o.remedial_lessons.length > 1 ? "s" : ""}</h3>}
          {o.remedial_lessons.map((l, i) => <Lesson key={l.id} l={l} open={i === 0} />)}
          <h3>{a.retry_options.includes("NEW_VARIANT") ? "Retry with practice or a new variant" : "Practise, then retry"}</h3>
          <div className="row">
            {a.retry_options.includes("PRACTICE") && <ActionButton className="primary" onClick={() => onRetry("PRACTICE")}>
              {a.mission.kind === "SCENARIO" ? "Retry with guided practice" : "Retry this lab"}</ActionButton>}
            {a.retry_options.includes("NEW_VARIANT") && <ActionButton onClick={() => onRetry("NEW_VARIANT")}>Retry with a new variant</ActionButton>}
            {a.retry_options.length === 0 && <span className="small muted">A newer attempt exists for this lab.</span>}
          </div>
        </>
      )}

      {o.criteria && (
        <details style={{ marginTop: 12 }}>
          <summary className="small">Full rubric breakdown ({o.criteria.length} criteria)</summary>
          <div className="table-wrap"><table>
            <thead><tr><th>Criterion</th><th>Score</th><th>Explanation</th></tr></thead>
            <tbody>{o.criteria.map((c) => <tr key={c.key}><td>{c.description}</td><td>{c.earned}/{c.points}</td><td className="small">{c.explanation}</td></tr>)}</tbody>
          </table></div>
        </details>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------- guided lab session (hands-on labs and the demo)

function GuideStep({ n, title, done, current, children }: { n: number; title: string; done: boolean; current: boolean; children?: ReactNode }) {
  return (
    <li className={`guide-step ${done ? "done" : current ? "current" : ""}`} aria-current={current ? "step" : undefined}>
      <div className="guide-step-head"><span className="step-num" aria-hidden>{done ? "✓" : n}</span><strong>{title}</strong></div>
      {current && children && <div className="guide-step-body">{children}</div>}
    </li>
  );
}

type Retry = (s: "PRACTICE" | "NEW_VARIANT") => Promise<void>;

function LabSession({ a, reload, setData, onRetry }: { a: MissionAttempt; reload: () => void; setData: (a: MissionAttempt) => void; onRetry: Retry }) {
  const m = a.mission;
  const work = a.phases.filter((p) => !["UNDERSTAND", "SUBMIT"].includes(p.key)).flatMap((p) => p.items);
  const understood = a.understanding.passed;
  const open = a.status === "IN_PROGRESS";
  const firstOpen = work.findIndex((w) => !w.done);
  const [showSubmit, setShowSubmit] = useState(false);
  const Lab = m.lab ? LABS[m.lab] : null;
  const focus = m.exercises?.map((e) => e.exercise);

  useEffect(() => {
    if (!open || !understood) return;
    const t = setInterval(reload, 6000); // lab results are verified on the server; keep the checklist live
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, understood]);

  const submitting = open && understood && (firstOpen === -1 || showSubmit);
  const labView = m.kind === "DEMO" && m.demo ? <DemoLab d={m.demo} onChange={reload} readOnly={!open} />
    : Lab ? <Lab embedded focus={focus} onChange={reload} /> : null;
  return (
    <div className="lab-session">
      <div className="lab-main">
        {a.outcome ? (
          <>
            <Outcome a={a} o={a.outcome} onRetry={onRetry} />
            <details className="card"><summary>Open the lab again</summary>{labView}</details>
          </>
        ) : !understood ? (
          <Card title="Understand the business problem"><Understand a={a} onChange={reload} /></Card>
        ) : labView}
      </div>
      <aside className="guide" aria-label="Lab instructions">
        <p className="eyebrow">Instructor · step by step</p>
        <h2>{m.title}</h2>
        <p className="small muted">{modeLabel(m)} · assigned by {m.assigned_by}</p>
        <ol className="guide-steps">
          <GuideStep n={1} title="Understand the business problem" done={understood} current={open && !understood}>
            <p className="small">Read the business problem in the lab panel and answer the questions. The correct options never leave the server.</p>
          </GuideStep>
          {work.map((w, i) => (
            <GuideStep key={w.key} n={i + 2} title={w.title} done={w.done} current={understood && open && !submitting && i === firstOpen}>
              <ol className="small instructions">{w.steps?.map((s) => <li key={s}>{s}</li>)}</ol>
              <div className="row">
                <button className="small" onClick={reload}>Check my progress</button>
                <button className="small ghost" onClick={() => setShowSubmit(true)}>Skip to submission</button>
              </div>
            </GuideStep>
          ))}
          <GuideStep n={work.length + 2} title="Explain and submit" done={!!a.submitted_at} current={submitting}>
            <SubmitForm a={a} compact onDone={(res) => { setData(res); setShowSubmit(false); window.scrollTo(0, 0); }} />
          </GuideStep>
        </ol>
        {a.outcome && <Banner tone={a.status === "PASSED" ? "ok" : "info"}>Result: {a.outcome.score}/100 — details in the lab panel.</Banner>}
        <Link className="small" to={`/levels/${m.level}`}>← Level {m.level} overview</Link>
      </aside>
    </div>
  );
}

// ----------------------------------------------------------------------------- simulation lab (scenario)

function ItemList({ items, onGo, readOnly }: { items: PhaseItem[]; onGo: (it: PhaseItem) => void; readOnly: boolean }) {
  return (
    <ul className="tasklist">
      {items.map((it) => {
        const where = TASK_ROUTES[it.key]?.[1];
        return (
          <li key={it.key}>
            <span className={`check ${it.done ? "done" : ""}`} aria-label={it.done ? "done" : "not done"}>{it.done ? "✓" : ""}</span>
            <div style={{ flex: 1 }}><div><strong>{it.title}</strong></div><div className="small muted">{it.description}</div></div>
            {where && !readOnly && it.kind === "task" && <button className="small" onClick={() => onGo(it)}>Open {where}</button>}
          </li>
        );
      })}
    </ul>
  );
}

function Observe({ a }: { a: MissionAttempt }) {
  const runs = a.observations?.runs ?? [];
  if (!a.session) return null;
  return runs.length === 0 ? <p className="small muted">No business day has run yet in this lab workspace.</p> : (
    <div className="table-wrap" style={{ marginTop: 8 }}><table>
      <thead><tr><th>Run</th><th>Type</th><th>Sim day</th><th>Events</th><th>Prevented</th><th>Alerts</th></tr></thead>
      <tbody>{runs.map((r) => (
        <tr key={r.run_number}><td>{r.run_number}</td><td>{r.mode === "validation" ? "Control-validation replay" : "Business day"}</td>
          <td>{r.sim_day}</td><td>{r.events}</td><td>{r.prevented_events}</td><td>{r.alerts}</td></tr>
      ))}</tbody>
    </table></div>
  );
}

function ScenarioSession({ a, reload, setData, onRetry }: { a: MissionAttempt; reload: () => void; setData: (a: MissionAttempt) => void; onRetry: Retry }) {
  const navigate = useNavigate();
  const { setSessionId, refresh: refreshSession } = useSession();
  const [phase, setPhase] = useState<string | null>(null);
  const readOnly = a.status !== "IN_PROGRESS";
  const firstOpen = a.phases.find((p) => p.done === false)?.key ?? "SUBMIT";
  const current = phase === "RESULT" && !a.outcome ? firstOpen : phase ?? (a.outcome ? "RESULT" : firstOpen);
  const go = (it: PhaseItem) => {
    if (a.session) setSessionId(a.session.id);
    navigate(TASK_ROUTES[it.key][0]);
  };
  const stepState = (p: MissionPhase) => (p.done ? "done" : p.key === current ? "current" : "");
  return (
    <>
      <ol className="stepper" aria-label="Lab phases">
        {a.phases.map((p, i) => (
          <li key={p.key} className={stepState(p)} aria-current={p.key === current ? "step" : undefined}>
            <button className="link" type="button" onClick={() => setPhase(p.key)}><span className="num">{p.done ? "✓" : i + 1}</span> <span>{p.title}</span></button>
          </li>
        ))}
        {a.outcome && (
          <li className={current === "RESULT" ? "current" : a.status === "PASSED" ? "done" : ""}>
            <button className="link" type="button" onClick={() => setPhase("RESULT")}><span className="num">★</span> <span>Assessment result</span></button>
          </li>
        )}
      </ol>
      {current === "RESULT" && a.outcome && <Outcome a={a} o={a.outcome} onRetry={onRetry} />}
      {a.phases.filter((p) => p.key === current).map((p) => {
        const idx = a.phases.findIndex((x) => x.key === p.key);
        return (
          <Card key={p.key} title={`${idx + 1} · ${p.title}`} className={`phase-card ${stepState(p)}`}
            actions={<>{p.done ? <Badge tone="ok">complete</Badge> : p.done === false ? <Badge tone="info">in progress</Badge> : null}<Provenance mode="SIMULATED" /></>}>
            <p className="small muted">{p.summary}</p>
            {p.key === "UNDERSTAND" ? <Understand a={a} onChange={reload} /> : p.key === "SUBMIT" ? (
              <>
                <ItemList items={p.items.filter((i) => i.kind !== "submission")} onGo={go} readOnly={readOnly} />
                {readOnly ? <p className="small muted">Submitted {fmtTime(a.submitted_at)}.</p>
                  : <SubmitForm a={a} onDone={(res) => { setData(res); setPhase("RESULT"); void refreshSession(); }} />}
              </>
            ) : (
              <>
                <ItemList items={p.items} onGo={go} readOnly={readOnly} />
                {p.key === "OBSERVE" && <Observe a={a} />}
                {p.key === "VALIDATE" && <p className="small muted">The replay uses a test identity cloned from the original actor's role, so it proves the control gap — not just one account — is closed.</p>}
              </>
            )}
            <div className="row between" style={{ marginTop: 12 }}>
              <span className="small muted">Phases can be revisited — the business-day run feeds evidence back into your investigation.</span>
              <span className="row">
                {idx < a.phases.length - 1 && <button className="small primary" onClick={() => setPhase(a.phases[idx + 1].key)}>Next phase →</button>}
                <button className="small ghost" onClick={reload}>Refresh status</button>
              </span>
            </div>
          </Card>
        );
      })}
    </>
  );
}

// ----------------------------------------------------------------------------- page

export default function Mission() {
  const { attemptId } = useParams();
  // A new attempt is a new view: remount so phase selection and form state start fresh.
  return <MissionView key={attemptId} attemptId={attemptId ?? ""} />;
}

function MissionView({ attemptId }: { attemptId: string }) {
  const navigate = useNavigate();
  const toast = useToast();
  const { sessionId, setSessionId, refresh: refreshSession } = useSession();
  const { data: a, error, loading, reload, setData } = useLoad(() => api.get<MissionAttempt>(`/api/career/attempts/${attemptId}`), [attemptId]);
  const missionSession = a?.status === "IN_PROGRESS" ? a.session?.id : undefined;
  useEffect(() => {
    // Working on a simulation lab makes its workspace the active one for every toolkit page.
    if (missionSession && missionSession !== sessionId) setSessionId(missionSession);
  }, [missionSession, sessionId, setSessionId]);
  if (loading) return <Loading label="Opening the lab…" />;
  if (error || !a) return <Card><Empty title="Lab not available"><ErrorBanner error={error} /><Link className="btn" to="/">My Journey</Link></Empty></Card>;
  const m = a.mission;
  const retry = async (strategy: "PRACTICE" | "NEW_VARIANT") => {
    const n = await api.post<MissionAttempt>(`/api/career/attempts/${a.id}/retry`, { strategy });
    if (n.session) setSessionId(n.session.id);
    toast(strategy === "PRACTICE" ? "New attempt started" : "New variant started");
    navigate(`/missions/${n.id}`);
  };
  return (
    <>
      <div className="crumbs"><Link to="/">My Journey</Link> / <Link to={`/levels/${m.level}`}>Level {m.level} · {m.level_title}</Link> / Lab</div>
      <div className="page-head">
        <div>
          <div className="row"><h1>{m.title}</h1>{m.kind !== "LAB" && <Provenance mode="SIMULATED" />}</div>
          <p className="small muted">{modeLabel(m)} · attempt {a.attempt_number}{a.strategy !== "ASSIGNED" && ` (${a.strategy === "PRACTICE" ? "retry" : "new variant"})`} · <Status value={a.status} /></p>
        </div>
        {a.session && <button onClick={() => { setSessionId(a.session!.id); void refreshSession(); navigate("/workspace"); }}>Open lab workspace</button>}
      </div>
      {a.practice_note && <Banner tone="info">{a.practice_note}</Banner>}
      {a.status === "ABANDONED" && <Banner tone="warn">This attempt was replaced by a newer one. <Link to={`/levels/${m.level}`}>Go to Level {m.level}</Link></Banner>}
      {m.kind === "SCENARIO" ? <ScenarioSession a={a} reload={reload} setData={setData} onRetry={retry} />
        : <LabSession a={a} reload={reload} setData={setData} onRetry={retry} />}
    </>
  );
}
