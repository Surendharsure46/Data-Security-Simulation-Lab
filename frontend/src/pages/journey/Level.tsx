import { useState } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router-dom";
import { api } from "../../api";
import { ActionButton, Badge, Banner, Bar, Card, ErrorBanner, Loading, Status } from "../../components/ui";
import { useCareer, useLoad } from "../../state";
import type { FundamentalItem, LevelDetail, NextInfo } from "../../types";
import { STEP_ICON, stepLabel, stepRoute } from "./nav";

function useLevel(n: number) {
  return useLoad(() => api.get<LevelDetail>(`/api/career/levels/${n}`), [n]);
}

// ----------------------------------------------------------------------------- level overview ("Before you start" + numbered steps)

export function LevelPage() {
  const n = Number(useParams().level);
  const navigate = useNavigate();
  const { data: d, error, loading } = useLevel(n);
  if (loading) return <Loading />;
  if (error || !d) return <ErrorBanner error={error} />;
  const pct = Math.round((100 * d.progress.done) / Math.max(1, d.progress.total));
  return (
    <>
      <div className="crumbs"><Link to="/">My Journey</Link> / Level {d.level}</div>
      <section className="level-hero">
        <div>
          <p className="eyebrow">Level {d.level} · {d.status === "COMPLETED" ? "completed" : d.unlocked ? "in progress" : "locked"}</p>
          <h1>{d.title}</h1>
          <p className="lead">{d.summary}</p>
          <Bar value={pct} label={`Level ${d.level} progress`} />
          <p className="small muted">{d.progress.done} of {d.progress.total} steps · your title at this level: <strong>{d.rank_title}</strong></p>
        </div>
        {d.next_step && d.unlocked && (
          <div className="continue-card">
            <p className="eyebrow">Next step</p>
            <h2>{STEP_ICON[d.next_step.type]} {d.next_step.title}</h2>
            <ActionButton className="primary cta" onClick={async () => navigate(await stepRoute(d.level, d.next_step!))}>Continue →</ActionButton>
          </div>
        )}
      </section>
      {!d.unlocked && <Banner tone="warn">Level {d.level} unlocks automatically when you complete Level {d.level - 1}.</Banner>}
      <div className="grid two">
        <div>
          <Card title="Before you start">
            <ul>{d.before_you_start.map((x) => <li key={x}>{x}</li>)}</ul>
            <h3>What you will be responsible for</h3>
            <ul className="small">{d.responsibilities.map((x) => <li key={x}>{x}</li>)}</ul>
            <p className="small"><Badge tone="info">Challenge</Badge> {d.challenge}</p>
          </Card>
        </div>
        <Card title={`The ${d.steps.length} steps`}>
          <ol className="step-list">
            {d.steps.map((s, i) => (
              <li key={s.key} className={s.status.toLowerCase()}>
                <span className="step-num" aria-hidden>{s.done ? "✓" : s.status === "LOCKED" ? "🔒" : i + 1}</span>
                <div className="step-text">
                  <strong>{s.title}</strong>
                  <span className="small muted">{stepLabel(s)}{s.latest_attempt && !s.done ? ` · last attempt ${s.latest_attempt.status.replace(/_/g, " ").toLowerCase()}` : ""}</span>
                </div>
                {s.status !== "LOCKED" && (
                  <ActionButton className={`small ${s.status === "CURRENT" ? "primary" : ""}`} onClick={async () => navigate(await stepRoute(d.level, s))}>
                    {s.done ? "Review" : s.type === "learn" ? "Read" : s.type === "check" ? "Take check" : "Open lab"}
                  </ActionButton>
                )}
              </li>
            ))}
          </ol>
        </Card>
      </div>
    </>
  );
}

// ----------------------------------------------------------------------------- one lesson per screen

function Briefing({ item }: { item: FundamentalItem }) {
  const o = item.organization!;
  return (
    <>
      <p className="lead">{o.company.description}</p>
      <p><strong>Mission:</strong> {o.mission_statement}</p>
      <h3>Crown-jewel data</h3>
      <div className="table-wrap"><table>
        <thead><tr><th>Data</th><th>Where it lives</th><th>Why it matters</th></tr></thead>
        <tbody>{o.crown_jewels.map((j) => <tr key={j.name}><td><strong>{j.name}</strong></td><td>{j.where}</td><td>{j.why}</td></tr>)}</tbody>
      </table></div>
      <div className="grid two" style={{ marginTop: 12 }}>
        <div><h3>Departments</h3><ul className="small">{o.departments.map((d) => <li key={d.name}><strong>{d.name}</strong> — {d.note}</li>)}</ul></div>
        <div><h3>Your team</h3><ul className="small">{o.team.map((t) => <li key={t.name}><strong>{t.name}</strong>, {t.role}. {t.note}</li>)}</ul></div>
      </div>
      <h3>What leadership is worried about</h3>
      <ul>{o.current_concerns.map((c) => <li key={c}>{c}</li>)}</ul>
      <p className="small muted">{o.disclaimer}</p>
    </>
  );
}

export function LearnStep() {
  const params = useParams();
  const n = Number(params.level);
  const key = params.key ?? "";
  const navigate = useNavigate();
  const { data: d, error, loading, setData } = useLevel(n);
  if (loading) return <Loading />;
  if (error || !d) return <ErrorBanner error={error} />;
  const idx = d.fundamentals.findIndex((f) => f.key === key);
  if (idx < 0) return <Navigate to={`/levels/${n}`} replace />;
  const item = d.fundamentals[idx];
  const total = d.fundamentals.length;
  const learnSteps = d.steps.filter((s) => s.type === "learn");
  const isRead = learnSteps[idx]?.done;
  const next = async () => {
    const updated = await api.post<LevelDetail>(`/api/career/levels/${n}/read/${encodeURIComponent(item.key)}`);
    setData(updated);
    window.scrollTo(0, 0);
    navigate(idx + 1 < total ? `/levels/${n}/learn/${encodeURIComponent(d.fundamentals[idx + 1].key)}` : `/levels/${n}/check`);
  };
  return (
    <div className="reader">
      <div className="crumbs"><Link to="/">My Journey</Link> / <Link to={`/levels/${n}`}>Level {n} · {d.title}</Link> / Fundamentals</div>
      <div className="reader-progress" aria-label={`Lesson ${idx + 1} of ${total}`}>
        {d.fundamentals.map((f, i) => (
          <Link key={f.key} to={`/levels/${n}/learn/${encodeURIComponent(f.key)}`} className={`dot ${i === idx ? "current" : learnSteps[i]?.done ? "done" : ""}`}
            aria-label={`${f.title}${learnSteps[i]?.done ? " (read)" : ""}`} />
        ))}
      </div>
      <p className="eyebrow">Fundamentals · step {idx + 1} of {total}{item.module ? ` · module ${item.module}` : ""}</p>
      <h1>{item.title}</h1>
      <article className="card reader-body">
        {item.type === "briefing" ? <Briefing item={item} /> : <p className="lead">{item.body}</p>}
        {item.practice && <Banner tone="info"><strong>Where you will practise this:</strong> {item.practice}</Banner>}
      </article>
      <div className="row between reader-nav">
        {idx > 0 ? <Link className="btn" to={`/levels/${n}/learn/${encodeURIComponent(d.fundamentals[idx - 1].key)}`}>← Previous</Link> : <Link className="btn" to={`/levels/${n}`}>← Level overview</Link>}
        <span className="small muted">{isRead ? "Reviewed ✓" : "Not yet reviewed"}</span>
        <ActionButton className="primary" onClick={next}>{idx + 1 < total ? "Got it — next lesson →" : "Got it — take the knowledge check →"}</ActionButton>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------- level knowledge check

export function LevelCheck() {
  const n = Number(useParams().level);
  const navigate = useNavigate();
  const { refresh } = useCareer();
  const { data: d, error, loading, reload } = useLevel(n);
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [result, setResult] = useState<{ score: number; passed: boolean; correct: boolean[]; next: NextInfo | null } | null>(null);
  if (loading) return <Loading />;
  if (error || !d) return <ErrorBanner error={error} />;
  const qs = d.check.questions;
  const unread = d.steps.filter((s) => s.type === "learn" && !s.done);
  const firstLab = d.steps.find((s) => s.type === "mission" && !s.done);
  return (
    <div className="reader">
      <div className="crumbs"><Link to="/">My Journey</Link> / <Link to={`/levels/${n}`}>Level {n} · {d.title}</Link> / Knowledge check</div>
      <p className="eyebrow">Knowledge check · {qs.length} questions · pass mark {Math.round(d.check.pass_mark * qs.length)}/{qs.length}</p>
      <h1>Level {n} knowledge check</h1>
      {d.check.passed && !result && <Banner tone="ok">You have already passed this check. Your labs are unlocked.</Banner>}
      {unread.length > 0 ? (
        <Card><p>Review the remaining fundamentals first: {unread.map((u) => u.title).join(", ")}.</p>
          <Link className="btn primary" to={`/levels/${n}/learn/${encodeURIComponent(unread[0].key)}`}>Go to {unread[0].title}</Link></Card>
      ) : (
        <Card>
          <div className="stack">
            {qs.map((q, i) => (
              <fieldset key={i} className="question">
                <legend>{i + 1}. {q.q} {result && (result.correct[i] ? <Badge tone="ok">correct</Badge> : <Badge tone="danger">incorrect</Badge>)}</legend>
                {q.options.map((o, j) => (
                  <label key={j} className="option">
                    <input type="radio" name={`lq${i}`} checked={answers[i] === j} onChange={() => setAnswers({ ...answers, [i]: j })} /> {o}
                  </label>
                ))}
              </fieldset>
            ))}
            <ActionButton className="primary cta" disabled={Object.keys(answers).length !== qs.length} onClick={async () => {
              const r = await api.post<{ score: number; passed: boolean; correct: boolean[]; next: NextInfo | null }>(`/api/career/levels/${n}/check`,
                { answers: qs.map((_, i) => answers[i]) });
              setResult(r);
              reload();
              await refresh();
            }}>Submit answers</ActionButton>
          </div>
        </Card>
      )}
      {result && (
        <Card className={result.passed ? "outcome-pass" : "outcome-fail"}>
          <h2>{result.passed ? "Passed — your labs are unlocked 🎉" : "Not yet — review and try again"}</h2>
          <p>Score {Math.round(result.score * 100)}%. {result.passed ? "Graded on the server." : "Only per-question correctness is shown, so the check stays meaningful. Reread the lessons marked by the questions you missed."}</p>
          <div className="row">
            {result.passed ? (
              firstLab && <ActionButton className="primary cta" onClick={async () => navigate(await stepRoute(n, firstLab))}>Start the first lab →</ActionButton>
            ) : (
              <><button onClick={() => { setResult(null); setAnswers({}); }}>Try again</button>
                <Link className="btn" to={`/levels/${n}/learn/${encodeURIComponent(d.fundamentals[0].key)}`}>Review the lessons</Link></>
            )}
          </div>
        </Card>
      )}
      <p className="small muted"><Status value={d.status} /> Level {n} · {d.progress.done}/{d.progress.total} steps</p>
    </div>
  );
}
