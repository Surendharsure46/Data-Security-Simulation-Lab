import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api";
import { Tour } from "../../components/Tour";
import { ActionButton, Badge, Bar, Card, ErrorBanner, Loading, Status, fmtTime } from "../../components/ui";
import { useLoad } from "../../state";
import type { Journey as JourneyT } from "../../types";
import { STEP_ICON, stepLabel, stepRoute } from "./nav";

const LEVEL_ICON: Record<string, string> = { seed: "🌱", tools: "🧰", search: "🔎", gear: "⚙️", layers: "🏛️", trophy: "🏆" };

const TOUR = [
  { target: "continue", title: "Your next step", text: "This card always shows exactly what to do next. Click Continue and the platform takes you there." },
  { target: "levels", title: "Six levels", text: "Each level has short lessons, a knowledge check and hands-on labs. Finish a level to unlock the next one automatically." },
  { target: "nav", title: "Navigation", text: "Purple is your learning path, cyan your progress, pink your tools. Tools unlock level by level — a lock shows the level that opens it." },
  { target: "skills", title: "Your skills", text: "Every lab you pass records the skills you demonstrated, with the evidence behind them." },
];

export default function Journey() {
  const navigate = useNavigate();
  const { data, error, loading } = useLoad(() => api.get<JourneyT>("/api/career/journey"), []);
  if (loading) return <Loading />;
  if (error || !data) return <ErrorBanner error={error} />;
  const ns = data.next_step;
  const pct = Math.round((100 * data.overall_progress.done) / Math.max(1, data.overall_progress.total));
  const recorded = data.skills.filter((s) => s.proficiency !== null);
  return (
    <>
      <Tour id="journey-v1" steps={TOUR} />
      <section className="journey-hero">
        <div>
          <p className="eyebrow">My journey · {data.organization.name}</p>
          <h1>{data.profile.role_title}</h1>
          <p className="muted">Level {data.profile.career_level} of {data.profile.top_level} — {data.current_level.title}. {data.current_level.summary}</p>
          <Bar value={pct} label="Overall journey progress" />
          <p className="small muted">{data.overall_progress.done} of {data.overall_progress.total} steps complete across all six levels</p>
        </div>
        <div className="continue-card" data-tour="continue">
          {data.journey_complete ? (
            <><p className="eyebrow">Journey complete</p><h2>🏆 All six levels done</h2><p className="small">Revisit any lab result or the Learning Library at any time.</p></>
          ) : ns ? (
            <>
              <p className="eyebrow">Next step · Level {ns.level}</p>
              <h2>{STEP_ICON[ns.type]} {ns.title}</h2>
              <p className="small muted">{stepLabel(ns)}</p>
              <ActionButton className="primary cta" onClick={async () => navigate(await stepRoute(ns.level, ns))}>Continue →</ActionButton>
            </>
          ) : (
            <><h2>Level {data.current_level.level} in progress</h2><Link className="btn primary" to={`/levels/${data.current_level.level}`}>Open level</Link></>
          )}
        </div>
      </section>

      <div className="grid side">
        <section data-tour="levels" aria-label="Levels">
          <ol className="level-path">
            {data.levels.map((lv) => {
              const lp = Math.round((100 * lv.progress.done) / Math.max(1, lv.progress.total));
              return (
                <li key={lv.level} className={`level-node ${lv.status.toLowerCase()}`}>
                  <div className="level-badge" aria-hidden>{lv.status === "LOCKED" ? "🔒" : lv.status === "COMPLETED" ? "✓" : LEVEL_ICON[lv.icon] ?? lv.level}</div>
                  <div className="level-body">
                    <div className="row between">
                      <h3>Level {lv.level} · {lv.title}</h3>
                      <Status value={lv.status} />
                    </div>
                    <p className="small muted">{lv.summary}</p>
                    {lv.status !== "LOCKED" && <Bar value={lp} label={`Level ${lv.level} progress`} />}
                    <div className="row between small" style={{ marginTop: 6 }}>
                      <span className="muted">{lv.status === "LOCKED" ? `Unlocks after Level ${lv.level - 1}` : `${lv.progress.done}/${lv.progress.total} steps · ${lv.labs} lab${lv.labs === 1 ? "" : "s"} · title: ${lv.rank_title}`}</span>
                      {lv.unlocked && <Link className={`btn small ${lv.status === "CURRENT" ? "primary" : ""}`} to={`/levels/${lv.level}`}>{lv.status === "COMPLETED" ? "Review" : "Open level"}</Link>}
                    </div>
                  </div>
                </li>
              );
            })}
          </ol>
        </section>
        <div>
          <Card title="Skills demonstrated" className="tight-card">
            <div data-tour="skills" className="stack">
              {recorded.length === 0 ? <p className="small muted">Pass your first lab to record a skill.</p> : recorded.map((s) => (
                <div key={s.skill}>
                  <div className="row between small"><span title={s.description}>{s.name}</span><span className="muted">{s.proficiency}%</span></div>
                  <Bar value={s.proficiency ?? 0} label={`${s.name} proficiency`} />
                </div>
              ))}
              {data.profile.role && (
                <p className="small muted">Focus for your role: {data.profile.role.focus.map((f) => data.skills.find((s) => s.skill === f)?.name ?? f).join(" · ")}</p>
              )}
            </div>
          </Card>
          <Card title="Recent lab results">
            {data.recent_outcomes.length === 0 ? <p className="small muted">No submissions yet.</p> : (
              <ul className="small">{data.recent_outcomes.map((o) => (
                <li key={o.attempt_id}><Link to={`/missions/${o.attempt_id}`}>L{o.level} · {o.title}</Link> <Status value={o.status} />{" "}
                  {o.score !== null && <Badge>{o.score}/100</Badge>} <span className="muted">{fmtTime(o.submitted_at)}</span></li>
              ))}</ul>
            )}
          </Card>
          <Card title="Your team">
            <ul className="small">{data.organization.team.map((t) => <li key={t.name}><strong>{t.name}</strong> — {t.role}</li>)}</ul>
          </Card>
        </div>
      </div>
    </>
  );
}
