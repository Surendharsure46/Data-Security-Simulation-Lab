import { Link } from "react-router-dom";
import { api } from "../../api";
import { ErrorBanner, Loading } from "../../components/ui";
import { useLoad } from "../../state";
import type { PublicContent } from "../../types";
import { PublicShell } from "./PublicShell";

// Step 1 of the journey: a dedicated page that introduces data security and motivates the learner.
export default function Welcome() {
  const { data, error, loading } = useLoad(() => api.get<PublicContent>("/api/career/public"), []);
  const actions = (
    <>
      <Link to="/login" className="btn ghost">Sign in</Link>
      <Link to="/get-started" className="btn primary cta">Let’s Get Started →</Link>
    </>
  );
  if (loading) return <PublicShell actions={actions}><Loading /></PublicShell>;
  if (error || !data) return <PublicShell actions={actions}><ErrorBanner error={error} /></PublicShell>;
  const w = data.welcome;
  return (
    <PublicShell actions={actions}>
      <section className="hero-xl">
        <p className="eyebrow">Data security training lab</p>
        <h1>{w.title}</h1>
        <p className="lead">{w.tagline}</p>
        <p className="hero-text">{w.intro}</p>
        <div className="row" style={{ marginTop: 18 }}>
          <Link to="/get-started" className="btn primary cta">Let’s Get Started →</Link>
          <a href="#learn-more" className="btn ghost">Learn the basics first</a>
        </div>
      </section>

      <section id="learn-more" className="public-section">
        <h2>Data security in four ideas</h2>
        <div className="grid two">
          {w.sections.map((s, i) => (
            <article key={s.title} className="card feature">
              <div className="feature-num" aria-hidden>{i + 1}</div>
              <h3>{s.title}</h3>
              <ul>{s.points.map((p) => <li key={p}>{p}</li>)}</ul>
            </article>
          ))}
        </div>
      </section>

      <section className="public-section">
        <h2>Why learn it here</h2>
        <div className="grid four">
          {w.motivation.map((m) => (
            <article key={m.title} className="card motivation"><h3>{m.title}</h3><p className="small">{m.text}</p></article>
          ))}
        </div>
      </section>

      <section className="public-section">
        <h2>Six levels from first steps to mastery</h2>
        <ol className="level-chips">
          {data.levels.map((lv) => (
            <li key={lv.level}><span className="chip-level">L{lv.level}</span><strong>{lv.title}</strong><span className="small muted">{lv.summary}</span></li>
          ))}
        </ol>
      </section>

      <section className="cta-band">
        <div>
          <h2>Ready to protect your first dataset?</h2>
          <p className="muted">Pick a role, then start Level 0. It takes about 30 minutes and needs no prior experience.</p>
        </div>
        <Link to="/get-started" className="btn primary cta">Let’s Get Started →</Link>
      </section>
    </PublicShell>
  );
}
