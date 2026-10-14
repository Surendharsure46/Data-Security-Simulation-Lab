import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, errorText } from "../../api";
import { ActionButton, Badge, ErrorBanner, Field, Loading } from "../../components/ui";
import { useAuth, useLoad, useOptionalCareer } from "../../state";
import type { CareerProfile, PublicContent } from "../../types";
import { PublicShell } from "./PublicShell";

export const PENDING_ROLE_KEY = "threatready.pendingRole";

export function rememberRole(role: string) {
  try {
    sessionStorage.setItem(PENDING_ROLE_KEY, role);
  } catch {
    /* storage unavailable: the role is asked again after sign-in */
  }
}

export function takePendingRole(): string | null {
  try {
    const r = sessionStorage.getItem(PENDING_ROLE_KEY);
    sessionStorage.removeItem(PENDING_ROLE_KEY);
    return r;
  } catch {
    return null;
  }
}

const ROLE_ICONS: Record<string, string> = { compass: "🧭", radar: "📡", shield: "🛡️", lock: "🔐" };

function AccountForm({ role }: { role: string }) {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<"register" | "login">("register");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    rememberRole(role);  // applied right after the account exists
    try {
      if (mode === "login") await login(username, password);
      else await register(username, displayName || username, password);
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit} className="stack">
      <div className="tabs" role="tablist">
        <button role="tab" type="button" aria-selected={mode === "register"} onClick={() => setMode("register")}>Create account</button>
        <button role="tab" type="button" aria-selected={mode === "login"} onClick={() => setMode("login")}>I already have an account</button>
      </div>
      <ErrorBanner error={error} />
      <Field label="Username" hint={mode === "register" ? "Your email address or a name using letters, digits and . _ - + @" : undefined}>
        <input name="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required minLength={3} maxLength={64} />
      </Field>
      {mode === "register" && (
        <Field label="Display name"><input name="display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></Field>
      )}
      <Field label="Password" hint={mode === "register" ? "At least 10 characters with upper- and lower-case letters and a digit." : undefined}>
        <input name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} value={password}
          onChange={(e) => setPassword(e.target.value)} required />
      </Field>
      <button className="primary cta" type="submit" disabled={busy || !role}>
        {busy && <span className="spinner" aria-hidden />}
        {mode === "login" ? "Sign in and start my journey" : "Create account and start Level 0"}
      </button>
    </form>
  );
}

// Step 2 of the journey: learn about the platform, see what you will do, choose a role, then sign up or sign in.
export default function GetStarted({ signedIn = false }: { signedIn?: boolean }) {
  const { data, error, loading } = useLoad(() => api.get<PublicContent>("/api/career/public"), []);
  const { user, logout } = useAuth();
  const career = useOptionalCareer();
  const navigate = useNavigate();
  const [role, setRole] = useState<string>("");
  const actions = signedIn ? (
    <><span className="small muted">{user?.display_name}</span><button className="ghost" onClick={() => void logout()}>Sign out</button></>
  ) : (
    <><Link to="/" className="btn ghost">← Welcome</Link><Link to="/login" className="btn ghost">Sign in</Link></>
  );
  if (loading) return <PublicShell actions={actions}><Loading /></PublicShell>;
  if (error || !data) return <PublicShell actions={actions}><ErrorBanner error={error} /></PublicShell>;
  const p = data.platform;
  const chosen = data.roles.find((r) => r.key === role);
  return (
    <PublicShell actions={actions}>
      <section className="hero-xl compact">
        <p className="eyebrow">Get started</p>
        <h1>{p.title}</h1>
        <p className="hero-text">{p.summary}</p>
      </section>

      <section className="public-section">
        <h2>What you will do in every level</h2>
        <ol className="loop">
          {p.loop.map((s, i) => (
            <li key={s.title}><span className="loop-num">{i + 1}</span><div><strong>{s.title}</strong><p className="small muted">{s.text}</p></div></li>
          ))}
        </ol>
      </section>

      <section className="public-section">
        <h2>Your path: Level 0 to Level 5</h2>
        <ol className="level-chips">
          {data.levels.map((lv) => (
            <li key={lv.level}><span className="chip-level">L{lv.level}</span><strong>{lv.title}</strong>
              <span className="small muted">{lv.summary}</span>
              <span className="small">{lv.lessons} lessons · {lv.labs} lab{lv.labs === 1 ? "" : "s"}</span></li>
          ))}
        </ol>
        <p className="small muted">Finish every lab in a level to unlock the next one automatically. Each lab walks you through: {data.phases.map((ph) => ph.title).join(" → ")}.</p>
      </section>

      <section className="public-section" aria-labelledby="choose-role">
        <h2 id="choose-role">Choose your role</h2>
        <p className="muted">Your role sets your job title and highlights the skills that matter most for it. Every role follows the same six levels, and you can change it later.</p>
        <div className="role-grid" role="radiogroup" aria-label="Role">
          {data.roles.map((r) => (
            <button key={r.key} type="button" role="radio" aria-checked={role === r.key} className={`role-card ${role === r.key ? "selected" : ""}`}
              onClick={() => setRole(r.key)}>
              <span className="role-icon" aria-hidden>{ROLE_ICONS[r.icon] ?? "★"}</span>
              <strong>{r.title}</strong>
              <span className="small">{r.summary}</span>
              {role === r.key && <Badge tone="ok">Selected</Badge>}
            </button>
          ))}
        </div>
      </section>

      <section className="public-section start-panel" id="start">
        {signedIn ? (
          <div className="row between">
            <div><h2>{chosen ? `Start as Trainee ${chosen.title}` : "Select a role to continue"}</h2>
              <p className="muted small">You begin at Level 0 — Foundation.</p></div>
            <ActionButton className="primary cta" disabled={!role} onClick={async () => {
              const prof = await api.put<CareerProfile>("/api/career/role", { role });
              career?.setProfile(prof);
              navigate("/");
            }}>Start my journey →</ActionButton>
          </div>
        ) : (
          <div className="grid two">
            <div>
              <h2>{chosen ? `Great choice: ${chosen.title}` : "Select a role, then create your account"}</h2>
              <ul className="small">{p.safety.map((s) => <li key={s}>{s}</li>)}</ul>
            </div>
            <div className="card">{role ? <AccountForm role={role} /> : <p className="muted">Choose a role above to continue.</p>}</div>
          </div>
        )}
      </section>
    </PublicShell>
  );
}
