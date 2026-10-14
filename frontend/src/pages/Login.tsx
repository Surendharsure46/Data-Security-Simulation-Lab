import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { errorText } from "../api";
import { Banner, ErrorBanner, Field } from "../components/ui";
import { useAuth } from "../state";

export default function Login() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "login") await login(username, password);
      else await register(username, displayName || username, password);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <div className="card auth-card">
        <div className="row between"><Link to="/" className="small">← Back to welcome</Link><Link to="/get-started" className="small">New here? Let’s get started →</Link></div>
        <h1>Threatready</h1>
        <p className="muted">
          A practical Data Security training and validation platform connecting enterprise simulations, policy engineering,
          security investigations and verified real-tool practice.
        </p>
        <Banner tone="info">All companies, people and records in this platform are synthetic. Simulated activity never affects a real system.</Banner>
        <div className="tabs" role="tablist">
          <button role="tab" aria-selected={mode === "login"} onClick={() => setMode("login")} type="button">Sign in</button>
          <button role="tab" aria-selected={mode === "register"} onClick={() => setMode("register")} type="button">Create learner account</button>
        </div>
        <form onSubmit={submit} className="stack">
          <ErrorBanner error={error} />
          <Field label="Username" hint={mode === "register" ? "Your email address or a name using letters, digits and . _ - + @" : undefined}>
            <input name="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required minLength={3} maxLength={64} />
          </Field>
          {mode === "register" && (
            <Field label="Display name">
              <input name="display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </Field>
          )}
          <Field label="Password" hint={mode === "register" ? "At least 10 characters with upper- and lower-case letters and a digit." : undefined}>
            <input name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password} onChange={(e) => setPassword(e.target.value)} required />
          </Field>
          <button className="primary" type="submit" disabled={busy}>
            {busy && <span className="spinner" aria-hidden />}
            {mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
