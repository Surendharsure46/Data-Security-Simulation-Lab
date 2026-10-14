import { useState } from "react";
import { Link } from "react-router-dom";
import { AuthForm } from "../components/AuthForm";
import { Banner } from "../components/ui";

export default function Login() {
  const [mode, setMode] = useState<"login" | "register">("login");

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
        <AuthForm key={mode} mode={mode} submitLabel={mode === "login" ? "Sign in" : "Create account"} />
      </div>
    </div>
  );
}
