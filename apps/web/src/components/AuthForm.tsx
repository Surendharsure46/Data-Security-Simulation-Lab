import { useState, type FormEvent, type ReactNode } from "react";
import { errorText } from "../api";
import { useAuth } from "../state";
import { Banner, ErrorBanner, Field } from "./ui";

/**
 * Email + password sign-in / registration, with the TOTP step when the account has two-factor authentication.
 * The session itself is an httpOnly cookie set by the server; nothing is stored in the browser by this form.
 */
export function AuthForm({ mode, submitLabel, beforeSubmit, disabled }: {
  mode: "login" | "register";
  submitLabel: ReactNode;
  beforeSubmit?: () => void;
  disabled?: boolean;
}) {
  const { login, register, verifyTotp } = useAuth();
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    beforeSubmit?.();
    try {
      if (needsCode) await verifyTotp(code.trim());
      else if (mode === "login") {
        if ((await login(email, password)) === "two_factor") setNeedsCode(true);
      } else if ((await register(email, displayName || email.split("@")[0], password)) === "verify") {
        setNotice(`Account created. We sent a verification link to ${email}; open it, then sign in.`);
      }
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="stack">
      <ErrorBanner error={error} />
      {notice && <Banner tone="info">{notice}</Banner>}
      {needsCode ? (
        <Field label="Authentication code" hint="Enter the 6-digit code from your authenticator app.">
          <input name="totp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" value={code}
            onChange={(e) => setCode(e.target.value)} required autoFocus />
        </Field>
      ) : (
        <>
          <Field label="Email">
            <input name="email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required maxLength={254} />
          </Field>
          {mode === "register" && (
            <Field label="Display name">
              <input name="display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={80} />
            </Field>
          )}
          <Field label="Password" hint={mode === "register" ? "At least 10 characters with upper- and lower-case letters and a digit." : undefined}>
            <input name="password" type="password" autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password} onChange={(e) => setPassword(e.target.value)} required />
          </Field>
        </>
      )}
      <button className="primary cta" type="submit" disabled={busy || disabled}>
        {busy && <span className="spinner" aria-hidden />}
        {needsCode ? "Verify code" : submitLabel}
      </button>
    </form>
  );
}
