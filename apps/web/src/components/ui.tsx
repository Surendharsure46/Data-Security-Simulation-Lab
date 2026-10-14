import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useSession } from "../state";

// ----------------------------------------------------------------------------- badges (always text, never colour alone)

type Tone = "neutral" | "ok" | "warn" | "danger" | "info" | "sim" | "real";

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Provenance({ mode }: { mode: string }) {
  const m = mode.toUpperCase();
  if (m.startsWith("REAL")) return <Badge tone="real" title="Runs a real operation in your isolated local lab">REAL LAB</Badge>;
  if (m.startsWith("INTEGRATED")) return <Badge tone="info" title="Uses a configured external product">INTEGRATED</Badge>;
  return <Badge tone="sim" title="Functional simulation with synthetic data — not real telemetry">SIMULATED</Badge>;
}

const TONES: Record<string, Tone> = {
  ALLOWED: "ok", SUCCESS: "ok", COMPLETED: "ok", VERIFIED: "ok", PASS: "ok", ENABLED: "ok", ACTIVE: "ok", ALLOW: "ok", DONE: "ok",
  ALLOWED_WITH_WARNING: "warn", WARN: "warn", MONITOR: "info", DETECTED: "info", RECORDED: "info", IN_PROGRESS: "info", OPEN: "info",
  PAUSED: "warn", MEDIUM: "warn", NEW: "warn",
  BLOCKED: "danger", DENIED: "danger", FAILURE: "danger", BLOCK: "danger", VERIFICATION_FAILED: "danger", HIGH: "danger", CRITICAL: "danger",
  DISABLED: "neutral", SUBMITTED: "neutral", CLOSED: "neutral", LOW: "neutral",
  TRUE_POSITIVE: "danger", BENIGN_POSITIVE: "ok", FALSE_POSITIVE: "ok", UNDETERMINED: "warn",
  PASSED: "ok", NOT_PASSED: "danger", PRACTICE_PASSED: "info", ABANDONED: "neutral", ASSIGNED: "info", LOCKED: "neutral",
  CURRENT: "info",
};

export function Status({ value }: { value: string | null | undefined }) {
  if (!value) return <Badge>—</Badge>;
  return <Badge tone={TONES[value] ?? "neutral"}>{value.replace(/_/g, " ")}</Badge>;
}

export function LabelBadge({ label }: { label: string | null | undefined }) {
  if (!label) return <Badge tone="warn">UNLABELED</Badge>;
  const tone: Tone = label === "restricted" ? "danger" : label === "confidential" ? "warn" : label === "internal" ? "info" : "ok";
  return <Badge tone={tone}>{label.toUpperCase()}</Badge>;
}

// ----------------------------------------------------------------------------- layout primitives

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-head">
          {typeof title === "string" ? <h2>{title}</h2> : title}
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function PageHead({ title, crumbs, children, actions, mode }: { title: string; crumbs?: string; children?: ReactNode; actions?: ReactNode; mode?: string }) {
  return (
    <div className="page-head">
      <div>
        {crumbs && <div className="crumbs"><Link to="/">Organization Home</Link> / {crumbs}</div>}
        <div className="row">
          <h1>{title}</h1>
          {mode && <Provenance mode={mode} />}
        </div>
        {children}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="row muted" role="status" aria-live="polite">
      <span className="spinner" aria-hidden /> {label}
    </div>
  );
}

export function ErrorBanner({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return (
    <div className="banner danger" role="alert">
      <strong>Error:</strong> {error}
    </div>
  );
}

export function Banner({ tone = "info", children }: { tone?: "info" | "ok" | "warn" | "danger"; children: ReactNode }) {
  return <div className={`banner ${tone}`}>{children}</div>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

export function Bar({ value, label }: { value: number; label: string }) {
  const v = Math.max(0, Math.min(100, value));
  return (
    <div className="bar" role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
      <span style={{ width: `${v}%` }} />
    </div>
  );
}

export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v]) => (
        <div key={k} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: [T, string][]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(([k, label]) => (
        <button key={k} role="tab" aria-selected={value === k} onClick={() => onChange(k)} type="button">
          {label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="field">
      {label}
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

export function fmtTime(iso: string | null | undefined) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace("Z", " UTC");
}

export function fmtNum(n: number | null | undefined) {
  return n === null || n === undefined ? "—" : n.toLocaleString("en-US");
}

// ----------------------------------------------------------------------------- toasts

interface Toast {
  id: number;
  tone: "ok" | "danger" | "info";
  text: string;
}
const ToastCtx = createContext<(text: string, tone?: Toast["tone"]) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Toast["tone"] = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, tone, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === "danger" ? 9000 : 4500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-host" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`} role={t.tone === "danger" ? "alert" : "status"}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

// ----------------------------------------------------------------------------- async action button

export function ActionButton({
  onClick, children, className = "", disabled, confirm, title,
}: { onClick: () => Promise<unknown> | void; children: ReactNode; className?: string; disabled?: boolean; confirm?: string; title?: string }) {
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  return (
    <button
      type="button"
      className={className}
      disabled={disabled || busy}
      title={title}
      onClick={async () => {
        if (confirm && !window.confirm(confirm)) return;
        setBusy(true);
        try {
          await onClick();
        } catch (e) {
          toast(e instanceof Error ? e.message : String(e), "danger");
        } finally {
          setBusy(false);
        }
      }}
    >
      {busy && <span className="spinner" aria-hidden />}
      {children}
    </button>
  );
}

// ----------------------------------------------------------------------------- session guard

export function NeedSession({ children }: { children: (sid: number) => ReactNode }) {
  const { session, sessionId } = useSession();
  if (!sessionId || !session) {
    return (
      <Card>
        <Empty title="No active scenario workspace">
          <p>This area works on the synthetic company inside a scenario session. Start or select one first.</p>
          <Link className="btn primary" to="/workspace">Open Simulation Workspace</Link>
        </Empty>
      </Card>
    );
  }
  return <>{children(session.id)}</>;
}

export function ReadOnlyNotice() {
  const { session, canWrite } = useSession();
  if (!session || canWrite) return null;
  return (
    <Banner tone="warn">
      This session is {session.status.toLowerCase()}
      {session.status === "PAUSED" ? " — resume it in the Simulation Workspace to make changes." : session.status === "SUBMITTED" ? " — it is read-only. Reset it to start a new attempt." : " — you are viewing another user's session (read-only)."}
    </Banner>
  );
}
