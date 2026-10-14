import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth, useCareer, useSession } from "../state";
import type { SessionSummary } from "../types";
import { LevelUpModal } from "./LevelUpModal";
import { TOOLS, toolFor, useToolAccess } from "./toolAccess";
import { startTour } from "./Tour";
import { Badge, Provenance, Status, fmtTime } from "./ui";

type Item = [string, string, string];  // [route, label, icon]

const SESSION_PATHS = ["/workspace", "/discovery", "/classification", "/policies", "/events", "/investigation", "/engineering", "/assessment"];

function NavItem([to, label, icon]: Item, right?: ReactNode) {
  return (
    <NavLink key={to} to={to} end={to === "/"}>
      <span className="ico" aria-hidden>{icon}</span>
      <span className="lbl">{label}</span>
      {right}
    </NavLink>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const { profile } = useCareer();
  const { session, sessionId, setSessionId } = useSession();
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  const navigate = useNavigate();
  const inToolkit = !!toolFor(loc.pathname);
  const access = useToolAccess();
  const visibleTools = TOOLS.filter((tl) => tl.group !== "Staff" || access.staff);
  const unlockedCount = visibleTools.filter(access.unlocked).length;
  const showSession = SESSION_PATHS.some((p) => loc.pathname.startsWith(p));
  const level = profile?.career_level ?? 0;
  const [toolkitOpen, setToolkitOpen] = useState(inToolkit);
  useEffect(() => {
    if (inToolkit) setToolkitOpen(true);
  }, [inToolkit]);

  useEffect(() => setOpen(false), [loc.pathname]);
  useEffect(() => {
    if (!showSession) return;
    api.get<SessionSummary[]>("/api/sessions").then(setSessions).catch(() => setSessions([]));
  }, [showSession, sessionId, session?.status, session?.attempt_number]);

  return (
    <div className="app">
      <a href="#main" className="sr-only">Skip to content</a>
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Primary" data-tour="nav">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)" />
            <path d="m10.5 16 4 4 7-8" stroke="var(--accent-ink)" strokeWidth="3" fill="none" />
          </svg>
          <div>Threatready<small>Data Security Lab</small></div>
        </div>
        <div className="nav learn">
          <div className="nav-group">Learn</div>
          {NavItem(["/", "My Journey", "🧭"])}
          {NavItem([`/levels/${level}`, `Current level · L${level}`, "🎯"])}
          {NavItem(["/mission", "Continue next step", "▶️"])}
        </div>
        <div className="nav progress">
          <div className="nav-group">Progress</div>
          {NavItem(["/progress", "Skills & Progress", "📊"])}
          {NavItem(["/learning", "Learning Library", "📚"])}
          {NavItem(["/assessment", "Assessment & Reports", "📝"])}
        </div>
        <details className="nav tools" open={toolkitOpen} onToggle={(e) => setToolkitOpen(e.currentTarget.open)}>
          <summary className="nav-group">Tools · {unlockedCount}/{visibleTools.length} unlocked</summary>
          <p className="nav-hint">Tools unlock as you level up. Inside a lab, everything it needs is already open.</p>
          {(["Labs", "Simulation", "Staff"] as const).map((g) => {
            const items = visibleTools.filter((tl) => tl.group === g).sort((a, b) => a.level - b.level);
            if (!items.length) return null;
            return (
              <div key={g}>
                <div className="nav-sub">{g === "Labs" ? "Hands-on labs" : g === "Simulation" ? "Simulation tools" : "Staff"}</div>
                {items.map((tl) => access.unlocked(tl)
                  ? NavItem([tl.to, tl.label, tl.icon], tl.group !== "Staff" ? <span className="lvl-chip" title={`Unlocked at Level ${tl.level}`}>L{tl.level}</span> : undefined)
                  : (
                    <span key={tl.to} className="nav-locked" title={`Unlocks at Level ${tl.level}: ${tl.why}`} aria-disabled="true">
                      <span className="ico" aria-hidden>🔒</span><span className="lbl">{tl.label}</span>
                      <span className="lvl-chip locked">L{tl.level}</span>
                    </span>
                  ))}
              </div>
            );
          })}
        </details>
      </nav>
      <div className="main">
        <header className="topbar">
          <div className="ctx">
            <button className="menu-toggle ghost" onClick={() => setOpen((o) => !o)} aria-label="Toggle navigation">☰</button>
            {showSession ? (
              <>
                <label className="row small" htmlFor="session-select">
                  <span className="muted">Workspace</span>
                  <select id="session-select" value={sessionId ?? ""} onChange={(e) => setSessionId(e.target.value ? Number(e.target.value) : null)} style={{ maxWidth: 320 }}>
                    <option value="">— none —</option>
                    {sessions.map((s) => (
                      <option key={s.id} value={s.id}>
                        #{s.id} {s.mission ? `${s.mission.mission_id} · ` : ""}{s.scenario_title} · {s.mode.toLowerCase()} · {s.status.toLowerCase()}
                      </option>
                    ))}
                  </select>
                </label>
                {session && (
                  <>
                    <Status value={session.status} />
                    <Badge tone="neutral" title="Simulation clock (UTC)">Sim clock {fmtTime(session.sim_clock)}</Badge>
                    <Provenance mode="SIMULATED" />
                  </>
                )}
              </>
            ) : (
              <span className="row small">
                <Badge tone="info">Level {level}</Badge>
                <strong>{profile?.role_title}</strong>
              </span>
            )}
          </div>
          <div className="row small">
            <button className="small ghost" onClick={() => { navigate("/"); setTimeout(startTour, 300); }} title="Show the guided tour">? Guided tour</button>
            <span>{user?.display_name}</span>
            <button className="small" onClick={() => void logout()}>Sign out</button>
          </div>
        </header>
        <main id="main" className="content">{children}</main>
      </div>
      <LevelUpModal />
    </div>
  );
}
