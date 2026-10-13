import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api } from "../api";
import { useAuth, useSession } from "../state";
import type { SessionSummary } from "../types";
import { Badge, Provenance, Status, fmtTime } from "./ui";

const NAV: { group: string; items: [string, string, string?][] }[] = [
  { group: "Learn", items: [["/", "Overview Dashboard"], ["/learning", "Learning Paths"]] },
  {
    group: "Scenario workspace",
    items: [
      ["/workspace", "Simulation Workspace"],
      ["/discovery", "Data Discovery", "M01"],
      ["/classification", "Classification Studio", "M01"],
      ["/policies", "DLP Policy Studio", "M02"],
      ["/events", "Security Event Explorer", "M07"],
      ["/investigation", "Incident Investigation", "M07"],
      ["/engineering", "Data Security Engineering", "M08"],
    ],
  },
  {
    group: "Labs",
    items: [
      ["/labs/encryption", "Encryption Lab", "M03"],
      ["/labs/database", "Database Security Lab", "M04"],
      ["/labs/privacy", "Privacy & Governance", "M05"],
      ["/labs/cloud", "Cloud Data Security / DSPM", "M06"],
      ["/labs/ai", "AI Data Security", "M09"],
      ["/real-tools", "Real-Tool Practice"],
    ],
  },
  { group: "Results", items: [["/assessment", "Assessment & Reports"], ["/admin", "Administrator / Lab Settings"]] },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const { session, sessionId, setSessionId } = useSession();
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [open, setOpen] = useState(false);
  const loc = useLocation();

  useEffect(() => setOpen(false), [loc.pathname]);
  useEffect(() => {
    api.get<SessionSummary[]>("/api/sessions").then(setSessions).catch(() => setSessions([]));
  }, [sessionId, session?.status, session?.attempt_number]);

  return (
    <div className="app">
      <a href="#main" className="sr-only">Skip to content</a>
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Primary">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="#3b6ef5" />
            <path d="m10.5 16 4 4 7-8" stroke="white" strokeWidth="3" fill="none" />
          </svg>
          <div>
            Threatready
            <small>Data Security Operations Lab</small>
          </div>
        </div>
        {NAV.map((g) => (
          <div key={g.group} className="nav">
            <div className="nav-group">{g.group}</div>
            {g.items.map(([to, label, tag]) => (
              <NavLink key={to} to={to} end={to === "/"}>
                <span>{label}</span>
                {tag && <span className="tag">{tag}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="main">
        <header className="topbar">
          <div className="ctx">
            <button className="menu-toggle ghost" onClick={() => setOpen((o) => !o)} aria-label="Toggle navigation">☰</button>
            <label className="row small" htmlFor="session-select">
              <span className="muted">Active workspace</span>
              <select
                id="session-select"
                value={sessionId ?? ""}
                onChange={(e) => setSessionId(e.target.value ? Number(e.target.value) : null)}
                style={{ maxWidth: 320 }}
              >
                <option value="">— none —</option>
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    #{s.id} {s.scenario_title} · attempt {s.attempt_number} · {s.mode.toLowerCase()} · {s.status.toLowerCase()}
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
          </div>
          <div className="row small">
            <span>
              {user?.display_name} <span className="muted">({user?.role})</span>
            </span>
            <button className="small" onClick={() => void logout()}>Sign out</button>
          </div>
        </header>
        <main id="main" className="content">{children}</main>
      </div>
    </div>
  );
}
