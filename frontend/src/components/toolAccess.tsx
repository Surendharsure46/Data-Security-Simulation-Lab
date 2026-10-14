import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useAuth, useCareer } from "../state";
import { Card } from "./ui";

// Standalone tools unlock with the level that first uses them, so beginners are not faced with
// advanced tools before they have learned what they are for. Inside a lab session every tool the
// lab needs is already available; this only governs the free-standing pages in the sidebar.
// Instructors and administrators see everything.

export interface Tool {
  to: string;
  label: string;
  icon: string;
  level: number;
  group: "Simulation" | "Labs" | "Staff";
  why: string;
}

export const TOOLS: Tool[] = [
  { to: "/labs/encryption", label: "Encryption Lab", icon: "🔐", level: 0, group: "Labs", why: "Level 0 introduces hashing; later levels add file encryption, key rotation and TLS." },
  { to: "/workspace", label: "Simulation Workspace", icon: "🖥️", level: 1, group: "Simulation", why: "Your first full enterprise simulation starts in Level 1." },
  { to: "/discovery", label: "Data Discovery", icon: "🔍", level: 1, group: "Simulation", why: "Level 1 teaches discovery scanning and detector evidence." },
  { to: "/classification", label: "Classification Studio", icon: "🏷️", level: 1, group: "Simulation", why: "Level 1 teaches classification, ownership and access review." },
  { to: "/policies", label: "DLP Policy Studio", icon: "🛡️", level: 1, group: "Simulation", why: "Level 1 teaches building and testing DLP policies." },
  { to: "/events", label: "Security Event Explorer", icon: "📡", level: 1, group: "Simulation", why: "The Level 1 simulation generates the events you explore here." },
  { to: "/investigation", label: "Incident Investigation", icon: "🕵️", level: 1, group: "Simulation", why: "The Level 1 simulation ends with triage, a case and a report." },
  { to: "/labs/database", label: "Database Security Lab", icon: "🗄️", level: 1, group: "Labs", why: "Level 1 covers least privilege and SQL injection." },
  { to: "/engineering", label: "Data Security Engineering", icon: "⚙️", level: 3, group: "Simulation", why: "Level 3 (Engineer) covers test suites, metrics and change records." },
  { to: "/labs/privacy", label: "Privacy & Governance", icon: "⚖️", level: 4, group: "Labs", why: "Level 4 (Architect) covers minimisation, retention and deletion." },
  { to: "/labs/cloud", label: "Cloud Data Security", icon: "☁️", level: 4, group: "Labs", why: "Level 4 (Architect) covers cloud exposure assessment." },
  { to: "/labs/ai", label: "AI Data Security", icon: "🤖", level: 4, group: "Labs", why: "Level 4 (Architect) covers prompt DLP, retrieval permissions and AI logs." },
  { to: "/real-tools", label: "Real-Tool Practice", icon: "🧰", level: 4, group: "Labs", why: "Guidance for practising on real products once you reach Level 4." },
  { to: "/admin", label: "Administrator Settings", icon: "🛠️", level: 99, group: "Staff", why: "For instructors and administrators." },
];

export function useToolAccess() {
  const { user } = useAuth();
  const { profile } = useCareer();
  const staff = user?.role === "admin" || user?.role === "instructor";
  const level = profile?.career_level ?? 0;
  const unlocked = (t: Tool) => (t.group === "Staff" ? staff : staff || t.level <= level);
  return { staff, level, unlocked };
}

export function toolFor(path: string): Tool | undefined {
  return TOOLS.find((t) => path === t.to || path.startsWith(`${t.to}/`));
}

/** Route guard for a standalone tool page: shows why it is locked instead of the tool. */
export function LevelGate({ path, children }: { path: string; children: ReactNode }) {
  const { level, unlocked } = useToolAccess();
  const tool = toolFor(path);
  if (!tool || unlocked(tool)) return <>{children}</>;
  return (
    <Card className="locked-tool">
      <div className="locked-icon" aria-hidden>🔒</div>
      <h1>{tool.icon} {tool.label}</h1>
      {tool.group === "Staff" ? <p>{tool.why}</p> : (
        <>
          <p className="lead">Unlocks at <strong>Level {tool.level}</strong>. You are on Level {level}.</p>
          <p className="muted">{tool.why} Tools open up as you level up, so each one arrives when you have learned what it is for.</p>
          <div className="row">
            <Link className="btn primary" to={`/levels/${level}`}>Continue Level {level}</Link>
            <Link className="btn" to="/">My Journey</Link>
          </div>
        </>
      )}
    </Card>
  );
}
