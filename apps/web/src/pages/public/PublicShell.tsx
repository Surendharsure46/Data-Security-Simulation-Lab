import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export function Brand() {
  return (
    <Link to="/" className="public-brand" aria-label="Threatready home">
      <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden>
        <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)" />
        <path d="m10.5 16 4 4 7-8" stroke="var(--accent-ink)" strokeWidth="3" fill="none" />
      </svg>
      <span>Threatready <small>Data Security</small></span>
    </Link>
  );
}

// Public pages (welcome, get started): a fixed top bar with the call to action in the top-right corner.
export function PublicShell({ actions, children }: { actions: ReactNode; children: ReactNode }) {
  return (
    <div className="public">
      <header className="public-top">
        <Brand />
        <nav className="row" aria-label="Get started">{actions}</nav>
      </header>
      <main id="main" className="public-main">{children}</main>
      <footer className="public-foot small muted">
        All companies, people and records in Threatready are synthetic. Simulated activity never affects a real system.
      </footer>
    </div>
  );
}
