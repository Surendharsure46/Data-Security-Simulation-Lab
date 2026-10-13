import type { Decision, TraceEntry, TraceNode } from "../types";
import { Badge, Status } from "./ui";

function fmt(v: unknown) {
  if (v === null || v === undefined) return "∅";
  return typeof v === "string" ? `"${v}"` : JSON.stringify(v);
}

function Node({ n }: { n: TraceNode }) {
  if (n.group) {
    return (
      <div className="trace-node">
        <div className="small muted">{n.group === "all" ? "ALL of" : "ANY of"} → {n.result ? "true" : "false"}</div>
        {n.children?.map((c, i) => <Node key={i} n={c} />)}
      </div>
    );
  }
  return (
    <div className={`trace-node trace-cond ${n.result ? "met" : "unmet"}`}>
      {n.result ? "✓" : "✗"} {n.field} {n.op} {n.value !== null && n.value !== undefined ? fmt(n.value) : ""} — actual {n.missing ? "MISSING" : fmt(n.actual)}
      {n.error && <span> ({n.error})</span>}
    </div>
  );
}

export function TraceEntryView({ e }: { e: TraceEntry }) {
  return (
    <div className="card tight" style={{ marginBottom: 8 }}>
      <div className="row between">
        <div className="row">
          <strong>{e.policy_key}</strong> <span className="muted small">v{e.policy_version} · {e.name}</span>
          <Badge>{e.kind}</Badge>
        </div>
        <div className="row">
          {e.skipped_reason ? <Badge>skipped</Badge> : e.matched ? <Badge tone="info">matched</Badge> : <Badge>no match</Badge>}
          {e.effective_outcome && <Status value={e.effective_outcome} />}
          {e.alert && <Badge tone="warn">alert</Badge>}
        </div>
      </div>
      {e.skipped_reason && <div className="small muted">{e.skipped_reason}</div>}
      {e.exception && <div className="small">Exception <strong>{e.exception.id}</strong> applied: {e.exception.description}</div>}
      {e.condition_trace && <Node n={e.condition_trace} />}
    </div>
  );
}

export function TraceList({ entries, decision }: { entries: TraceEntry[]; decision?: Decision }) {
  return (
    <div>
      {decision && (
        <div className="banner info">
          <strong>Decision: {decision.outcome}</strong> — {decision.reason}
        </div>
      )}
      {entries.map((e) => <TraceEntryView key={e.policy_key} e={e} />)}
    </div>
  );
}
