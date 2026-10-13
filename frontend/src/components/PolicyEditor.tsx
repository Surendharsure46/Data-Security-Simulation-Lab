import type { Condition, ConditionGroup, PolicyDefinition, PolicyException } from "../types";
import { isGroup } from "../types";
import { Field } from "./ui";

export const FIELDS = [
  "action.type", "actor.id", "actor.department", "actor.role", "actor.employment_type", "actor.groups",
  "content.label", "content.label_rank", "content.detected_types", "content.max_confidence", "content.match_count", "content.record_count",
  "resource.id", "resource.system", "resource.department", "resource.owner_assigned",
  "destination.id", "destination.kind", "destination.category", "destination.sanctioned", "destination.internal", "destination.domain",
  "context.business_justification", "context.ticket_id", "context.after_hours", "context.device_managed",
];
const OPS = ["eq", "neq", "in", "not_in", "contains_any", "contains_all", "contains_none", "gt", "gte", "lt", "lte", "exists", "not_exists", "label_at_least", "label_below"];
const LIST_OPS = new Set(["in", "not_in", "contains_any", "contains_all", "contains_none"]);
const NUM_OPS = new Set(["gt", "gte", "lt", "lte"]);
const ACTIONS = ["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT"];

export function emptyDefinition(): PolicyDefinition {
  return {
    name: "New DLP policy", description: "", kind: "DLP", priority: 100, applies_to_actions: ["UPLOAD", "EMAIL"],
    conditions: { match: "all", conditions: [{ field: "destination.sanctioned", op: "eq", value: false }] },
    outcome: "MONITOR", severity: "MEDIUM", alert: true, escalate: false, alert_title: "", exceptions: [], test_cases: [],
  };
}

function valueToText(c: Condition): string {
  if (c.value === undefined || c.value === null) return "";
  if (Array.isArray(c.value)) return c.value.join(", ");
  return String(c.value);
}

function parseValue(op: string, text: string): unknown {
  if (op === "exists" || op === "not_exists") return null;
  if (LIST_OPS.has(op)) return text.split(",").map((s) => s.trim()).filter(Boolean);
  if (NUM_OPS.has(op)) return text === "" ? "" : Number(text);
  if (text === "true") return true;
  if (text === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(text)) return Number(text);
  return text;
}

function ConditionRow({ c, onChange, onRemove }: { c: Condition; onChange: (c: Condition) => void; onRemove: () => void }) {
  const noValue = c.op === "exists" || c.op === "not_exists";
  return (
    <div className="cond-row">
      <select aria-label="Field" value={c.field} onChange={(e) => onChange({ ...c, field: e.target.value })}>
        {FIELDS.map((f) => <option key={f}>{f}</option>)}
      </select>
      <select aria-label="Operator" value={c.op} onChange={(e) => onChange({ ...c, op: e.target.value, value: parseValue(e.target.value, valueToText(c)) })}>
        {OPS.map((o) => <option key={o}>{o}</option>)}
      </select>
      <input aria-label="Value" disabled={noValue} placeholder={LIST_OPS.has(c.op) ? "comma-separated list" : noValue ? "(no value)" : "value (true/false/number/text)"}
        defaultValue={valueToText(c)} key={`${c.op}-${valueToText(c)}`}
        onBlur={(e) => onChange({ ...c, value: parseValue(c.op, e.target.value) })} />
      <button type="button" className="small ghost" onClick={onRemove} aria-label="Remove condition">✕</button>
    </div>
  );
}

export function GroupEditor({ g, onChange, depth = 1, onRemove }: { g: ConditionGroup; onChange: (g: ConditionGroup) => void; depth?: number; onRemove?: () => void }) {
  const set = (i: number, c: Condition | ConditionGroup) => onChange({ ...g, conditions: g.conditions.map((x, j) => (j === i ? c : x)) });
  const remove = (i: number) => onChange({ ...g, conditions: g.conditions.filter((_, j) => j !== i) });
  return (
    <div className="cond-group">
      <div className="row between">
        <label className="row small">
          Match
          <select value={g.match} onChange={(e) => onChange({ ...g, match: e.target.value as "all" | "any" })}>
            <option value="all">ALL conditions</option>
            <option value="any">ANY condition</option>
          </select>
        </label>
        {onRemove && <button type="button" className="small ghost" onClick={onRemove}>Remove group</button>}
      </div>
      {g.conditions.map((c, i) =>
        isGroup(c) ? (
          <GroupEditor key={i} g={c} depth={depth + 1} onChange={(n) => set(i, n)} onRemove={() => remove(i)} />
        ) : (
          <ConditionRow key={i} c={c} onChange={(n) => set(i, n)} onRemove={() => remove(i)} />
        ),
      )}
      <div className="row">
        <button type="button" className="small" onClick={() => onChange({ ...g, conditions: [...g.conditions, { field: "content.label", op: "label_at_least", value: "confidential" }] })}>+ Condition</button>
        {depth < 3 && (
          <button type="button" className="small" onClick={() => onChange({ ...g, conditions: [...g.conditions, { match: "any", conditions: [{ field: "content.detected_types", op: "contains_any", value: ["CREDIT_CARD"] }] }] })}>+ Nested group</button>
        )}
      </div>
    </div>
  );
}

export function PolicyEditor({ value, onChange, lockKind }: { value: PolicyDefinition; onChange: (d: PolicyDefinition) => void; lockKind?: boolean }) {
  const d = value;
  const set = (patch: Partial<PolicyDefinition>) => onChange({ ...d, ...patch });
  const setExc = (i: number, e: PolicyException) => set({ exceptions: d.exceptions.map((x, j) => (j === i ? e : x)) });
  return (
    <div className="stack">
      <div className="grid two">
        <Field label="Name"><input value={d.name} onChange={(e) => set({ name: e.target.value })} /></Field>
        <Field label="Alert title"><input value={d.alert_title} onChange={(e) => set({ alert_title: e.target.value })} /></Field>
      </div>
      <Field label="Purpose / description"><textarea value={d.description} onChange={(e) => set({ description: e.target.value })} /></Field>
      <div className="grid four">
        <Field label="Kind">
          <select value={d.kind} disabled={lockKind} onChange={(e) => set({ kind: e.target.value as "DLP" | "DETECTION", outcome: e.target.value === "DETECTION" ? "MONITOR" : d.outcome })}>
            <option>DLP</option><option>DETECTION</option>
          </select>
        </Field>
        <Field label="Outcome" hint={d.kind === "DETECTION" ? "Detection policies only monitor." : "BLOCK > WARN > MONITOR > ALLOW"}>
          <select value={d.outcome} onChange={(e) => set({ outcome: e.target.value as PolicyDefinition["outcome"] })}>
            {(d.kind === "DETECTION" ? ["MONITOR"] : ["ALLOW", "MONITOR", "WARN", "BLOCK"]).map((o) => <option key={o}>{o}</option>)}
          </select>
        </Field>
        <Field label="Severity">
          <select value={d.severity} onChange={(e) => set({ severity: e.target.value as PolicyDefinition["severity"] })}>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((o) => <option key={o}>{o}</option>)}
          </select>
        </Field>
        <Field label="Priority" hint="Lower wins ties"><input type="number" min={1} max={1000} value={d.priority} onChange={(e) => set({ priority: Number(e.target.value) })} /></Field>
      </div>
      <div className="row">
        <label className="inline-check"><input type="checkbox" checked={d.alert} onChange={(e) => set({ alert: e.target.checked })} /> Raise alert</label>
        <label className="inline-check"><input type="checkbox" checked={d.escalate} onChange={(e) => set({ escalate: e.target.checked })} /> Escalate</label>
      </div>
      <fieldset style={{ border: "1px solid var(--border)", borderRadius: 6 }}>
        <legend className="small">Applies to actions (empty = all)</legend>
        <div className="row">
          {ACTIONS.map((a) => (
            <label key={a} className="inline-check">
              <input type="checkbox" checked={d.applies_to_actions.includes(a)}
                onChange={(e) => set({ applies_to_actions: e.target.checked ? [...d.applies_to_actions, a] : d.applies_to_actions.filter((x) => x !== a) })} />
              {a}
            </label>
          ))}
        </div>
      </fieldset>
      <div>
        <h3>Matching conditions</h3>
        <GroupEditor g={d.conditions} onChange={(g) => set({ conditions: g })} />
      </div>
      <div>
        <div className="row between">
          <h3>Exceptions</h3>
          <button type="button" className="small" onClick={() => set({ exceptions: [...d.exceptions, {
            id: `EX-${d.exceptions.length + 1}`, description: "Describe the business reason", outcome: "ALLOW",
            when: { match: "all", conditions: [{ field: "destination.id", op: "eq", value: "dst-paybridge-email" }] },
          }] })}>+ Exception</button>
        </div>
        <p className="small muted">The first matching exception (in order) replaces the outcome and suppresses the alert unless "keep alert" is set.</p>
        {d.exceptions.map((ex, i) => (
          <div key={i} className="card tight">
            <div className="grid three">
              <Field label="ID"><input value={ex.id} onChange={(e) => setExc(i, { ...ex, id: e.target.value })} /></Field>
              <Field label="Outcome">
                <select value={ex.outcome} onChange={(e) => setExc(i, { ...ex, outcome: e.target.value as "ALLOW" | "MONITOR" })}><option>ALLOW</option><option>MONITOR</option></select>
              </Field>
              <label className="inline-check"><input type="checkbox" checked={!!ex.keep_alert} onChange={(e) => setExc(i, { ...ex, keep_alert: e.target.checked })} /> keep alert</label>
            </div>
            <Field label="Business reason"><input value={ex.description} onChange={(e) => setExc(i, { ...ex, description: e.target.value })} /></Field>
            <GroupEditor g={ex.when} onChange={(g) => setExc(i, { ...ex, when: g })} />
            <button type="button" className="small ghost" onClick={() => set({ exceptions: d.exceptions.filter((_, j) => j !== i) })}>Remove exception</button>
          </div>
        ))}
      </div>
    </div>
  );
}
