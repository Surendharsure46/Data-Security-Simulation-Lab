import { useEffect, useState } from "react";
import { api } from "../api";
import { PolicyEditor } from "../components/PolicyEditor";
import { ActionButton, Badge, Banner, Card, Field, Loading, PageHead, Provenance, Status, Tabs, useToast } from "../components/ui";
import { useLoad } from "../state";
import type { PolicyDefinition } from "../types";

function Done({ ok }: { ok: boolean }) {
  return ok ? <Badge tone="ok">Exercise passed</Badge> : <Badge>Not yet passed</Badge>;
}

export interface LabViewProps { embedded?: boolean; focus?: string[]; onChange?: () => void }

const AI_TAB_FOR: Record<string, "gateway" | "rag" | "logging"> = { prompt_gateway: "gateway", rag_acl: "rag", retention: "logging" };

export default function AiLab({ embedded = false, focus, onChange }: LabViewProps = {}) {
  const toast = useToast();
  const ov0 = useLoad(() => api.get("/api/labs/ai"), []);
  const ov = { ...ov0, reload: () => { ov0.reload(); onChange?.(); } };
  const [tab, setTab] = useState<"gateway" | "rag" | "logging">(focus?.length ? AI_TAB_FOR[focus[0]] : "gateway");
  const [policy, setPolicy] = useState<PolicyDefinition | null>(null);
  const [gw, setGw] = useState<any>(null);
  const [rq, setRq] = useState({ role: "support_agent", query: "what is rita silva salary" });
  const [rr, setRr] = useState<any>(null);
  const [rt, setRt] = useState<any>(null);
  const [log, setLog] = useState<any>(null);
  const [logRes, setLogRes] = useState<any>(null);
  useEffect(() => {
    if (ov.data && !policy) {
      const p = ov.data.state.gateway_policy;
      setPolicy({ description: "", priority: 100, applies_to_actions: [], severity: "MEDIUM", alert: true, escalate: false, alert_title: "", exceptions: [], test_cases: [], ...p });
      setLog(ov.data.state.logging);
    }
  }, [ov.data, policy]);
  if (ov.loading || !policy) return <Loading />;
  const d = ov.data;
  const passed: string[] = d.passed;
  return (
    <>
      {!embedded && <PageHead title="AI Data Security" crumbs="AI Data Security" mode="SIMULATED" actions={
        <ActionButton confirm="Reset the AI lab configuration?" onClick={async () => { await api.post("/api/labs/ai/reset"); setPolicy(null); setGw(null); setRr(null); setRt(null); setLogRes(null); ov.reload(); }}>Reset lab</ActionButton>
      }>
        <p>{d.note} Basic exercises never require a paid model API, and no user data leaves the platform.</p>
      </PageHead>}
      <Tabs tabs={([["gateway", "Prompt gateway (DLP for AI)"], ["rag", "Permission-aware retrieval"], ["logging", "AI logging & retention"]] as [typeof tab, string][])
        .filter(([k]) => !focus?.length || focus.some((f) => AI_TAB_FOR[f] === k))} value={tab} onChange={setTab} />

      {tab === "gateway" && (
        <div className="grid side">
          <Card title="Gateway policy" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("prompt_gateway")} /></>}>
            <p className="small">The same policy engine as the DLP Policy Studio evaluates every prompt (action <code>AI_PROMPT</code>). Content detectors scan the prompt text. Goal: block sensitive prompts to the unapproved AI and bank/card/secret data everywhere, while approved and harmless use continues.</p>
            <PolicyEditor value={policy} onChange={setPolicy} lockKind />
            <ActionButton className="primary" onClick={async () => {
              const r = await api.put("/api/labs/ai/gateway", { policy });
              setGw(r);
              const ev = await api.post("/api/labs/ai/gateway/evaluate");
              setGw(ev);
              ov.reload();
              toast(ev.passed ? "All prompts handled correctly" : `${ev.correct}/${ev.total} prompts handled correctly`, ev.passed ? "ok" : "info");
            }}>Save & evaluate prompts</ActionButton>
          </Card>
          <Card title="Prompt test set">
            <div className="table-wrap"><table>
              <thead><tr><th>Prompt</th><th>Destination</th><th>Expected</th>{gw && <><th>Detected</th><th>Outcome</th></>}</tr></thead>
              <tbody>{d.prompts.map((p: any) => {
                const r = gw?.results.find((x: any) => x.id === p.id);
                return (
                  <tr key={p.id}><td className="small"><strong>{p.id}</strong> ({p.actor_dept}) {p.text}</td><td className="small">{p.destination}</td><td><Status value={p.expected} /></td>
                    {gw && <><td className="small">{r?.detected_types.join(", ") || "—"}</td><td><Status value={r?.outcome} /> {r && (r.correct ? "✓" : "✗")}</td></>}</tr>
                );
              })}</tbody>
            </table></div>
          </Card>
        </div>
      )}

      {tab === "rag" && (
        <div className="grid two">
          <Card title="Retriever configuration" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("rag_acl")} /></>}>
            {(["enforce_acl", "index_restricted_docs"] as const).map((k) => (
              <label key={k} className="inline-check" style={{ display: "flex" }}>
                <input type="checkbox" checked={d.state.rag[k]} onChange={async (e) => { await api.put("/api/labs/ai/rag", { ...d.state.rag, [k]: e.target.checked }); setRt(null); ov.reload(); }} />
                {k === "enforce_acl" ? "Enforce source-document permissions at retrieval time" : "Index HR (restricted) documents"}
              </label>
            ))}
            <h3 style={{ marginTop: 10 }}>Documents and permissions</h3>
            <ul className="small">{d.documents.map((doc: any) => <li key={doc.id}><strong>{doc.id}</strong> {doc.title} — {doc.acl.join(", ")}</li>)}</ul>
            <ActionButton className="primary" onClick={async () => { setRt(await api.post("/api/labs/ai/rag/tests")); ov.reload(); }}>Run access tests</ActionButton>
            {rt && (
              <div className="table-wrap" style={{ marginTop: 8 }}><table>
                <thead><tr><th>Test</th><th>Role</th><th>Retrieved</th><th>Result</th></tr></thead>
                <tbody>{rt.results.map((r: any) => <tr key={r.id}><td className="small">{r.id}: {r.query}</td><td>{r.role}</td><td>{r.retrieved.join(", ") || "—"}</td>
                  <td>{r.passed ? <Badge tone="ok">pass</Badge> : <Badge tone="danger">{r.leaked.length ? `leaked ${r.leaked.join(", ")}` : "missing expected"}</Badge>}</td></tr>)}</tbody>
              </table></div>
            )}
          </Card>
          <Card title="Ask the assistant (retrieval only)">
            <div className="grid two">
              <Field label="Role"><select value={rq.role} onChange={(e) => setRq({ ...rq, role: e.target.value })}>{Object.keys(d.roles).map((r) => <option key={r}>{r}</option>)}</select></Field>
              <Field label="Query"><input value={rq.query} onChange={(e) => setRq({ ...rq, query: e.target.value })} /></Field>
            </div>
            <ActionButton onClick={async () => setRr(await api.post("/api/labs/ai/rag/query", rq))}>Retrieve</ActionButton>
            {rr && <ul>{rr.results.map((x: any) => <li key={x.id}>{x.id} {x.title} <span className="small muted">(score {x.score}, ACL {x.acl.join(", ")})</span></li>)}{rr.results.length === 0 && <li className="muted">No documents retrieved.</li>}</ul>}
          </Card>
        </div>
      )}

      {tab === "logging" && log && (
        <Card title="AI prompt logging configuration" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("retention")} /></>}>
          <div className="grid four">
            <Field label="Prompt logging"><select value={log.prompt_logging} onChange={(e) => setLog({ ...log, prompt_logging: e.target.value })}>{d.logging_options.prompt_logging.map((o: string) => <option key={o}>{o}</option>)}</select></Field>
            <Field label="Retention (days)"><input type="number" min={0} value={log.retention_days} onChange={(e) => setLog({ ...log, retention_days: Number(e.target.value) })} /></Field>
            <Field label="Who can read logs"><select value={log.log_access} onChange={(e) => setLog({ ...log, log_access: e.target.value })}>{d.logging_options.log_access.map((o: string) => <option key={o}>{o}</option>)}</select></Field>
            <label className="inline-check"><input type="checkbox" checked={log.vendor_training_opt_in} onChange={(e) => setLog({ ...log, vendor_training_opt_in: e.target.checked })} />Share prompts with vendor for training</label>
          </div>
          <ActionButton className="primary" onClick={async () => { setLogRes(await api.put("/api/labs/ai/logging", log)); ov.reload(); }}>Save & check</ActionButton>
          {logRes && (logRes.passed ? <Banner tone="ok">No findings.</Banner> : <ul>{logRes.findings.map((f: any) => <li key={f.id}><strong>{f.id}</strong> {f.finding} <span className="muted">Fix: {f.fix}</span></li>)}</ul>)}
        </Card>
      )}
    </>
  );
}
