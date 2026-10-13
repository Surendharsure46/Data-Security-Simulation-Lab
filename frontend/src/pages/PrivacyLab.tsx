import { useState } from "react";
import { api, download } from "../api";
import { ActionButton, Badge, Banner, Card, Field, Loading, PageHead, Provenance, useToast } from "../components/ui";
import { useLoad } from "../state";

function Done({ ok }: { ok: boolean }) {
  return ok ? <Badge tone="ok">Exercise passed</Badge> : <Badge>Not yet passed</Badge>;
}

export default function PrivacyLab() {
  const toast = useToast();
  const ov = useLoad(() => api.get("/api/labs/privacy"), []);
  const [dec, setDec] = useState<Record<string, { decision: string; reason: string }>>({});
  const [minRes, setMinRes] = useState<any>(null);
  const [rule, setRule] = useState({ inactive_days: 365, no_consent_days: 90, respect_legal_hold: true });
  const [preview, setPreview] = useState<any>(null);
  const [exec, setExec] = useState<any>(null);
  const [report, setReport] = useState<string | null>(null);
  if (ov.loading) return <Loading />;
  const d = ov.data;
  const passed: string[] = d.passed;
  const decisions = { ...Object.fromEntries(d.fields.map((f: string) => [f, d.state.field_decisions[f] ?? { decision: "KEEP", reason: "" }])), ...dec };
  return (
    <>
      <PageHead title="Privacy & Data Governance" crumbs="Privacy & Governance" mode="SIMULATED" actions={
        <ActionButton confirm="Restore the original 30 synthetic records and clear your decisions?" onClick={async () => { await api.post("/api/labs/privacy/reset"); setDec({}); setPreview(null); setExec(null); setReport(null); ov.reload(); }}>Reset lab</ActionButton>
      }>
        <p>{d.note} This lab teaches privacy-control practice; it is not legal advice and makes no compliance claim. Lab date: {d.lab_today}.</p>
      </PageHead>
      <Card title="Documented purpose and records standard">
        <p><strong>Purpose:</strong> {d.purpose}</p>
        <p><strong>Standard:</strong> {d.retention_standard}</p>
      </Card>
      <Card title="1. Data minimisation" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("minimization")} /></>}>
        <p className="small">For each field in the marketing-leads dataset, decide KEEP or REMOVE for the documented purpose and give a reason.</p>
        <div className="table-wrap"><table>
          <thead><tr><th>Field</th><th>Example value</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody>{d.fields.map((f: string) => (
            <tr key={f}><td className="mono">{f}</td><td className="small mono">{String(d.state.leads[0]?.[f] ?? "")}</td>
              <td><select aria-label={`Decision for ${f}`} value={decisions[f].decision} onChange={(e) => setDec({ ...dec, [f]: { ...decisions[f], decision: e.target.value } })}><option>KEEP</option><option>REMOVE</option></select></td>
              <td><input aria-label={`Reason for ${f}`} value={decisions[f].reason} onChange={(e) => setDec({ ...dec, [f]: { ...decisions[f], reason: e.target.value } })} placeholder="why?" /></td></tr>
          ))}</tbody>
        </table></div>
        <ActionButton className="primary" onClick={async () => { const r = await api.put("/api/labs/privacy/minimization", { decisions }); setMinRes(r); ov.reload(); }}>Submit decisions</ActionButton>
        {minRes && (minRes.passed ? <Banner tone="ok">Minimisation decisions accepted. {minRes.note}</Banner> : (
          <Banner tone="warn">Not yet: {minRes.missing_removals.length > 0 && `fields not needed for this purpose remain (${minRes.missing_removals.length}); `}{minRes.wrongly_removed.length > 0 && `fields the purpose or retention rules depend on were removed (${minRes.wrongly_removed.length}).`}</Banner>
        ))}
      </Card>
      <Card title="2. Retention and verified deletion" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("retention")} /></>}>
        <div className="grid three">
          <Field label="Delete when inactive for more than (days)"><input type="number" min={1} value={rule.inactive_days} onChange={(e) => setRule({ ...rule, inactive_days: Number(e.target.value) })} /></Field>
          <Field label="Delete leads without consent after (days)"><input type="number" min={1} value={rule.no_consent_days} onChange={(e) => setRule({ ...rule, no_consent_days: Number(e.target.value) })} /></Field>
          <label className="inline-check"><input type="checkbox" checked={rule.respect_legal_hold} onChange={(e) => setRule({ ...rule, respect_legal_hold: e.target.checked })} />Legal hold overrides deletion</label>
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <ActionButton onClick={async () => setPreview(await api.post("/api/labs/privacy/retention/evaluate", rule))}>Evaluate (dry run)</ActionButton>
          <ActionButton className="danger" disabled={!preview} confirm="Permanently delete the matching records from your disposable lab dataset?" onClick={async () => {
            const r = await api.post("/api/labs/privacy/retention/execute", { confirm: true });
            setExec(r); setPreview(null); ov.reload();
            toast(r.passed ? "Deletion verified against the standard" : (r.feedback ?? "Deletion did not meet the standard"), r.passed ? "ok" : "danger");
          }}>Execute deletion</ActionButton>
          <span className="small muted">{d.state.leads.length} records currently in the dataset · {d.state.deleted.length} deleted so far</span>
        </div>
        {preview && (
          <div className="table-wrap" style={{ marginTop: 8 }}><table>
            <thead><tr><th>Lead</th><th>Reasons</th><th>Legal hold</th><th>Planned action</th></tr></thead>
            <tbody>{preview.matches.map((m: any) => <tr key={m.lead_id}><td>{m.lead_id}</td><td className="small">{m.reasons.join("; ")}</td><td>{m.legal_hold ? <Badge tone="warn">HOLD</Badge> : "—"}</td><td>{m.action}</td></tr>)}</tbody>
          </table></div>
        )}
        {exec && <Banner tone={exec.passed ? "ok" : "danger"}>Deleted {exec.deleted.length}; remaining {exec.remaining}. {exec.verification} {exec.feedback}</Banner>}
        {d.state.critical && <Banner tone="danger">Critical: {d.state.critical}</Banner>}
      </Card>
      <Card title="3. Privacy findings report" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("report")} /></>}>
        <div className="row">
          <ActionButton onClick={async () => { setReport(await api.text("/api/labs/privacy/report")); ov.reload(); }}>Generate report</ActionButton>
          <ActionButton onClick={() => download("/api/labs/privacy/report", "privacy-findings-report.md")}>Download Markdown</ActionButton>
        </div>
        {report && <pre style={{ marginTop: 8 }}>{report}</pre>}
      </Card>
    </>
  );
}
