import { useState } from "react";
import { api } from "../api";
import { ActionButton, Badge, Banner, Card, LabelBadge, Loading, PageHead, Provenance, Status, useToast } from "../components/ui";
import { useLoad } from "../state";

export default function CloudLab() {
  const toast = useToast();
  const ov = useLoad(() => api.get("/api/labs/cloud"), []);
  const [assessment, setAssessment] = useState<any>(null);
  const [answer, setAnswer] = useState("");
  const [verify, setVerify] = useState<any>(null);
  if (ov.loading) return <Loading />;
  const d = ov.data;
  const passed: string[] = d.passed;
  const change = async (bucket: string, field: string, value: unknown) => {
    await api.post("/api/labs/cloud/change", { bucket, field, value });
    setVerify(null);
    ov.reload();
  };
  return (
    <>
      <PageHead title="Cloud Data Security / DSPM" crumbs="Cloud DSPM Lab" mode="SIMULATED" actions={
        <ActionButton confirm="Restore the original storage configuration?" onClick={async () => { await api.post("/api/labs/cloud/reset"); setAssessment(null); setVerify(null); ov.reload(); }}>Reset lab</ActionButton>
      }>
        <p>{d.note} Credentials for real cloud accounts are never requested; an optional real-cloud exercise requires your own sandbox account (see Real-Tool Practice).</p>
      </PageHead>
      <div className="row" style={{ marginBottom: 10 }}>
        <span className="small">Assess {passed.includes("assess") ? <Badge tone="ok">passed</Badge> : <Badge>not yet</Badge>}</span>
        <span className="small">Remediate {passed.includes("remediate") ? <Badge tone="ok">passed</Badge> : <Badge>not yet</Badge>}</span>
      </div>
      <Card title="Storage estate (current configuration)" actions={<Provenance mode="SIMULATED" />}>
        <div className="table-wrap"><table>
          <thead><tr><th>Bucket</th><th>Data</th><th>Purpose / requirement</th><th>Access</th><th>Encryption</th><th>Access logging</th></tr></thead>
          <tbody>{d.buckets.map((b: any) => (
            <tr key={b.name}>
              <td className="mono">{b.name}<div className="small muted">{b.objects} objects{b.records ? ` · ${b.records.toLocaleString()} records` : ""}</div></td>
              <td><LabelBadge label={b.data_label} /></td>
              <td className="small">{b.purpose}{b.business_requirement && <div><Badge tone="info">{b.business_requirement}</Badge></div>}</td>
              <td>
                <select value={b.access} aria-label={`Access for ${b.name}`} onChange={(e) => change(b.name, "access", e.target.value)}>{d.access_options.map((o: string) => <option key={o}>{o}</option>)}</select>
                {b.cross_account_principals.map((p: string) => (
                  <div key={p} className="small">{p} <button className="small ghost" onClick={() => change(b.name, "remove_principal", p)}>remove</button></div>
                ))}
              </td>
              <td><input type="checkbox" aria-label={`Encryption for ${b.name}`} checked={b.encryption} onChange={(e) => change(b.name, "encryption", e.target.checked)} /></td>
              <td><input type="checkbox" aria-label={`Logging for ${b.name}`} checked={b.access_logging} onChange={(e) => change(b.name, "access_logging", e.target.checked)} /></td>
            </tr>
          ))}</tbody>
        </table></div>
        <p className="small muted">Risk model: {d.risk_model}</p>
      </Card>
      <div className="grid two">
        <Card title="Exposure assessment">
          <div className="row">
            <ActionButton className="primary" onClick={async () => { setAssessment(await api.post("/api/labs/cloud/assess")); ov.reload(); }}>Run assessment</ActionButton>
            <span className="small muted">{d.assessments_run} assessments run</span>
          </div>
          {assessment && (
            <>
              <p>Total exposure of non-public data: <strong>{assessment.total_exposure_non_public}</strong> (target ≤ {assessment.target})</p>
              <div className="table-wrap"><table>
                <thead><tr><th>Bucket</th><th>Score</th><th>Sensitivity × breadth</th><th>Missing controls</th></tr></thead>
                <tbody>{assessment.buckets.map((b: any) => <tr key={b.bucket}><td className="mono">{b.bucket}</td><td><strong>{b.score}</strong></td><td>{b.sensitivity} × {b.breadth}</td><td>{b.missing_controls}</td></tr>)}</tbody>
              </table></div>
            </>
          )}
          <hr />
          <div className="row">
            <select value={answer} onChange={(e) => setAnswer(e.target.value)} aria-label="Highest exposure bucket"><option value="">— highest-exposure bucket in the original estate —</option>{d.buckets.map((b: any) => <option key={b.name}>{b.name}</option>)}</select>
            <ActionButton disabled={!answer} onClick={async () => { const r = await api.post("/api/labs/cloud/assess/answer", { bucket: answer }); toast(r.correct ? "Correct" : "Not the highest exposure — compare the scores", r.correct ? "ok" : "danger"); ov.reload(); }}>Submit</ActionButton>
          </div>
        </Card>
        <Card title="Verify remediation">
          <p className="small">Reduce exposure to the target without breaking documented business requirements, run a fresh assessment after your last change, then verify.</p>
          <ActionButton className="primary" onClick={async () => { setVerify(await api.post("/api/labs/cloud/verify")); ov.reload(); }}>Verify</ActionButton>
          {verify && (verify.passed ? <Banner tone="ok">Verified: exposure {verify.assessment.total_exposure_non_public} ≤ target and requirements intact.</Banner> : <Banner tone="warn"><ul>{verify.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul></Banner>)}
        </Card>
      </div>
      <Card title="Synthetic cloud audit events" actions={<Provenance mode="SIMULATED" />}>
        <Banner tone="warn">These events are generated by the simulation from the current configuration. They are not AWS CloudTrail, Azure Monitor or Google Cloud audit logs.</Banner>
        <div className="table-wrap" style={{ maxHeight: 320, overflowY: "auto" }}><table>
          <thead><tr><th>Time</th><th>Bucket</th><th>Principal</th><th>Operation</th><th>Source IP</th><th>Result</th></tr></thead>
          <tbody>{d.audit_events.map((e: any, i: number) => <tr key={i}><td className="small">{e.time}</td><td className="mono small">{e.bucket}</td><td>{e.principal}</td><td>{e.operation}</td><td className="mono small">{e.source_ip}</td><td><Status value={e.result === "Success" ? "SUCCESS" : e.result} /></td></tr>)}</tbody>
        </table></div>
      </Card>
    </>
  );
}
