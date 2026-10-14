import { useState } from "react";
import { api } from "../api";
import type { DemoContent, Decision, TraceEntry } from "../types";
import { TraceList } from "./Trace";
import { ActionButton, Banner, Card, Provenance, Status } from "./ui";

// Level 0 interactive demo lab: real detectors and the real policy engine on one synthetic record.

interface ScanResult { findings: { detector: string; match_count: number; confidence: string; evidence: { line: number; masked_value: string }[] }[]; explanation: string }
interface ClassifyResult { label: string; correct: boolean; feedback: string }
interface TransferResult { destination: { name: string }; label_used: string | null; decision: Decision; trace: TraceEntry[]; consequence: string }

export function DemoLab({ d, onChange, readOnly = false }: { d: DemoContent; onChange?: () => void; readOnly?: boolean }) {
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [label, setLabel] = useState("");
  const [classified, setClassified] = useState<ClassifyResult | null>(null);
  const [transfers, setTransfers] = useState<TransferResult[]>([]);
  return (
    <>
      <Card title={`1. Inspect: ${d.record_name}`} actions={<Provenance mode="SIMULATED" />}>
        <pre>{d.record}</pre>
        <ActionButton className={scan ? "" : "primary"} disabled={readOnly} onClick={async () => {
          setScan(await api.post<ScanResult>("/api/career/demo/scan", {}));
          onChange?.();
        }}>Run discovery detectors</ActionButton>
        {scan && (
          <div style={{ marginTop: 10 }}>
            <div className="table-wrap"><table>
              <thead><tr><th>Detector</th><th>Matches</th><th>Confidence</th><th>Masked evidence</th></tr></thead>
              <tbody>{scan.findings.map((f) => (
                <tr key={f.detector}><td>{f.detector}</td><td>{f.match_count}</td><td><Status value={f.confidence} /></td>
                  <td className="mono">{f.evidence.map((e) => e.masked_value).join(", ")}</td></tr>
              ))}</tbody>
            </table></div>
            <p className="small muted">{scan.explanation}</p>
          </div>
        )}
      </Card>
      <Card title="2. Decide how sensitive it is">
        <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
          <legend className="small muted">Choose a label from the company label scheme</legend>
          {d.labels.map((l) => (
            <label key={l.key} className="inline-check" style={{ display: "flex", marginBottom: 4 }}>
              <input type="radio" name="demo-label" value={l.key} checked={label === l.key} onChange={() => setLabel(l.key)} />
              <span><strong>{l.name}</strong> — <span className="small">{l.description}</span></span>
            </label>
          ))}
        </fieldset>
        <ActionButton disabled={!label || readOnly} onClick={async () => {
          setClassified(await api.post<ClassifyResult>("/api/career/demo/classify", { label }));
          onChange?.();
        }}>Apply label</ActionButton>
        {classified && <Banner tone={classified.correct ? "ok" : "warn"}>{classified.feedback}</Banner>}
      </Card>
      <Card title="3. Observe what the DLP control does">
        <p className="small">Someone tries to send this record. The same policy engine used in every lab decides the outcome.</p>
        <div className="row">
          {d.destinations.map((dst) => (
            <ActionButton key={dst.key} disabled={readOnly} onClick={async () => {
              const r = await api.post<TransferResult>("/api/career/demo/transfer", { destination: dst.key });
              setTransfers((t) => [r, ...t].slice(0, 3));
              onChange?.();
            }}>Send to {dst.name}</ActionButton>
          ))}
        </div>
        {transfers.map((t, i) => (
          <div key={i} className="card tight" style={{ marginTop: 10 }}>
            <div className="row"><strong>{t.destination.name}</strong> <Status value={t.decision.outcome} />
              <span className="small muted">label used: {t.label_used ?? "unlabeled"}</span></div>
            <p className="small">{t.consequence}</p>
            <details><summary className="small">Why? Policy evaluation trace</summary><TraceList entries={t.trace} decision={t.decision} /></details>
          </div>
        ))}
      </Card>
    </>
  );
}
