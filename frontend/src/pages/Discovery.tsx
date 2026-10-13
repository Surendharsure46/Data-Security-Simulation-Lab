import { useState } from "react";
import { Link } from "react-router-dom";
import { api, download } from "../api";
import {
  ActionButton, Badge, Card, Empty, ErrorBanner, Field, KV, LabelBadge, Loading, NeedSession, PageHead, ReadOnlyNotice, Status, fmtNum, useToast,
} from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Asset } from "../types";

function AssetDetail({ sid, assetKey, onClose }: { sid: number; assetKey: string; onClose: () => void }) {
  const { refresh } = useSession();
  const { data, error, loading } = useLoad(async () => {
    const d = await api.get(`/api/sessions/${sid}/assets/${assetKey}`);
    void refresh();
    return d;
  }, [sid, assetKey]);
  if (loading) return <Card><Loading /></Card>;
  if (error || !data) return <ErrorBanner error={error} />;
  return (
    <Card title={data.name} actions={<><Link className="btn small" to={`/classification?asset=${data.key}`}>Classify</Link><button className="small ghost" onClick={onClose}>Close</button></>}>
      <KV items={[
        ["Asset key", <span className="mono">{data.key}</span>], ["Type", `${data.asset_type} · ${data.data_structure}`], ["System", data.system],
        ["Location", <span className="mono">{data.location}</span>], ["Department", data.department],
        ["Owner", data.owner_key ?? <Badge tone="warn">MISSING OWNER</Badge>], ["Label", <LabelBadge label={data.label_key} />],
        ["Records", fmtNum(data.record_count)], ["Quarantined", data.quarantined ? "yes" : "no"], ["Description", data.description],
      ]} />
      <h3 style={{ marginTop: 12 }}>Stored content sample (synthetic)</h3>
      <pre>{data.content_sample}</pre>
      <h3>Detector findings (latest scan)</h3>
      {data.findings.length === 0 ? <p className="muted small">No findings — run a discovery scan, or this content has no matches.</p> : (
        <div className="table-wrap"><table>
          <thead><tr><th>Detector</th><th>Matches</th><th>Confidence</th><th>Masked evidence</th><th>Rules → label</th></tr></thead>
          <tbody>{data.findings.map((f: any) => (
            <tr key={f.detector}><td>{f.detector}</td><td>{f.match_count}</td><td><Status value={f.confidence} /></td>
              <td className="small mono">{f.evidence.map((e: any, i: number) => <div key={i}>line {e.line}: {e.masked_value} {e.note && <em>({e.note})</em>}</div>)}</td>
              <td className="small">{f.rule_keys.join(", ") || "—"} {f.recommended_label && <>→ <LabelBadge label={f.recommended_label} /></>}</td></tr>
          ))}</tbody>
        </table></div>
      )}
      <h3 style={{ marginTop: 12 }}>Access grants</h3>
      <div className="table-wrap"><table>
        <thead><tr><th>Grant</th><th>Principal</th><th>Members</th><th>Permission</th><th>Justification</th><th>Status</th></tr></thead>
        <tbody>{data.grants.map((g: any) => (
          <tr key={g.key}><td className="mono">{g.key}</td><td>{g.principal_name}</td><td className="small">{g.members.join(", ")}</td><td>{g.permission}</td>
            <td className="small">{g.justification}</td><td><Status value={g.status} /> {g.review_decision && <Badge>{`reviewed: ${g.review_decision}`}</Badge>}</td></tr>
        ))}</tbody>
      </table></div>
      <h3 style={{ marginTop: 12 }}>Effective access ({data.effective_access.length} identities)</h3>
      <div className="table-wrap"><table>
        <thead><tr><th>Identity</th><th>Type</th><th>Department</th><th>Via</th></tr></thead>
        <tbody>{data.effective_access.map((e: any) => (
          <tr key={e.identity}><td>{e.display_name} <span className="muted small">{e.identity}</span></td><td>{e.employment_type}</td><td>{e.department}</td><td className="small">{e.via}</td></tr>
        ))}</tbody>
      </table></div>
    </Card>
  );
}

function Inner({ sid }: { sid: number }) {
  const { canWrite, refresh } = useSession();
  const toast = useToast();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | "unlabeled" | "no_owner">("all");
  const [selected, setSelected] = useState<string | null>(null);
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (filter === "unlabeled") params.set("unlabeled", "true");
  if (filter === "no_owner") params.set("no_owner", "true");
  const assets = useLoad(() => api.get<Asset[]>(`/api/sessions/${sid}/assets?${params}`), [sid, q, filter]);
  const detectors = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/discovery/detectors`), [sid]);
  return (
    <>
      <PageHead title="Data Discovery" crumbs="Data Discovery" mode="SIMULATED" actions={<>
        <ActionButton className="primary" disabled={!canWrite} onClick={async () => {
          const r = await api.post(`/api/sessions/${sid}/discovery/scan`);
          toast(`Scan #${r.scan_number}: ${r.findings} findings across ${r.assets_scanned} assets`);
          assets.reload();
          await refresh();
        }}>Run discovery scan</ActionButton>
        <ActionButton onClick={() => download(`/api/sessions/${sid}/reports/inventory?format=csv`, `inventory-session${sid}.csv`)}>Export inventory (CSV)</ActionButton>
      </>}>
        <p>Discovery answers <em>where</em> data is and what it contains; classification decides how sensitive it is. Detector results are evidence for your decision, not the decision itself.</p>
      </PageHead>
      <ReadOnlyNotice />
      <div className="grid side">
        <div>
          <Card>
            <div className="row" style={{ marginBottom: 10 }}>
              <Field label="Search"><input value={q} onChange={(e) => setQ(e.target.value)} placeholder="name, location, description" /></Field>
              <Field label="Show">
                <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)}>
                  <option value="all">All assets</option><option value="unlabeled">Unlabeled only</option><option value="no_owner">Missing owner only</option>
                </select>
              </Field>
            </div>
            <ErrorBanner error={assets.error} />
            {assets.loading ? <Loading /> : assets.data?.length === 0 ? <Empty title="No matching assets" /> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Asset</th><th>Department</th><th>Owner</th><th>Label</th><th>Records</th><th>Detectors</th><th>Scan recommends</th></tr></thead>
                <tbody>{assets.data?.map((a) => (
                  <tr key={a.key} className={`selectable ${selected === a.key ? "selected" : ""}`} onClick={() => setSelected(a.key)}
                    tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setSelected(a.key)} aria-label={`Open ${a.name}`}>
                    <td><strong>{a.name}</strong><div className="small muted">{a.system}</div></td>
                    <td>{a.department}</td>
                    <td>{a.owner_key ?? <Badge tone="warn">missing</Badge>}</td>
                    <td><LabelBadge label={a.label_key} /></td>
                    <td>{fmtNum(a.record_count)}</td>
                    <td className="small">{a.scanned ? (a.detectors?.join(", ") || "none") : <span className="muted">not scanned</span>}</td>
                    <td>{a.recommended_label ? <LabelBadge label={a.recommended_label} /> : "—"}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </Card>
          <Card title="Detector catalogue">
            <div className="table-wrap"><table>
              <thead><tr><th>Detector</th><th>Validation</th><th>Context keywords</th></tr></thead>
              <tbody>{detectors.data?.map((d) => (
                <tr key={d.key}><td><strong>{d.key}</strong><div className="small muted">{d.description}</div></td>
                  <td>{d.validator ? "checksum/structure" : "pattern"}{d.requires_keyword ? " + keyword required" : ""}</td>
                  <td className="small">{d.keywords.join(", ") || "—"}</td></tr>
              ))}</tbody>
            </table></div>
          </Card>
        </div>
        <div>{selected ? <AssetDetail sid={sid} assetKey={selected} onClose={() => setSelected(null)} /> : <Card><Empty title="Select an asset"><p>Open an asset to inspect metadata, masked detector evidence, grants and effective access.</p></Empty></Card>}</div>
      </div>
    </>
  );
}

export default function Discovery() {
  return <NeedSession>{(sid) => <Inner sid={sid} />}</NeedSession>;
}
