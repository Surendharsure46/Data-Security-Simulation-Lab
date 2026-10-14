import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import {
  ActionButton, Badge, Banner, Card, ErrorBanner, Field, LabelBadge, Loading, NeedSession, PageHead, ReadOnlyNotice, Status, Tabs, fmtTime, useToast,
} from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Asset, Identity, Label } from "../types";

function AssignForm({ sid, asset, labels, people, onSaved }: { sid: number; asset: Asset & { handling_notes?: string; exception_note?: string }; labels: Label[]; people: Identity[]; onSaved: () => void }) {
  const { canWrite, refresh } = useSession();
  const toast = useToast();
  const [label, setLabel] = useState(asset.label_key ?? "");
  const [owner, setOwner] = useState(asset.owner_key ?? "");
  const [justification, setJustification] = useState("");
  const [handling, setHandling] = useState(asset.handling_notes ?? "");
  const [exception, setException] = useState(asset.exception_note ?? "");
  useEffect(() => {
    setLabel(asset.label_key ?? "");
    setOwner(asset.owner_key ?? "");
    setHandling(asset.handling_notes ?? "");
    setException(asset.exception_note ?? "");
    setJustification("");
  }, [asset.key, asset.label_key, asset.owner_key, asset.handling_notes, asset.exception_note]);
  const chosen = labels.find((l) => l.key === label);
  return (
    <Card title={`Classify: ${asset.name}`}>
      <div className="stack">
        <Field label="Label">
          <select value={label} onChange={(e) => setLabel(e.target.value)} aria-label="Label">
            <option value="">— choose —</option>
            {labels.map((l) => <option key={l.key} value={l.key}>{l.name}</option>)}
          </select>
        </Field>
        {chosen && <p className="small muted">{chosen.description} Handling: {chosen.handling}</p>}
        <Field label="Data owner" hint="Accountable person (not a service identity)">
          <select value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Data owner">
            <option value="">{asset.owner_key ? "— keep current —" : "— none —"}</option>
            {people.filter((p) => p.employment_type === "EMPLOYEE").map((p) => <option key={p.key} value={p.key}>{p.display_name} — {p.title}</option>)}
          </select>
        </Field>
        <Field label="Justification" hint="Cite the evidence and business context (min 10 characters)">
          <textarea value={justification} onChange={(e) => setJustification(e.target.value)} aria-label="Justification" />
        </Field>
        <Field label="Handling requirements"><input value={handling} onChange={(e) => setHandling(e.target.value)} /></Field>
        <Field label="Exception (if any)"><input value={exception} onChange={(e) => setException(e.target.value)} /></Field>
        <ActionButton className="primary" disabled={!canWrite || !label || justification.trim().length < 10} onClick={async () => {
          await api.post(`/api/sessions/${sid}/classification/assign`, {
            asset_key: asset.key, label_key: label, justification, owner_key: owner || null, handling_notes: handling, exception_note: exception,
          });
          toast(`Saved: ${asset.name} → ${label}`);
          onSaved();
          await refresh();
        }}>Save classification</ActionButton>
      </div>
    </Card>
  );
}

function Register({ sid }: { sid: number }) {
  const [params] = useSearchParams();
  const reg = useLoad(() => api.get(`/api/sessions/${sid}/classification/register`), [sid]);
  const labels = useLoad(() => api.get<Label[]>(`/api/sessions/${sid}/labels`), [sid]);
  const people = useLoad(() => api.get<Identity[]>(`/api/sessions/${sid}/identities`), [sid]);
  const [sel, setSel] = useState<string | null>(params.get("asset"));
  if (reg.loading || labels.loading || people.loading) return <Loading />;
  const assets: any[] = reg.data?.assets ?? [];
  const asset = assets.find((a) => a.key === sel);
  return (
    <div className="grid side">
      <div>
        <Card title="Classification register">
          <ErrorBanner error={reg.error} />
          <div className="table-wrap"><table>
            <thead><tr><th>Asset</th><th>Label</th><th>Owner</th><th>Handling</th><th>Exception</th></tr></thead>
            <tbody>{assets.map((a) => (
              <tr key={a.key} className={`selectable ${sel === a.key ? "selected" : ""}`} onClick={() => setSel(a.key)} tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && setSel(a.key)}>
                <td>{a.name}</td><td><LabelBadge label={a.label_key} /></td><td>{a.owner_key ?? <Badge tone="warn">missing</Badge>}</td>
                <td className="small">{a.handling_notes || "—"}</td><td className="small">{a.exception_note || "—"}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </Card>
        <Card title="Change history">
          {reg.data.history.length === 0 ? <p className="muted">No classification changes yet.</p> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Sim time</th><th>Asset</th><th>Change</th><th>Justification</th></tr></thead>
              <tbody>{reg.data.history.slice().reverse().map((h: any, i: number) => (
                <tr key={i}><td className="small">{fmtTime(h.sim_time)}</td><td>{h.asset_key}</td>
                  <td><LabelBadge label={h.previous} /> → <LabelBadge label={h.label} /></td><td className="small">{h.justification}</td></tr>
              ))}</tbody>
            </table></div>
          )}
        </Card>
      </div>
      <div>
        {asset ? <AssignForm sid={sid} asset={asset} labels={labels.data ?? []} people={people.data ?? []} onSaved={reg.reload} /> : (
          <Card title="Label scheme">
            <p className="small muted">Select an asset to classify it. This scenario uses the following configurable scheme:</p>
            {labels.data?.map((l) => <div key={l.key} style={{ marginBottom: 8 }}><LabelBadge label={l.key} /> <span className="small">{l.description}</span><div className="small muted">Handling: {l.handling}</div></div>)}
          </Card>
        )}
      </div>
    </div>
  );
}

function Rules({ sid }: { sid: number }) {
  const { canWrite } = useSession();
  const toast = useToast();
  const rules = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/classification/rules`), [sid]);
  const labels = useLoad(() => api.get<Label[]>(`/api/sessions/${sid}/labels`), [sid]);
  const [edits, setEdits] = useState<Record<string, any>>({});
  if (rules.loading) return <Loading />;
  return (
    <Card title="Classification rules" actions={<span className="small muted">Rules turn detector findings into label recommendations. Re-run the scan after editing.</span>}>
      <div className="table-wrap"><table>
        <thead><tr><th>Rule</th><th>Detectors</th><th>Enabled</th><th>Min matches</th><th>Min confidence</th><th>Recommends</th><th /></tr></thead>
        <tbody>{rules.data?.map((r) => {
          const e = { ...r, ...edits[r.key] };
          const upd = (patch: any) => setEdits({ ...edits, [r.key]: { ...edits[r.key], ...patch } });
          return (
            <tr key={r.key}>
              <td><strong>{r.key}</strong><div className="small muted">{r.name} · v{r.version}</div></td>
              <td className="small">{r.detectors.join(", ")}</td>
              <td><input type="checkbox" checked={e.enabled} onChange={(ev) => upd({ enabled: ev.target.checked })} aria-label={`${r.key} enabled`} /></td>
              <td><input type="number" min={1} value={e.min_matches} style={{ width: 70 }} onChange={(ev) => upd({ min_matches: Number(ev.target.value) })} /></td>
              <td><select value={e.min_confidence} onChange={(ev) => upd({ min_confidence: ev.target.value })}>{["LOW", "MEDIUM", "HIGH"].map((c) => <option key={c}>{c}</option>)}</select></td>
              <td><select value={e.recommended_label} onChange={(ev) => upd({ recommended_label: ev.target.value })}>{labels.data?.map((l) => <option key={l.key} value={l.key}>{l.name}</option>)}</select></td>
              <td><ActionButton className="small" disabled={!canWrite || !edits[r.key]} onClick={async () => {
                await api.put(`/api/sessions/${sid}/classification/rules/${r.key}`, { enabled: e.enabled, min_matches: e.min_matches, min_confidence: e.min_confidence, recommended_label: e.recommended_label, detectors: r.detectors });
                toast(`${r.key} updated`);
                setEdits({ ...edits, [r.key]: undefined });
                rules.reload();
              }}>Save</ActionButton></td>
            </tr>
          );
        })}</tbody>
      </table></div>
    </Card>
  );
}

function AccessReview({ sid }: { sid: number }) {
  const { canWrite, refresh } = useSession();
  const toast = useToast();
  const grants = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/access`), [sid]);
  const groups = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/groups`), [sid]);
  const [notes, setNotes] = useState<Record<string, string>>({});
  if (grants.loading || groups.loading) return <Loading />;
  const gmap = Object.fromEntries((groups.data ?? []).map((g) => [g.key, g]));
  return (
    <Card title="Access review" actions={<span className="small muted">REVOKE changes the environment immediately and is recorded as a remediation action.</span>}>
      <Banner tone="info">Ask, for each grant: does every member need this access for their job? Inherited folder permissions and broad groups are common sources of excess.</Banner>
      <div className="table-wrap"><table>
        <thead><tr><th>Grant</th><th>Asset</th><th>Principal (members)</th><th>Perm.</th><th>Justification</th><th>Status</th><th>Review note</th><th>Decision</th></tr></thead>
        <tbody>{grants.data?.map((g) => (
          <tr key={g.key}>
            <td className="mono">{g.key}</td><td className="small">{g.asset_key}</td>
            <td className="small">{gmap[g.principal_key]?.name ?? g.principal_key}<div className="muted">{(gmap[g.principal_key]?.members ?? [g.principal_key]).join(", ")}</div></td>
            <td>{g.permission}</td><td className="small">{g.justification}</td>
            <td><Status value={g.status} />{g.review_decision && <div><Badge>{g.review_decision}</Badge></div>}</td>
            <td><input aria-label={`Review note for ${g.key}`} value={notes[g.key] ?? g.review_note ?? ""} onChange={(e) => setNotes({ ...notes, [g.key]: e.target.value })} placeholder="why?" /></td>
            <td className="row">
              {(["KEEP", "REVOKE"] as const).map((d) => (
                <ActionButton key={d} className={`small ${d === "REVOKE" ? "danger" : ""}`} disabled={!canWrite || (notes[g.key] ?? "").trim().length < 5 || g.status === "REVOKED"}
                  title="Enter a review note (5+ characters) first"
                  onClick={async () => {
                    await api.post(`/api/sessions/${sid}/access/${g.key}/review`, { decision: d, note: notes[g.key] });
                    toast(`${g.key}: ${d}`);
                    grants.reload();
                    await refresh();
                  }}>{d}</ActionButton>
              ))}
            </td>
          </tr>
        ))}</tbody>
      </table></div>
    </Card>
  );
}

function Inner({ sid }: { sid: number }) {
  const [params] = useSearchParams();
  const [tab, setTab] = useState<"register" | "access" | "rules">(params.get("tab") === "access" ? "access" : "register");
  return (
    <>
      <PageHead title="Classification Studio" crumbs="Classification Studio" mode="SIMULATED">
        <p>Assign labels with justification, record ownership and handling requirements, tune recommendation rules and review who can access sensitive data. Every change persists and affects later policy evaluations.</p>
      </PageHead>
      <ReadOnlyNotice />
      <Tabs tabs={[["register", "Register & labels"], ["access", "Ownership & access review"], ["rules", "Recommendation rules"]]} value={tab} onChange={setTab} />
      {tab === "register" && <Register sid={sid} />}
      {tab === "access" && <AccessReview sid={sid} />}
      {tab === "rules" && <Rules sid={sid} />}
    </>
  );
}

export default function Classification() {
  return <NeedSession>{(sid) => <Inner sid={sid} />}</NeedSession>;
}
