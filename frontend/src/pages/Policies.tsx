import { useEffect, useState } from "react";
import { api } from "../api";
import { PolicyEditor, emptyDefinition } from "../components/PolicyEditor";
import { TraceList } from "../components/Trace";
import {
  ActionButton, Badge, Banner, Card, Empty, ErrorBanner, Field, Loading, NeedSession, PageHead, ReadOnlyNotice, Status, Tabs, fmtTime, useToast,
} from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Asset, Decision, Destination, Identity, Policy, PolicyDefinition, TraceEntry } from "../types";

function TestWorkspace({ sid, draft }: { sid: number; draft?: { key: string; definition: PolicyDefinition } }) {
  const { canWrite } = useSession();
  const ids = useLoad(() => api.get<Identity[]>(`/api/sessions/${sid}/identities`), [sid]);
  const assets = useLoad(() => api.get<Asset[]>(`/api/sessions/${sid}/assets`), [sid]);
  const dests = useLoad(() => api.get<Destination[]>(`/api/sessions/${sid}/destinations`), [sid]);
  const [f, setF] = useState({ actor: "u-jokafor", action: "UPLOAD", resource: "ast-cust-export-q1", destination: "dst-personal-cloud", record_count: "", hour: 12, ticket_id: "", business_justification: "" });
  const [res, setRes] = useState<{ context: any; entries: TraceEntry[]; decision: Decision; note: string; draft_included: boolean } | null>(null);
  const run = async (withDraft: boolean) => {
    const body: any = { actor: f.actor, action: f.action, resource: f.resource, hour: f.hour,
      destination: f.action === "DOWNLOAD" ? null : f.destination,
      context: { ticket_id: f.ticket_id || undefined, business_justification: f.business_justification || undefined } };
    if (f.record_count) body.record_count = Number(f.record_count);
    if (withDraft && draft) body.draft = draft;
    setRes(await api.post(`/api/sessions/${sid}/policies/test`, body));
  };
  return (
    <div className="stack">
      <div className="grid four">
        <Field label="Actor"><select value={f.actor} onChange={(e) => setF({ ...f, actor: e.target.value })}>{ids.data?.map((i) => <option key={i.key} value={i.key}>{i.display_name} ({i.employment_type.toLowerCase()})</option>)}</select></Field>
        <Field label="Action"><select value={f.action} onChange={(e) => setF({ ...f, action: e.target.value })}>{["DOWNLOAD", "EXPORT", "EMAIL", "UPLOAD", "COPY_TO_USB", "AI_PROMPT", "PRINT"].map((a) => <option key={a}>{a}</option>)}</select></Field>
        <Field label="Resource"><select value={f.resource} onChange={(e) => setF({ ...f, resource: e.target.value })}>{assets.data?.map((a) => <option key={a.key} value={a.key}>{a.name}</option>)}</select></Field>
        <Field label="Destination"><select value={f.destination} disabled={f.action === "DOWNLOAD"} onChange={(e) => setF({ ...f, destination: e.target.value })}>{dests.data?.map((d) => <option key={d.key} value={d.key}>{d.name}</option>)}</select></Field>
        <Field label="Records (default: asset)"><input inputMode="numeric" value={f.record_count} onChange={(e) => setF({ ...f, record_count: e.target.value.replace(/\D/g, "") })} /></Field>
        <Field label="Hour (UTC)"><input type="number" min={0} max={23} value={f.hour} onChange={(e) => setF({ ...f, hour: Number(e.target.value) })} /></Field>
        <Field label="Ticket ID"><input value={f.ticket_id} onChange={(e) => setF({ ...f, ticket_id: e.target.value })} /></Field>
        <Field label="Justification"><input value={f.business_justification} onChange={(e) => setF({ ...f, business_justification: e.target.value })} /></Field>
      </div>
      <div className="row">
        <ActionButton className="primary" disabled={!canWrite} onClick={() => run(false)}>Test against saved policies</ActionButton>
        {draft && <ActionButton disabled={!canWrite} onClick={() => run(true)}>Test with unsaved draft</ActionButton>}
      </div>
      {res && (
        <div>
          <Banner tone="warn">{res.note}{res.draft_included ? " The unsaved draft replaced the saved version of this policy for this test only (not recorded)." : ""}</Banner>
          <TraceList entries={res.entries} decision={res.decision} />
          <details><summary>Evaluation context (test input)</summary><pre>{JSON.stringify(res.context, null, 2)}</pre></details>
        </div>
      )}
    </div>
  );
}

function Versions({ sid, policy, onChanged }: { sid: number; policy: Policy; onChanged: () => void }) {
  const { canWrite } = useSession();
  const toast = useToast();
  const [a, setA] = useState(Math.max(1, policy.current_version - 1));
  const [b, setB] = useState(policy.current_version);
  const diff = useLoad(() => api.get(`/api/sessions/${sid}/policies/${policy.key}/diff?a=${a}&b=${b}`), [sid, policy.key, a, b, policy.current_version]);
  return (
    <div className="stack">
      <div className="table-wrap"><table>
        <thead><tr><th>Version</th><th>Author</th><th>Change note</th><th>Created</th><th /></tr></thead>
        <tbody>{policy.versions.slice().reverse().map((v) => (
          <tr key={v.version}><td>v{v.version} {v.version === policy.current_version && <Badge tone="info">current</Badge>}</td><td>{v.author}</td><td>{v.change_note}</td><td className="small">{fmtTime(v.created_at)}</td>
            <td>{v.version !== policy.current_version && <ActionButton className="small" disabled={!canWrite} confirm={`Create a new version restoring v${v.version}?`}
              onClick={async () => { await api.post(`/api/sessions/${sid}/policies/${policy.key}/rollback`, { to_version: v.version }); toast("Rolled back as a new version"); onChanged(); }}>Restore</ActionButton>}</td></tr>
        ))}</tbody>
      </table></div>
      <div className="row">
        <Field label="Compare"><select value={a} onChange={(e) => setA(Number(e.target.value))}>{policy.versions.map((v) => <option key={v.version} value={v.version}>v{v.version}</option>)}</select></Field>
        <Field label="with"><select value={b} onChange={(e) => setB(Number(e.target.value))}>{policy.versions.map((v) => <option key={v.version} value={v.version}>v{v.version}</option>)}</select></Field>
      </div>
      {diff.data && (diff.data.changes.length === 0 ? <p className="muted">No differences.</p> : (
        <div className="table-wrap"><table>
          <thead><tr><th>Path</th><th>Change</th><th>Before</th><th>After</th></tr></thead>
          <tbody>{diff.data.changes.map((c: any, i: number) => (
            <tr key={i}><td className="mono small">{c.path}</td><td>{c.change}</td><td className="mono small">{JSON.stringify(c.before)}</td><td className="mono small">{JSON.stringify(c.after)}</td></tr>
          ))}</tbody>
        </table></div>
      ))}
    </div>
  );
}

function Inner({ sid }: { sid: number }) {
  const { canWrite, refresh } = useSession();
  const toast = useToast();
  const list = useLoad(() => api.get<Policy[]>(`/api/sessions/${sid}/policies`), [sid]);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState<PolicyDefinition>(emptyDefinition());
  const [newKey, setNewKey] = useState("POL-DLP-");
  const [note, setNote] = useState("");
  const [tab, setTab] = useState<"edit" | "test" | "versions">("edit");
  const [err, setErr] = useState<string | null>(null);
  const detail = useLoad(() => (selected ? api.get<Policy>(`/api/sessions/${sid}/policies/${selected}`) : Promise.resolve(null)), [sid, selected]);

  useEffect(() => {
    if (detail.data) setDraft(JSON.parse(JSON.stringify(detail.data.definition)));
  }, [detail.data]);

  const reloadAll = async () => {
    list.reload();
    detail.reload();
    await refresh();
  };

  const p = detail.data;
  return (
    <>
      <PageHead title="DLP Policy Studio" crumbs="DLP Policy Studio" mode="SIMULATED" actions={
        <button className="primary" disabled={!canWrite} onClick={() => { setCreating(true); setSelected(null); setDraft(emptyDefinition()); setTab("edit"); setErr(null); }}>New policy</button>
      }>
        <p>Policies are validated structured rules executed by the backend engine. Every save creates an immutable version; events and alerts record the exact version that decided them.</p>
      </PageHead>
      <ReadOnlyNotice />
      <div className="grid side" style={{ gridTemplateColumns: "minmax(0, .8fr) minmax(0, 2fr)" }}>
        <Card title="Policies">
          {list.loading ? <Loading /> : (
            <div className="table-wrap"><table>
              <tbody>{list.data?.map((x) => (
                <tr key={x.key} className={`selectable ${selected === x.key ? "selected" : ""}`} tabIndex={0}
                  onClick={() => { setSelected(x.key); setCreating(false); setErr(null); }} onKeyDown={(e) => e.key === "Enter" && setSelected(x.key)}>
                  <td><strong>{x.key}</strong> {x.baseline && <Badge>baseline</Badge>}<div className="small muted">{x.definition.name}</div>
                    <div className="row small"><Status value={x.status} /><Status value={x.definition.outcome} /><span>v{x.current_version}</span><Badge>{x.kind}</Badge></div></td>
                </tr>
              ))}</tbody>
            </table></div>
          )}
          <hr />
          <p className="small muted">Precedence: disabled skipped → scope and conditions → first matching exception → most restrictive outcome (BLOCK &gt; WARN &gt; MONITOR &gt; ALLOW) → priority → key.</p>
        </Card>
        <div>
          <ErrorBanner error={err} />
          {creating && (
            <Card title="Create policy">
              <Field label="Policy key" hint="Format POL-XXXX (uppercase letters, digits, hyphens)"><input value={newKey} onChange={(e) => setNewKey(e.target.value.toUpperCase())} aria-label="Policy key" /></Field>
              <PolicyEditor value={draft} onChange={setDraft} />
              <Field label="Change note"><input value={note} onChange={(e) => setNote(e.target.value)} /></Field>
              <div className="row" style={{ marginTop: 8 }}>
                <ActionButton className="primary" disabled={!canWrite} onClick={async () => {
                  setErr(null);
                  try {
                    await api.post(`/api/sessions/${sid}/policies`, { key: newKey, definition: draft, change_note: note || "Created" });
                  } catch (e) { setErr(e instanceof Error ? e.message : String(e)); return; }
                  toast(`Created ${newKey}`);
                  setCreating(false);
                  setSelected(newKey);
                  await reloadAll();
                }}>Save policy</ActionButton>
              </div>
              <hr />
              <h3>Test this draft before saving</h3>
              <TestWorkspace sid={sid} draft={{ key: newKey, definition: draft }} />
            </Card>
          )}
          {!creating && !p && <Card><Empty title="Select a policy"><p>Choose a policy to edit, test or compare versions, or create a new one.</p></Empty></Card>}
          {!creating && p && (
            <Card title={<div className="row"><h2>{p.key}</h2><Status value={p.status} /><Badge>v{p.current_version}</Badge></div>} actions={
              <ActionButton disabled={!canWrite} onClick={async () => {
                await api.post(`/api/sessions/${sid}/policies/${p.key}/status`, { status: p.status === "ENABLED" ? "DISABLED" : "ENABLED" });
                toast(`${p.key} ${p.status === "ENABLED" ? "disabled" : "enabled"}`);
                await reloadAll();
              }}>{p.status === "ENABLED" ? "Disable" : "Enable"}</ActionButton>
            }>
              <Tabs tabs={[["edit", "Edit"], ["test", "Test workspace"], ["versions", `Versions (${p.versions.length})`]]} value={tab} onChange={setTab} />
              {tab === "edit" && (
                <>
                  <PolicyEditor value={draft} onChange={setDraft} lockKind />
                  <Field label="Change note (required)"><input value={note} onChange={(e) => setNote(e.target.value)} aria-label="Change note" /></Field>
                  <div className="row" style={{ marginTop: 8 }}>
                    <ActionButton className="primary" disabled={!canWrite || note.trim().length < 3} onClick={async () => {
                      setErr(null);
                      try {
                        await api.put(`/api/sessions/${sid}/policies/${p.key}`, { definition: draft, change_note: note });
                      } catch (e) { setErr(e instanceof Error ? e.message : String(e)); return; }
                      toast(`${p.key}: new version saved`);
                      setNote("");
                      await reloadAll();
                    }}>Save new version</ActionButton>
                    <button onClick={() => setDraft(JSON.parse(JSON.stringify(p.definition)))}>Discard changes</button>
                  </div>
                </>
              )}
              {tab === "test" && <TestWorkspace sid={sid} draft={{ key: p.key, definition: draft }} />}
              {tab === "versions" && <Versions sid={sid} policy={p} onChanged={() => void reloadAll()} />}
            </Card>
          )}
        </div>
      </div>
    </>
  );
}

export default function Policies() {
  return <NeedSession>{(sid) => <Inner sid={sid} />}</NeedSession>;
}
