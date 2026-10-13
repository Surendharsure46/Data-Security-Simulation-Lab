import { useState } from "react";
import { api } from "../api";
import { ActionButton, Badge, Banner, Card, Field, Loading, PageHead, Provenance, Status, Tabs, useToast } from "../components/ui";
import { useLoad } from "../state";

function Done({ ok }: { ok: boolean }) {
  return ok ? <Badge tone="ok">Exercise passed</Badge> : <Badge>Not yet passed</Badge>;
}

function ResultTable({ r }: { r: any }) {
  if (!r) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <div className="row small"><Status value={r.decision ?? (r.error ? "ERROR" : "ALLOWED")} /> {r.row_count} row(s){r.truncated ? " (display truncated at 200)" : ""}
        {r.audit_id && <span className="muted">audit #{r.audit_id}</span>}</div>
      {r.error && <Banner tone="danger">{r.error}</Banner>}
      {r.executed_sql && <pre>{r.executed_sql}{r.bound_parameters?.length ? `\n-- bound parameter: ${JSON.stringify(r.bound_parameters[0])}` : ""}</pre>}
      {r.rows?.length > 0 && (
        <div className="table-wrap" style={{ maxHeight: 300, overflowY: "auto" }}><table>
          <thead><tr>{(r.columns ?? ["id", "full_name", "email"]).map((c: string) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>{r.rows.slice(0, 50).map((row: unknown[], i: number) => <tr key={i}>{row.map((v, j) => <td key={j} className="small">{String(v)}</td>)}</tr>)}</tbody>
        </table></div>
      )}
    </div>
  );
}

export default function DatabaseLab() {
  const toast = useToast();
  const ov = useLoad(() => api.get("/api/labs/database"), []);
  const audit = useLoad(() => api.get("/api/labs/database/audit"), []);
  const [tab, setTab] = useState<"query" | "privilege" | "injection" | "masking" | "audit" | "backup">("privilege");
  const [role, setRole] = useState("support_agent");
  const [sql, setSql] = useState("SELECT * FROM customers LIMIT 5");
  const [qr, setQr] = useState<any>(null);
  const [email, setEmail] = useState("x' OR '1'='1");
  const [lk, setLk] = useState<any[]>([]);
  const [bk, setBk] = useState<any[]>([]);
  if (ov.loading) return <Loading />;
  const d = ov.data;
  const passed: string[] = d.passed;
  const reloadAll = () => { ov.reload(); audit.reload(); };
  const runQuery = async (r = role, s = sql) => { setQr(await api.post("/api/labs/database/query", { role: r, sql: s })); reloadAll(); };

  const QueryBox = (
    <div className="stack">
      <div className="row">
        <Field label="Run as role"><select value={role} onChange={(e) => setRole(e.target.value)} aria-label="Role">{Object.keys(d.roles).map((r) => <option key={r}>{r}</option>)}</select></Field>
        <span className="small muted">{d.roles[role]}</span>
      </div>
      <textarea className="mono" value={sql} onChange={(e) => setSql(e.target.value)} aria-label="SQL statement" />
      <div className="row"><ActionButton className="primary" onClick={() => runQuery()}>Execute (one statement)</ActionButton><span className="small muted">Tables: {d.tables.join(", ")}</span></div>
      <ResultTable r={qr} />
    </div>
  );

  return (
    <>
      <PageHead title="Database Security Lab" crumbs="Database Security Lab" mode="REAL_LAB" actions={
        <ActionButton confirm="Recreate your lab database from scratch?" onClick={async () => { await api.post("/api/labs/database/reset"); toast("Lab database recreated"); setQr(null); reloadAll(); }}>Reset lab database</ActionButton>
      }>
        <p>Your own disposable SQLite database with 300 synthetic customers. Statements really execute. <strong>SQLite has no native roles or GRANT</strong>: this lab enforces roles with SQLite's authorizer callback, the engine's real per-statement access hook. PostgreSQL/MySQL would use GRANT/REVOKE — see Real-Tool Practice.</p>
      </PageHead>
      <div className="row" style={{ marginBottom: 10 }}>
        {["least_privilege", "injection", "masking", "audit", "backup_restore"].map((x) => <span key={x} className="row small">{x.replace("_", " ")} <Done ok={passed.includes(x)} /></span>)}
      </div>
      <Tabs tabs={[["privilege", "Least privilege"], ["injection", "SQL injection"], ["masking", "Masking"], ["audit", "Audit log"], ["backup", "Backup & restore"], ["query", "Free query"]]} value={tab} onChange={setTab} />

      {tab === "privilege" && (
        <div className="grid two">
          <Card title="Role grants (enforced by authorizer)" actions={<Provenance mode="REAL_LAB" />}>
            <div className="table-wrap"><table>
              <thead><tr><th>Role</th><th>Object</th><th>Privilege</th><th /></tr></thead>
              <tbody>{d.grants.map((g: any) => (
                <tr key={`${g.role}-${g.table_name}`}><td>{g.role}</td><td className="mono">{g.table_name}</td><td>{g.privilege}</td>
                  <td><ActionButton className="small danger" confirm={`Revoke ${g.privilege} on ${g.table_name} from ${g.role}?`} onClick={async () => { await api.post("/api/labs/database/grants/revoke", { role: g.role, table: g.table_name }); toast("Revoked"); reloadAll(); }}>Revoke</ActionButton></td></tr>
              ))}</tbody>
            </table></div>
            <p className="small">Task: identify the grant that breaks least privilege, revoke it, then prove (1) the role is denied the full table and (2) still reads the masked view.</p>
          </Card>
          <Card title="Test as a role">{QueryBox}</Card>
        </div>
      )}

      {tab === "injection" && (
        <Card title="Customer lookup: concatenated vs parameterised" actions={<Provenance mode="REAL_LAB" />}>
          <p className="small">The support portal looks customers up by email. Enter an input and run it through both implementations. The vulnerable version builds SQL by string concatenation; the parameterised version binds the value.</p>
          <div className="row">
            <input style={{ flex: 1, minWidth: 240 }} className="mono" value={email} onChange={(e) => setEmail(e.target.value)} aria-label="Lookup input" />
            <ActionButton onClick={async () => { const r = await api.post("/api/labs/database/lookup", { mode: "vulnerable", email }); setLk((x) => [{ ...r }, ...x].slice(0, 4)); ov.reload(); }}>Run vulnerable lookup</ActionButton>
            <ActionButton className="primary" onClick={async () => { const r = await api.post("/api/labs/database/lookup", { mode: "parameterized", email }); setLk((x) => [{ ...r }, ...x].slice(0, 4)); ov.reload(); }}>Run parameterised lookup</ActionButton>
          </div>
          {lk.map((r, i) => <div key={i} className="card tight"><Badge tone={r.mode === "vulnerable" ? "danger" : "ok"}>{r.mode}</Badge><ResultTable r={r} /></div>)}
        </Card>
      )}

      {tab === "masking" && (
        <div className="grid two">
          <Card title="Masking view: customers_masked" actions={<Provenance mode="REAL_LAB" />}>
            {Object.entries(d.masking).map(([col, on]) => (
              <label key={col} className="inline-check" style={{ display: "flex" }}>
                <input type="checkbox" checked={on as boolean} onChange={async (e) => { await api.put("/api/labs/database/masking", { column: col, enabled: e.target.checked }); reloadAll(); }} />
                Mask <code>{col}</code>
              </label>
            ))}
            <h3 style={{ marginTop: 10 }}>Generated view definition</h3>
            <pre>{d.masked_view_sql}</pre>
            <Banner tone="warn">Masking is not encryption: the base table still stores full values. Only roles without access to <code>customers</code> are protected.</Banner>
          </Card>
          <Card title="Verify as the support role">
            <ActionButton className="primary" onClick={() => { setRole("support_agent"); setSql("SELECT * FROM customers_masked LIMIT 5"); return runQuery("support_agent", "SELECT * FROM customers_masked LIMIT 5"); }}>Query customers_masked as support_agent</ActionButton>
            <ResultTable r={qr} />
          </Card>
        </div>
      )}

      {tab === "audit" && (
        <Card title="Query audit log" actions={<Provenance mode="REAL_LAB" />}>
          <p className="small">{audit.data?.note} Identify the entry that indicates suspicious bulk access.</p>
          <div className="table-wrap" style={{ maxHeight: 460, overflowY: "auto" }}><table>
            <thead><tr><th>#</th><th>Time (UTC)</th><th>Role</th><th>Statement</th><th>Rows</th><th>Decision</th><th>Source</th><th /></tr></thead>
            <tbody>{audit.data?.entries.map((e: any) => (
              <tr key={e.id}><td>{e.id}</td><td className="small">{e.ts}</td><td>{e.role}</td><td className="mono small">{e.statement}</td><td>{e.rows_returned}</td>
                <td><Status value={e.decision} /></td><td className="small">{e.source}</td>
                <td><ActionButton className="small" onClick={async () => { const r = await api.post("/api/labs/database/audit/identify", { audit_id: e.id }); toast(r.explanation, r.correct ? "ok" : "danger"); ov.reload(); }}>Flag as suspicious</ActionButton></td></tr>
            ))}</tbody>
          </table></div>
        </Card>
      )}

      {tab === "backup" && (
        <Card title="Backup, incident, restore, verify" actions={<Provenance mode="REAL_LAB" />}>
          <p className="small">Uses SQLite's online backup API. Steps: take a backup → simulate a damaging clean-up script → restore from that backup → verify row count and checksum.</p>
          <div className="row">
            <ActionButton onClick={async () => { const r = await api.post("/api/labs/database/backup"); setBk((x) => [...x, { step: "backup", ...r }]); reloadAll(); }}>1. Back up</ActionButton>
            <ActionButton className="danger" onClick={async () => { const r = await api.post("/api/labs/database/damage"); setBk((x) => [...x, { step: "damage", ...r }]); reloadAll(); }}>2. Simulate damaging script</ActionButton>
            <ActionButton disabled={!d.state.backup_id} onClick={async () => { const r = await api.post("/api/labs/database/restore", { backup_id: d.state.backup_id }); setBk((x) => [...x, { step: "restore", ...r }]); reloadAll(); }}>3. Restore latest backup</ActionButton>
            <ActionButton disabled={!d.state.backup_id} onClick={async () => { const r = await api.post("/api/labs/database/verify", { backup_id: d.state.backup_id }); setBk((x) => [...x, { step: "verify", ...r }]); reloadAll(); }}>4. Verify</ActionButton>
          </div>
          <p className="small muted">Backups available: {d.backups.join(", ") || "none"}</p>
          {bk.length > 0 && <pre>{bk.map((x) => JSON.stringify(x)).join("\n")}</pre>}
        </Card>
      )}

      {tab === "query" && <Card title="Free query console" actions={<Provenance mode="REAL_LAB" />}>{QueryBox}<p className="small muted">Guardrails: one statement, 2-second budget, 200 displayed rows, ATTACH/PRAGMA and internal tables denied, writes only for dba.</p></Card>}
    </>
  );
}
