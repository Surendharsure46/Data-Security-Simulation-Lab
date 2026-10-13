import { useState } from "react";
import { api } from "../api";
import { ActionButton, Badge, Banner, Card, Empty, Field, Loading, NeedSession, PageHead, ReadOnlyNotice, Status, fmtTime, useToast } from "../components/ui";
import { useLoad, useSession } from "../state";
import type { Policy } from "../types";

function Metric({ label, value }: { label: string; value: string | number | null }) {
  return <div><div className="stat">{value ?? "n/a"}</div><div className="stat-label">{label}</div></div>;
}

function Inner({ sid }: { sid: number }) {
  const { canWrite, refresh } = useSession();
  const toast = useToast();
  const suite = useLoad(() => api.get(`/api/sessions/${sid}/engineering/test-suite`), [sid]);
  const runs = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/engineering/test-suite/runs`), [sid]);
  const policies = useLoad(() => api.get<Policy[]>(`/api/sessions/${sid}/policies`), [sid]);
  const changes = useLoad(() => api.get<any[]>(`/api/sessions/${sid}/engineering/change-records`), [sid]);
  const [cmp, setCmp] = useState<{ a: number; b: number }>({ a: 1, b: 2 });
  const comparison = useLoad(() => (runs.data && runs.data.length >= 2 ? api.get(`/api/sessions/${sid}/engineering/test-suite/compare?a=${cmp.a}&b=${cmp.b}`) : Promise.resolve(null)), [sid, cmp.a, cmp.b, runs.data?.length]);
  const [cr, setCr] = useState({ policy_key: "", from_version: 1, to_version: 1, reason: "", expected_impact: "", rollback_plan: "", test_run_id: "" });
  const latest = runs.data?.[runs.data.length - 1];
  const pol = policies.data?.find((p) => p.key === cr.policy_key);

  return (
    <>
      <PageHead title="Data Security Engineering" crumbs="Data Security Engineering" mode="SIMULATED" actions={
        <ActionButton className="primary" disabled={!canWrite} onClick={async () => {
          const r = await api.post(`/api/sessions/${sid}/engineering/test-suite/run`);
          toast(`Run #${r.run_number}: precision ${r.metrics.precision ?? "n/a"}, recall ${r.metrics.recall ?? "n/a"}`);
          runs.reload();
          setCmp({ a: Math.max(1, r.run_number - 1), b: r.run_number });
          await refresh();
        }}>Run labelled test suite</ActionButton>
      }>
        <p>Measure the current policy set against a labelled synthetic dataset, compare runs to catch regressions, and document changes. Metrics describe this test set only — never production performance.</p>
      </PageHead>
      <ReadOnlyNotice />
      {latest ? (
        <Card title={`Latest run #${latest.run_number}`} actions={<span className="small muted">{fmtTime(latest.created_at)}</span>}>
          <div className="grid four">
            <Metric label="Precision" value={latest.metrics.precision} /><Metric label="Recall" value={latest.metrics.recall} />
            <Metric label="False positives" value={latest.metrics.fp} /><Metric label="False negatives" value={latest.metrics.fn} />
          </div>
          <Banner tone="warn">{latest.metrics.scope_note}</Banner>
          <div className="table-wrap"><table>
            <thead><tr><th>Case</th><th>Expected</th><th>Outcome</th><th>Decided by</th><th>Alerts</th><th>Result</th></tr></thead>
            <tbody>{latest.results.map((r: any) => (
              <tr key={r.id}><td><strong>{r.id}</strong> {r.description}</td><td>{r.should_prevent ? <Badge tone="danger">PREVENT</Badge> : <Badge tone="ok">ALLOW</Badge>}</td>
                <td><Status value={r.outcome} /></td><td className="small">{r.decisive_policy ?? "—"}</td><td className="small">{r.alerts.join(", ") || "—"}</td>
                <td>{r.correct ? <Badge tone="ok">correct</Badge> : <Badge tone="danger">{r.should_prevent ? "false negative" : "false positive"}</Badge>}</td></tr>
            ))}</tbody>
          </table></div>
        </Card>
      ) : (
        <Card title="Labelled test suite">
          {suite.loading ? <Loading /> : (
            <>
              <p className="small">{suite.data.note}</p>
              <div className="table-wrap"><table>
                <thead><tr><th>Case</th><th>Actor</th><th>Action</th><th>Resource → destination</th><th>Expected</th></tr></thead>
                <tbody>{suite.data.cases.map((c: any) => (
                  <tr key={c.id}><td><strong>{c.id}</strong> {c.description}</td><td>{c.actor}</td><td>{c.action}</td><td className="small">{c.resource} → {c.destination}</td>
                    <td>{c.should_prevent ? <Badge tone="danger">PREVENT</Badge> : <Badge tone="ok">ALLOW</Badge>}</td></tr>
                ))}</tbody>
              </table></div>
            </>
          )}
        </Card>
      )}
      <div className="grid two">
        <Card title="Run history & regression comparison">
          {!runs.data?.length ? <Empty title="No runs yet" /> : (
            <>
              <div className="table-wrap"><table>
                <thead><tr><th>Run</th><th>Precision</th><th>Recall</th><th>FP</th><th>FN</th><th>Policies (version/status)</th></tr></thead>
                <tbody>{runs.data.map((r) => (
                  <tr key={r.id}><td>#{r.run_number}</td><td>{r.metrics.precision ?? "n/a"}</td><td>{r.metrics.recall ?? "n/a"}</td><td>{r.metrics.fp}</td><td>{r.metrics.fn}</td>
                    <td className="small">{Object.entries(r.policy_snapshot).map(([k, v]: any) => `${k} v${v.version}${v.status === "DISABLED" ? " (off)" : ""}`).join(", ")}</td></tr>
                ))}</tbody>
              </table></div>
              {runs.data.length >= 2 && (
                <>
                  <div className="row" style={{ marginTop: 10 }}>
                    <Field label="Compare run"><select value={cmp.a} onChange={(e) => setCmp({ ...cmp, a: Number(e.target.value) })}>{runs.data.map((r) => <option key={r.id} value={r.run_number}>#{r.run_number}</option>)}</select></Field>
                    <Field label="with run"><select value={cmp.b} onChange={(e) => setCmp({ ...cmp, b: Number(e.target.value) })}>{runs.data.map((r) => <option key={r.id} value={r.run_number}>#{r.run_number}</option>)}</select></Field>
                  </div>
                  {comparison.data && (
                    <div className="stack">
                      <p><Badge tone="ok">{comparison.data.fixes} fixed</Badge> <Badge tone="danger">{comparison.data.regressions} regressed</Badge> <Badge>{comparison.data.changed.length} changed</Badge></p>
                      <ul className="small">{comparison.data.changed.map((c: any) => <li key={c.id}>{c.id} {c.description}: {c.before} → {c.after} ({c.kind})</li>)}</ul>
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </Card>
        <Card title="Change records">
          <div className="stack">
            <div className="grid three">
              <Field label="Policy"><select value={cr.policy_key} onChange={(e) => { const p = policies.data?.find((x) => x.key === e.target.value); setCr({ ...cr, policy_key: e.target.value, from_version: Math.max(1, (p?.current_version ?? 1) - 1), to_version: p?.current_version ?? 1 }); }}>
                <option value="">— choose —</option>{policies.data?.map((p) => <option key={p.key}>{p.key}</option>)}</select></Field>
              <Field label="From version"><select value={cr.from_version} onChange={(e) => setCr({ ...cr, from_version: Number(e.target.value) })}>{pol?.versions.map((v) => <option key={v.version} value={v.version}>v{v.version}</option>)}</select></Field>
              <Field label="To version"><select value={cr.to_version} onChange={(e) => setCr({ ...cr, to_version: Number(e.target.value) })}>{pol?.versions.map((v) => <option key={v.version} value={v.version}>v{v.version}</option>)}</select></Field>
            </div>
            <Field label="Reason for change"><textarea value={cr.reason} onChange={(e) => setCr({ ...cr, reason: e.target.value })} /></Field>
            <Field label="Expected impact"><input value={cr.expected_impact} onChange={(e) => setCr({ ...cr, expected_impact: e.target.value })} /></Field>
            <Field label="Rollback plan"><input value={cr.rollback_plan} onChange={(e) => setCr({ ...cr, rollback_plan: e.target.value })} /></Field>
            <Field label="Test evidence (suite run)"><select value={cr.test_run_id} onChange={(e) => setCr({ ...cr, test_run_id: e.target.value })}>
              <option value="">— none —</option>{runs.data?.map((r) => <option key={r.id} value={r.id}>run #{r.run_number}</option>)}</select></Field>
            <ActionButton className="primary" disabled={!canWrite || !cr.policy_key || cr.reason.trim().length < 10} onClick={async () => {
              await api.post(`/api/sessions/${sid}/engineering/change-records`, { ...cr, test_run_id: cr.test_run_id ? Number(cr.test_run_id) : null });
              toast("Change record created");
              changes.reload();
            }}>Create change record</ActionButton>
          </div>
          <hr />
          {changes.data?.map((c) => (
            <div key={c.id} className="small" style={{ marginBottom: 8 }}>
              <strong>CR-{c.id}</strong> {c.policy_key} v{c.from_version} → v{c.to_version} · {fmtTime(c.created_at)}<br />{c.reason}
              {c.test_run_id && <> · evidence: test run id {c.test_run_id}</>}
            </div>
          ))}
        </Card>
      </div>
    </>
  );
}

export default function Engineering() {
  return <NeedSession>{(sid) => <Inner sid={sid} />}</NeedSession>;
}
