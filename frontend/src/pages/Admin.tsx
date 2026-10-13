import { api } from "../api";
import { ActionButton, Badge, Banner, Card, Loading, PageHead, Status, fmtTime, useToast } from "../components/ui";
import { useAuth, useLoad, useSession } from "../state";

export default function Admin() {
  const { user } = useAuth();
  const { setSessionId } = useSession();
  const toast = useToast();
  const staff = user?.role === "admin" || user?.role === "instructor";
  const users = useLoad(() => (staff ? api.get<any[]>("/api/admin/users") : Promise.resolve([])), [staff]);
  const audit = useLoad(() => (staff ? api.get<any[]>("/api/admin/audit?limit=100") : Promise.resolve([])), [staff]);
  const ints = useLoad(() => api.get<any[]>("/api/integrations"), []);
  const sessions = useLoad(() => (staff ? api.get<any[]>("/api/sessions?all_users=true") : Promise.resolve([])), [staff]);

  if (!staff) {
    return (
      <>
        <PageHead title="Administrator / Lab Settings" crumbs="Administrator" />
        <Banner tone="info">This area is available to instructors and administrators. Ask an administrator to change your role. Learners can reset their own scenarios in the Simulation Workspace and each lab page.</Banner>
      </>
    );
  }
  return (
    <>
      <PageHead title="Administrator / Lab Settings" crumbs="Administrator">
        <p>Users, integration switches and the platform audit trail for your organisation. Role checks are enforced by the server; instructors have read-only access to learner sessions.</p>
      </PageHead>
      <Card title="Users">
        {users.loading ? <Loading /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created</th><th /></tr></thead>
            <tbody>{users.data?.map((u) => (
              <tr key={u.id}><td>{u.display_name} <span className="muted small">{u.username}</span></td><td>{u.role}</td><td>{u.is_active ? <Badge tone="ok">active</Badge> : <Badge>disabled</Badge>}</td>
                <td className="small">{fmtTime(u.created_at)}</td>
                <td className="row">{user?.role === "admin" && u.id !== user.id && (
                  <>
                    <select value={u.role} aria-label={`Role for ${u.username}`} onChange={async (e) => { await api.patch(`/api/admin/users/${u.id}`, { role: e.target.value }); toast("Role updated"); users.reload(); }}>
                      <option>learner</option><option>instructor</option><option>admin</option>
                    </select>
                    <ActionButton className="small" onClick={async () => { await api.patch(`/api/admin/users/${u.id}`, { is_active: !u.is_active }); users.reload(); }}>{u.is_active ? "Disable" : "Enable"}</ActionButton>
                  </>
                )}</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
      <Card title="Learner sessions (read-only review)">
        <div className="table-wrap"><table>
          <thead><tr><th>Session</th><th>User</th><th>Mode</th><th>Status</th><th>Updated</th><th /></tr></thead>
          <tbody>{sessions.data?.map((s) => (
            <tr key={s.id}><td>#{s.id} {s.scenario_title} (attempt {s.attempt_number})</td><td>{s.user_id}</td><td>{s.mode}</td><td><Status value={s.status} /></td>
              <td className="small">{fmtTime(s.updated_at)}</td><td><button className="small" onClick={() => { setSessionId(s.id); toast(`Viewing session #${s.id} (read-only)`, "info"); }}>View</button></td></tr>
          ))}</tbody>
        </table></div>
      </Card>
      <Card title="Integrations">
        <div className="table-wrap"><table>
          <thead><tr><th>Connector</th><th>Status</th><th>Enabled</th><th /></tr></thead>
          <tbody>{ints.data?.map((i) => (
            <tr key={i.key}><td>{i.name}</td><td>{i.status.replace(/_/g, " ")}</td><td>{i.enabled ? "yes" : "no"}</td>
              <td>{user?.role === "admin" && i.status === "IMPLEMENTED" && (
                <ActionButton className="small" onClick={async () => { await api.put(`/api/admin/integrations/${i.key}`, { enabled: !i.enabled }); ints.reload(); }}>{i.enabled ? "Disable" : "Enable"}</ActionButton>
              )}</td></tr>
          ))}</tbody>
        </table></div>
      </Card>
      <Card title="Platform audit log (latest 100)">
        <div className="table-wrap" style={{ maxHeight: 420, overflowY: "auto" }}><table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
          <tbody>{audit.data?.map((a) => (
            <tr key={a.id}><td className="small">{fmtTime(a.created_at)}</td><td>{a.user_id ?? "—"}</td><td>{a.action}</td><td className="small">{a.target_type} {a.target_id}</td><td className="small mono">{JSON.stringify(a.detail)}</td></tr>
          ))}</tbody>
        </table></div>
      </Card>
      <Card title="Data reset and backup">
        <p className="small">Full local reset (development): stop the server and run <code>python -m app.cli reset-data --yes</code> then <code>python -m app.cli init-db</code> in <code>backend/</code>. Back up the SQLite file <code>backend/var/threatready.db</code> while the server is stopped. See docs/DEPLOYMENT.md.</p>
      </Card>
    </>
  );
}
