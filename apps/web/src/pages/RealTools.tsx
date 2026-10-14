import { Link } from "react-router-dom";
import { api } from "../api";
import { Badge, Banner, Card, Loading, PageHead, Provenance } from "../components/ui";
import { useLoad } from "../state";

const STATUS_TONE: Record<string, "ok" | "warn" | "neutral"> = { IMPLEMENTED: "ok", GUIDE_ONLY: "warn", NOT_IMPLEMENTED: "neutral" };

export default function RealTools() {
  const ints = useLoad(() => api.get<any[]>("/api/integrations"), []);
  const labs = useLoad(() => api.get<any>("/api/labs/status"), []);
  return (
    <>
      <PageHead title="Real-Tool Practice" crumbs="Real-Tool Practice">
        <p>Where you can practise with real tools today, and an honest status for every vendor integration. A documentation link or guided procedure is not a completed integration.</p>
      </PageHead>
      <Card title="Real lab exercises available now" actions={<Provenance mode="REAL_LAB" />}>
        {labs.loading ? <Loading /> : (
          <div className="grid two">
            <div>
              <h3><Link to="/labs/encryption">Encryption Lab</Link></h3>
              <ul className="small">{Object.entries(labs.data.encryption.exercises).map(([k, v]) => <li key={k}>{k.replace(/_/g, " ")} {v ? <Badge tone="ok">passed</Badge> : null}</li>)}</ul>
            </div>
            <div>
              <h3><Link to="/labs/database">Database Security Lab (SQLite)</Link></h3>
              <ul className="small">{Object.entries(labs.data.database.exercises).map(([k, v]) => <li key={k}>{k.replace(/_/g, " ")} {v ? <Badge tone="ok">passed</Badge> : null}</li>)}</ul>
            </div>
          </div>
        )}
      </Card>
      <Card title="Connector status">
        {ints.loading ? <Loading /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Connector</th><th>Mode</th><th>Status</th><th>Capability</th><th>Mechanism / permissions</th><th>Tested</th><th>Limitations</th></tr></thead>
            <tbody>{ints.data?.map((i) => (
              <tr key={i.key}><td><strong>{i.name}</strong></td><td><Provenance mode={i.mode} /></td><td><Badge tone={STATUS_TONE[i.status]}>{i.status.replace(/_/g, " ")}</Badge></td>
                <td className="small">{i.capability}</td><td className="small">{i.mechanism}<div className="muted">{i.permissions}</div></td>
                <td>{i.tested ? "yes (automated tests)" : "no"}</td><td className="small">{i.limitations}</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
      <div className="grid two">
        <Card title="Guided procedure: Wireshark TLS metadata (outside the platform)">
          <Banner tone="warn">Capture only traffic on networks and devices you own or are explicitly authorised to monitor.</Banner>
          <ol className="small">
            <li>Install Wireshark from the official site and start a capture on your own lab machine's interface.</li>
            <li>Open an HTTPS site you control (or a public test page). Stop the capture.</li>
            <li>Apply the display filter <code>tls.handshake.type == 1</code> and inspect the Client Hello: find the Server Name Indication.</li>
            <li>Check the negotiated version and cipher in the Server Hello; note that in TLS 1.3 the certificate is encrypted.</li>
            <li>Compare with the in-app TLS exercise and record what remained visible.</li>
          </ol>
        </Card>
        <Card title="Guided procedure: PostgreSQL least privilege (outside the platform)">
          <ol className="small">
            <li>Run a disposable PostgreSQL instance you control (for example a local container).</li>
            <li>Create roles <code>support_agent</code> and <code>analyst</code> with <code>NOLOGIN</code>; grant <code>SELECT</code> on a masked view only.</li>
            <li>Verify with <code>SET ROLE support_agent; SELECT * FROM customers;</code> that access is denied.</li>
            <li>Enable statement logging or pgaudit and confirm the denied attempt is recorded.</li>
          </ol>
          <p className="small muted">An in-platform PostgreSQL lab is not implemented in this release.</p>
        </Card>
      </div>
    </>
  );
}
