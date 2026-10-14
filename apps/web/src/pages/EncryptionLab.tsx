import { useState } from "react";
import { api } from "../api";
import { ActionButton, Badge, Banner, Card, Field, KV, Loading, PageHead, Provenance, useToast } from "../components/ui";
import { useLoad } from "../state";

function Done({ ok }: { ok: boolean }) {
  return ok ? <Badge tone="ok">Exercise passed</Badge> : <Badge>Not yet passed</Badge>;
}

export interface LabViewProps { embedded?: boolean; focus?: string[]; onChange?: () => void }

export default function EncryptionLab({ embedded = false, focus, onChange }: LabViewProps = {}) {
  const toast = useToast();
  const ov0 = useLoad(() => api.get("/api/labs/encryption"), []);
  const ov = { ...ov0, reload: () => { ov0.reload(); onChange?.(); } };
  const show = (x: string) => !focus || focus.includes(x);
  const [hashes, setHashes] = useState<Record<string, string>>({});
  const [answer, setAnswer] = useState("");
  const [pass, setPass] = useState("");
  const [encOut, setEncOut] = useState<any>(null);
  const [decOut, setDecOut] = useState<any>(null);
  const [envOut, setEnvOut] = useState<any[]>([]);
  const [tls, setTls] = useState<string[]>([]);
  const [tlsOut, setTlsOut] = useState<any>(null);
  const [cfg, setCfg] = useState<any>(null);
  const [findings, setFindings] = useState<any[] | null>(null);
  const [hmac, setHmac] = useState({ message: "Transfer 4,210.55 to KR-E-100231", out: null as any });

  if (ov.loading) return <Loading />;
  const d = ov.data;
  const passed: string[] = d.passed;
  const config = cfg ?? d.config;
  const setC = (patch: any) => setCfg({ ...config, ...patch });

  return (
    <>
      {!embedded && <PageHead title="Encryption Lab" crumbs="Encryption Lab" mode="REAL_LAB">
        <p>Exercises 1–3 perform real cryptographic operations with the audited <code>cryptography</code> library on disposable synthetic files in your private lab folder. Exercises 4–5 are simulated reviews. No custom cryptography is used.</p>
      </PageHead>}

      {show("hashing") && <Card title="1. Hashing vs encryption" actions={<><Provenance mode="REAL_LAB" /><Done ok={passed.includes("hashing")} /></>}>
        <p className="small">Finance published a SHA-256 manifest for the original payroll batch. Three copies arrived; one was altered in transit. Hash each file and find the modified one.</p>
        <KV items={[["Published manifest (original)", <code>{d.manifest.original_batch_sha256}</code>]]} />
        <div className="table-wrap" style={{ marginTop: 8 }}><table>
          <thead><tr><th>File</th><th>SHA-256</th><th>Matches manifest?</th><th /></tr></thead>
          <tbody>{d.files.map((f: string) => (
            <tr key={f}><td>{f}</td><td className="mono small">{hashes[f] ?? "—"}</td>
              <td>{hashes[f] ? (hashes[f] === d.manifest.original_batch_sha256 ? <Badge tone="ok">match</Badge> : <Badge tone="danger">MISMATCH</Badge>) : "—"}</td>
              <td><ActionButton className="small" onClick={async () => { const r = await api.post("/api/labs/encryption/hash", { file: f }); setHashes((h) => ({ ...h, [f]: r.sha256 })); }}>Compute SHA-256</ActionButton></td></tr>
          ))}</tbody>
        </table></div>
        <div className="row" style={{ marginTop: 8 }}>
          <select value={answer} onChange={(e) => setAnswer(e.target.value)} aria-label="Modified file"><option value="">— which file was modified? —</option>{d.files.map((f: string) => <option key={f}>{f}</option>)}</select>
          <ActionButton disabled={!answer} onClick={async () => { const r = await api.post("/api/labs/encryption/hash/answer", { modified_file: answer }); toast(r.explanation, r.correct ? "ok" : "danger"); ov.reload(); }}>Submit answer</ActionButton>
        </div>
        <details style={{ marginTop: 8 }}><summary>HMAC: proving origin as well as integrity</summary>
          <div className="row"><input style={{ flex: 1 }} value={hmac.message} onChange={(e) => setHmac({ ...hmac, message: e.target.value })} aria-label="HMAC message" />
            <ActionButton className="small" onClick={async () => setHmac({ ...hmac, out: await api.post("/api/labs/encryption/hmac", { message: hmac.message }) })}>Compute</ActionButton></div>
          {hmac.out && <KV items={[["SHA-256", <code>{hmac.out.sha256}</code>], ["HMAC-SHA256", <code>{hmac.out.hmac_sha256}</code>], ["Why", hmac.out.note]]} />}
        </details>
      </Card>}

      {show("file_roundtrip") && <Card title="2. Authenticated file encryption (AES-256-GCM + scrypt)" actions={<><Provenance mode="REAL_LAB" /><Done ok={passed.includes("file_roundtrip")} /></>}>
        <p className="small">Encrypt the synthetic <code>customer_sample.csv</code>. Then prove: (a) a wrong passphrase is rejected, (b) the right one restores identical plaintext, and (c) after tampering, even the right passphrase is rejected.</p>
        <div className="row">
          <Field label="Passphrase (12+ characters, lab only)"><input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" aria-label="Lab passphrase" /></Field>
          <ActionButton className="primary" disabled={pass.length < 12} onClick={async () => { setEncOut(await api.post("/api/labs/encryption/file/encrypt", { passphrase: pass })); setDecOut(null); }}>Encrypt</ActionButton>
          <ActionButton disabled={!encOut && !d.state.file?.encrypted} onClick={async () => { setDecOut(await api.post("/api/labs/encryption/file/decrypt", { passphrase: pass })); ov.reload(); }}>Decrypt with this passphrase</ActionButton>
          <ActionButton className="danger" disabled={!encOut && !d.state.file?.encrypted} onClick={async () => { const r = await api.post("/api/labs/encryption/file/tamper"); toast(`Flipped one bit at byte ${r.modified_byte_offset}`, "info"); ov.reload(); }}>Tamper with ciphertext</ActionButton>
        </div>
        {encOut && <KV items={[["Header (authenticated)", <code>{JSON.stringify(encOut.header)}</code>], ["Ciphertext bytes", encOut.ciphertext_bytes], ["Ciphertext prefix", <code>{encOut.ciphertext_prefix_hex}…</code>], ["Plaintext SHA-256", <code>{encOut.plaintext_sha256}</code>]]} />}
        {decOut && (decOut.success ? <Banner tone="ok">Decrypted. Plaintext SHA-256 {decOut.plaintext_sha256.slice(0, 16)}… matches original: {String(decOut.matches_original)}</Banner> : <Banner tone="danger">{decOut.error}</Banner>)}
        {decOut?.checks && <p className="small">Checks: wrong key rejected {decOut.checks.wrong_key_rejected ? "✓" : "✗"} · correct key restores {decOut.checks.correct_ok ? "✓" : "✗"} · tamper rejected {decOut.checks.tamper_rejected ? "✓" : "✗"}</p>}
      </Card>}

      {show("envelope_rotation") && <Card title="3. Envelope encryption and key rotation" actions={<><Provenance mode="REAL_LAB" /><Done ok={passed.includes("envelope_rotation")} /></>}>
        <p className="small">A data key (DEK) encrypts the backup; a key-encryption key (KEK) wraps the DEK (RFC 3394). Rotate the KEK, confirm the bulk ciphertext did not change, and decrypt with the new KEK. Try the retired KEK too.</p>
        <div className="row">
          <ActionButton onClick={async () => setEnvOut([await api.post("/api/labs/encryption/envelope/init")])}>1. Initialise</ActionButton>
          <ActionButton onClick={async () => { const r = await api.post("/api/labs/encryption/envelope/rotate"); setEnvOut((o) => [...o, { step: "rotate", ...r }]); }}>2. Rotate KEK</ActionButton>
          <ActionButton onClick={async () => {
            const r = await api.post("/api/labs/encryption/envelope/decrypt", {});
            setEnvOut((o) => [...o, { step: "decrypt (active KEK)", ...r }]);
            ov.reload();
          }}>3. Decrypt (active KEK)</ActionButton>
          <ActionButton onClick={async () => { const r = await api.post("/api/labs/encryption/envelope/decrypt", { kek_id: "kek-v1" }); setEnvOut((o) => [...o, { step: "decrypt (kek-v1)", ...r }]); }}>Try retired kek-v1</ActionButton>
        </div>
        {envOut.length > 0 && <pre>{envOut.map((o) => JSON.stringify(o, null, 1)).join("\n")}</pre>}
        <Banner tone="info">The lab keyring is a file in your lab folder purely for teaching. Production KEKs stay inside a KMS or HSM.</Banner>
      </Card>}

      {show("tls_metadata") && <Card title="4. TLS: what an observer still sees" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("tls_metadata")} /></>}>
        <p className="small">{d.tls.capture.description}</p>
        <div className="table-wrap"><table><thead><tr><th>t (s)</th><th>Direction</th><th>Record</th><th>Detail</th></tr></thead>
          <tbody>{d.tls.capture.records.map((r: any, i: number) => <tr key={i}><td>{r.t}</td><td>{r.dir}</td><td>{r.type}</td><td className="small mono">{r.detail}</td></tr>)}</tbody></table></div>
        <p className="small" style={{ marginTop: 8 }}>Select everything a passive network observer can see for this TLS 1.3 session:</p>
        <div className="grid two">{Object.entries(d.tls.items).map(([k, v]) => (
          <label key={k} className="inline-check"><input type="checkbox" checked={tls.includes(k)} onChange={(e) => setTls(e.target.checked ? [...tls, k] : tls.filter((x) => x !== k))} />{v as string}</label>
        ))}</div>
        <ActionButton onClick={async () => { const r = await api.post("/api/labs/encryption/tls/answer", { visible: tls }); setTlsOut(r); ov.reload(); }}>Check answer</ActionButton>
        {tlsOut && <p>{tlsOut.correct_count}/{tlsOut.total} correct {tlsOut.passed ? <Badge tone="ok">passed</Badge> : <Badge tone="warn">try again</Badge>}</p>}
      </Card>}

      {show("config_review") && <Card title="5. Encryption configuration review" actions={<><Provenance mode="SIMULATED" /><Done ok={passed.includes("config_review")} /></>}>
        <p className="small">Service: {config.service}. Change settings, save, then run the validator until no findings remain.</p>
        <div className="grid four">
          <Field label="Minimum TLS"><select value={config.tls_min_version} onChange={(e) => setC({ tls_min_version: e.target.value })}>{d.config_options.tls_min_version.map((o: string) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="At-rest algorithm"><select value={config.at_rest_algorithm} onChange={(e) => setC({ at_rest_algorithm: e.target.value })}>{d.config_options.at_rest_algorithm.map((o: string) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Key location"><select value={config.key_location} onChange={(e) => setC({ key_location: e.target.value })}>{d.config_options.key_location.map((o: string) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Secret storage"><select value={config.secret_storage} onChange={(e) => setC({ secret_storage: e.target.value })}>{d.config_options.secret_storage.map((o: string) => <option key={o}>{o}</option>)}</select></Field>
          <Field label="Key rotation (days)"><input type="number" min={0} value={config.key_rotation_days} onChange={(e) => setC({ key_rotation_days: Number(e.target.value) })} /></Field>
          <label className="inline-check"><input type="checkbox" checked={config.verify_server_certificate} onChange={(e) => setC({ verify_server_certificate: e.target.checked })} />Verify server certificate</label>
          <label className="inline-check"><input type="checkbox" checked={config.backup_encryption} onChange={(e) => setC({ backup_encryption: e.target.checked })} />Encrypt backups</label>
        </div>
        <fieldset style={{ border: "1px solid var(--border)", borderRadius: 6, marginTop: 8 }}><legend className="small">Cipher suites</legend>
          <div className="grid two">{d.config_options.cipher_suites.map((s: string) => (
            <label key={s} className="inline-check small mono"><input type="checkbox" checked={config.cipher_suites.includes(s)} onChange={(e) => setC({ cipher_suites: e.target.checked ? [...config.cipher_suites, s] : config.cipher_suites.filter((x: string) => x !== s) })} />{s}</label>
          ))}</div>
        </fieldset>
        <div className="row" style={{ marginTop: 8 }}>
          <ActionButton className="primary" onClick={async () => {
            const { service: _s, ...body } = config;
            void _s;
            await api.put("/api/labs/encryption/config", body);
            const r = await api.post("/api/labs/encryption/config/validate");
            setFindings(r.findings);
            ov.reload();
          }}>Save & validate</ActionButton>
          <ActionButton onClick={async () => { await api.post("/api/labs/encryption/config/reset"); setCfg(null); setFindings(null); ov.reload(); }}>Reset to weak configuration</ActionButton>
        </div>
        {findings && (findings.length === 0 ? <Banner tone="ok">No findings. Configuration meets every validator rule.</Banner> : (
          <div className="table-wrap" style={{ marginTop: 8 }}><table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Fix</th></tr></thead>
            <tbody>{findings.map((f) => <tr key={f.id}><td>{f.id}</td><td><Badge tone={f.severity === "MEDIUM" ? "warn" : "danger"}>{f.severity}</Badge></td><td>{f.finding}</td><td className="small">{f.fix}</td></tr>)}</tbody></table></div>
        ))}
      </Card>}
    </>
  );
}
