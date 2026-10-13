# Integrations and real-tool status

The registry is served by `GET /api/integrations` and shown on the **Real-Tool Practice** page. “Tested” means covered by this repository's automated tests.

| Connector | Mode | Status | Mechanism | Permissions | Tested | Limitations / cleanup |
|---|---|---|---|---|---|---|
| Local cryptography | REAL_LAB | Implemented | Python `cryptography` 44.0.3 (AESGCM, Scrypt, RFC 3394 key wrap), `hashlib`/`hmac` | Write access to the user's lab folder only | Yes (`tests/test_labs.py`) | Lab keyring is a file for teaching, not a KMS. Cleanup: `python -m app.cli reset-data --yes` or delete `var/labs/user-*/crypto`. |
| SQLite lab database | REAL_LAB | Implemented | Python `sqlite3`: `set_authorizer`, `set_progress_handler`, online backup API | Lab folder only | Yes | SQLite has no native roles; enforcement is the authorizer callback, not GRANT/REVOKE. Reset from the lab page. |
| Normalised event export | SIMULATED | Implemented | `GET /api/sessions/{id}/export/events` (JSON Lines, common schema) | Session read access; admin can disable | Yes | Export only; events stay labelled SIMULATED. |
| PostgreSQL lab | REAL_LAB | Not implemented | — | — | No | Guided procedure only on the Real-Tool Practice page. |
| Wireshark | REAL_LAB | Guide only | Manual, outside the platform | Capture only authorised traffic | No | The in-app TLS exercise uses a simulated handshake summary. |
| Microsoft Purview | INTEGRATED | Not implemented | Would require official Microsoft Graph / Purview APIs | Licensed tenant + read-only app consent | No | No connector code exists; nothing in the UI represents Purview data. |
| Microsoft Sentinel / SIEM | INTEGRATED | Not implemented | — | Workspace reader | No | Use the JSON Lines export with your own SIEM lab. |
| AWS (CloudTrail / S3 posture) | INTEGRATED | Not implemented | — | Read-only role in a sandbox account | No | Cloud DSPM lab is a local simulation; its events are not AWS telemetry. |
| External AI provider | INTEGRATED | Not implemented | — | — | No | All explanations are deterministic templates; no data leaves the platform. |

Principles for future connectors (enforced by review): read-only by default; writes only to explicitly authorised test resources with confirmation; credentials scoped and stored outside the database; every run recorded in `IntegrationRun` with provenance `INTEGRATED`; vendor events never merged into simulated streams without their provenance.
