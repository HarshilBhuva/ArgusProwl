# Security and API access

## Authentication model

API-key authentication is opt-in for backward compatibility. Set
`TH_API__AUTH_ENABLED=true` (or `api.auth_enabled: true`) before exposing the
service beyond a trusted local environment.

The existing `ARGUSPROWL_API_KEY` remains supported and is treated as an
administrator credential. For least-privilege access, configure multiple named
credentials through the `ARGUSPROWL_API_KEYS` environment variable. Its value
must be a JSON object keyed by a non-secret key ID:

```json
{
  "soc-viewer-01": {
    "secret": "replace-with-a-random-secret-of-at-least-32-characters",
    "subject": "soc-viewer",
    "role": "viewer"
  },
  "soc-analyst-01": {
    "secret": "use-a-different-random-secret-of-at-least-32-characters",
    "subject": "soc-analyst",
    "role": "analyst"
  },
  "platform-admin-01": {
    "secret": "use-another-independent-random-secret-of-at-least-32-characters",
    "subject": "platform-admin",
    "role": "admin"
  }
}
```

Pass the same value into the container environment; do not commit real secrets
to YAML, source control, CI logs, or issue reports. Secrets are compared using
constant-time comparison and are never included in audit events or responses.

## Role boundaries

| Role | Access |
| --- | --- |
| `viewer` | Read API resources; no write operations |
| `analyst` | Viewer access plus alert acknowledge/close, incident transitions/close/annotations, and entity annotations |
| `admin` | All API operations, including audit-log reads |

Authorization is deny-by-default for write operations. Newly introduced write
routes must be explicitly added to the analyst policy or remain administrator
only. The audit reader at `GET /api/v1/audit` is administrator-only.

The legacy single API key is administrator-level for compatibility. Rotate it
and migrate to named role-bearing keys when multiple operators need different
permissions.

The current React client does not yet provide an API-key login or credential
entry flow. Enabling API authentication protects the API, but browser-side
requests from the existing UI will not include these keys; use an authenticated
API client or a trusted authentication-aware reverse proxy until frontend
authentication is implemented.

## Audit trail

Non-public API requests produce durable SQLite audit records in
`data/audit.db` by default. Override the path with
`ARGUSPROWL_AUDIT_DB_PATH` or `api.audit_db_path`.

The log records UTC timestamp, event type, authenticated subject, role, HTTP
method, URL path (without query string), response status, request ID, and direct
peer IP. It deliberately excludes request bodies, query parameters, authorization
headers, and API-key values. Request-start records are persisted before the
handler executes; if the audit store cannot accept that record, the request is
rejected with HTTP 503. Completion-record failures leave the durable start
record as evidence of an incomplete audit lifecycle.

Each event now stores a SHA-256 hash over its canonical event fields and the
previous event hash. This creates an ordered chain: edits, deletions, insertions,
or reordering within the retained history are detected by
`GET /api/v1/audit/integrity` (administrator-only). Existing audit databases are
migrated in place and their retained rows are chained in insertion order without
discarding events. New events are appended with their chain link in the same
SQLite transaction.

The chain is tamper-evident against modification that does not also recompute
every subsequent link. It is not a digital signature or an external trust
anchor: an attacker able to rewrite the database and recompute the complete
chain can forge a new history, and truncation of the newest tail cannot be
detected without an independently retained checkpoint. The integrity endpoint
is administrator-only.

### External audit-chain checkpoints

Operators can create an independently authenticated checkpoint and retain it
outside the host/database:

```bash
export ARGUSPROWL_AUDIT_CHECKPOINT_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

# Create a new checkpoint; existing files are never overwritten.
argusprowl audit-checkpoint create --output /secure-export/audit-2026-11-03.json

# Verify later using the same key and configured audit database.
argusprowl audit-checkpoint verify /secure-export/audit-2026-11-03.json
```

The key must be at least 32 bytes and must be managed separately from both the
audit database and checkpoint file. Do not place it in source control, the
database directory, command-line arguments, or logs. Store checkpoint files in
a separately controlled system (for example, an access-restricted backup
destination or external evidence repository). A checkpoint is HMAC-SHA-256
authenticated; it is not a public-key signature and requires the same secret
for verification.

Checkpoint creation first verifies the complete current chain, then anchors its
event count, last event ID, and last event hash. Verification authenticates the
checkpoint and confirms the database still contains that exact prefix while
also validating the current chain. Appends after the checkpoint are permitted.
A checkpoint detects rewrites or truncation at/before its anchor; it cannot
detect loss or rewriting of events appended after the most recent checkpoint.
Create and export checkpoints at an operationally appropriate cadence, and
retain multiple historical checkpoints independently. The checkpoint file is
created with restrictive permissions and is never overwritten.

Automatic scheduling, remote checkpoint transport, key rotation, and key
recovery are not implemented. Losing the signing key makes the checkpoint
unverifiable. A compromised signing key permits an attacker to forge a
replacement checkpoint.

Automatic retention, rotation, and external archival are not implemented;
monitor database growth and define an operator-managed retention/backup policy.
Protect the SQLite file, backups, and host filesystem permissions.

## Deployment notes

The API may run without authentication only when its enabled listener binds to
a loopback address (`127.0.0.1`, `::1`, or `localhost`). Configuration
validation rejects non-loopback binds unless API-key authentication is enabled
and at least one credential is configured. A legacy single API key used for a
remote listener must contain at least 32 ASCII characters; named role-based
credentials are validated individually. Hostnames other than the literal
`localhost` are treated as remotely reachable without DNS resolution, so
configuration fails closed rather than relying on mutable DNS answers.

For a remote deployment, configure authentication and credentials before
changing the bind address:

```yaml
api:
  enabled: true
  host: 0.0.0.0
  auth_enabled: true
  auth_header_name: X-ArgusProwl-Key
  api_keys:
    analyst-1:
      secret: REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS
      subject: analyst-1
      role: analyst
```

Alternatively, supply the legacy administrator key through
`ARGUSPROWL_API_KEY`. Keep secrets in deployment secret management, not in
YAML committed to source control. Terminate TLS at a trusted reverse proxy or
use an appropriately secured transport boundary.

- Keep the service behind TLS when traffic crosses an untrusted network.
- Use separate random secrets per operator or service identity.
- Store secrets in deployment secret management, not in the repository.
- Keep the audit database on persistent storage and include it in backup policy.
- Authentication remains disabled unless explicitly enabled; the default
  single-node quickstart is intended for local development only.
