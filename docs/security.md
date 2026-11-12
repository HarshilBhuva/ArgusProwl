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
    "role": "viewer",
    "enabled": true,
    "expires_at": "2027-01-01T00:00:00Z"
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
Named keys may set `enabled: false` to disable a credential in configuration,
and may set `expires_at` to an ISO-8601 timestamp with an explicit UTC marker
or offset. Expired and disabled keys are rejected on every request; expiry is
checked at authentication time, not only at startup. Keys without these fields
retain the existing enabled/no-expiry behavior.

Administrators can persistently revoke any configured key (including the
legacy administrator key) without a restart:

```http
POST /api/v1/auth/keys/{key_id}/revoke
X-ArgusProwl-Key: <administrator-key>
```

Revocations are stored in the same durable SQLite database as the API audit
log and are checked on every key and browser-session authentication. A
revoked key remains revoked across process restarts and cannot be re-enabled
by restoring its configuration entry; issue a new key ID and secret instead.
The endpoint is administrator-only and records an `API_KEY_REVOKED` audit
event. Keep the audit/revocation database on persistent storage and include it
in backups.

Failed authentication attempts are throttled per client IP. The default policy
allows 10 failures in a rolling 60-second window, then applies a 5-minute
lockout and returns HTTP 429 with `Retry-After`. A successful authentication
clears the client's failure history. The limiter is process-local; deployments
with multiple API replicas should enforce an additional shared rate limit at
the reverse proxy until distributed limiter state is implemented.

For zero-downtime rotation, add a new key ID and secret alongside the old key,
deploy the updated configuration, switch clients to the new credential, then
revoke the old key using the administrator endpoint. Browser sessions are
signed by the API key that created them, so persistent revocation invalidates
its outstanding sessions on the next request.

## Role boundaries

| Role | Access |
| --- | --- |
| `viewer` | Read API resources; no write operations |
| `analyst` | Viewer access plus alert acknowledge/close, incident transitions/close/annotations, entity annotations, and owned hunt creation/management |
| `admin` | All API operations, including audit-log reads |

Authorization is deny-by-default for write operations. Newly introduced write
routes must be explicitly added to the analyst policy or remain administrator
only. The audit reader at `GET /api/v1/audit` is administrator-only.

The legacy single API key is administrator-level for compatibility. Rotate it
and migrate to named role-bearing keys when multiple operators need different
permissions.

### Browser sessions

When API authentication is enabled, the React client uses the following flow:

1. `GET /api/v1/auth/status` reports whether API authentication is enabled.
2. The operator enters an API key into the sign-in form.
3. `POST /api/v1/auth/session` validates the key and issues a short-lived
   signed session cookie.
4. The API validates that cookie on protected requests and enforces the same
   role policy used by API-key header clients.
5. `DELETE /api/v1/auth/session` ends the browser session.

The browser cookie is HttpOnly, SameSite=Strict, scoped to `/api`, and expires
after one hour. It is marked Secure when the request uses HTTPS. The API key is
not written to localStorage, sessionStorage, or returned in the login response.
Session tokens are stateless HMAC-SHA-256 tokens signed with the associated API
key secret. The API rechecks the credential's enabled and expiry state on every
request. Browser login and unsafe cookie-authenticated requests require a
same-origin Origin header; missing or mismatched origins are rejected. When
deployed behind a TLS reverse proxy, preserve the external Host header and set
`X-Forwarded-Proto` to the browser-facing scheme so Origin validation and the
Secure cookie attribute use the public origin. Logout clears the current browser cookie; a copied token cannot be
individually revoked and remains valid until expiry or credential revocation.
Cross-origin browser clients should use a separately designed authentication
boundary; browser sessions are intentionally same-origin only.

Non-browser clients may continue sending `X-ArgusProwl-Key` (or the configured
header) directly. The detailed component diagnostics at
`GET /api/v1/health/details` require authentication. Public `GET /health` and
`GET /api/v1/health` expose only aggregate liveness metadata and do not disclose
collector names, queue-loss counters, storage diagnostics, or internal error
messages. Authenticated `GET /api/v1/health/details` reports collector state,
queue pressure and loss counters, storage read-probe status, and cumulative
beaconing/correlation/evidence-persistence error counters. A nonzero error
counter leaves the detection-pipeline component degraded for the remainder of
the process lifetime; restart only after preserving and investigating the
diagnostic evidence.

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
is administrator-only. Browser login successes, failures, and session
termination events are recorded without storing API-key values or request bodies.

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

Telemetry-evidence retention and cleanup are configurable under
`telemetry_evidence`; this policy does not automatically apply to the API audit
database or hunt records. Audit-log retention, audit-database rotation, and
external archival remain operator-managed. Monitor database growth, run and
verify SQLite backups, and protect database files and backups with host
filesystem permissions.


## Deployment tenancy boundary

ArgusProwl currently has a **single-tenant-per-instance** data model. Authenticated
principals in one instance share alert, incident, entity-intelligence, telemetry
evidence, and audit data according to their role. Non-admin hunt access is
owner-scoped, but that does not provide organization-level tenant isolation for
the rest of the platform. Do not host multiple customer organizations in one
instance. Until tenant identifiers and isolation constraints are enforced across
all persistence layers, deploy a separate application instance and separate
storage volumes for each customer.

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
      enabled: true
      expires_at: "2027-01-01T00:00:00Z"
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
