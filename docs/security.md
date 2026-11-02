# Security and API access

## Authentication model

API-key authentication is opt-in for backward compatibility. Set
\`TH_API__AUTH_ENABLED=true\` (or \`api.auth_enabled: true\`) before exposing the
service beyond a trusted local environment.

The existing \`ARGUSPROWL_API_KEY\` remains supported and is treated as an
administrator credential. For least-privilege access, configure multiple named
credentials through the \`ARGUSPROWL_API_KEYS\` environment variable. Its value
must be a JSON object keyed by a non-secret key ID:

\`\`\`json
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
\`\`\`

Pass the same value into the container environment; do not commit real secrets
to YAML, source control, CI logs, or issue reports. Secrets are compared using
constant-time comparison and are never included in audit events or responses.

## Role boundaries

| Role | Access |
| --- | --- |
| \`viewer\` | Read API resources; no write operations |
| \`analyst\` | Viewer access plus alert acknowledge/close, incident transitions/close/annotations, and entity annotations |
| \`admin\` | All API operations, including audit-log reads |

Authorization is deny-by-default for write operations. Newly introduced write
routes must be explicitly added to the analyst policy or remain administrator
only. The audit reader at \`GET /api/v1/audit\` is administrator-only.

The legacy single API key is administrator-level for compatibility. Rotate it
and migrate to named role-bearing keys when multiple operators need different
permissions.

## Audit trail

Non-public API requests produce durable SQLite audit records in
\`data/audit.db\` by default. Override the path with
\`ARGUSPROWL_AUDIT_DB_PATH\` or \`api.audit_db_path\`.

The log records UTC timestamp, event type, authenticated subject, role, HTTP
method, URL path (without query string), response status, request ID, and direct
peer IP. It deliberately excludes request bodies, query parameters, authorization
headers, and API-key values. Request-start records are persisted before the
handler executes; if the audit store cannot accept that record, the request is
rejected with HTTP 503. Completion-record failures leave the durable start
record as evidence of an incomplete audit lifecycle.

Audit records are append-only through the application API. This is not a
cryptographically tamper-evident log: operators must protect the SQLite file,
backups, and host filesystem permissions. External log shipping and signed
integrity chains are outside this PR.

## Deployment notes

- Keep the service behind TLS when traffic crosses an untrusted network.
- Use separate random secrets per operator or service identity.
- Store secrets in deployment secret management, not in the repository.
- Keep the audit database on persistent storage and include it in backup policy.
- Authentication remains disabled unless explicitly enabled; the default
  single-node quickstart is intended for local development only.
