# Detector rule revision history

## Scope

ArgusProwl rules are YAML configuration, validated by the fixed detector allow-list in
`RuleLoader`. A numeric `version` in YAML is not, by itself, an audit trail.
`RuleRevisionStore` provides append-only snapshots over the configured `Storage`
adapter.

## Revision contract

- `rule_id` is the stable identity; each revision uses a strictly increasing integer.
- A revision snapshot includes detector type, enabled state, confidence threshold,
  parameters, ATT&CK tactic/technique, and source path.
- Canonical JSON (sorted keys, compact separators, finite numbers only) is SHA-256
  hashed. The hash identifies the complete snapshot, not just detector parameters.
- A revision identifier is deterministic for `rule_id + version`. Repeating an
  identical write is idempotent. Reusing a version with different content is rejected.
- Revision history stores the authenticated actor and mandatory change reason.
- Revisions are stored in the `detector_rule_revisions` collection and are never
  overwritten by this service.

## Rollback semantics

Rollback is a forward change, not deletion or time travel. `rollback_candidate`
returns the historical detector configuration with the next version number and
the source version recorded in `rollback_from_version`. It deliberately does not
write YAML, activate a detector, or claim a successful runtime rollback. A future
administrative workflow must authorize the operation, validate the candidate with
`RuleLoader`, persist the new revision, atomically publish the active configuration,
and emit an audit event before activation.

## Operational boundary

This service is persistence infrastructure, not an administrative API. The caller
must supply the authenticated actor; do not pass user-controlled identity strings
as actor attribution. The Storage contract is used with an atomic insert-if-absent operation. SQLite implements
that operation transactionally; other backends fail closed until they provide an atomic
implementation. SQLite is the supported application store today.
The current release does not expose rule revision history or rollback through the
HTTP API, and it does not yet pin each generated alert to a rule content hash.
Those are explicit follow-on integration requirements.
