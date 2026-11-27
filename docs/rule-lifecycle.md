# Detector rule lifecycle

## API

Rule administration requires API authentication to be enabled and a validated
principal with the `admin` role. Viewer and analyst principals can read rule
revision history but cannot mutate or activate rules.

- `GET /api/v1/rules/{rule_id}/revisions` returns bounded, newest-first history.
- `PUT /api/v1/rules/{rule_id}` creates and activates a forward revision.
- `POST /api/v1/rules/{rule_id}/rollback` restores a historical configuration
  as a new forward revision; it never deletes or rewrites history.

Mutations require `expected_version` and a non-empty `change_reason`.
A stale expected version returns HTTP 409. Invalid detector configuration
returns HTTP 422 before the active rule file or registry is changed.

## Activation sequence

1. Resolve the rule by its stable `rule_id`.
2. Check the caller's expected version.
3. Write a candidate YAML file beside the active file.
4. Validate it through `RuleLoader` and construct the detector instance.
5. Persist the immutable revision and its canonical SHA-256 fingerprint.
6. Append a hash-chained `RULE_REVISION_PREPARED` audit event.
7. Atomically replace the active YAML file and detector registry entry.
8. Append `RULE_REVISION_ACTIVATED` to the audit chain.

If activation fails after the file replacement, the service restores the original
file bytes and leaves the previous registry entry intact. Temporary files are
removed on both success and failure.

## Boundaries

- The detector type remains constrained by the existing `RuleLoader.DETECTORS`
  allow-list; this API does not load arbitrary Python code.
- Existing YAML metadata such as names, descriptions, severity, tags, and
  suppression metadata is preserved when a rule is changed.
- Rule history is persisted in a dedicated SQLite database adjacent to the
  configured API audit database.
- Existing active rules with a version greater than 1 and no revision history
  must be imported before the first mutation; the service fails closed rather
  than inventing missing historical revisions.
- Alert-level revision provenance is implemented separately so alert creation
  can pin the exact active rule hash without coupling the API to detector code.
