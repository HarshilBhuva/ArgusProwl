# Persistence guarantees and limitations

## Current persistence flow

- The ingestion consumer calls the core detection pipeline. A completed core path is counted by PR #14 independently of optional evidence persistence.
- `AlertManager.send_alert()` enqueues the alert, attempts SQLite alert persistence when enabled, then dispatches it to configured providers. A failed persistence result does not suppress provider delivery or change the existing return contract; it is logged and counted in `get_statistics()`.
- `TelemetryEvidenceService` stores each normalized event and its provenance in one `Storage` record in the `telemetry_evidence` collection. The default application storage adapter is SQLite. A successful `Storage.save()` returns only after the adapter's transaction context commits.
- The evidence service keeps a bounded in-memory cache for queries and warms it from committed storage on startup. Its persistence success/failure counters are `evidence_persistence_writes_succeeded` and `evidence_persistence_writes_failed`.
- Application shutdown drains the processing worker before closing alert persistence and the shared storage adapter.

## Atomicity and partial failure

An event and its provenance metadata are serialized into one storage payload, so the SQLite adapter writes them in one record-level transaction. Provenance updates replace that record only after the write commits; a failed write is raised and does not update the in-memory cache.

Alert persistence and telemetry evidence persistence are separate stores and are **not one cross-database transaction**. Therefore:
- If an alert is persisted but evidence persistence fails, the alert remains committed and retains its source/contributing event IDs, but the referenced event may be unavailable in evidence search. The evidence failure is logged and counted separately; core processing success remains independent.
- If evidence is persisted but alert persistence fails, the evidence remains available, but there may be no durable alert record. Alert persistence failure is logged and exposed in alert-manager statistics.
- Neither failure triggers automatic retries. The event consumer continues; operators can investigate persistence counters/logs. Exactly-once processing is not guaranteed.

## Duplicate behavior

- Repeated persistence of the same event ID and identical normalized-event payload is idempotent; the existing detection-source provenance is preserved.
- Reuse of an event ID with different event content is rejected as an integrity conflict.
- Repeated persistence of the same alert ID and identical alert payload is idempotent. Reusing an alert ID with a different payload is rejected by alert persistence.
- The in-memory evidence cache and durable evidence collection use the configured evidence capacity as the retention boundary. Evicted records are deleted from durable storage; a failed deletion is logged and counted as a persistence operation failure.

## Recovery and remaining limitations

Committed evidence is reloaded from the configured SQLite database on service initialization. Recovery requires the same database path and a healthy readable database. SQLite WAL and the adapter's commit boundary provide local transactional durability; this does not protect against disk loss, manual database deletion, or corruption.

The evidence and alert stores remain independently committed. A future transactional outbox or unified transaction boundary could reduce orphaned alert/evidence references, but that would be a separate architectural change. The current design deliberately avoids retry loops, a new backend, and exactly-once claims.
