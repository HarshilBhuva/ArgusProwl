# Persistence guarantees and limitations

## Current persistence flow

- The ingestion consumer calls the core detection pipeline. A completed core path is counted by PR #14 independently of optional evidence persistence.
- `AlertManager.send_alert()` enqueues the alert, attempts SQLite alert persistence when `alert_persistence.enabled` is true, then dispatches it to configured providers. Alert persistence remains opt-in for compatibility. A failed persistence result does not suppress provider delivery or change the existing return contract; it is logged and counted in `get_statistics()`.
- `TelemetryEvidenceService` stores each normalized event and its provenance in one `Storage` record in the `telemetry_evidence` collection. The default application storage adapter is SQLite. A successful `Storage.save()` returns only after the adapter's transaction context commits.
- The evidence service keeps a bounded in-memory hot cache and warms it from committed storage on startup. The SQLite adapter maintains a derived `telemetry_evidence_index` in the same transaction as each authoritative JSON evidence record. The index stores normalized query dimensions and B-tree indexes for timestamp/event ID, hostname, username, process, source/destination IP, event type, and source type. A one-time schema migration backfills existing evidence records.
- SQLite-backed search reads the durable index rather than scanning the hot cache. Results use ascending `(timestamp, event_id)` keyset pagination with an opaque cursor; the API caps each page at 500 records. The `total_count` is the number of matches before cursor position. The domain substring filter remains a residual predicate and is not guaranteed to use a selective B-tree index.
- Cache eviction is not durable retention: evicted events remain in SQLite and remain searchable/detail-resolvable. `retained_events` reports hot-cache occupancy; `durable_events` reports the authoritative indexed evidence count. There is not yet a scheduled durable retention/compaction policy.
- Search/detail results expose `AVAILABLE`, `DEGRADED`, or `UNAVAILABLE` recovery status; a successful empty search remains `AVAILABLE`, while a failed startup read is `UNAVAILABLE` and skipped malformed records make recovery `DEGRADED`. Health statistics expose `recovery_status` and `recovery_reason` without changing core detection processing status. Its committed-write counters are `evidence_persistence_writes_succeeded` and `evidence_persistence_writes_failed`; load, recovery, malformed-record, and index/search failures are tracked separately as `evidence_persistence_operations_failed`.
- Application shutdown drains the processing worker before closing alert persistence and the shared storage adapter.

## Atomicity and partial failure

An event and its current provenance metadata are serialized into one storage payload, so the SQLite adapter writes them in one record-level transaction. Later provenance enrichment replaces that record only after its write commits; a failed write is raised and does not update the in-memory cache. A sequence that updates multiple event records is not atomic as a group, so a failure can leave some events with their previously committed provenance.

Alert persistence and telemetry evidence persistence are separate stores and are **not one cross-database transaction**. Therefore:
- If an alert is persisted but evidence persistence fails, the alert remains committed and retains its source/contributing event IDs, but the referenced event may be unavailable in evidence search. The evidence failure is logged and counted separately; core processing success remains independent.
- If evidence is persisted but alert persistence fails, the evidence remains available, but there may be no durable alert record. Alert persistence failure is logged and exposed in alert-manager statistics.
- Neither failure triggers automatic retries. The event consumer continues; operators can investigate persistence counters/logs. Exactly-once processing is not guaranteed.

## Duplicate behavior

- Repeated persistence of the same event ID and identical normalized-event payload is idempotent; the existing detection-source provenance is preserved.
- Reuse of an event ID with different event content is rejected as an integrity conflict.
- Repeated persistence of the same alert ID and identical alert payload is idempotent. Reusing an alert ID with a different payload is rejected by alert persistence.
- The in-memory evidence cache is bounded by the configured evidence capacity. Cache eviction does not delete the authoritative SQLite evidence record or its index row. This preserves historical search but means durable disk growth is not bounded by the cache capacity. A separately configured retention/compaction policy is required before production deployments can claim bounded durable storage.

## Recovery and remaining limitations

Committed evidence is reloaded into the bounded hot cache from the configured SQLite database on service initialization. The indexed search path can query durable history outside that cache. Recovery requires the same `storage.database_path` and a healthy readable database. Durable alert recovery additionally requires `alert_persistence.enabled` and the same `alert_persistence.db_path` across restarts. SQLite WAL and the adapter's commit boundary provide local transactional durability; this does not protect against disk loss, manual database deletion, or corruption.

The evidence and alert stores remain independently committed. A future transactional outbox or unified transaction boundary could reduce orphaned alert/evidence references, but that would be a separate architectural change. The current design deliberately avoids retry loops, a new backend, and exactly-once claims.


## Indexed search boundaries

- The SQLite evidence index is a derived projection; the JSON payload in `records` remains authoritative. Index updates and evidence writes share one SQLite transaction, and deletes remove both rows atomically.
- Existing databases are backfilled once. Malformed legacy payloads are skipped by the index migration and remain visible to the evidence service's recovery diagnostics; they are not silently synthesized.
- Keyset cursors are opaque transport tokens, not authorization credentials. They are bound to the last returned timestamp/event ID and should be treated as untrusted input. Cursor pagination avoids offset scans and duplicate/skip behavior caused by inserts before the current position, but it is not a multi-request snapshot transaction.
- PostgreSQL and ClickHouse adapters remain architecture placeholders. Indexed historical search is currently implemented by the SQLite adapter only; other storage adapters must explicitly implement the search capability before claiming equivalent behavior.
