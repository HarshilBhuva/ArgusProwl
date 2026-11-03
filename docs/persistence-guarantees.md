# Persistence guarantees and limitations

## Current persistence flow

- The ingestion consumer calls the core detection pipeline. A completed core path is counted by PR #14 independently of optional evidence persistence.
- `AlertManager.send_alert()` enqueues the alert, attempts SQLite alert persistence when `alert_persistence.enabled` is true, then dispatches it to configured providers. Alert persistence remains opt-in for compatibility. A failed persistence result does not suppress provider delivery or change the existing return contract; it is logged and counted in `get_statistics()`.
- `TelemetryEvidenceService` stores each normalized event and its provenance in one `Storage` record in the `telemetry_evidence` collection. The default application storage adapter is SQLite. A successful `Storage.save()` returns only after the adapter's transaction context commits.
- The evidence service keeps a bounded in-memory hot cache and warms it from committed storage on startup. The SQLite adapter maintains a derived `telemetry_evidence_index` in the same transaction as each authoritative JSON evidence record. The index stores normalized query dimensions and B-tree indexes for timestamp/event ID, hostname, username, process, source/destination IP, event type, and source type. A one-time schema migration backfills existing evidence records.
- SQLite-backed search reads the durable index rather than scanning the hot cache. Results use ascending `(timestamp, event_id)` keyset pagination with an opaque cursor; the API caps each page at 500 records. The `total_count` is the number of matches before cursor position. The domain substring filter remains a residual predicate and is not guaranteed to use a selective B-tree index.
- Cache eviction is not durable retention: evicted events remain in SQLite and remain searchable/detail-resolvable. `retained_events` reports hot-cache occupancy; `durable_events` reports the authoritative indexed evidence count. Durable retention is separately configured and disabled by default.
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


## Durable evidence retention and SQLite operations

- Durable deletion is opt-in through `telemetry_evidence.retention_enabled`. The default is `false`; upgrading an existing installation never silently deletes historical evidence.
- When enabled on the SQLite backend, the application runs a background maintenance worker. It computes a UTC age cutoff from `retention_days` and deletes at most `cleanup_batch_size` expired records per `cleanup_interval_seconds` interval.
- Each batch selects the oldest expired evidence first and deletes the authoritative JSON record and its derived index row in one SQLite transaction. A failed batch rolls back both sides; the worker logs the failure, increments the failure counter, and retries at the next interval.
- The cutoff is exclusive: records timestamped exactly at the cutoff are retained. Retention is based on normalized event time, not ingestion time. Events with future timestamps are therefore not eligible until their event time passes the configured age threshold.
- After a successful batch, the adapter requests a passive WAL checkpoint. This is non-blocking and does not promise physical database-file shrinkage. SQLite may retain free pages for reuse; `database_bytes` and `wal_bytes` are reported separately in evidence statistics. No automatic `VACUUM` is run because it can require substantial I/O and temporary disk space.
- Evidence statistics expose the last batch timestamp, most recent deleted count, failed batch count, last error, and SQLite file sizes. `SQLiteAdapter.check_integrity()` exposes SQLite's `quick_check` diagnostic for explicit operational verification; it is not run on every stats request.
- Scheduled cleanup is only wired for SQLite. Other configured storage backends are not silently treated as retention-capable; the application logs and skips the worker.
- Retention removes evidence records and their search-index rows. It does not rewrite alerts, incidents, hunt records, or historical references to the removed event IDs. Those references remain and resolve as unavailable/evicted through existing evidence lookup behavior.
- Backups remain an operator responsibility. A valid backup must capture the SQLite database consistently (for example, through SQLite's backup API or after a coordinated checkpoint); copying only the main database file while WAL writes are active is not a supported backup procedure.


## SQLite backup, verification, and restore

- `SQLiteBackupManager.create_backup()` uses Python's SQLite online backup API. SQLite coordinates the snapshot with active transactions and includes committed WAL content; operators must not substitute a raw copy of the main database file while the application is writing.
- Each backup consists of a SQLite database file and a companion `.manifest.json` file. The manifest records its format version, UTC creation time, application version supplied by the operator, SQLite `user_version`, database filename, byte size, and SHA-256 checksum.
- Backup publication uses temporary files in the destination directory and atomic file replacement. The manifest is published last and acts as the completion marker. Existing backup destinations are rejected rather than overwritten; use a new unique backup filename for each run.
- `SQLiteBackupManager.verify_backup()` validates manifest structure and format, filename, byte size, SHA-256, SQLite `quick_check`, and schema version. A backup is not considered restorable until verification succeeds.
- `SQLiteBackupManager.restore_backup()` verifies first, copies the backup into a staging database, checks integrity and schema version again, then atomically replaces the destination database file. A failed verification or staging step leaves the existing destination file unchanged.
- Restore is an **offline operation**. Stop ArgusProwl and all processes that can write to the target database before restoring. The manager refuses to proceed when target `-wal` or `-shm` sidecars exist; it does not attempt to terminate processes or remove sidecars automatically.
- The manifest checksum detects accidental corruption or tampering only when the manifest itself is trusted. It is not a digital signature, does not provide authenticity against an attacker who can replace both files, and does not encrypt backup contents.
- This capability creates and verifies local backup files on demand. It does not schedule backups, upload them offsite, implement retention of backup generations, encrypt backups, or guarantee a particular RPO/RTO. Operators remain responsible for protected off-host copies, access controls, backup cadence, and periodic restore drills.


### SQLite backup operator CLI

The CLI exposes the local backup manager without starting the detection application:

```bash
# Create a new consistent backup from storage.database_path
python -m argusprowl backup create --output backups/argusprowl-2026-11-03.db

# Verify the database and companion manifest before relying on a backup
python -m argusprowl backup verify backups/argusprowl-2026-11-03.db

# Restore to the configured storage.database_path (application must be stopped)
python -m argusprowl backup restore backups/argusprowl-2026-11-03.db --confirm-offline
```

- Create and restore load the selected configuration and require `storage.backend: sqlite`; they use its `storage.database_path`.
- Verify is self-contained and does not need to load application configuration.
- Restore refuses to run unless the operator supplies `--confirm-offline`. This is an explicit operator acknowledgement, not an automated proof that writers have stopped. The backup manager also rejects existing target WAL/SHM sidecars.
- Backup output paths are unique: an existing database or manifest is never overwritten.
- These commands remain local and on-demand. They do not schedule jobs, upload backups, or guarantee that operators have performed a restore drill.


### Read-only SQLite storage diagnostics

The operator CLI can inspect the configured SQLite database without starting ingestion, collectors, or the API:

```bash
# Run SQLite quick_check and report storage/evidence metrics
python -m argusprowl storage check

# Report capacity and durable record metrics without an integrity scan
python -m argusprowl storage stats
```

- Both commands open the configured database in SQLite read-only mode and require `storage.backend: sqlite`.
- `check` runs `PRAGMA quick_check`; a non-`ok` result returns a non-zero runtime exit code.
- `stats` skips the integrity scan and reports page count, free pages, database/WAL file sizes, schema version, durable record count, and evidence-index count when that index exists.
- Diagnostics do not initialize schema, run migrations, checkpoint the WAL, repair corruption, or modify database contents.
- These are point-in-time local diagnostics, not continuous monitoring or a guarantee that the storage device is healthy.
