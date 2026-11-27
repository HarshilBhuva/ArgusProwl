# Beta Entry and Stable Release Readiness Audit

**Baseline:** `main` after PR #102 (2026-11-27)  
**Audit branch:** `docs/beta-entry-readiness`  
**Scope:** release gates for a single-tenant, SQLite-backed deployment  
**Status:** P0 Alpha-exit gates closed; Beta entry is justified for the narrow single-node scope. This is not a production certification.

This document separates verified implementation facts from release requirements that still need runtime validation. Passing CI is necessary, but it is not evidence of operational readiness by itself.

## Executive assessment

ArgusProwl now has additional verified reliability coverage: API startup test-harness cleanup, evidence-outage isolation, graceful-shutdown timeout handling, a role/method authorization matrix, a durable alert/evidence recovery outbox with idempotent replay, startup recovery and an explicit `reconcile alert-evidence --repair` workflow, cross-store partial-commit and restart-recovery tests, a three-store SQLite restore drill, and a real Zeek PCAP replay through a production detection rule.

The P0 gates required before Beta are now closed by implementation and CI evidence, including real container replacement with a persistent SQLite volume (PR #99). ArgusProwl can therefore move from Alpha to Beta within the deliberately narrow scope below. This does **not** establish Stable or production readiness. Alert and evidence stores remain independently committed; the outbox provides at-least-once recovery, not cross-store atomicity or exactly-once processing. Telemetry unavailable when a recovery envelope is written cannot be reconstructed. A restic-based encrypted S3-compatible backup runner, daily systemd timer, generation retention, status reporting, and isolated set restore are now implemented. They still require customer-specific repository/key configuration and a successful host-loss drill; no RPO/RTO is claimed. The real-PCAP acceptance case remains a benign baseline rather than a malicious efficacy/false-positive evaluation.

The v1 release target should remain deliberately narrow:

- one application instance per customer/workspace;
- SQLite as the supported application persistence backend;
- telemetry supplied by separately configured collectors or replay;
- no multi-tenant shared instance, multi-replica deployment, or PostgreSQL parity claim.

## Confirmed implementation and boundaries

| Area | Verified baseline | Release implication |
| --- | --- | --- |
| API authorization | Viewer/analyst/admin roles; deny-by-default route allowlists; object-level ownership checks; non-admin evidence access constrained to exact event IDs; route/method role matrix and owner-isolation integration tests are in CI | Keep authorization fail-closed; extend the matrix whenever routes or roles change. |
| Credential lifecycle | First-admin bootstrap; named credentials; expiry/disable checks; persistent key revocation; persistent browser-session revocation | Validate restart, concurrent-request, and shared-database behavior in integration tests. |
| Authentication throttling | 10 failures per client IP in 60 seconds, followed by a 5-minute lockout; limiter is process-local | Multi-replica use requires a shared reverse-proxy rate limit or a distributed limiter. |
| Ingestion overload | Bounded FIFO buffer supports block, drop-newest, and drop-oldest; receive/buffer/process/failure/drop/reject counters and queue-depth metrics are present | Do not treat overflow as invisible. Verify each configured policy and expose loss counters operationally. |
| Alert queue | Bounded, process-local queue rejects new alerts at capacity; queue state is lost on restart | Do not mistake the analyst workflow queue for durable alert storage. Verify durable alert recovery separately. |
| Alert/evidence persistence | Independent stores and commits; alert plus recovery envelope share one alert-database transaction; source and available contributor payloads are replayed idempotently at startup and through `reconcile alert-evidence --repair`; replay verifies provenance and retains failed rows with attempt diagnostics; outage, restart, and repair paths are tested | Beta scope accepts at-least-once recovery. Cross-store atomicity and exactly-once processing remain absent. Recovery cannot recreate contributor payloads unavailable when the envelope was captured. Monitor pending count/age and protect duplicated telemetry in the alert database; close operational monitoring before Stable. |
| Evidence persistence | SQLite authoritative JSON records and derived search index are updated transactionally; evidence cache is bounded independently of durable retention | Monitor disk/WAL growth and verify index rebuild/recovery from malformed legacy rows. |
| Retention | Evidence retention is opt-in and SQLite-only; alert, incident, hunt and audit lifecycles are not governed by the same policy | Define product-level retention and dangling-reference expectations before Stable. |
| Backup/restore | WAL-safe single-store backups; coordinated multi-store backup sets; isolated all-member set restore; restic client-side encryption to S3-compatible storage; daily systemd schedule; repository checks; host-grouped retention; last-success/failure status; CI restore drill for evidence, alerts, API audit when enabled, and credential revocation | Implementation is present, but each deployment must configure its own S3 repository and recovery key and complete an isolated host-loss drill. No RPO/RTO claim until measured. |
| Audit integrity | SHA-256 chain and HMAC external checkpoints are implemented | Checkpoint scheduling, transport, key rotation/recovery and audit retention remain operational tasks. |
| Storage | SQLite is the active application store. PostgreSQL adapter is not a drop-in application-store replacement; evidence search/entity projections/retention parity are missing | Officially scope v1 to SQLite; do not advertise PostgreSQL application parity. |
| Tenancy | Single-tenant-per-instance model; owner scoping is not tenant isolation | Separate instances and volumes per customer until tenant IDs are enforced in every query and relationship. |

## Release blockers and work order

### P0 — closed for Beta entry

1. **Prove alert/evidence failure behavior — closed for Beta entry.**
   - CI now injects evidence-store failure after a production alert commit and verifies that core processing succeeds while reconciliation reports the missing event reference.
   - Provider exception logging and evidence persistence counters are covered; `reconcile alert-evidence` emits bounded JSON findings, and `reconcile alert-evidence --repair` replays pending outbox envelopes before reporting the remaining consistency state.
   - Repair is at-least-once and idempotent, not a cross-database transaction. It can restore only source/contributor payloads captured in the outbox; unavailable telemetry remains unresolved. Alert persistence and telemetry evidence must both be enabled.
   - Preserve idempotency; do not claim exactly-once delivery.

2. **Prove overload and shutdown behavior — closed for Beta entry.**
   - Existing live-buffer tests cover drop-newest, drop-oldest, block timeout, blocked producer/consumer wake-up on close, queue metrics, and provider delivery during alert-queue saturation.
   - Shutdown tests verify accepted-event draining and that a timed-out worker retains its dependencies until a second shutdown completes.
   - PR #99 extends the Docker image smoke test: it writes a probe row into the configured SQLite database, removes and recreates the application container with the same named data volume, and verifies the row after restart. The Docker Build workflow passed this check. This proves container replacement persistence, not host-loss recovery or backup correctness.

3. **Complete authorization acceptance matrix — closed for Beta entry within the single-tenant scope.**
   - A viewer/analyst/admin method-and-endpoint matrix now checks read, investigation-write, admin, audit-read-only, unknown-role, unsupported-method, and full-path matching behavior.
   - Existing integration tests cover missing ownership metadata, foreign-owned embedded evidence references, revoked/expired credentials, copied browser cookies after logout, restart, and object-level concealment.
   - Global evidence searches are rejected for non-admin callers before the evidence search/pagination operation; exact event-ID access is checked against event ownership. Global entity/IOC investigations and incident timelines remain administrator-only where owner-filtered aggregation is not implemented. Keep adding matrix cases whenever routes or roles change.

### P1 — required for a supported Stable single-node deployment

4. **Operational backup lifecycle — automation and isolated set restore implemented; deployment validation remains open.**
   - CI creates independent online backups, simulates loss of the event/evidence, alert, and security (audit plus credential/session revocation) SQLite stores, restores them offline, and verifies schema, evidence provenance, alerts, audit-chain integrity, and key revocation.
   - PR #102 adds a restic runner for client-side encrypted S3-compatible copies, repository/data verification, host-grouped generation retention, atomic last-success/last-failure status, and a daily systemd timer. PR #101 adds coordinated backup sets and isolated all-member restore.
   - Still required per deployment: provision and initialize the remote repository, protect/recover the restic password independently, enable the timer, alert on stale/failed status, and complete a host-loss restore drill that starts the full application on an isolated host.
   - Publish an explicit RPO/RTO statement only after operational drills support it.

5. **Storage and retention lifecycle.**
   - Document disk-capacity thresholds and WAL monitoring.
   - Define alert, incident, hunt, evidence, and audit retention semantics, including references to expired evidence.
   - Test retention concurrent with evidence search and application restart.
   - Keep SQLite as the supported application backend until another backend has full feature parity.

6. **Deployment hardening.**
   - Publish a single-instance deployment profile covering persistent volumes, TLS/reverse proxy, secrets, permissions, health checks, upgrades, and offline restore. `docs/backup-operations.md` now provides the restic/S3/systemd setup and recovery runbook.
   - Explicitly warn that process-local authentication throttling is not a multi-replica control.
   - PR #99 verifies container replacement with a persistent volume. A production-like host interruption and full restore drill remain Stable-release requirements.

### P1 — detection acceptance

7. **Validate with real telemetry — first benign PCAP baseline added.**
   - CI downloads a pinned Zeek quickstart PCAP, runs it through the official Zeek container, parses the resulting two conn.log records, and submits them to the production `first_seen_src_dst` detection path with evidence persistence assertions.
   - Source and replay instructions are documented in `docs/real-telemetry-validation.md`; the PCAP is downloaded at test time, not vendored.
   - This is a benign baseline, not malicious-detection efficacy. Still required: labeled malicious captures, positive/negative regression cases, false-positive measurement, parser coverage for other telemetry families, and sustained replay results.

8. **Rule lifecycle and regression.**
   - Verify stable rule identity/versioning, validation, enable/disable, rollback, and audit history.
   - Add benign and malicious regression cases for every shipped high-value rule.
   - Do not add ML detectors or claim detection efficacy without measured evaluation.

### P2 — after Beta stability

9. **Release engineering.**
   - Add versioned container publication, SBOM, image provenance/signing, release notes, and upgrade/rollback instructions.
   - Verify a clean install from a tagged release, not only a development checkout.
   - Define support policy and compatibility/deprecation expectations.

10. **Documentation accuracy.**
    - Replace the historical placeholder in `docs/productization.md` with current CI-derived verification data.
    - Rewrite `docs/single-process.md` against current runtime code; it currently carries an explicit warning that its content is historical and must be revalidated.
    - Keep README capability and deployment claims aligned with tested behavior.

## CI coverage: what it proves and what it does not

The backend workflow now runs compile checks, Ruff, the full pytest suite, configuration validation, Bandit, PostgreSQL adapter integration, a Docker Compose startup/health probe, and a dedicated real-PCAP-to-Zeek-to-production-detection acceptance job. The Docker Build workflow also replaces a running product container while retaining its named SQLite data volume and verifies the database probe after restart. The frontend workflow runs TypeScript checks, Vitest, a production build, and Playwright E2E when frontend files change.

The Docker integration job still verifies API health rather than telemetry detection; the separate real-telemetry job covers the narrow Zeek quickstart baseline. The persistent-volume replacement check passed in [Docker Build run 46061146209](https://github.com/HarshilBhuva/ArgusProwl/actions/runs/46061146209). Backend CI passed in [run 46061146214](https://github.com/HarshilBhuva/ArgusProwl/actions/runs/46061146214). PostgreSQL CI validates the generic adapter contract, not full application persistence parity.

Green CI validates the backup-set and restic orchestration code paths with stubs; it does not prove a live S3 repository, customer secret recovery, timer execution, missing-event reconstruction, malicious detection efficacy, false-positive measurement, or a production host-loss restore drill.

## Explicitly out of scope for v1

- Rust rewrite or language migration.
- Kubernetes or multi-node deployment.
- Shared multi-tenant SaaS.
- PostgreSQL/ClickHouse parity before there is a concrete deployment requirement.
- Autonomous response.
- A bundled host sensor, packet-capture agent, message broker, or telemetry lake.
- Additional ML detectors without measured false-positive and detection results.

## Evidence reviewed

- `README.md`: product workflow, deployment distinction, supported telemetry, SQLite scope, and current Beta label.
- `docs/security.md`: authentication, bootstrap, credential revocation, rate limiting, role boundaries, audit chain, tenant boundary, and object ownership.
- `docs/persistence-guarantees.md`: independent alert/evidence commits, no retries/exactly-once guarantee, SQLite evidence index, retention, and backup/restore guarantees.
- `docs/postgresql-storage.md`: PostgreSQL adapter limitations and missing application-store parity.
- `docs/architecture.md`: current processing pipeline and SQLite entity projection.
- `src/argusprowl/reliability/buffer.py`: explicit overflow policies and ingestion counters.
- `src/argusprowl/lifecycle/queue.py`: bounded, in-memory alert workflow queue.
- `src/argusprowl/alerting/alert_manager.py`: queue-full handling, optional alert persistence, and provider dispatch behavior.
- `.github/workflows/backend-ci.yml` and `.github/workflows/frontend-ci.yml`: current automated validation scope.
- `tests/unit/test_api_role_authorization_matrix.py` and existing API ownership/revocation integration tests: role and object-level authorization coverage.
- `tests/integration/test_queue_saturation_live.py` and `tests/unit/test_application_shutdown_drain.py`: overload, close/unblock, drain, and shutdown-timeout behavior.
- `tests/integration/test_end_to_end_alert_provenance.py`, `tests/unit/test_alert_evidence_reconciliation.py`, and the reconciliation CLI tests: partial-commit behavior and diagnostic coverage.
- `tests/integration/test_sqlite_restore_drill.py` and `tests/unit/test_sqlite_backup_set.py`: core-store and isolated backup-set restore coverage.
- `docs/backup-operations.md`, `scripts/argusprowl-backup-restic.sh`, and `deploy/systemd/argusprowl-backup.*`: encrypted off-host backup operations and scheduling.
- `docs/real-telemetry-validation.md` and `tests/integration/test_real_pcap_detection_replay.py`: pinned Zeek quickstart PCAP acceptance path.
- `docs/single-process.md` and `docs/productization.md`: historical documentation warnings.

This audit records verified implementation and CI evidence, not operational certification. The three P0 gates are closed and Beta entry is supported for a single-instance, single-tenant SQLite deployment. Customer-specific S3/key/timer configuration and a production-like restore/host-loss drill, complete product retention semantics, rule lifecycle evidence, and malicious telemetry efficacy/false-positive measurement remain Stable-release gates. Do not advertise production certification or multi-tenant/multi-replica support.
