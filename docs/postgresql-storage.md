# PostgreSQL storage foundation

The PostgreSQL adapter provides the generic `Storage` contract using JSONB
records, a bounded psycopg connection pool, transactional writes, and a
versioned schema-migration ledger.

## Install

Install the optional driver extra:

```bash
pip install 'argusprowl[postgresql]'
```

## Configuration

```yaml
storage:
  backend: postgresql
  connection_string: ""
  pool_min_size: 1
  pool_max_size: 10
  pool_timeout_seconds: 10
  connect_timeout_seconds: 10
```

Set `ARGUSPROWL_DATABASE_URL` to supply the connection string from the
deployment secret store. Environment configuration takes precedence over YAML.
Do not commit credentials or place production secrets in a checked-in config.

The adapter can also be instantiated directly with a connection string and
pool settings. Call `close()` during application shutdown. Use
`health_check()` for a lightweight connectivity probe.

## Scope and limitations

This is the storage foundation, not yet a drop-in replacement for the current
SQLite application store. Existing SQLite persistence includes specialized
telemetry-evidence indexes, entity-intelligence projections, evidence search,
and retention behavior that are not implemented by this generic adapter.
The application composition root therefore continues to use SQLite until the
follow-up parity work is complete. Do not switch a production deployment to
PostgreSQL on the basis of this adapter alone.

This adapter does not yet provide workspace/tenant isolation. Generic
collection and record identifiers are not tenant boundaries. Do not expose
this backend as a multi-tenant service until tenant identity is persisted and
enforced by every repository query, aggregation, background task, and
relationship lookup.

Schema migrations are versioned and serialized with a PostgreSQL transaction
advisory lock. The migration ledger and records are created transactionally.
