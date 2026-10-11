"""Verify the Zeek -> Vector -> ClickHouse telemetry pipeline.

Queries the local ClickHouse HTTP interface to confirm that the pipeline
is capturing and storing live network traffic. Designed for manual
verification after the data plane is brought up with Docker Compose.

Usage:
    .venv/bin/python scripts/verify_telemetry.py

Environment:
    CLICKHOUSE_HOST  Default: localhost
    CLICKHOUSE_PORT  Default: 8123
    CLICKHOUSE_DB    Default: argusprowl
"""

from __future__ import annotations

import argparse
import datetime
import sys
import urllib.error
import urllib.request

CLICKHOUSE_HOST = "localhost"
CLICKHOUSE_PORT = 8123
DATABASE = "argusprowl"


def _query(sql: str, *, host: str = CLICKHOUSE_HOST, port: int = CLICKHOUSE_PORT) -> str:
    """Execute a ClickHouse query via the HTTP interface and return stdout."""
    url = f"http://{host}:{port}/?database={DATABASE}&query={urllib.parse.quote(sql)}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode("utf-8").strip()
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"ClickHouse unreachable at {host}:{port} (database={DATABASE}): {exc.reason}"
        ) from exc


def _query_int(sql: str) -> int:
    """Execute a scalar query and return the integer result."""
    result = _query(sql)
    try:
        return int(result)
    except ValueError as exc:
        raise RuntimeError(f"Unexpected scalar response for '{sql}': {result!r}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the Zeek -> Vector -> ClickHouse telemetry pipeline."
    )
    parser.add_argument(
        "--host", default=CLICKHOUSE_HOST, help="ClickHouse HTTP host (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=CLICKHOUSE_PORT, help="ClickHouse HTTP port (default: 8123)"
    )
    args = parser.parse_args()

    separator = "=" * 70
    print(separator)
    print("  ArgusProwl Telemetry Pipeline Verification")
    print(f"  ClickHouse: {args.host}:{args.port}  database={DATABASE}")
    print(f"  Timestamp:  {datetime.datetime.now(datetime.UTC).isoformat()}")
    print(separator)

    # --- Reachability / DB check ------------------------------------------------
    try:
        _query("SELECT 1")
    except RuntimeError as exc:
        print(f"\nERROR: {exc}")
        print("Ensure ClickHouse is running and the argusprowl database exists.")
        print("  docker compose up -d clickhouse")
        return 1

    # --- Record counts ----------------------------------------------------------
    tables = ["raw_zeek_ssl"]
    # raw_zeek_conn is optional — probe the system tables to avoid a hard failure.
    try:
        known = _query(
            "SELECT name FROM system.tables "
            f"WHERE database = '{DATABASE}' AND name LIKE 'raw_zeek%'"
        )
        tables.extend(name for name in known.splitlines() if name not in tables)
    except RuntimeError:  # pragma: no cover — non-fatal
        pass

    print("\n--- Record Counts ---")
    for table in tables:
        try:
            count = _query_int(f"SELECT count(*) FROM {DATABASE}.{table}")
            print(f"  {table:25s}  {count:>10,d} rows")
        except RuntimeError as exc:
            print(f"  {table:25s}  -- error: {exc}")

    # --- Latest TLS flows -------------------------------------------------------
    print("\n--- Latest TLS Flows (raw_zeek_ssl) ---")
    try:
        rows_str = _query(
            "SELECT ts, id_orig_h, id_resp_h, version, server_name "
            f"FROM {DATABASE}.raw_zeek_ssl "
            "ORDER BY ts DESC LIMIT 5"
        )
        if not rows_str:
            print("  (no rows yet — the pipeline may still be warming up)")
        else:
            print(
                f"  {'timestamp':<28s} {'source_ip':<18s} {'dest_ip':<18s} {'version':<8s}  server_name"
            )
            print(f"  {'-' * 26}  {'-' * 16}  {'-' * 16}  {'-' * 6}  {'-' * 20}")
            for row in rows_str.splitlines():
                parts = row.split("\t")
                if len(parts) >= 5:
                    ts, orig, resp, ver, sni = parts[0], parts[1], parts[2], parts[3], parts[4]
                    print(f"  {ts:<28s} {orig:<18s} {resp:<18s} {ver:<8s}  {sni}")
                else:
                    print(f"  {row}")
    except RuntimeError as exc:
        print(f"  -- error: {exc}")

    # --- Summary ---------------------------------------------------------------
    print("\n" + separator)
    try:
        ssl_count = _query_int(f"SELECT count(*) FROM {DATABASE}.raw_zeek_ssl")
    except RuntimeError:
        ssl_count = 0
    if ssl_count == 0:
        print(
            "  RESULT: No SSL records found. Verify the data plane is running and traffic is flowing."
        )
        print("  Commands:")
        print("    docker compose up -d clickhouse zeek vector")
        print("    # generate traffic:")
        print("    curl https://google.com")
        print("    .venv/bin/python scripts/verify_telemetry.py")
        return 2
    print(f"  RESULT: Pipeline OK — {ssl_count:,d} SSL records captured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
