#!/usr/bin/env bash
set -euo pipefail

image="${1:-argusprowl:ci}"
container_name="argusprowl-smoke-${GITHUB_RUN_ID:-local}-$$"
volume_name="${container_name}-data"
port="${ARGUSPROWL_SMOKE_PORT:-18080}"
api_key="argusprowl-ci-test-key-0123456789abcdef0123456789abcdef"
tmp_dir="$(mktemp -d)"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  docker volume rm "$volume_name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

echo "Checking runtime user..."
runtime_user="$(docker run --rm --entrypoint whoami "$image")"
if [[ "$runtime_user" == "root" || -z "$runtime_user" ]]; then
  echo "Image must run as a non-root user (got: $runtime_user)" >&2
  exit 1
fi

echo "Checking frontend assets..."
docker run --rm --entrypoint sh "$image" -c \
  'test -f /app/static/index.html && test -d /app/static/assets/'

echo "Checking runtime image excludes build tooling..."
docker run --rm --entrypoint sh "$image" -c '
  for tool in node npm uv; do
    if command -v "$tool" >/dev/null 2>&1; then
      echo "Unexpected runtime tool: $tool" >&2
      exit 1
    fi
  done
'

echo "Checking writable application directories..."
docker run --rm --entrypoint sh "$image" -c \
  'touch /app/data/.write_test /app/logs/.write_test && rm /app/data/.write_test /app/logs/.write_test'

docker volume create "$volume_name" >/dev/null

start_container() {
  docker run -d --name "$container_name" \
    -p "127.0.0.1:$port:8080" \
    --volume "$volume_name:/app/data" \
    -e TH_API__HOST=0.0.0.0 \
    -e TH_API__PORT=8080 \
    -e TH_API__AUTH_ENABLED=true \
    -e "ARGUSPROWL_API_KEY=$api_key" \
    "$image" >/dev/null
}

wait_for_health() {
  local deadline=$((SECONDS + 20))
  until curl --fail --silent --show-error --max-time 1 "http://127.0.0.1:$port/health" >/dev/null; do
    if (( SECONDS >= deadline )); then
      echo "API never became healthy within 20 seconds" >&2
      docker logs "$container_name" || true
      exit 1
    fi
    sleep 0.2
  done
}

echo "Starting container for HTTP and SPA checks..."
start_container
wait_for_health

root_status="$(curl --silent --output "$tmp_dir/root.html" --write-out '%{http_code}' "http://127.0.0.1:$port/")"
[[ "$root_status" == "200" ]] || { echo "GET / returned $root_status" >&2; exit 1; }
grep -q '<' "$tmp_dir/root.html" || { echo "GET / did not return HTML" >&2; exit 1; }

api_status="$(curl --silent --output "$tmp_dir/api-error.json" --write-out '%{http_code}' \
  -H "X-ArgusProwl-Key: $api_key" "http://127.0.0.1:$port/api/v1/nonexistent")"
[[ "$api_status" == "404" || "$api_status" == "405" ]] || {
  echo "Unknown API route returned $api_status (expected 404/405)" >&2
  exit 1
}
if grep -qi 'html' "$tmp_dir/api-error.json"; then
  echo "Unknown API route was incorrectly handled by the SPA" >&2
  exit 1
fi

health_api_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H "X-ArgusProwl-Key: $api_key" "http://127.0.0.1:$port/api/v1/health")"
[[ "$health_api_status" == "200" || "$health_api_status" == "503" ]] || {
  echo "/api/v1/health returned unexpected status $health_api_status" >&2
  exit 1
}

spa_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Accept: text/html' "http://127.0.0.1:$port/alerts/xyz")"
[[ "$spa_status" == "200" ]] || { echo "SPA route returned $spa_status" >&2; exit 1; }

running="$(docker inspect --format '{{.State.Running}}' "$container_name")"
[[ "$running" == "true" ]] || { echo "Container process is not running" >&2; exit 1; }

echo "Writing a probe into the configured SQLite database..."
docker exec "$container_name" /app/.venv/bin/python -c '
import sqlite3
connection = sqlite3.connect("/app/data/argusprowl.db")
with connection:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS _argusprowl_container_restart_probe "
        "(probe_id INTEGER PRIMARY KEY, marker TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT OR REPLACE INTO _argusprowl_container_restart_probe "
        "(probe_id, marker) VALUES (1, ?)",
        ("persistent-volume-survived-container-replacement",),
    )
connection.close()
'

echo "Replacing the container while retaining its data volume..."
docker rm -f "$container_name" >/dev/null
start_container
wait_for_health

docker exec "$container_name" /app/.venv/bin/python -c '
import sqlite3
connection = sqlite3.connect("file:/app/data/argusprowl.db?mode=ro", uri=True)
row = connection.execute(
    "SELECT marker FROM _argusprowl_container_restart_probe WHERE probe_id = 1"
).fetchone()
connection.close()
assert row == ("persistent-volume-survived-container-replacement",), row
'

echo "Docker runtime and persistent-volume restart checks passed for $image (user=$runtime_user)."
