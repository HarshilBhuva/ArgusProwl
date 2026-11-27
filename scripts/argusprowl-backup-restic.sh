#!/usr/bin/env bash
# Encrypted off-host backup orchestration using the maintained restic client.
set -Eeuo pipefail
umask 077

: "${ARGUSPROWL_CONFIG:?Set ARGUSPROWL_CONFIG to the production YAML config path}"
: "${ARGUSPROWL_BACKUP_ROOT:?Set ARGUSPROWL_BACKUP_ROOT to a protected local backup directory}"
: "${RESTIC_REPOSITORY:?Set RESTIC_REPOSITORY to an initialized S3-compatible restic repository}"
: "${RESTIC_PASSWORD_FILE:?Set RESTIC_PASSWORD_FILE to a separately protected restic password file}"

ARGUSPROWL_PYTHON="${ARGUSPROWL_PYTHON:-python3}"
RESTIC_CHECK_DATA_PERCENT="${RESTIC_CHECK_DATA_PERCENT:-5}"
RESTIC_HOST="${RESTIC_HOST:-$(hostname -f)}"
ARGUSPROWL_LOCAL_KEEP="${ARGUSPROWL_LOCAL_KEEP:-2}"
STATUS_FILE="$ARGUSPROWL_BACKUP_ROOT/backup-status.json"

fail() {
    printf '[argusprowl-backup] ERROR: %s\n' "$*" >&2
    exit 1
}

command -v "$ARGUSPROWL_PYTHON" >/dev/null 2>&1 || fail "ArgusProwl Python executable not found."
command -v python3 >/dev/null 2>&1 || fail "python3 is required for atomic backup status reporting."
command -v restic >/dev/null 2>&1 || fail "restic executable not found."
[[ -f "$ARGUSPROWL_CONFIG" ]] || fail "Configuration file does not exist."
[[ -f "$RESTIC_PASSWORD_FILE" && -r "$RESTIC_PASSWORD_FILE" ]] || fail "Restic password file is missing or unreadable."
[[ "$RESTIC_REPOSITORY" == s3:* ]] || fail "RESTIC_REPOSITORY must use an S3-compatible s3: URL."
[[ "$RESTIC_CHECK_DATA_PERCENT" =~ ^[0-9]+$ ]] || fail "RESTIC_CHECK_DATA_PERCENT must be an integer."
(( RESTIC_CHECK_DATA_PERCENT >= 1 && RESTIC_CHECK_DATA_PERCENT <= 100 )) || fail "RESTIC_CHECK_DATA_PERCENT must be between 1 and 100."
[[ "$ARGUSPROWL_LOCAL_KEEP" =~ ^[0-9]+$ ]] || fail "ARGUSPROWL_LOCAL_KEEP must be an integer."
(( ARGUSPROWL_LOCAL_KEEP >= 2 )) || fail "ARGUSPROWL_LOCAL_KEEP must be at least 2."

mkdir -p "$ARGUSPROWL_BACKUP_ROOT"
chmod 700 "$ARGUSPROWL_BACKUP_ROOT"
backup_root_real="$(realpath "$ARGUSPROWL_BACKUP_ROOT")"
password_file_real="$(realpath "$RESTIC_PASSWORD_FILE")"
case "$password_file_real" in
    "$backup_root_real"/*) fail "Keep the restic password outside the backup directory." ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
generation="$ARGUSPROWL_BACKUP_ROOT/argusprowl-$timestamp"
backup_output="$(mktemp "$ARGUSPROWL_BACKUP_ROOT/.restic-backup.XXXXXX")"
snapshot_id=""

write_status() {
    local state="$1"
    local error_message="$2"
    python3 - "$STATUS_FILE" "$state" "$generation" "$snapshot_id" "$error_message" <<'PY'
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

path = Path(sys.argv[1])
state, generation, snapshot_id, error_message = sys.argv[2:]
try:
    status = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(status, dict):
        status = {}
except (OSError, UnicodeError, json.JSONDecodeError):
    status = {}

now = datetime.now(UTC).isoformat()
status.update({
    "state": state,
    "updated_at": now,
    "last_generation": generation,
})
if state == "success":
    status["last_success_at"] = now
    status["last_snapshot_id"] = snapshot_id
    status["last_error"] = None
else:
    status["last_failure_at"] = now
    status["last_error"] = error_message
document = json.dumps(status, sort_keys=True, indent=2) + "\n"
descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(document)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if os.path.exists(temporary_name):
        os.unlink(temporary_name)
PY
}

on_exit() {
    local result=$?
    if (( result != 0 )); then
        write_status "failed" "backup command exited with status $result" || true
    fi
    rm -f -- "$backup_output"
    return "$result"
}
trap on_exit EXIT

application_version="$("$ARGUSPROWL_PYTHON" -c 'import argusprowl; print(argusprowl.__version__)')"
"$ARGUSPROWL_PYTHON" -m argusprowl --config "$ARGUSPROWL_CONFIG" backup set-create \
    --output-dir "$generation" --confirm-offline
[[ -d "$generation" ]] || fail "Backup-set command returned success without publishing a generation."
"$ARGUSPROWL_PYTHON" -m argusprowl --config "$ARGUSPROWL_CONFIG" backup set-verify "$generation"

# restic encrypts repository data client-side. Credentials and the password are
# supplied through the process environment / password file, never CLI arguments.
restic backup --json --host "$RESTIC_HOST" --tag argusprowl \
    --tag "version-$application_version" "$generation" \
    | tee "$backup_output"

snapshot_id="$(python3 - "$backup_output" <<'PY'
import json
import sys

snapshot_id = None
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("message_type") == "summary" and event.get("snapshot_id"):
            snapshot_id = event["snapshot_id"]
if not snapshot_id:
    raise SystemExit("restic did not return a snapshot ID")
print(snapshot_id)
PY
)"

# Verify repository structure and a configurable sample of stored data, then
# confirm the exact newly-created snapshot is readable before pruning history.
restic check "--read-data-subset=${RESTIC_CHECK_DATA_PERCENT}%"
restic ls "$snapshot_id" >/dev/null
restic forget --tag argusprowl --group-by host --keep-last 2 --keep-daily 7 --keep-weekly 4 \
    --keep-monthly 12 --prune

# Bound local plaintext growth only after the remote snapshot has passed checks
# and retention. Keep at least two complete local generations; skip any candidate
# that fails verification rather than deleting a potentially useful recovery copy.
mapfile -t local_generations < <(
    find "$ARGUSPROWL_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d \
        -name 'argusprowl-*' -printf '%f\\n' | sort -r
)
verified_generations=()
for generation_name in "${local_generations[@]}"; do
    if "$ARGUSPROWL_PYTHON" -m argusprowl --config "$ARGUSPROWL_CONFIG" \
        backup set-verify "$ARGUSPROWL_BACKUP_ROOT/$generation_name" >/dev/null; then
        verified_generations+=("$generation_name")
    else
        printf '[argusprowl-backup] Retaining unverified local generation %s\\n' \
            "$generation_name" >&2
    fi
done
for ((index=ARGUSPROWL_LOCAL_KEEP; index<${#verified_generations[@]}; index++)); do
    rm -rf -- "$ARGUSPROWL_BACKUP_ROOT/${verified_generations[$index]}"
done

write_status "success" ""
printf '[argusprowl-backup] Verified encrypted snapshot %s\n' "$snapshot_id"
