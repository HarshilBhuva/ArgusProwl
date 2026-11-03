"""Signed external checkpoints for the SQLite API audit hash chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

_FORMAT_VERSION = 1
_GENESIS_HASH = "0" * 64
_EVENT_FIELDS = (
    "id", "timestamp", "event_type", "actor_id", "role",
    "method", "path", "status_code", "request_id", "client_ip",
)


class AuditCheckpointError(RuntimeError):
    """Raised when an audit checkpoint cannot be created or verified."""


class AuditCheckpointManager:
    """Create and verify HMAC-authenticated checkpoints outside the audit DB.

    The signing key must be managed independently from both the audit database
    and checkpoint file. A checkpoint anchors the chain at a specific event;
    it does not prove that events appended after that anchor were retained.
    """

    def __init__(self, signing_key: str | bytes) -> None:
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        if len(key) < 32:
            raise AuditCheckpointError("Checkpoint signing key must be at least 32 bytes.")
        self._key = key

    @staticmethod
    def _canonical(value: dict[str, object]) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    @staticmethod
    def _event_hash(event: dict[str, object], previous_hash: str) -> str:
        payload = {field: event[field] for field in _EVENT_FIELDS}
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(previous_hash.encode("ascii") + b"\n" + canonical).hexdigest()

    def _read_verified_chain(
        self, database_path: str | Path
    ) -> tuple[int, int | None, str]:
        path = Path(database_path).expanduser().resolve()
        if not path.is_file():
            raise AuditCheckpointError(f"Audit database does not exist: {path}")
        uri = f"file:{quote(str(path))}?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("BEGIN")
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(api_audit_events)")
                }
                if not set(_EVENT_FIELDS).issubset(columns) or not {
                    "previous_hash", "event_hash"
                }.issubset(columns):
                    raise AuditCheckpointError("Audit database has no supported hash-chain schema.")
                rows = connection.execute(
                    """
                    SELECT id, timestamp, event_type, actor_id, role, method, path,
                           status_code, request_id, client_ip, previous_hash, event_hash
                    FROM api_audit_events ORDER BY id ASC
                    """
                ).fetchall()
                previous_hash = _GENESIS_HASH
                for row in rows:
                    event = {field: row[field] for field in _EVENT_FIELDS}
                    expected_hash = self._event_hash(event, previous_hash)
                    if row["previous_hash"] != previous_hash or row["event_hash"] != expected_hash:
                        raise AuditCheckpointError(
                            f"Audit chain integrity failure at event ID {event['id']}."
                        )
                    previous_hash = expected_hash
                last_id = int(rows[-1]["id"]) if rows else None
                return len(rows), last_id, previous_hash
        except sqlite3.Error as exc:
            raise AuditCheckpointError(f"Unable to read audit database: {exc}") from exc

    def create_checkpoint(
        self, database_path: str | Path, checkpoint_path: str | Path
    ) -> dict[str, object]:
        """Verify the full chain and publish a signed checkpoint without overwrite."""
        event_count, last_event_id, last_event_hash = self._read_verified_chain(database_path)
        payload: dict[str, object] = {
            "format_version": _FORMAT_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "event_count": event_count,
            "last_event_id": last_event_id,
            "last_event_hash": last_event_hash,
        }
        signature = hmac.new(self._key, self._canonical(payload), hashlib.sha256).hexdigest()
        document = {"payload": payload, "hmac_sha256": signature}
        destination = Path(checkpoint_path).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(destination, flags, 0o600)
        except FileExistsError as exc:
            raise AuditCheckpointError(f"Checkpoint already exists; refusing overwrite: {destination}") from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise AuditCheckpointError(f"Unable to publish audit checkpoint: {exc}") from exc
        return payload

    def verify_checkpoint(
        self, database_path: str | Path, checkpoint_path: str | Path
    ) -> dict[str, object]:
        """Verify checkpoint authenticity and that the DB still contains its anchor."""
        path = Path(checkpoint_path).expanduser()
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AuditCheckpointError(f"Unable to read checkpoint: {exc}") from exc
        if not isinstance(document, dict) or set(document) != {"payload", "hmac_sha256"}:
            raise AuditCheckpointError("Checkpoint document has an invalid structure.")
        payload = document["payload"]
        signature = document["hmac_sha256"]
        required = {
            "format_version", "created_at", "event_count",
            "last_event_id", "last_event_hash",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise AuditCheckpointError("Checkpoint payload has an invalid structure.")
        if payload["format_version"] != _FORMAT_VERSION:
            raise AuditCheckpointError("Unsupported audit checkpoint format version.")
        if (
            not isinstance(signature, str)
            or len(signature) != 64
            or any(char not in "0123456789abcdef" for char in signature)
        ):
            raise AuditCheckpointError("Checkpoint signature is malformed.")
        expected_signature = hmac.new(
            self._key, self._canonical(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise AuditCheckpointError("Checkpoint authentication failed; key or payload mismatch.")
        count = payload["event_count"]
        last_id = payload["last_event_id"]
        last_hash = payload["last_event_hash"]
        if (
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            or (count == 0 and last_id is not None)
            or (count > 0 and (not isinstance(last_id, int) or isinstance(last_id, bool) or last_id < 1))
            or not isinstance(last_hash, str)
            or len(last_hash) != 64
            or any(char not in "0123456789abcdef" for char in last_hash)
        ):
            raise AuditCheckpointError("Checkpoint anchor values are invalid.")

        current_count, current_id, current_hash = self._read_verified_chain(database_path)
        if current_count < count:
            raise AuditCheckpointError("Audit database was truncated before the checkpoint anchor.")
        if count == 0:
            if last_hash != _GENESIS_HASH:
                raise AuditCheckpointError("Empty checkpoint has an invalid genesis hash.")
        else:
            path_obj = Path(database_path).expanduser().resolve()
            uri = f"file:{quote(str(path_obj))}?mode=ro"
            try:
                with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
                    row = connection.execute(
                        "SELECT event_hash FROM api_audit_events WHERE id = ?", (last_id,)
                    ).fetchone()
            except sqlite3.Error as exc:
                raise AuditCheckpointError(f"Unable to verify checkpoint anchor: {exc}") from exc
            if row is None or row[0] != last_hash:
                raise AuditCheckpointError("Audit database no longer contains the checkpoint anchor.")
            if current_id is None or current_id < last_id:
                raise AuditCheckpointError("Audit database tail precedes the checkpoint anchor.")
        return {
            "valid": True,
            "checkpoint_event_count": count,
            "checkpoint_last_event_id": last_id,
            "current_event_count": current_count,
            "current_last_event_id": current_id,
            "current_last_event_hash": current_hash,
        }
