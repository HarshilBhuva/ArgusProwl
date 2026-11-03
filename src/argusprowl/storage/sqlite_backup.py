"""Consistent SQLite backup, verification, and offline restore operations.

The backup API includes committed WAL content in the destination database. Restore
is deliberately an offline operation: callers must stop application writers first.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


class SQLiteBackupError(RuntimeError):
    """Raised when a SQLite backup cannot be created, verified, or restored."""


@dataclass(frozen=True, slots=True)
class BackupManifest:
    """Integrity and compatibility metadata for one SQLite backup."""

    format_version: int
    created_at: str
    application_version: str
    schema_version: int
    database_file: str
    database_size_bytes: int
    sha256: str


class SQLiteBackupManager:
    """Create consistent backups and perform verified offline restores."""

    FORMAT_VERSION = 1

    @staticmethod
    def _manifest_path(backup_path: Path) -> Path:
        return Path(f"{backup_path}.manifest.json")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _quick_check(connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA quick_check").fetchall()
        if not rows or any(str(row[0]).lower() != "ok" for row in rows):
            raise SQLiteBackupError("SQLite integrity check failed.")

    @staticmethod
    def _schema_version(connection: sqlite3.Connection) -> int:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        """Best-effort directory sync after atomic publication."""
        try:
            descriptor = os.open(path, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            return

    def create_backup(
        self,
        database_path: str | Path,
        backup_path: str | Path,
        *,
        application_version: str,
    ) -> BackupManifest:
        """Publish a new SQLite-consistent backup and its manifest.

        Existing destinations are rejected to avoid replacing a valid backup
        with a partially published pair after a process or host failure.
        """
        source = Path(database_path)
        destination = Path(backup_path)
        manifest_path = self._manifest_path(destination)
        if not application_version or not application_version.strip():
            raise ValueError("application_version must be a non-empty string.")
        if not source.is_file():
            raise SQLiteBackupError("Source SQLite database does not exist.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or manifest_path.exists():
            raise FileExistsError("Backup destination or manifest already exists.")

        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        os.close(fd)
        temporary_database = Path(temporary_name)
        temporary_manifest = Path(f"{temporary_database}.manifest")
        try:
            with sqlite3.connect(source) as source_connection:
                with sqlite3.connect(temporary_database) as backup_connection:
                    source_connection.backup(backup_connection)
                    self._quick_check(backup_connection)
                    schema_version = self._schema_version(backup_connection)

            size_bytes = temporary_database.stat().st_size
            manifest = BackupManifest(
                format_version=self.FORMAT_VERSION,
                created_at=datetime.now(UTC).isoformat(),
                application_version=application_version.strip(),
                schema_version=schema_version,
                database_file=destination.name,
                database_size_bytes=size_bytes,
                sha256=self._sha256(temporary_database),
            )
            with temporary_manifest.open("x", encoding="utf-8") as stream:
                json.dump(asdict(manifest), stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            with temporary_database.open("rb") as stream:
                os.fsync(stream.fileno())

            # The manifest is the publication marker and is always written last.
            os.replace(temporary_database, destination)
            os.replace(temporary_manifest, manifest_path)
            self._fsync_directory(destination.parent)
            return manifest
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise SQLiteBackupError("Unable to create SQLite backup.") from exc
        finally:
            temporary_database.unlink(missing_ok=True)
            temporary_manifest.unlink(missing_ok=True)

    def verify_backup(self, backup_path: str | Path) -> BackupManifest:
        """Verify manifest shape, file size, SHA-256, and SQLite integrity."""
        backup = Path(backup_path)
        manifest_file = self._manifest_path(backup)
        try:
            raw = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest = BackupManifest(**raw)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise SQLiteBackupError("Backup manifest is missing or invalid.") from exc

        if (
            not isinstance(manifest.format_version, int)
            or isinstance(manifest.format_version, bool)
            or manifest.format_version != self.FORMAT_VERSION
        ):
            raise SQLiteBackupError("Unsupported backup manifest format.")
        if (
            not isinstance(manifest.database_file, str)
            or manifest.database_file != backup.name
        ):
            raise SQLiteBackupError("Backup manifest filename does not match.")
        if (
            not isinstance(manifest.application_version, str)
            or not manifest.application_version.strip()
            or not isinstance(manifest.schema_version, int)
            or isinstance(manifest.schema_version, bool)
            or manifest.schema_version < 0
            or not isinstance(manifest.database_size_bytes, int)
            or isinstance(manifest.database_size_bytes, bool)
            or manifest.database_size_bytes < 0
            or not isinstance(manifest.sha256, str)
            or len(manifest.sha256) != 64
            or any(character not in "0123456789abcdef" for character in manifest.sha256)
        ):
            raise SQLiteBackupError("Backup manifest fields are invalid.")
        try:
            created_at = datetime.fromisoformat(manifest.created_at.replace("Z", "+00:00"))
            if created_at.tzinfo is None:
                raise ValueError("Backup timestamp must include a timezone.")
        except (AttributeError, TypeError, ValueError) as exc:
            raise SQLiteBackupError("Backup manifest timestamp is invalid.") from exc
        if not backup.is_file() or backup.stat().st_size != manifest.database_size_bytes:
            raise SQLiteBackupError("Backup database size does not match its manifest.")
        if not hmac.compare_digest(self._sha256(backup), manifest.sha256):
            raise SQLiteBackupError("Backup SHA-256 checksum mismatch.")

        try:
            with sqlite3.connect(f"file:{backup.resolve()}?mode=ro", uri=True) as connection:
                self._quick_check(connection)
                if self._schema_version(connection) != manifest.schema_version:
                    raise SQLiteBackupError("Backup schema version does not match its manifest.")
        except sqlite3.Error as exc:
            raise SQLiteBackupError("Backup database cannot be opened or checked.") from exc
        return manifest

    def restore_backup(
        self,
        backup_path: str | Path,
        destination_path: str | Path,
    ) -> BackupManifest:
        """Restore a verified backup through a staged, atomic database replace.

        The application must be stopped. Existing WAL/SHM sidecars are rejected
        because they indicate a database that may still be active or uncheckpointed.
        """
        manifest = self.verify_backup(backup_path)
        backup = Path(backup_path)
        destination = Path(destination_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("-wal", "-shm"):
            if Path(f"{destination}{suffix}").exists():
                raise SQLiteBackupError(
                    "Restore target has SQLite sidecars; stop the application and retry."
                )

        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.restore.", suffix=".tmp", dir=destination.parent
        )
        os.close(fd)
        staged = Path(temporary_name)
        try:
            with sqlite3.connect(f"file:{backup.resolve()}?mode=ro", uri=True) as source:
                with sqlite3.connect(staged) as target:
                    source.backup(target)
                    self._quick_check(target)
                    if self._schema_version(target) != manifest.schema_version:
                        raise SQLiteBackupError("Restored schema version does not match manifest.")
            os.replace(staged, destination)
            self._fsync_directory(destination.parent)
            return manifest
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteBackupError("Unable to restore SQLite backup.") from exc
        finally:
            staged.unlink(missing_ok=True)
