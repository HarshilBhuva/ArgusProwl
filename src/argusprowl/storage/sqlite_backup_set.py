"""Verified backup-set coordination for ArgusProwl's independent SQLite stores.

A backup set is a coordinated operator workflow, not a cross-database transaction.
Callers must stop all application writers before creating the set.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from argusprowl.storage.sqlite_backup import SQLiteBackupError, SQLiteBackupManager


class SQLiteBackupSetError(RuntimeError):
    """Raised when a multi-database backup set cannot be created or verified."""


class SQLiteBackupSetManager:
    """Publish, verify, and restore complete generations of independent SQLite stores."""

    FORMAT_VERSION = 1
    _NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")

    def __init__(self, backup_manager: SQLiteBackupManager | None = None) -> None:
        self._backup_manager = backup_manager or SQLiteBackupManager()

    @staticmethod
    def _write_json(path: Path, value: dict[str, object]) -> None:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def create_backup_set(
        self,
        databases: Mapping[str, str | Path],
        output_directory: str | Path,
        *,
        application_version: str,
    ) -> dict[str, object]:
        """Create a complete generation and publish it with one directory rename.

        The operator must stop ArgusProwl and every writer first. Each database is
        copied through SQLite's online backup API; this set manifest ties the
        independently consistent snapshots to one operator-declared generation.
        """
        if not application_version or not application_version.strip():
            raise ValueError("application_version must be a non-empty string.")
        if not databases:
            raise ValueError("At least one SQLite database is required.")

        normalized: dict[str, Path] = {}
        resolved_sources: set[Path] = set()
        for name, source_value in databases.items():
            if not isinstance(name, str) or not self._NAME_PATTERN.fullmatch(name):
                raise ValueError(f"Invalid backup database name: {name!r}")
            source = Path(source_value)
            if not source.is_file():
                raise SQLiteBackupSetError(f"Configured SQLite database is missing: {name}")
            resolved_source = source.resolve()
            if resolved_source in resolved_sources:
                raise ValueError("Each configured SQLite store must use a distinct database file.")
            resolved_sources.add(resolved_source)
            normalized[name] = source

        destination = Path(output_directory)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(f"Backup generation already exists: {destination}")

        staging = Path(tempfile.mkdtemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=destination.parent
        ))
        entries: list[dict[str, object]] = []
        try:
            for name, source in sorted(normalized.items()):
                filename = f"{name}.db"
                manifest = self._backup_manager.create_backup(
                    source,
                    staging / filename,
                    application_version=application_version.strip(),
                )
                entries.append({
                    "name": name,
                    "database_file": filename,
                    "manifest_file": f"{filename}.manifest.json",
                    "created_at": manifest.created_at,
                    "schema_version": manifest.schema_version,
                    "database_size_bytes": manifest.database_size_bytes,
                    "sha256": manifest.sha256,
                })

            document: dict[str, object] = {
                "format_version": self.FORMAT_VERSION,
                "created_at": datetime.now(UTC).isoformat(),
                "application_version": application_version.strip(),
                "databases": entries,
            }
            self._write_json(staging / "backup-set.json", document)
            self.verify_backup_set(staging)
            self._sync_directory(staging)
            os.rename(staging, destination)
            self._sync_directory(destination.parent)
            return document
        except (OSError, SQLiteBackupError, ValueError) as exc:
            raise SQLiteBackupSetError("Unable to create complete SQLite backup set.") from exc
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def verify_backup_set(self, backup_directory: str | Path) -> dict[str, object]:
        """Verify every database and manifest before accepting a generation."""
        directory = Path(backup_directory)
        try:
            document = json.loads(
                (directory / "backup-set.json").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SQLiteBackupSetError("Backup-set manifest is missing or invalid.") from exc

        if not isinstance(document, dict) or set(document) != {
            "format_version", "created_at", "application_version", "databases"
        }:
            raise SQLiteBackupSetError("Backup-set manifest fields are invalid.")
        if (
            not isinstance(document["format_version"], int)
            or isinstance(document["format_version"], bool)
            or document["format_version"] != self.FORMAT_VERSION
        ):
            raise SQLiteBackupSetError("Unsupported backup-set format.")
        if (
            not isinstance(document["application_version"], str)
            or not document["application_version"].strip()
        ):
            raise SQLiteBackupSetError("Backup-set application version is invalid.")

        try:
            created_at = datetime.fromisoformat(
                str(document["created_at"]).replace("Z", "+00:00")
            )
            if created_at.tzinfo is None:
                raise ValueError
        except ValueError as exc:
            raise SQLiteBackupSetError("Backup-set timestamp is invalid.") from exc

        entries = document["databases"]
        if not isinstance(entries, list) or not entries:
            raise SQLiteBackupSetError("Backup set contains no databases.")

        names: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "name", "database_file", "manifest_file", "created_at",
                "schema_version", "database_size_bytes", "sha256",
            }:
                raise SQLiteBackupSetError("Backup-set database entry is invalid.")

            name = entry["name"]
            if (
                not isinstance(name, str)
                or not self._NAME_PATTERN.fullmatch(name)
                or name in names
            ):
                raise SQLiteBackupSetError(
                    "Backup-set database names are invalid or duplicated."
                )
            names.add(name)

            filename = f"{name}.db"
            if (
                entry["database_file"] != filename
                or entry["manifest_file"] != f"{filename}.manifest.json"
            ):
                raise SQLiteBackupSetError("Backup-set database paths are invalid.")

            try:
                manifest = self._backup_manager.verify_backup(directory / filename)
            except (SQLiteBackupError, OSError) as exc:
                raise SQLiteBackupSetError(
                    f"Backup verification failed for {name}."
                ) from exc

            if (
                manifest.created_at != entry["created_at"]
                or manifest.schema_version != entry["schema_version"]
                or manifest.database_size_bytes != entry["database_size_bytes"]
                or manifest.sha256 != entry["sha256"]
            ):
                raise SQLiteBackupSetError(f"Backup-set metadata mismatch for {name}.")

        return document

    def restore_backup_set(
        self,
        backup_directory: str | Path,
        output_directory: str | Path,
    ) -> dict[str, object]:
        """Restore every member into a new isolated directory.

        The destination is published with one directory rename only after every
        member has been verified and restored. This never modifies live stores.
        """
        source = Path(backup_directory)
        document = self.verify_backup_set(source)
        destination = Path(output_directory)
        source_resolved = source.resolve()
        destination_resolved = destination.resolve()
        if (
            destination_resolved == source_resolved
            or source_resolved in destination_resolved.parents
        ):
            raise ValueError("Restore output must not be inside the source backup generation.")

        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise FileExistsError(f"Restore output already exists: {destination}")

        staging = Path(tempfile.mkdtemp(
            prefix=f".{destination.name}.", suffix=".restore", dir=destination.parent
        ))
        try:
            for entry in document["databases"]:
                filename = str(entry["database_file"])
                manifest_filename = str(entry["manifest_file"])
                shutil.copy2(source / filename, staging / filename)
                shutil.copy2(source / manifest_filename, staging / manifest_filename)
                self._backup_manager.verify_backup(staging / filename)

            shutil.copy2(source / "backup-set.json", staging / "backup-set.json")
            self.verify_backup_set(staging)
            self._sync_directory(staging)
            os.rename(staging, destination)
            self._sync_directory(destination.parent)
            return document
        except (OSError, SQLiteBackupError, ValueError) as exc:
            raise SQLiteBackupSetError("Unable to restore complete SQLite backup set.") from exc
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
