"""ATT&CK knowledge service.

Provides validated local snapshot management and read-only knowledge
lookup for the ATT&CK knowledge layer.

Security bounds enforced on import:
- Maximum input bytes: 50 MB
- Maximum STIX objects: 50,000
- Maximum techniques: 10,000
- Maximum tactics: 100
- Maximum technique ID length: 12 characters
- Maximum name length: 256 characters
- Maximum description length: 4,096 characters

ATT&CK version semantics:
- The authoritative ATT&CK release is extracted from the object's
  ``x_mitre_version`` field on an x-mitre-matrix or x-mitre-collection.
- ``x_mitre_attack_spec_version`` describes the ATT&CK data specification,
  not the ATT&CK release, and must never be used as a release fallback.
- STIX ``spec_version`` (e.g. "2.1") is NEVER treated as an ATT&CK version.
- If no authoritative version is present, import is rejected with
  ``ValidationError`` — the service never silently returns "unknown".

Snapshot replacement semantics:
- New snapshot is written to a temp file first.
- Validation is performed on the temp file before any filesystem mutation.
- Only after successful validation does the service rotate:
    current → previous (only if previous does not already exist)
    temp → current (atomic rename)
- In-memory state is committed only after both filesystem renames succeed.
  If validation fails or the temp write fails, both in-memory state and
  on-disk files remain completely unchanged.
- If the current→previous rotation succeeds but the temp→current rename
  then fails (e.g. due to a filesystem error), the in-memory state is
  NOT updated.  On disk, the old current data will be at the previous
  path; current will be absent.  A subsequent service restart will detect
  this condition and recover with DEGRADED status, serving the old data
  from the previous file.
- Startup recovery: current → previous → EMPTY / UNAVAILABLE.

Filesystem/symlink handling:
- Paths are resolved with ``Path.resolve()`` which follows symlinks.
- The service does NOT prevent symlinked paths; it operates on the
  resolved target.
- Temporary files are created in the same directory as the snapshot
  path (prefix ``.attck_snapshot_``) to ensure same-filesystem
  ``os.replace`` atomicity.
- Temp files are never treated as active snapshots.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from argusprowl.attck.models import AttckSnapshotMetadata, AttckTactic, AttckTechnique
from argusprowl.constants.attck import AttckKnowledgeStatus
from argusprowl.constants.log_names import LogName
from argusprowl.exceptions.exceptions import ValidationError
from argusprowl.logging.logger_factory import LoggerFactory

# ── Security bounds ──────────────────────────────────────────────────
_MAX_INPUT_BYTES: int = 50 * 1024 * 1024  # 50 MB
_MAX_STIX_OBJECTS: int = 50_000
_MAX_TECHNIQUES: int = 10_000
_MAX_TACTICS: int = 100
_MAX_TECHNIQUE_ID_LEN: int = 12
_MAX_NAME_LEN: int = 256
_MAX_DESCRIPTION_LEN: int = 4_096

# ── ATT&CK version pattern ───────────────────────────────────────────
# Matches versions like "14.0", "15.1", "16.0", "18.1" etc.
# ATT&CK versions use major.minor (two numeric components); allow
# one or two components to be conservative.
_ATTCK_VERSION_PATTERN: re.Pattern[str] = re.compile(r"^\d+(\.\d+){1,2}$")


class AttckKnowledgeService:
    """Read-only ATT&CK knowledge service with validated local snapshots.

    The service manages versioned local snapshots of ATT&CK data imported
    from official STIX 2.1 sources.  It provides deterministic lookup by
    technique and tactic IDs.

    Status model:
        AVAILABLE:   Valid active snapshot is loaded.
        EMPTY:       No snapshot has ever been successfully installed.
        DEGRADED:    Current snapshot failed; previous known-good is active.
        UNAVAILABLE: No usable snapshot can be loaded.

    Security notes:
        - ``Path.resolve()`` follows symlinks; the service operates on the
          resolved target path.
        - Temp files use prefix ``.attck_snapshot_`` and are created in the
          same directory as the snapshot to guarantee same-filesystem
          ``os.replace`` atomicity.
        - Temp files are never treated as active snapshots.
    """

    def __init__(
        self,
        snapshot_path: str | Path,
        previous_snapshot_path: str | Path | None = None,
        *,
        enabled: bool = True,
    ) -> None:
        self._snapshot_path = Path(snapshot_path).resolve()
        if previous_snapshot_path is not None and str(previous_snapshot_path).strip():
            self._previous_snapshot_path = Path(previous_snapshot_path).resolve()
        else:
            self._previous_snapshot_path = self._snapshot_path.with_suffix(
                self._snapshot_path.suffix + ".previous"
            )
        self._enabled = enabled
        self._techniques: dict[str, AttckTechnique] = {}
        self._tactics: dict[str, AttckTactic] = {}
        self._metadata: AttckSnapshotMetadata | None = None
        self._status: AttckKnowledgeStatus = AttckKnowledgeStatus.EMPTY
        self._logger = LoggerFactory.get_logger(LogName.ROOT + ".attck")

        if self._enabled:
            self._load_on_init()
        else:
            self._status = AttckKnowledgeStatus.UNAVAILABLE

    # ── Startup loading ──────────────────────────────────────────────

    def _load_on_init(self) -> None:
        """Try to load a snapshot at startup.

        Order: current → previous → EMPTY / UNAVAILABLE.

        A malformed snapshot is NEVER reported as AVAILABLE.
        """
        # Try current snapshot
        if self._snapshot_path.is_file():
            try:
                self._load_from_path(self._snapshot_path)
                self._status = AttckKnowledgeStatus.AVAILABLE
                self._logger.info(
                    "ATT&CK knowledge status: AVAILABLE (version=%s, techniques=%d, tactics=%d)",
                    self._metadata.version if self._metadata else "unknown",
                    len(self._techniques),
                    len(self._tactics),
                )
                return
            except Exception as exc:
                self._logger.warning(
                    "Current ATT&CK snapshot corrupt at %s: %s",
                    self._snapshot_path,
                    exc,
                )

        # Try previous snapshot
        if self._previous_snapshot_path.is_file():
            try:
                self._load_from_path(self._previous_snapshot_path)
                self._status = AttckKnowledgeStatus.DEGRADED
                self._logger.warning(
                    "ATT&CK knowledge status: DEGRADED — using previous snapshot from %s (version=%s)",
                    self._previous_snapshot_path,
                    self._metadata.version if self._metadata else "unknown",
                )
                return
            except Exception as exc:
                self._logger.warning(
                    "Previous ATT&CK snapshot also corrupt at %s: %s",
                    self._previous_snapshot_path,
                    exc,
                )

        # Nothing usable
        if self._snapshot_path.exists() or self._previous_snapshot_path.exists():
            self._status = AttckKnowledgeStatus.UNAVAILABLE
            self._logger.error("ATT&CK knowledge status: UNAVAILABLE — all snapshots corrupt")
        else:
            self._status = AttckKnowledgeStatus.EMPTY
            self._logger.info("ATT&CK knowledge status: EMPTY — no snapshot installed")

    # ── Internal loading ─────────────────────────────────────────────

    def _load_from_path(self, path: Path) -> None:
        """Read, validate, and commit a snapshot from *path*.

        Raises on any validation failure.  On failure, in-memory state
        is NOT partially populated.
        """
        raw_bytes = self._read_bounded(path)
        parsed = self._parse_json(raw_bytes)
        techniques, tactics = self._validate_and_extract(parsed)
        integrity = hashlib.sha256(raw_bytes).hexdigest()
        version = self._extract_version(parsed, integrity_hash=integrity)

        # Only commit after full validation succeeds
        self._techniques = techniques
        self._tactics = tactics
        self._metadata = AttckSnapshotMetadata(
            version=version,
            imported_at=datetime.now(UTC),
            source=str(path),
            integrity_hash=integrity,
            technique_count=len(techniques),
            tactic_count=len(tactics),
        )

    # ── Import ───────────────────────────────────────────────────────

    def import_snapshot(self, data: bytes | str | Path) -> AttckSnapshotMetadata:
        """Import a new ATT&CK snapshot.

        Failure semantics:
        - If validation fails or the temp file write fails, both in-memory
          state and on-disk files are completely unchanged.
        - If the current→previous rotation succeeds but the temp→current
          rename then fails, in-memory state is NOT updated.  On disk, the
          old current data will be at the previous path; current will be
          absent.  A subsequent restart will recover with DEGRADED status.

        The validated new snapshot is kept in a temporary file until all
        validation is complete.  Only then are the filesystem renames
        attempted.

        Args:
            data: Raw STIX 2.1 JSON as bytes, string, or file path.

        Returns:
            Metadata for the imported snapshot.

        Raises:
            ValidationError: If the snapshot fails validation.
        """
        if not self._enabled:
            raise ValidationError("ATT&CK knowledge service is disabled.")

        # Resolve input to bytes
        if isinstance(data, Path):
            raw_bytes = self._read_bounded(data)
        elif isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        # Enforce size bound before parsing
        if len(raw_bytes) > _MAX_INPUT_BYTES:
            raise ValidationError(
                f"Input exceeds maximum size: {len(raw_bytes)} > {_MAX_INPUT_BYTES} bytes",
                details={"size": len(raw_bytes)},
            )

        # Parse and validate BEFORE any filesystem mutation
        parsed = self._parse_json(raw_bytes)
        techniques, tactics = self._validate_and_extract(parsed)
        integrity = hashlib.sha256(raw_bytes).hexdigest()
        version = self._extract_version(parsed, integrity_hash=integrity)

        # Write to temp file in the same directory (same filesystem for rename)
        self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path_str = tempfile.mkstemp(
            dir=str(self._snapshot_path.parent),
            prefix=".attck_snapshot_",
            suffix=".json",
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw_bytes)
                fh.flush()
                os.fsync(fh.fileno())

            # Rotate: current → previous, temp → current
            # Never delete previous before new is safely installed.
            if self._snapshot_path.is_file() and not self._previous_snapshot_path.exists():
                # Preserve existing previous (don't overwrite it)
                # Safe to move current → previous
                os.replace(str(self._snapshot_path), str(self._previous_snapshot_path))
            # else: keep the existing previous, current will be overwritten

            os.replace(str(tmp_path), str(self._snapshot_path))
        except BaseException:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
            raise

        # Commit to memory (validation already passed)
        self._techniques = techniques
        self._tactics = tactics
        self._metadata = AttckSnapshotMetadata(
            version=version,
            imported_at=datetime.now(UTC),
            source="import",
            integrity_hash=integrity,
            technique_count=len(techniques),
            tactic_count=len(tactics),
        )
        self._status = AttckKnowledgeStatus.AVAILABLE

        self._logger.info(
            "Imported ATT&CK snapshot: version=%s, techniques=%d, tactics=%d",
            version,
            len(techniques),
            len(tactics),
        )

        return self._metadata

    # ── Read-only lookup APIs ────────────────────────────────────────

    def get_technique(self, technique_id: str) -> AttckTechnique | None:
        """Look up a technique by ID.  Returns None for unknown IDs."""
        if not self._enabled or self._status in (
            AttckKnowledgeStatus.EMPTY,
            AttckKnowledgeStatus.UNAVAILABLE,
        ):
            return None
        return self._techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> AttckTactic | None:
        """Look up a tactic by ID.  Returns None for unknown IDs."""
        if not self._enabled or self._status in (
            AttckKnowledgeStatus.EMPTY,
            AttckKnowledgeStatus.UNAVAILABLE,
        ):
            return None
        return self._tactics.get(tactic_id)

    def get_status(self) -> AttckKnowledgeStatus:
        """Get the current knowledge status."""
        return self._status

    def get_version(self) -> str | None:
        """Get the ATT&CK version of the active snapshot, or None."""
        if self._metadata is None:
            return None
        return self._metadata.version

    def get_metadata(self) -> AttckSnapshotMetadata | None:
        """Get metadata for the active snapshot, or None."""
        return self._metadata

    @property
    def is_enabled(self) -> bool:
        """Whether the service is enabled."""
        return self._enabled

    @property
    def snapshot_path(self) -> Path:
        """Path to the current snapshot file."""
        return self._snapshot_path

    @property
    def previous_snapshot_path(self) -> Path:
        """Path to the previous snapshot file."""
        return self._previous_snapshot_path

    # ── Validation helpers ───────────────────────────────────────────

    @staticmethod
    def _read_bounded(path: Path) -> bytes:
        """Read a file, rejecting it if it exceeds the size bound.

        Note: ``Path.resolve()`` follows symlinks. The service operates
        on the resolved target path.
        """
        resolved = path.resolve()
        if not resolved.is_file():
            raise ValidationError(
                f"Snapshot path is not a regular file: {resolved}",
                details={"path": str(resolved)},
            )

        file_size = resolved.stat().st_size
        if file_size > _MAX_INPUT_BYTES:
            raise ValidationError(
                f"Snapshot file exceeds maximum size: {file_size} > {_MAX_INPUT_BYTES} bytes",
                details={"path": str(resolved), "size": file_size},
            )

        return resolved.read_bytes()

    @staticmethod
    def _parse_json(raw: bytes) -> Any:
        """Parse JSON, raising ValidationError on failure."""
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValidationError(f"Invalid JSON in snapshot: {exc}") from exc

    @classmethod
    def _validate_and_extract(
        cls, data: Any
    ) -> tuple[dict[str, AttckTechnique], dict[str, AttckTactic]]:
        """Validate STIX structure and extract techniques/tactics.

        Returns:
            (techniques_dict, tactics_dict)

        Raises:
            ValidationError: On any structural or bounds violation.
        """
        if not isinstance(data, dict):
            raise ValidationError("Snapshot root must be a JSON object.")

        # Validate root is a STIX bundle
        cls._validate_bundle_root(data)

        objects = cls._extract_objects(data)

        if len(objects) > _MAX_STIX_OBJECTS:
            raise ValidationError(
                f"Snapshot contains too many objects: {len(objects)} > {_MAX_STIX_OBJECTS}",
                details={"object_count": len(objects)},
            )

        techniques: dict[str, AttckTechnique] = {}
        tactics: dict[str, AttckTactic] = {}
        seen_technique_ids: set[str] = set()
        seen_tactic_ids: set[str] = set()

        for obj in objects:
            if not isinstance(obj, dict):
                raise ValidationError(
                    "STIX objects must be JSON objects; found a non-object entry."
                )

            obj_type = obj.get("type", "")

            if obj_type == "attack-pattern":
                cls._parse_attack_pattern(obj, techniques, seen_technique_ids)
            elif obj_type == "x-mitre-tactic":
                cls._parse_tactic_object(obj, tactics, seen_tactic_ids)
            # Unsupported STIX object types are silently ignored — they
            # are not required for the minimal knowledge model.

        if len(techniques) > _MAX_TECHNIQUES:
            raise ValidationError(
                f"Too many techniques: {len(techniques)} > {_MAX_TECHNIQUES}",
                details={"technique_count": len(techniques)},
            )

        if len(tactics) > _MAX_TACTICS:
            raise ValidationError(
                f"Too many tactics: {len(tactics)} > {_MAX_TACTICS}",
                details={"tactic_count": len(tactics)},
            )

        return techniques, tactics

    @staticmethod
    def _validate_bundle_root(data: dict[str, Any]) -> None:
        """Validate that the root object has a valid STIX bundle structure."""
        # A STIX bundle must have type "bundle" and an "objects" field
        bundle_type = data.get("type")
        if bundle_type != "bundle":
            raise ValidationError(
                f"Snapshot root must be a STIX bundle (type='bundle'), got type='{bundle_type}'"
            )

        # Validate objects field exists and is a list
        objects = data.get("objects")
        if objects is None:
            raise ValidationError("Snapshot bundle is missing 'objects' field.")
        if not isinstance(objects, list):
            raise ValidationError(
                f"Snapshot 'objects' must be a list, got {type(objects).__name__}."
            )

    @staticmethod
    def _extract_objects(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract STIX objects from a bundle."""
        objects = data.get("objects")
        if isinstance(objects, list):
            return objects
        return []

    @classmethod
    def _parse_attack_pattern(
        cls,
        obj: dict[str, Any],
        techniques: dict[str, AttckTechnique],
        seen_ids: set[str],
    ) -> None:
        """Parse one STIX attack-pattern into an AttckTechnique.

        Raises ValidationError for malformed required fields.
        Detects duplicate ATT&CK technique IDs.
        """
        # Validate STIX object ID
        obj_id = obj.get("id")
        if not obj_id or not isinstance(obj_id, str):
            raise ValidationError("attack-pattern object missing valid 'id' field.")
        if not obj_id.startswith("attack-pattern--"):
            raise ValidationError(f"attack-pattern object has invalid ID format: '{obj_id}'")

        # Validate external_references structure before using it
        ext_refs = obj.get("external_references")
        if ext_refs is not None and not isinstance(ext_refs, list):
            raise ValidationError("external_references must be a list of objects.")
        for ref in ext_refs or []:
            if not isinstance(ref, dict):
                raise ValidationError("external_references entries must be objects.")

        technique_id = cls._extract_external_id(obj, "mitre-attack")
        if not technique_id:
            return

        # Validate technique ID format
        if not re.match(r"^[A-Z]\d{4}(\.\d{3})?$", technique_id):
            raise ValidationError(f"Technique ID has invalid format: '{technique_id}'")

        if len(technique_id) > _MAX_TECHNIQUE_ID_LEN:
            raise ValidationError(
                f"Technique ID too long: '{technique_id}' ({len(technique_id)} > {_MAX_TECHNIQUE_ID_LEN})",
            )

        # Detect duplicate technique IDs
        if technique_id in seen_ids:
            raise ValidationError(f"Duplicate ATT&CK technique ID: '{technique_id}'")
        seen_ids.add(technique_id)

        name = obj.get("name")
        if not isinstance(name, str) or not name:
            raise ValidationError(f"Technique '{technique_id}' has missing or invalid 'name'.")
        if len(name) > _MAX_NAME_LEN:
            raise ValidationError(
                f"Technique name too long for {technique_id}: {len(name)} > {_MAX_NAME_LEN}",
            )

        description = obj.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str):
            raise ValidationError(
                f"Technique '{technique_id}' has invalid 'description' (must be a string)."
            )
        # Some official ATT&CK releases contain descriptions slightly above
        # the service's storage bound. Preserve the useful prefix rather than
        # rejecting the entire bundle; the stored model remains size-bounded.
        if len(description) > _MAX_DESCRIPTION_LEN:
            description = description[:_MAX_DESCRIPTION_LEN]

        # Validate kill_chain_phases structure
        tactic: str | None = None
        kcp = obj.get("kill_chain_phases")
        if kcp is not None:
            if not isinstance(kcp, list):
                raise ValidationError(
                    f"Technique '{technique_id}' kill_chain_phases must be a list."
                )
            for phase in kcp:
                if not isinstance(phase, dict):
                    raise ValidationError(
                        f"Technique '{technique_id}' kill_chain_phases entries must be objects."
                    )
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase.get("phase_name")
                    if isinstance(phase_name, str) and phase_name:
                        tactic = phase_name
                        break

        # Determine parent technique for sub-techniques
        parent_id: str | None = None
        if "." in technique_id:
            parent_id = technique_id.split(".")[0]

        techniques[technique_id] = AttckTechnique(
            technique_id=technique_id,
            name=name,
            description=description,
            tactic=tactic,
            parent_technique_id=parent_id,
        )

    @classmethod
    def _parse_tactic_object(
        cls,
        obj: dict[str, Any],
        tactics: dict[str, AttckTactic],
        seen_ids: set[str],
    ) -> None:
        """Parse one STIX x-mitre-tactic into an AttckTactic.

        Raises ValidationError for malformed required fields.
        Detects duplicate ATT&CK tactic IDs.
        """
        # Validate STIX object ID
        obj_id = obj.get("id")
        if not obj_id or not isinstance(obj_id, str):
            raise ValidationError("x-mitre-tactic object missing valid 'id' field.")
        if not obj_id.startswith("x-mitre-tactic--"):
            raise ValidationError(f"x-mitre-tactic object has invalid ID format: '{obj_id}'")

        shortname = obj.get("x_mitre_shortname")
        if shortname is not None and not isinstance(shortname, str):
            raise ValidationError(
                "x-mitre-tactic object has invalid 'x_mitre_shortname' (must be a string)."
            )
        tactic_id = shortname or ""
        if not tactic_id:
            tactic_id = cls._extract_external_id(obj, "mitre-attack")
        if not tactic_id:
            return

        # Validate tactic ID format (lowercase alphanumeric with hyphens)
        if not re.match(r"^[a-z][a-z0-9-]*$", tactic_id):
            raise ValidationError(f"Tactic ID has invalid format: '{tactic_id}'")

        # Detect duplicate tactic IDs
        if tactic_id in seen_ids:
            raise ValidationError(f"Duplicate ATT&CK tactic ID: '{tactic_id}'")
        seen_ids.add(tactic_id)

        name = obj.get("name")
        if not isinstance(name, str) or not name:
            raise ValidationError(f"Tactic '{tactic_id}' has missing or invalid 'name'.")
        if len(name) > _MAX_NAME_LEN:
            raise ValidationError(
                f"Tactic name too long for {tactic_id}: {len(name)} > {_MAX_NAME_LEN}",
            )

        description = obj.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str):
            raise ValidationError(
                f"Tactic '{tactic_id}' has invalid 'description' (must be a string)."
            )
        if len(description) > _MAX_DESCRIPTION_LEN:
            raise ValidationError(
                f"Tactic description too long for {tactic_id}: "
                f"{len(description)} > {_MAX_DESCRIPTION_LEN}",
            )

        tactics[tactic_id] = AttckTactic(
            tactic_id=tactic_id,
            name=name,
            description=description,
        )

    @staticmethod
    def _extract_external_id(obj: dict[str, Any], source_name: str) -> str:
        """Extract external_id from external_references matching *source_name*.

        Validates external_references structure before accessing it.
        """
        ext_refs = obj.get("external_references")
        if not isinstance(ext_refs, list):
            return ""
        for ref in ext_refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("source_name") == source_name:
                ext_id = ref.get("external_id")
                if isinstance(ext_id, str) and ext_id:
                    return ext_id
        return ""

    @staticmethod
    def _extract_version(data: dict[str, Any], *, integrity_hash: str | None = None) -> str:
        """Extract the ATT&CK release from its authoritative collection object.

        The collection's x_mitre_version identifies the ATT&CK release.
        A matrix object's x_mitre_version can describe that object itself
        (for example, "1.0"), so it is only a fallback for older bundles
        that have no collection metadata. STIX spec_version is unrelated.
        """
        collection_versions: set[str] = set()
        matrix_versions: set[str] = set()

        for obj in data.get("objects", []):
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type")
            if obj_type not in {"x-mitre-collection", "x-mitre-matrix"}:
                continue

            version = obj.get("x_mitre_version")
            if not isinstance(version, str) or not version.strip():
                continue
            if not _ATTCK_VERSION_PATTERN.fullmatch(version):
                raise ValidationError(f"Malformed ATT&CK version: {version!r}")

            if obj_type == "x-mitre-collection":
                collection_versions.add(version)
            else:
                matrix_versions.add(version)

        versions = collection_versions or matrix_versions
        if not versions:
            raise ValidationError("Missing authoritative ATT&CK version.")
        if len(versions) > 1:
            raise ValidationError(f"Ambiguous ATT&CK version: found {', '.join(sorted(versions))}.")
        return next(iter(versions))
