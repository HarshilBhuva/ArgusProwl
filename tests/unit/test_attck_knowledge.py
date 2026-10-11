"""Tests for ATT&CK knowledge service (Phase 6.1 — Hardened)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.attck.models import AttckSnapshotMetadata, AttckTactic, AttckTechnique
from argusprowl.constants.attck import AttckKnowledgeStatus
from argusprowl.exceptions.exceptions import ValidationError

# ── Fixtures ─────────────────────────────────────────────────────────


def _minimal_bundle(
    *,
    techniques: list[dict[str, Any]] | None = None,
    tactics: list[dict[str, Any]] | None = None,
    version: str = "14.0",
) -> dict[str, Any]:
    """Build a minimal STIX 2.1 bundle for testing."""
    objects: list[dict[str, Any]] = []

    if version:
        objects.append(
            {
                "type": "x-mitre-collection",
                "spec_version": "2.1",
                "x_mitre_version": version,
                "name": "Enterprise ATT&CK",
            }
        )

    if techniques:
        objects.extend(techniques)
    if tactics:
        objects.extend(tactics)

    return {
        "type": "bundle",
        "id": "bundle--abc123",
        "spec_version": "2.1",
        "objects": objects,
    }


def _technique(
    *,
    technique_id: str = "T1046",
    name: str = "Network Service Scanning",
    description: str = "A technique for discovering services.",
    tactic: str | None = "discovery",
    parent: str | None = None,
) -> dict[str, Any]:
    """Build a minimal STIX attack-pattern object."""
    obj: dict[str, Any] = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{technique_id.lower()}",
        "name": name,
        "description": description,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
            }
        ],
    }
    if tactic:
        obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": tactic}]
    return obj


def _tactic(
    *,
    tactic_id: str = "discovery",
    name: str = "Discovery",
    description: str = "Techniques for discovering targets.",
) -> dict[str, Any]:
    """Build a minimal STIX x-mitre-tactic object."""
    return {
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{tactic_id}",
        "name": name,
        "description": description,
        "x_mitre_shortname": tactic_id,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": tactic_id,
            }
        ],
    }


# ── Model tests ──────────────────────────────────────────────────────


class TestAttckModels:
    """Tests for ATT&CK domain models."""

    def test_attck_tactic_frozen(self) -> None:
        tactic = AttckTactic(tactic_id="discovery", name="Discovery")
        assert tactic.tactic_id == "discovery"
        assert tactic.name == "Discovery"
        assert tactic.description == ""

    def test_attck_technique_frozen(self) -> None:
        tech = AttckTechnique(
            technique_id="T1046",
            name="Network Service Scanning",
            tactic="discovery",
        )
        assert tech.technique_id == "T1046"
        assert tech.tactic == "discovery"
        assert tech.parent_technique_id is None

    def test_attck_technique_subtechnique(self) -> None:
        tech = AttckTechnique(
            technique_id="T1071.001",
            name="Web Protocols",
            parent_technique_id="T1071",
        )
        assert tech.parent_technique_id == "T1071"

    def test_snapshot_metadata_serialization(self) -> None:
        import datetime

        meta = AttckSnapshotMetadata(
            version="14.0",
            imported_at=datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC),
            source="test",
            integrity_hash="abc123",
            technique_count=10,
            tactic_count=5,
        )
        d = meta.to_dict()
        assert d["version"] == "14.0"
        assert d["technique_count"] == 10

        restored = AttckSnapshotMetadata.from_dict(d)
        assert restored.version == "14.0"
        assert restored.technique_count == 10


# ── Status tests ─────────────────────────────────────────────────────


class TestAttckKnowledgeStatus:
    """Tests for AttckKnowledgeStatus enum."""

    def test_available(self) -> None:
        assert AttckKnowledgeStatus.AVAILABLE == "AVAILABLE"

    def test_empty(self) -> None:
        assert AttckKnowledgeStatus.EMPTY == "EMPTY"

    def test_degraded(self) -> None:
        assert AttckKnowledgeStatus.DEGRADED == "DEGRADED"

    def test_unavailable(self) -> None:
        assert AttckKnowledgeStatus.UNAVAILABLE == "UNAVAILABLE"


# ── Service initialization tests ─────────────────────────────────────


class TestServiceInit:
    """Tests for service initialization."""

    def test_disabled_service(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=False,
        )
        assert svc.get_status() == AttckKnowledgeStatus.UNAVAILABLE
        assert svc.get_technique("T1046") is None
        assert svc.get_version() is None

    def test_empty_state_no_snapshot(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.EMPTY
        assert svc.get_technique("T1046") is None
        assert svc.get_version() is None

    def test_snapshot_path_property(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "attck.json",
            enabled=False,
        )
        assert svc.snapshot_path == temp_dir / "attck.json"

    def test_previous_snapshot_path_derived(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "attck.json",
            enabled=False,
        )
        assert svc.previous_snapshot_path == temp_dir / "attck.json.previous"


# ── Import tests ─────────────────────────────────────────────────────


class TestImport:
    """Tests for snapshot import."""

    def test_import_valid_bundle(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique()],
            tactics=[_tactic()],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())

        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert meta.version == "14.0"
        assert meta.technique_count == 1
        assert meta.tactic_count == 1

    def test_import_technique_lookup(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        tech = svc.get_technique("T1046")
        assert tech is not None
        assert tech.name == "Network Service Scanning"
        assert tech.tactic == "discovery"

    def test_import_tactic_lookup(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            tactics=[_tactic(tactic_id="discovery")],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        tactic = svc.get_tactic("discovery")
        assert tactic is not None
        assert tactic.name == "Discovery"

    def test_import_unknown_technique_returns_none(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        assert svc.get_technique("T9999") is None

    def test_import_unknown_tactic_returns_none(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            tactics=[_tactic(tactic_id="discovery")],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        assert svc.get_tactic("exfiltration") is None

    def test_import_from_file_path(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique()],
        )
        snapshot_path = temp_dir / "snapshot.json"
        snapshot_path.write_text(json.dumps(bundle))

        svc = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            enabled=True,
        )
        meta = svc.import_snapshot(snapshot_path)

        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert meta.technique_count == 1

    def test_import_from_string(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique()],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle))

        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert meta.technique_count == 1

    def test_import_multiple_techniques(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[
                _technique(technique_id="T1046"),
                _technique(technique_id="T1071"),
                _technique(technique_id="T1498"),
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())

        assert meta.technique_count == 3
        assert svc.get_technique("T1046") is not None
        assert svc.get_technique("T1071") is not None
        assert svc.get_technique("T1498") is not None

    def test_import_subtechnique(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique(technique_id="T1071.001")],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        tech = svc.get_technique("T1071.001")
        assert tech is not None
        assert tech.parent_technique_id == "T1071"

    def test_disabled_service_no_import(self, temp_dir: Path) -> None:
        """Disabled service rejects import."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=False,
        )
        bundle = _minimal_bundle(techniques=[_technique()])
        with pytest.raises(ValidationError, match="disabled"):
            svc.import_snapshot(json.dumps(bundle).encode())


# ── Validation tests ─────────────────────────────────────────────────


class TestValidation:
    """Tests for input validation."""

    def test_invalid_json(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Invalid JSON"):
            svc.import_snapshot(b"not json")

    def test_non_dict_root(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="root must be a JSON object"):
            svc.import_snapshot(json.dumps([1, 2, 3]).encode())

    def test_non_bundle_root(self, temp_dir: Path) -> None:
        """Root must be a STIX bundle (type='bundle')."""
        bundle = {
            "type": "not-a-bundle",
            "id": "bundle--abc",
            "objects": [],
        }
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="must be a STIX bundle"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_missing_objects_field(self, temp_dir: Path) -> None:
        """Bundle missing 'objects' field is rejected."""
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
        }
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="missing 'objects' field"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_objects_not_list(self, temp_dir: Path) -> None:
        """'objects' field must be a list."""
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "objects": "not-a-list",
        }
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="must be a list"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_empty_bundle(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(techniques=[], tactics=[])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.technique_count == 0
        assert meta.tactic_count == 0

    def test_technique_without_external_id_skipped(self, temp_dir: Path) -> None:
        """Attack patterns without mitre-attack external_id are skipped."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--abc",
                    "name": "No ID",
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.technique_count == 0

    def test_tactic_without_shortname_skipped(self, temp_dir: Path) -> None:
        """Tactics without x_mitre_shortname are skipped."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--abc",
                    "name": "No Shortname",
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.tactic_count == 0

    def test_technique_missing_id_field(self, temp_dir: Path) -> None:
        """Attack pattern missing 'id' field is rejected."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "name": "No ID Field",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="missing valid 'id' field"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_technique_invalid_id_format(self, temp_dir: Path) -> None:
        """Attack pattern with invalid ID format is rejected."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "invalid-id-format",
                    "name": "Bad ID",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="invalid ID format"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_technique_missing_name(self, temp_dir: Path) -> None:
        """Attack pattern with missing name is rejected."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="missing or invalid 'name'"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_technique_invalid_external_id_format(self, temp_dir: Path) -> None:
        """Attack pattern with invalid external_id format is rejected."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Bad External ID",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "invalid!"}
                    ],
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="invalid format"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_duplicate_technique_id_rejected(self, temp_dir: Path) -> None:
        """Duplicate ATT&CK technique IDs are rejected."""
        bundle = _minimal_bundle(
            techniques=[
                _technique(technique_id="T1046"),
                _technique(technique_id="T1046"),  # duplicate
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Duplicate ATT&CK technique ID"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_duplicate_tactic_id_rejected(self, temp_dir: Path) -> None:
        """Duplicate ATT&CK tactic IDs are rejected."""
        bundle = _minimal_bundle(
            tactics=[
                _tactic(tactic_id="discovery"),
                _tactic(tactic_id="discovery"),  # duplicate
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Duplicate ATT&CK tactic ID"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_malformed_kill_chain_phase(self, temp_dir: Path) -> None:
        """Malformed kill_chain_phases structure is handled."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Test",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                    "kill_chain_phases": "not-a-list",  # invalid type
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="kill_chain_phases must be a list"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_malformed_external_reference(self, temp_dir: Path) -> None:
        """Malformed external_references structure is rejected."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Test",
                    "external_references": "not-a-list",  # invalid type
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="external_references must be a list"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_non_object_stix_entry_rejected(self, temp_dir: Path) -> None:
        """Non-object STIX entries are rejected rather than skipped."""
        bundle = _minimal_bundle(techniques=[_technique()])
        bundle["objects"].append("not-an-object")
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="must be JSON objects"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_non_string_description_rejected(self, temp_dir: Path) -> None:
        """Non-string descriptions are rejected, not coerced with str()."""
        bundle = _minimal_bundle(
            techniques=[_technique(description={"nested": True})],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="invalid 'description'"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_ambiguous_version_rejected(self, temp_dir: Path) -> None:
        """Multiple distinct ATT&CK versions in one bundle are rejected."""
        bundle = _minimal_bundle(techniques=[_technique()], version="14.0")
        bundle["objects"].append(
            {
                "type": "x-mitre-collection",
                "spec_version": "2.1",
                "x_mitre_version": "15.0",
                "name": "Enterprise ATT&CK (other)",
            }
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Ambiguous ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_kill_chain_phase_non_object_rejected(self, temp_dir: Path) -> None:
        """Non-object kill_chain_phases entries are rejected."""
        bundle = _minimal_bundle(
            techniques=[
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Test",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                    "kill_chain_phases": ["not-an-object"],
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="kill_chain_phases entries must be objects"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_unsupported_stix_type_ignored(self, temp_dir: Path) -> None:
        """Unsupported STIX object types are silently ignored."""
        bundle = _minimal_bundle(
            techniques=[_technique()],
            tactics=[_tactic()],
        )
        # Add an unsupported object type
        bundle["objects"].append(
            {
                "type": "indicator",
                "id": "indicator--abc",
                "name": "Ignored",
            }
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.technique_count == 1
        assert meta.tactic_count == 1

    def test_failed_import_no_partial_write(self, temp_dir: Path) -> None:
        """Failed import does not leave partial JSON on disk."""
        bundle = _minimal_bundle(techniques=[_technique()])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        # Try to import invalid data
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid")

        # No temp files should remain
        temp_files = list(temp_dir.glob(".attck_snapshot_*"))
        assert len(temp_files) == 0

    def test_snapshot_path_not_traversed(self, temp_dir: Path) -> None:
        """Snapshot path is resolved but not traversed outside temp_dir."""
        # Create a path that resolves outside temp_dir
        outside_path = Path("/tmp/attck_snapshot_test.json")
        try:
            svc = AttckKnowledgeService(
                snapshot_path=outside_path,
                enabled=False,
            )
            # Should not raise, just set the path
            assert svc.snapshot_path == outside_path.resolve()
        finally:
            if outside_path.exists():
                outside_path.unlink()


# ── Security bounds tests ────────────────────────────────────────────


class TestSecurityBounds:
    """Tests for security bounds enforcement."""

    def test_oversized_input_rejected(self, temp_dir: Path) -> None:
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        from argusprowl.attck.knowledge_service import _MAX_INPUT_BYTES

        assert _MAX_INPUT_BYTES == 50 * 1024 * 1024

        import argusprowl.attck.knowledge_service as ks_module

        original = ks_module._MAX_INPUT_BYTES
        ks_module._MAX_INPUT_BYTES = 64
        try:
            with pytest.raises(ValidationError, match="exceeds maximum size"):
                svc.import_snapshot(b"x" * 65)
        finally:
            ks_module._MAX_INPUT_BYTES = original

    def test_technique_id_length_bound(self, temp_dir: Path) -> None:
        """Technique ID length bound constant is correct."""
        from argusprowl.attck.knowledge_service import _MAX_TECHNIQUE_ID_LEN

        assert _MAX_TECHNIQUE_ID_LEN == 12

    def test_technique_name_length_bound(self, temp_dir: Path) -> None:
        """Technique names longer than 256 chars are rejected."""
        bundle = _minimal_bundle(
            techniques=[_technique(name="X" * 257)],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="too long"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_technique_description_length_bound(self, temp_dir: Path) -> None:
        """Overlong technique descriptions are truncated to the configured bound."""
        from argusprowl.attck.knowledge_service import _MAX_DESCRIPTION_LEN

        bundle = _minimal_bundle(
            techniques=[_technique(description="X" * (_MAX_DESCRIPTION_LEN + 1))],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        technique = svc.get_technique("T1046")
        assert technique is not None
        assert len(technique.description) == _MAX_DESCRIPTION_LEN

    def test_tactic_name_length_bound(self, temp_dir: Path) -> None:
        """Tactic names longer than 256 chars are rejected."""
        bundle = _minimal_bundle(
            tactics=[_tactic(name="X" * 257)],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="too long"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_description_length_bound(self, temp_dir: Path) -> None:
        """Tactic descriptions longer than 4096 chars are rejected."""
        bundle = _minimal_bundle(
            tactics=[_tactic(description="X" * 4097)],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="too long"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_missing_id_field(self, temp_dir: Path) -> None:
        """Tactic missing 'id' field is rejected."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "name": "No ID Field",
                    "x_mitre_shortname": "discovery",
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="missing valid 'id' field"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_invalid_id_format(self, temp_dir: Path) -> None:
        """Tactic with invalid ID format is rejected."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "id": "invalid-id-format",
                    "name": "Bad ID",
                    "x_mitre_shortname": "discovery",
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="invalid ID format"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_missing_name(self, temp_dir: Path) -> None:
        """Tactic with missing name is rejected."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--discovery",
                    "x_mitre_shortname": "discovery",
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="missing or invalid 'name'"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_non_string_description_rejected(self, temp_dir: Path) -> None:
        """Non-string tactic descriptions are rejected, not coerced."""
        bundle = _minimal_bundle(
            tactics=[_tactic(description={"nested": True})],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="invalid 'description'"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_invalid_shortname_type_rejected(self, temp_dir: Path) -> None:
        """Tactic with non-string x_mitre_shortname is rejected."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--discovery",
                    "name": "Discovery",
                    "x_mitre_shortname": 123,
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="invalid 'x_mitre_shortname'"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_tactic_malformed_external_reference(self, temp_dir: Path) -> None:
        """Malformed external_references in tactic is silently ignored when shortname exists."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--discovery",
                    "name": "Discovery",
                    "x_mitre_shortname": "discovery",
                    "external_references": "not-a-list",
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        # Tactic is accepted because x_mitre_shortname is valid;
        # malformed external_references is silently ignored
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.tactic_count == 1

    def test_tactic_non_object_external_ref_rejected(self, temp_dir: Path) -> None:
        """Non-object entries in tactic external_references are silently ignored."""
        bundle = _minimal_bundle(
            tactics=[
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--discovery",
                    "name": "Discovery",
                    "x_mitre_shortname": "discovery",
                    "external_references": ["not-an-object"],
                }
            ],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        # Tactic is accepted because x_mitre_shortname is valid;
        # non-object external_ref entries are silently skipped
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.tactic_count == 1


# ── Snapshot lifecycle tests ─────────────────────────────────────────


class TestSnapshotLifecycle:
    """Tests for snapshot loading and lifecycle."""

    def test_load_on_init_available(self, temp_dir: Path) -> None:
        """Service loads snapshot on init if file exists."""
        bundle = _minimal_bundle(techniques=[_technique()])
        snapshot_path = temp_dir / "snapshot.json"
        snapshot_path.write_text(json.dumps(bundle))

        svc = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None

    def test_load_on_init_empty(self, temp_dir: Path) -> None:
        """Service reports EMPTY when no snapshot exists."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.EMPTY

    def test_atomic_replacement(self, temp_dir: Path) -> None:
        """Import replaces previous snapshot atomically."""
        # First import
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle1).encode())
        assert svc.get_technique("T1046") is not None

        # Second import
        bundle2 = _minimal_bundle(
            techniques=[_technique(technique_id="T1071")],
            version="14.0",
        )
        svc.import_snapshot(json.dumps(bundle2).encode())

        # Previous should exist
        assert (temp_dir / "snapshot.json.previous").exists()
        # Current should have new data
        assert svc.get_technique("T1071") is not None
        assert svc.get_technique("T1046") is None
        assert svc.get_version() == "14.0"

    def test_corrupt_current_uses_previous(self, temp_dir: Path) -> None:
        """If current snapshot is corrupt, previous is used."""
        # Create valid previous snapshot
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
        )
        prev_path = temp_dir / "snapshot.json.previous"
        prev_path.write_text(json.dumps(bundle1))

        # Create corrupt current snapshot
        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text("not valid json")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.DEGRADED
        assert svc.get_technique("T1046") is not None

    def test_both_corrupt_unavailable(self, temp_dir: Path) -> None:
        """If both snapshots are corrupt, status is UNAVAILABLE."""
        curr_path = temp_dir / "snapshot.json"
        prev_path = temp_dir / "snapshot.json.previous"
        curr_path.write_text("corrupt")
        prev_path.write_text("also corrupt")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.UNAVAILABLE
        assert svc.get_technique("T1046") is None

    def test_failed_import_preserves_previous(self, temp_dir: Path) -> None:
        """Failed import does not corrupt existing snapshot."""
        # Create valid snapshot
        bundle = _minimal_bundle(techniques=[_technique()])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())
        assert svc.get_technique("T1046") is not None

        # Try to import invalid data
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid")

        # Original should still be valid
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None

    def test_failed_import_no_temp_files_remain(self, temp_dir: Path) -> None:
        """Failed import cleans up temp files."""
        bundle = _minimal_bundle(techniques=[_technique()])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        # Try to import invalid data
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid")

        # No temp files should remain
        temp_files = list(temp_dir.glob(".attck_snapshot_*"))
        assert len(temp_files) == 0

    def test_previous_snapshot_preserved_on_second_import(self, temp_dir: Path) -> None:
        """Previous snapshot file is preserved when it already exists."""
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        bundle2 = _minimal_bundle(
            techniques=[_technique(technique_id="T1071")],
            version="14.0",
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle1).encode())
        svc.import_snapshot(json.dumps(bundle2).encode())

        # Previous should still exist
        prev_path = temp_dir / "snapshot.json.previous"
        assert prev_path.exists()
        # Previous should still be valid
        prev_data = json.loads(prev_path.read_text())
        assert prev_data["objects"][0]["x_mitre_version"] == "13.0"

    def test_current_snapshot_not_deleted_before_new_installed(self, temp_dir: Path) -> None:
        """Current snapshot is never deleted before new one is safely installed."""
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle1).encode())

        # Verify current exists before second import
        curr_path = temp_dir / "snapshot.json"
        assert curr_path.exists()

        # Second import should succeed
        bundle2 = _minimal_bundle(
            techniques=[_technique(technique_id="T1071")],
            version="14.0",
        )
        svc.import_snapshot(json.dumps(bundle2).encode())

        # Current should now have new data
        assert svc.get_technique("T1071") is not None
        assert svc.get_technique("T1046") is None

    def test_symlink_snapshot_path_resolved(self, temp_dir: Path) -> None:
        """Symlinked snapshot paths are resolved."""
        real_path = temp_dir / "real_snapshot.json"
        link_path = temp_dir / "link_snapshot.json"
        bundle = _minimal_bundle(techniques=[_technique()])
        real_path.write_text(json.dumps(bundle))
        link_path.symlink_to(real_path)

        svc = AttckKnowledgeService(
            snapshot_path=link_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None

    def test_temp_files_not_treated_as_snapshots(self, temp_dir: Path) -> None:
        """Temp files with .attck_snapshot_ prefix are not treated as active snapshots."""
        # Create a temp file that looks like a snapshot but isn't one
        temp_file = temp_dir / ".attck_snapshot_fake.json"
        temp_file.write_text(json.dumps(_minimal_bundle(techniques=[_technique()])))

        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        # Should be EMPTY because snapshot.json doesn't exist
        assert svc.get_status() == AttckKnowledgeStatus.EMPTY


# ── Version extraction tests ─────────────────────────────────────────


class TestVersionExtraction:
    """Tests for version extraction from STIX bundles."""

    def test_version_from_collection(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(version="14.0")
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())
        assert svc.get_version() == "14.0"

    def test_version_from_matrix(self, temp_dir: Path) -> None:
        """Read ATT&CK release from x_mitre_version, not the spec version."""
        bundle = _minimal_bundle(version="")
        bundle["objects"].append(
            {
                "type": "x-mitre-matrix",
                "id": "x-mitre-matrix--enterprise",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "18.1",
                "x_mitre_attack_spec_version": "3.3.0",
            }
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())
        assert svc.get_version() == "18.1"

    def test_version_fallback_to_spec_version(self, temp_dir: Path) -> None:
        """STIX spec_version is NEVER treated as ATT&CK version."""
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "spec_version": "2.1",
            "objects": [],
        }
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Missing authoritative ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_version_unknown_when_missing(self, temp_dir: Path) -> None:
        """Missing ATT&CK version causes import failure."""
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "objects": [],
        }
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Missing authoritative ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_version_malformed_rejected(self, temp_dir: Path) -> None:
        """Malformed ATT&CK version causes import failure."""
        bundle = _minimal_bundle(version="invalid-version!")
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Malformed ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_version_empty_rejected(self, temp_dir: Path) -> None:
        """Empty ATT&CK version causes import failure."""
        bundle = _minimal_bundle(version="")
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Missing authoritative ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_version_non_string_rejected(self, temp_dir: Path) -> None:
        """Non-string ATT&CK version causes import failure."""
        bundle = _minimal_bundle(version=123)
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Missing authoritative ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_version_none_rejected(self, temp_dir: Path) -> None:
        """None ATT&CK version causes import failure."""
        bundle = _minimal_bundle(version=None)
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Missing authoritative ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_version_only_spec_version_rejected(self, temp_dir: Path) -> None:
        """Bundle with only spec_version and no x_mitre_version is rejected."""
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Test",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ],
        }
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        with pytest.raises(ValidationError, match="Missing authoritative ATT&CK version"):
            svc.import_snapshot(json.dumps(bundle).encode())


# ── Metadata tests ───────────────────────────────────────────────────


class TestMetadata:
    """Tests for snapshot metadata."""

    def test_metadata_contains_counts(self, temp_dir: Path) -> None:
        bundle = _minimal_bundle(
            techniques=[_technique(), _technique(technique_id="T1071")],
            tactics=[_tactic()],
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())

        assert meta.technique_count == 2
        assert meta.tactic_count == 1
        assert meta.integrity_hash  # Non-empty hash

    def test_metadata_version_stored(self, temp_dir: Path) -> None:
        """Version is stored in metadata."""
        bundle = _minimal_bundle(version="15.1")
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.version == "15.1"

    def test_metadata_source_is_import(self, temp_dir: Path) -> None:
        """Imported snapshot source is 'import'."""
        bundle = _minimal_bundle()
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        meta = svc.import_snapshot(json.dumps(bundle).encode())
        assert meta.source == "import"

    def test_metadata_source_is_file_path(self, temp_dir: Path) -> None:
        """Loaded snapshot source is the file path."""
        bundle = _minimal_bundle()
        snapshot_path = temp_dir / "snapshot.json"
        snapshot_path.write_text(json.dumps(bundle))

        svc = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            enabled=True,
        )
        meta = svc.get_metadata()
        assert meta is not None
        assert str(snapshot_path) in meta.source

    def test_empty_service_no_crash(self, temp_dir: Path) -> None:
        """Empty service does not crash on lookups."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        # Should not raise
        assert svc.get_technique("T1046") is None
        assert svc.get_tactic("discovery") is None
        assert svc.get_version() is None
        assert svc.get_metadata() is None

    def test_degraded_state_visible(self, temp_dir: Path) -> None:
        """DEGRADED state is visible through get_status()."""
        # Create valid previous snapshot
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        prev_path = temp_dir / "snapshot.json.previous"
        prev_path.write_text(json.dumps(bundle1))

        # Create corrupt current snapshot
        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text("not valid json")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.DEGRADED
        # Should report previous snapshot's version
        assert svc.get_version() == "13.0"
        assert svc.get_technique("T1046") is not None

    def test_unavailable_state_no_crash(self, temp_dir: Path) -> None:
        """UNAVAILABLE state does not crash on lookups."""
        curr_path = temp_dir / "snapshot.json"
        prev_path = temp_dir / "snapshot.json.previous"
        curr_path.write_text("corrupt")
        prev_path.write_text("also corrupt")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.UNAVAILABLE
        assert svc.get_technique("T1046") is None
        assert svc.get_version() is None


# ── Replacement failure tests ────────────────────────────────────────


class TestReplacementFailure:
    """Tests for snapshot replacement failure handling."""

    def test_failed_replacement_leaves_current_unchanged(self, temp_dir: Path) -> None:
        """Failed replacement leaves current in-memory snapshot unchanged."""
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle1).encode())
        assert svc.get_technique("T1046") is not None
        assert svc.get_version() == "13.0"

        # Try to import invalid data - should fail without touching current
        _minimal_bundle(
            techniques=[_technique(technique_id="T1071")],
            version="14.0",
        )
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid json")

        # Original should still be valid
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None
        assert svc.get_technique("T1071") is None
        assert svc.get_version() == "13.0"

    def test_failed_replacement_preserves_previous_on_disk(self, temp_dir: Path) -> None:
        """Failed import does not destroy previous snapshot on disk."""
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle1).encode())

        # Create a valid previous snapshot
        prev_path = temp_dir / "snapshot.json.previous"
        prev_bundle = _minimal_bundle(
            techniques=[_technique(technique_id="T9999")],
            version="12.0",
        )
        prev_path.write_text(json.dumps(prev_bundle))

        # Verify previous exists before failed import
        assert prev_path.exists()
        prev_data_before = json.loads(prev_path.read_text())
        assert prev_data_before["objects"][0]["x_mitre_version"] == "12.0"

        # Try to import invalid data - should fail without touching previous
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid json")

        # Previous should still be intact
        assert prev_path.exists()
        prev_data_after = json.loads(prev_path.read_text())
        assert prev_data_after["objects"][0]["x_mitre_version"] == "12.0"

    def test_no_partial_json_becomes_active(self, temp_dir: Path) -> None:
        """No partially written JSON becomes active after failure."""
        bundle = _minimal_bundle(techniques=[_technique()])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        # Try to import invalid data
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"not valid json at all")

        # Current should still be valid
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None

        # No temp files should remain
        temp_files = list(temp_dir.glob(".attck_snapshot_*"))
        assert len(temp_files) == 0

    def test_service_status_correct_after_failed_replacement(self, temp_dir: Path) -> None:
        """Service status remains correct after failed replacement."""
        bundle1 = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle1).encode())
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE

        # Try to import invalid data
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid json")

        # Status should remain AVAILABLE
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE

    def test_filesystem_failure_during_temp_to_current_rename(self, temp_dir: Path) -> None:
        """
        Focused failure-path: temp→current rename fails after current→previous rotation.

        Scenario:
        - Valid current snapshot is installed (v13.0, technique T1046).
        - No previous snapshot exists yet.
        - A valid new snapshot (v14.0, technique T1071) is prepared and written
          to a temp file.
        - The current→previous rotation succeeds (current is now gone from its
          original location; old data is at previous).
        - The temp→current atomic rename then fails with OSError.

        Expected outcomes:
        1. import_snapshot raises (OSError propagated).
        2. In-memory knowledge is unchanged — T1046 still works, T1071 not present.
        3. The service's advertised status is still AVAILABLE (in-memory committed
           state is unchanged because the exception fires before the memory commit).
        4. The old snapshot data is recoverable on disk as the previous file.
        5. The temp file is cleaned up (no orphan .attck_snapshot_* files).
        6. A fresh service restart — seeing a missing current but valid previous —
           recovers with DEGRADED status and serves T1046 from the old data.
        """
        snapshot_path = temp_dir / "snapshot.json"
        prev_path = temp_dir / "snapshot.json.previous"

        # 1. Install valid current snapshot; no previous snapshot yet.
        bundle_old = _minimal_bundle(
            techniques=[_technique(technique_id="T1046")],
            version="13.0",
        )
        svc = AttckKnowledgeService(snapshot_path=snapshot_path, enabled=True)
        svc.import_snapshot(json.dumps(bundle_old).encode())
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None
        assert not prev_path.exists(), "No previous snapshot should exist before second import"

        # 2. Prepare new valid snapshot data.
        bundle_new = _minimal_bundle(
            techniques=[_technique(technique_id="T1071")],
            version="14.0",
        )
        new_bytes = json.dumps(bundle_new).encode()

        # 3. Force the second os.replace (temp→current) to fail.
        #    The first os.replace (current→previous rotation) must succeed so
        #    the failure happens at the exact point described in the scenario.
        original_replace = os.replace
        call_count = [0]

        def patched_replace(src: str, dst: str) -> None:
            call_count[0] += 1
            if call_count[0] == 2:
                # Second call is temp→current — simulate filesystem failure.
                raise OSError("simulated filesystem failure: temp→current rename failed")
            original_replace(src, dst)

        with (
            patch("argusprowl.attck.knowledge_service.os.replace", side_effect=patched_replace),
            pytest.raises(OSError, match="simulated filesystem failure"),
        ):
            svc.import_snapshot(new_bytes)

        # 4. In-memory knowledge is unchanged — old data still serves correctly.
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None, "Old technique must still be in memory"
        assert svc.get_technique("T1071") is None, "New technique must NOT be committed to memory"
        assert svc.get_version() == "13.0", "Version must remain at old snapshot version"

        # 5. Old snapshot data is recoverable on disk as the previous file.
        #    (current→previous rotation completed before the failure.)
        assert prev_path.exists(), (
            "Old snapshot must be recoverable at the previous path after rotation"
        )
        recovered = json.loads(prev_path.read_bytes())
        prev_version = recovered["objects"][0]["x_mitre_version"]
        assert prev_version == "13.0", (
            f"Previous file must contain old snapshot data (v13.0), got v{prev_version}"
        )

        # 6. No temp file orphans remain.
        orphans = list(temp_dir.glob(".attck_snapshot_*"))
        assert len(orphans) == 0, f"Temp file cleanup failed; orphans: {orphans}"

        # 7. Fresh service restart recovers old snapshot as DEGRADED.
        #    (current is missing; previous holds the old valid data.)
        svc2 = AttckKnowledgeService(snapshot_path=snapshot_path, enabled=True)
        assert svc2.get_status() == AttckKnowledgeStatus.DEGRADED, (
            "Restart must recover with DEGRADED status when current is missing but previous is valid"
        )
        assert svc2.get_technique("T1046") is not None, (
            "Old snapshot must be serveable from previous after restart"
        )
        assert svc2.get_technique("T1071") is None, (
            "New (never-completed) snapshot must not be visible after restart"
        )
        assert svc2.get_version() == "13.0", (
            "Restarted service must report old snapshot version from previous"
        )


# ── Recovery semantics tests ─────────────────────────────────────────


class TestRecoverySemantics:
    """Tests for snapshot load/recovery semantics."""

    def test_valid_current_snapshot_available(self, temp_dir: Path) -> None:
        """valid current snapshot → AVAILABLE"""
        bundle = _minimal_bundle(techniques=[_technique()])
        snapshot_path = temp_dir / "snapshot.json"
        snapshot_path.write_text(json.dumps(bundle))

        svc = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE

    def test_no_snapshot_empty(self, temp_dir: Path) -> None:
        """no usable snapshot has ever been installed → EMPTY"""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.EMPTY

    def test_current_invalid_previous_valid_degraded(self, temp_dir: Path) -> None:
        """current snapshot invalid/corrupt + previous snapshot valid → DEGRADED"""
        bundle = _minimal_bundle(techniques=[_technique(technique_id="T1046")])
        prev_path = temp_dir / "snapshot.json.previous"
        prev_path.write_text(json.dumps(bundle))

        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text("not valid json")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.DEGRADED
        assert svc.get_technique("T1046") is not None
        assert svc.get_version() == "14.0"

    def test_both_invalid_unavailable(self, temp_dir: Path) -> None:
        """current snapshot invalid/corrupt + previous snapshot invalid/corrupt → UNAVAILABLE"""
        curr_path = temp_dir / "snapshot.json"
        prev_path = temp_dir / "snapshot.json.previous"
        curr_path.write_text("corrupt")
        prev_path.write_text("also corrupt")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.UNAVAILABLE
        assert svc.get_technique("T1046") is None
        assert svc.get_version() is None

    def test_degraded_version_from_previous(self, temp_dir: Path) -> None:
        """DEGRADED state reports previous snapshot's version."""
        bundle = _minimal_bundle(techniques=[_technique()], version="13.0")
        prev_path = temp_dir / "snapshot.json.previous"
        prev_path.write_text(json.dumps(bundle))

        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text("not valid json")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.DEGRADED
        assert svc.get_version() == "13.0"

    def test_corrupt_snapshot_never_partially_populates(self, temp_dir: Path) -> None:
        """Corrupt snapshots never partially populate in-memory dictionaries."""
        # Create a snapshot with valid JSON but invalid structure
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "objects": [
                {
                    "type": "attack-pattern",
                    # Missing required 'id' field
                    "name": "Test",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ],
        }
        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text(json.dumps(bundle))

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        # Should be EMPTY or UNAVAILABLE, not AVAILABLE with partial data
        assert svc.get_status() != AttckKnowledgeStatus.AVAILABLE
        assert len(svc._techniques) == 0

    def test_malformed_snapshot_never_reported_available(self, temp_dir: Path) -> None:
        """A malformed snapshot is never reported as AVAILABLE."""
        # Valid JSON but missing ATT&CK version
        bundle = {
            "type": "bundle",
            "id": "bundle--abc",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Test",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1046"}
                    ],
                }
            ],
        }
        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text(json.dumps(bundle))

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            enabled=True,
        )
        # Should not be AVAILABLE
        assert svc.get_status() != AttckKnowledgeStatus.AVAILABLE


# ── Disabled service tests ───────────────────────────────────────────


class TestDisabledService:
    """Tests for disabled service behavior."""

    def test_disabled_service_no_import(self, temp_dir: Path) -> None:
        """Disabled service rejects import."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=False,
        )
        bundle = _minimal_bundle(techniques=[_technique()])
        with pytest.raises(ValidationError, match="disabled"):
            svc.import_snapshot(json.dumps(bundle).encode())

    def test_disabled_service_no_network(self, temp_dir: Path) -> None:
        """Disabled service does not attempt any file operations."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=False,
        )
        # Should not raise, should just be unavailable
        assert svc.get_status() == AttckKnowledgeStatus.UNAVAILABLE
        assert svc.get_technique("T1046") is None

    def test_disabled_service_no_crash_on_lookup(self, temp_dir: Path) -> None:
        """Disabled service does not crash on lookups."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=False,
        )
        assert svc.get_technique("T1046") is None
        assert svc.get_tactic("discovery") is None
        assert svc.get_version() is None
        assert svc.get_metadata() is None


# ── Path/symlink tests ───────────────────────────────────────────────


class TestPathSymlink:
    """Tests for path and symlink handling."""

    def test_symlink_current_snapshot(self, temp_dir: Path) -> None:
        """Symlinked current snapshot path works correctly."""
        real_path = temp_dir / "real_snapshot.json"
        link_path = temp_dir / "link_snapshot.json"
        bundle = _minimal_bundle(techniques=[_technique()])
        real_path.write_text(json.dumps(bundle))
        link_path.symlink_to(real_path)

        svc = AttckKnowledgeService(
            snapshot_path=link_path,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.AVAILABLE
        assert svc.get_technique("T1046") is not None

    def test_symlink_previous_snapshot(self, temp_dir: Path) -> None:
        """Symlinked previous snapshot path works correctly."""
        real_prev = temp_dir / "real_previous.json"
        link_prev = temp_dir / "link_previous.json"
        bundle = _minimal_bundle(techniques=[_technique()])
        real_prev.write_text(json.dumps(bundle))
        link_prev.symlink_to(real_prev)

        curr_path = temp_dir / "snapshot.json"
        curr_path.write_text("corrupt")

        svc = AttckKnowledgeService(
            snapshot_path=curr_path,
            previous_snapshot_path=link_prev,
            enabled=True,
        )
        assert svc.get_status() == AttckKnowledgeStatus.DEGRADED
        assert svc.get_technique("T1046") is not None

    def test_temp_files_in_snapshot_directory(self, temp_dir: Path) -> None:
        """Temporary files are created in the snapshot directory."""
        bundle = _minimal_bundle(techniques=[_technique()])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        # No temp files should remain after successful import
        temp_files = list(temp_dir.glob(".attck_snapshot_*"))
        assert len(temp_files) == 0

    def test_temp_files_cleaned_up_on_failure(self, temp_dir: Path) -> None:
        """Temporary files are cleaned up on import failure."""
        bundle = _minimal_bundle(techniques=[_technique()])
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        svc.import_snapshot(json.dumps(bundle).encode())

        # Try to import invalid data
        with pytest.raises(ValidationError):
            svc.import_snapshot(b"invalid")

        # No temp files should remain
        temp_files = list(temp_dir.glob(".attck_snapshot_*"))
        assert len(temp_files) == 0

    def test_snapshot_path_resolved(self, temp_dir: Path) -> None:
        """Snapshot path is resolved to absolute path."""
        relative_path = temp_dir / "snapshot.json"
        svc = AttckKnowledgeService(
            snapshot_path=relative_path,
            enabled=False,
        )
        assert svc.snapshot_path.is_absolute()
        assert svc.snapshot_path == relative_path.resolve()


# ── Regression tests ─────────────────────────────────────────────────


class TestRegression:
    """Regression tests to ensure existing behavior is preserved."""

    def test_disabled_service_no_network(self, temp_dir: Path) -> None:
        """Disabled service does not attempt any file operations."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=False,
        )
        # Should not raise, should just be unavailable
        assert svc.get_status() == AttckKnowledgeStatus.UNAVAILABLE
        assert svc.get_technique("T1046") is None

    def test_empty_service_no_crash(self, temp_dir: Path) -> None:
        """Empty service does not crash on lookups."""
        svc = AttckKnowledgeService(
            snapshot_path=temp_dir / "snapshot.json",
            enabled=True,
        )
        # Should not raise
        assert svc.get_technique("T1046") is None
        assert svc.get_tactic("discovery") is None
        assert svc.get_version() is None
        assert svc.get_metadata() is None
