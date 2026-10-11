"""Focused tests for the Phase 6.2 approved ATT&CK mapping registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from argusprowl.attck.mapping_registry import AttckMappingRegistry, MappingType
from argusprowl.attck.models import AttckTechnique
from argusprowl.constants.attck import AttckKnowledgeStatus
from argusprowl.exceptions.exceptions import ValidationError


class FakeKnowledgeService:
    """Small CP6.1-compatible knowledge service test double."""

    def __init__(
        self,
        techniques: dict[str, AttckTechnique],
        *,
        enabled: bool = True,
        status=AttckKnowledgeStatus.AVAILABLE,
    ):
        self._techniques = techniques
        self.is_enabled = enabled
        self._status = status

    def get_status(self):
        return self._status

    def get_technique(self, technique_id: str):
        return self._techniques.get(technique_id)


def _knowledge(*ids: str) -> FakeKnowledgeService:
    return FakeKnowledgeService(
        {
            technique_id: AttckTechnique(
                technique_id=technique_id, name=f"Technique {technique_id}"
            )
            for technique_id in ids
        }
    )


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_all_approved_cp31_mappings_are_present() -> None:
    knowledge = _knowledge("T1046", "T1498", "T1110", "T1071", "T1041")
    registry = AttckMappingRegistry(knowledge)

    assert len(registry.get_all()) == 11
    assert [(m.rule_id, m.technique_id, m.mapping_type.value) for m in registry.get_all()] == [
        ("beaconing_detector", "T1071", "SUPPORTED"),
        ("connection_flood", "T1498", "DIRECT"),
        ("event_count_correlation", "T1110", "SUPPORTED"),
        ("failed_connections", "T1110", "SUPPORTED"),
        ("horizontal_scan", "T1046", "DIRECT"),
        ("long_connection", "T1041", "SUPPORTED"),
        ("long_connection", "T1071", "SUPPORTED"),
        ("port_scan", "T1046", "DIRECT"),
        ("syn_scan", "T1046", "SUPPORTED"),
        ("syn_scan", "T1498", "SUPPORTED"),
        ("vertical_scan", "T1046", "DIRECT"),
    ]


def test_lookup_is_deterministic_and_bounded() -> None:
    registry = AttckMappingRegistry(_knowledge("T1046", "T1498", "T1110", "T1071", "T1041"))
    first = registry.get_for_rule("long_connection")
    second = registry.get_for_rule("long_connection")
    assert first == second
    assert len(first) == 2
    assert isinstance(registry.get_all(), tuple)


def test_mapping_types_have_exact_semantics() -> None:
    assert MappingType.DIRECT.value == "DIRECT"
    assert MappingType.SUPPORTED.value == "SUPPORTED"
    assert MappingType.CONTEXTUAL.value == "CONTEXTUAL"
    assert MappingType.NONE.value == "NONE"


def test_contextual_and_none_are_accepted(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: contextual_rule\n    technique_id: T1046\n    mapping_type: CONTEXTUAL\n  - rule_id: no_mapping_rule\n    technique_id: T1046\n    mapping_type: NONE\n""",
    )
    registry = AttckMappingRegistry(_knowledge("T1046"), path)
    assert [m.mapping_type for m in registry.get_all()] == [
        MappingType.CONTEXTUAL,
        MappingType.NONE,
    ]


def test_unknown_technique_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T9999\n    mapping_type: DIRECT\n""",
    )
    with pytest.raises(ValidationError, match="Unknown ATT&CK technique_id"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_unknown_subtechnique_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    subtechnique_id: T1046.999\n    mapping_type: DIRECT\n""",
    )
    with pytest.raises(ValidationError, match="Unknown ATT&CK subtechnique_id"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_subtechnique_parent_relationship_is_validated(tmp_path: Path) -> None:
    techniques = {
        "T1046": AttckTechnique("T1046", "Parent"),
        "T1046.001": AttckTechnique("T1046.001", "Child", parent_technique_id="T1498"),
        "T1498": AttckTechnique("T1498", "Other Parent"),
    }
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    subtechnique_id: T1046.001\n    mapping_type: DIRECT\n""",
    )
    with pytest.raises(ValidationError, match="does not belong"):
        AttckMappingRegistry(FakeKnowledgeService(techniques), path)


def test_duplicate_mapping_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    mapping_type: DIRECT\n  - rule_id: test_rule\n    technique_id: T1046\n    mapping_type: DIRECT\n""",
    )
    with pytest.raises(ValidationError, match="Duplicate ATT&CK mapping"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_invalid_mapping_type_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    mapping_type: CONFIDENT\n""",
    )
    with pytest.raises(ValidationError, match="Invalid ATT&CK mapping type"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_malformed_yaml_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path / "mappings.yaml", "mappings: [\n  - rule_id: broken\n")
    with pytest.raises(ValidationError, match="Malformed"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_unsafe_yaml_construct_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        "mappings: !!python/object/apply:os.system ['echo unsafe']\n",
    )
    with pytest.raises(ValidationError):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_invalid_rule_id_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: "bad rule id"\n    technique_id: T1046\n    mapping_type: DIRECT\n""",
    )
    with pytest.raises(ValidationError, match="Invalid rule_id"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_unknown_fields_are_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    mapping_type: DIRECT\n    confidence: 1.0\n""",
    )
    with pytest.raises(ValidationError, match="unknown fields"):
        AttckMappingRegistry(_knowledge("T1046"), path)


def test_knowledge_service_unavailable_fails_closed(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    mapping_type: DIRECT\n""",
    )
    knowledge = FakeKnowledgeService({}, status=AttckKnowledgeStatus.UNAVAILABLE)
    with pytest.raises(ValidationError, match="unavailable"):
        AttckMappingRegistry(knowledge, path)


def test_disabled_knowledge_service_does_not_create_authority(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mappings.yaml",
        """mappings:\n  - rule_id: test_rule\n    technique_id: T1046\n    mapping_type: DIRECT\n""",
    )
    with pytest.raises(ValidationError, match="disabled"):
        AttckMappingRegistry(
            FakeKnowledgeService({"T1046": AttckTechnique("T1046", "T")}, enabled=False), path
        )


def test_rule_metadata_is_not_an_authoritative_source(tmp_path: Path) -> None:
    path = _write(tmp_path / "mappings.yaml", "mappings: []\n")
    registry = AttckMappingRegistry(_knowledge("T1046"), path)
    assert registry.get_for_rule("port_scan") == ()
    assert registry.get_all() == ()


def test_rejected_cp31_mappings_remain_absent() -> None:
    registry = AttckMappingRegistry(_knowledge("T1046", "T1498", "T1110", "T1071", "T1041"))
    rejected = {
        ("first_seen_host_process", "T1057"),
        ("first_seen_src_dst", "T1046"),
        ("first_seen_src_dst", "T1041"),
        ("connection_flood", "T1499"),
    }
    actual = {(m.rule_id, m.technique_id) for m in registry.get_all()}
    assert rejected.isdisjoint(actual)


def test_conditional_mapping_is_preserved() -> None:
    registry = AttckMappingRegistry(_knowledge("T1046", "T1498", "T1110", "T1071", "T1041"))
    mappings = registry.get_for_rule("event_count_correlation")
    assert len(mappings) == 1
    mapping = mappings[0]
    assert mapping.technique_id == "T1110"
    assert mapping.condition == "authentication-context"
    assert mapping.rationale is not None
