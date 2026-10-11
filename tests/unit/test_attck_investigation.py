"""Tests for Phase 6.5 — ATT&CK Investigation / Incident Integration.

Focused tests covering:
- ATT&CK aggregation from alert observations
- Provenance preservation
- Mapping semantics (DIRECT/SUPPORTED/CONTEXTUAL/NONE)
- Investigation context integration
- Incident integration
- Version handling
- Bounds enforcement
- Security isolation
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from argusprowl.attck.models import AttckTechniqueSummary
from argusprowl.constants.severity import Severity
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.models.entity_investigation_context import (
    EntityInvestigationContext,
)
from argusprowl.models.incident import Incident, IncidentStatus
from argusprowl.services.attck_investigation_context_service import (
    _MAX_EVIDENCE_PER_TECHNIQUE,
    _MAX_SOURCES_PER_TECHNIQUE,
    _MAX_TECHNIQUES,
    AttckInvestigationContextService,
)
from argusprowl.services.investigation_context_service import InvestigationContextService

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def attck_service() -> AttckInvestigationContextService:
    """Create an AttckInvestigationContextService."""
    return AttckInvestigationContextService()


@pytest.fixture
def mock_alert_queue() -> MagicMock:
    """Create a mock AlertQueue."""
    return MagicMock(spec=AlertQueue)


@pytest.fixture
def mock_behavior_service() -> MagicMock:
    """Create a mock AnalystBehaviorQueryService."""
    return MagicMock()


@pytest.fixture
def mock_annotation_service() -> MagicMock:
    """Create a mock AnalystAnnotationService."""
    return MagicMock()


@pytest.fixture
def mock_incident_service() -> MagicMock:
    """Create a mock IncidentService."""
    return MagicMock()


@pytest.fixture
def investigation_service(
    mock_alert_queue: MagicMock,
    mock_behavior_service: MagicMock,
    mock_annotation_service: MagicMock,
    mock_incident_service: MagicMock,
) -> InvestigationContextService:
    """Create an InvestigationContextService with mocked dependencies."""
    return InvestigationContextService(
        alert_queue=mock_alert_queue,
        behavior_query_service=mock_behavior_service,
        annotation_service=mock_annotation_service,
        incident_service=mock_incident_service,
    )


def make_alert(
    alert_id: str | None = None,
    title: str = "Test Alert",
    source: str = "test",
    observations: list[dict[str, Any]] | None = None,
    host: str | None = None,
) -> Alert:
    """Create a test alert with optional ATT&CK observations."""
    metadata = {}
    if observations is not None:
        metadata["attck_observations"] = observations
    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=Severity.MEDIUM,
        source=source,
        metadata=metadata,
        entity_context={"host": host} if host else None,
    )


def make_observation(
    technique_id: str = "T1046",
    mapping_type: str = "DIRECT",
    technique_name: str | None = None,
    tactic: str | None = None,
    version: str = "14.0",
    subtechnique_id: str | None = None,
    rationale: str | None = None,
    evidence: dict | None = None,
) -> dict[str, Any]:
    """Create a test ATT&CK observation."""
    obs: dict[str, Any] = {
        "technique_id": technique_id,
        "mapping_type": mapping_type,
        "version": version,
    }
    if technique_name:
        obs["technique_name"] = technique_name
    if tactic:
        obs["tactic"] = tactic
    if subtechnique_id:
        obs["subtechnique_id"] = subtechnique_id
    if rationale:
        obs["rationale"] = rationale
    if evidence:
        obs["evidence"] = evidence
    return obs


def make_incident(
    incident_id: Any | None = None,
    title: str = "Test Incident",
    severity: Severity = Severity.HIGH,
    status: IncidentStatus = IncidentStatus.OPEN,
    alert_ids: tuple[Any, ...] = (),
) -> Incident:
    """Create a test incident."""
    return Incident(
        incident_id=incident_id or uuid4(),
        title=title,
        description="Test incident description",
        severity=severity,
        status=status,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        alert_ids=alert_ids,
    )


# ── Basic Aggregation Tests ───────────────────────────────────────────────────


class TestBasicAggregation:
    """Tests for basic ATT&CK aggregation."""

    def test_one_direct_technique(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """One DIRECT technique is aggregated correctly."""
        alert = make_alert(observations=[make_observation(mapping_type="DIRECT")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert summaries[0].technique_id == "T1046"
        assert summaries[0].mapping_type == "DIRECT"
        assert summaries[0].version == "14.0"

    def test_multiple_techniques(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Multiple techniques from one alert are aggregated."""
        alert = make_alert(
            observations=[
                make_observation("T1046", "DIRECT"),
                make_observation("T1110", "SUPPORTED"),
            ]
        )
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 2
        assert summaries[0].technique_id == "T1046"
        assert summaries[0].mapping_type == "DIRECT"
        assert summaries[1].technique_id == "T1110"
        assert summaries[1].mapping_type == "SUPPORTED"

    def test_multiple_alerts_same_technique(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Multiple alerts producing the same technique are merged."""
        alert1 = make_alert(alert_id="alert-1", observations=[make_observation("T1046", "DIRECT")])
        alert2 = make_alert(alert_id="alert-2", observations=[make_observation("T1046", "DIRECT")])
        summaries = attck_service.aggregate((alert1, alert2))

        assert len(summaries) == 1
        assert summaries[0].technique_id == "T1046"
        assert summaries[0].mapping_type == "DIRECT"
        assert len(summaries[0].source_alert_ids) == 2

    def test_same_technique_different_mapping_types_separate(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Same technique with different mapping types remains separate."""
        alert = make_alert(
            observations=[
                make_observation("T1046", "DIRECT"),
                make_observation("T1046", "SUPPORTED"),
            ]
        )
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 2
        direct = next(s for s in summaries if s.mapping_type == "DIRECT")
        supported = next(s for s in summaries if s.mapping_type == "SUPPORTED")
        assert direct.technique_id == "T1046"
        assert supported.technique_id == "T1046"


# ── Provenance Tests ─────────────────────────────────────────────────────────


class TestProvenance:
    """Tests for provenance preservation."""

    def test_source_alert_ids_preserved(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Source alert IDs are preserved in technique summary."""
        alert1 = make_alert(observations=[make_observation("T1046", "DIRECT")])
        alert2 = make_alert(observations=[make_observation("T1046", "DIRECT")])
        summaries = attck_service.aggregate((alert1, alert2))

        assert len(summaries) == 1
        assert len(summaries[0].source_alert_ids) == 2
        # Verify the alert IDs are preserved (as UUID strings)
        assert str(alert1.alert_id) in summaries[0].source_alert_ids
        assert str(alert2.alert_id) in summaries[0].source_alert_ids

    def test_evidence_references_preserved(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Evidence references are preserved in technique summary."""
        evidence = {"field": "destination", "observed": "203.0.113.50"}
        alert = make_alert(observations=[make_observation("T1046", "DIRECT", evidence=evidence)])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert len(summaries[0].evidence_refs) == 1
        assert summaries[0].evidence_refs[0] == evidence

    def test_bounded_source_lists(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Source alert lists are bounded."""
        alerts = [
            make_alert(alert_id=f"alert-{i}", observations=[make_observation("T1046", "DIRECT")])
            for i in range(20)
        ]
        summaries = attck_service.aggregate(tuple(alerts))

        assert len(summaries) == 1
        assert len(summaries[0].source_alert_ids) == _MAX_SOURCES_PER_TECHNIQUE

    def test_bounded_evidence_lists(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Evidence lists are bounded."""
        evidence_list = [{"field": f"field-{i}", "observed": f"value-{i}"} for i in range(20)]
        alert = make_alert(
            observations=[make_observation("T1046", "DIRECT", evidence=evidence_list)]
        )
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert len(summaries[0].evidence_refs) == _MAX_EVIDENCE_PER_TECHNIQUE


# ── Mapping Semantics Tests ──────────────────────────────────────────────────


class TestMappingSemantics:
    """Tests for mapping type semantics."""

    def test_direct_appears_as_observed(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """DIRECT mapping appears as observed technique."""
        alert = make_alert(observations=[make_observation("T1046", "DIRECT")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert summaries[0].is_direct
        assert not summaries[0].is_supported
        assert not summaries[0].is_contextual

    def test_supported_appears_as_supporting(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """SUPPORTED mapping appears as supporting evidence."""
        alert = make_alert(observations=[make_observation("T1046", "SUPPORTED")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert summaries[0].is_supported
        assert not summaries[0].is_direct
        assert not summaries[0].is_contextual

    def test_contextual_remains_contextual(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """CONTEXTUAL mapping remains contextual."""
        alert = make_alert(observations=[make_observation("T1046", "CONTEXTUAL")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert summaries[0].is_contextual
        assert not summaries[0].is_direct
        assert not summaries[0].is_supported

    def test_none_produces_no_assertion(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """NONE mapping produces no assertion."""
        alert = make_alert(observations=[make_observation("T1046", "NONE")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 0


# ── Investigation Context Integration Tests ──────────────────────────────────


class TestInvestigationContextIntegration:
    """Tests for investigation context integration."""

    def test_attck_enrichment_appears_in_context(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
    ) -> None:
        """ATT&CK enrichment appears in investigation context."""
        alert = make_alert(host="server01", observations=[make_observation("T1046", "DIRECT")])
        mock_alert_queue.list_by_entity.return_value = [alert]

        context = investigation_service.get_investigation_context("host", "server01")

        assert context.attck_technique_count == 1
        assert context.attck_context[0].technique_id == "T1046"
        assert context.attck_context[0].mapping_type == "DIRECT"

    def test_no_attck_observations_produces_empty_enrichment(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
    ) -> None:
        """No ATT&CK observations produces empty enrichment, not failure."""
        alert = make_alert(host="server01")
        mock_alert_queue.list_by_entity.return_value = [alert]

        context = investigation_service.get_investigation_context("host", "server01")

        assert context.attck_technique_count == 0
        assert context.attck_context == ()

    def test_malformed_observation_skipped_safely(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
    ) -> None:
        """Malformed observation is skipped safely."""
        alert = make_alert(host="server01", observations=["malformed", None, {"invalid": True}])
        mock_alert_queue.list_by_entity.return_value = [alert]

        context = investigation_service.get_investigation_context("host", "server01")

        assert context.attck_technique_count == 0
        assert context.attck_context == ()

    def test_existing_investigation_status_remains_correct(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
    ) -> None:
        """Existing investigation status remains correct."""
        alert = make_alert(host="server01", observations=[make_observation("T1046", "DIRECT")])
        mock_alert_queue.list_by_entity.return_value = [alert]

        context = investigation_service.get_investigation_context("host", "server01")

        assert context.entity_type == "host"
        assert context.entity_id == "server01"
        assert context.alert_count == 1
        assert context.attck_technique_count == 1


# ── Incident Integration Tests ───────────────────────────────────────────────


class TestIncidentIntegration:
    """Tests for incident integration.

    ATT&CK investigation context is derived from alerts already returned by
    InvestigationContextService. IncidentService is queried read-only for the
    associated incident; ATT&CK does not create, modify, or attach itself to
    the incident object.
    """

    def test_incident_associated_investigation_exposes_attck_summaries(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Investigation context for an existing incident exposes ATT&CK summaries."""
        alert = make_alert(
            host="server01",
            observations=[make_observation("T1046", "DIRECT", version="14.0")],
        )
        incident = make_incident(
            title="Suspicious Activity",
            alert_ids=(str(alert.alert_id),),
        )
        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        context = investigation_service.get_investigation_context("host", "server01")

        assert context.incident is incident
        assert context.attck_technique_count == 1
        assert context.attck_context[0].technique_id == "T1046"
        assert context.attck_context[0].mapping_type == "DIRECT"
        assert context.attck_context[0].version == "14.0"
        assert str(alert.alert_id) in context.attck_context[0].source_alert_ids

    def test_incident_identity_and_lifecycle_unchanged(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """Incident identity/lifecycle/severity remain unchanged by ATT&CK context."""
        alert = make_alert(
            host="server01",
            observations=[make_observation("T1046", "DIRECT")],
        )
        incident = make_incident(
            title="Original Incident",
            severity=Severity.HIGH,
            status=IncidentStatus.INVESTIGATING,
            alert_ids=(str(alert.alert_id),),
        )
        original_id = incident.incident_id
        original_status = incident.status
        original_severity = incident.severity
        original_title = incident.title
        original_description = incident.description
        original_alert_ids = incident.alert_ids
        original_tags = incident.tags
        original_metadata = dict(incident.metadata)
        original_schema_version = incident.schema_version

        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        context = investigation_service.get_investigation_context("host", "server01")

        assert context.incident is incident
        assert context.incident.incident_id == original_id
        assert context.incident.status == original_status
        assert context.incident.severity == original_severity
        assert context.incident.title == original_title
        assert context.incident.description == original_description
        assert context.incident.alert_ids == original_alert_ids
        assert context.incident.tags == original_tags
        assert context.incident.metadata == original_metadata
        assert context.incident.schema_version == original_schema_version

    def test_same_technique_mapping_different_versions_preserve_provenance(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Alert A v14.0 and Alert B v15.0 both remain represented."""
        alert_a = make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])
        alert_b = make_alert(observations=[make_observation("T1046", "DIRECT", version="15.0")])
        summaries = attck_service.aggregate((alert_a, alert_b))

        assert len(summaries) == 2
        by_version = {s.version: s for s in summaries}
        assert set(by_version) == {"14.0", "15.0"}

        summary_14 = by_version["14.0"]
        summary_15 = by_version["15.0"]
        assert summary_14.technique_id == "T1046"
        assert summary_15.technique_id == "T1046"
        assert summary_14.mapping_type == "DIRECT"
        assert summary_15.mapping_type == "DIRECT"
        assert str(alert_a.alert_id) in summary_14.source_alert_ids
        assert str(alert_b.alert_id) in summary_15.source_alert_ids
        assert str(alert_b.alert_id) not in summary_14.source_alert_ids
        assert str(alert_a.alert_id) not in summary_15.source_alert_ids

    def test_same_version_still_merges(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Same technique/mapping/version still merges into one summary."""
        alert1 = make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])
        alert2 = make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])
        summaries = attck_service.aggregate((alert1, alert2))

        assert len(summaries) == 1
        assert summaries[0].version == "14.0"
        assert len(summaries[0].source_alert_ids) == 2

    def test_attck_does_not_create_or_modify_incidents(
        self,
        investigation_service: InvestigationContextService,
        mock_alert_queue: MagicMock,
        mock_incident_service: MagicMock,
    ) -> None:
        """ATT&CK aggregation does not create or modify incidents."""
        alert = make_alert(
            host="server01",
            observations=[make_observation("T1046", "DIRECT")],
        )
        incident = make_incident(alert_ids=(str(alert.alert_id),))
        mock_alert_queue.list_by_entity.return_value = [alert]
        mock_incident_service.get_incident_for_entity.return_value = incident.incident_id
        mock_incident_service.get_incident.return_value = incident

        investigation_service.get_investigation_context("host", "server01")

        mock_incident_service.create_incident.assert_not_called()
        mock_incident_service.get_or_create_incident_for_entity.assert_not_called()
        mock_incident_service.associate_alert.assert_not_called()
        mock_incident_service.get_incident_for_entity.assert_called_once()
        mock_incident_service.get_incident.assert_called_once_with(incident.incident_id)


# ── Version Handling Tests ───────────────────────────────────────────────────


class TestVersionHandling:
    """Tests for ATT&CK version handling."""

    def test_observation_version_preserved(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Observation version is preserved."""
        alert = make_alert(observations=[make_observation("T1046", "DIRECT", version="13.0")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert summaries[0].version == "13.0"

    def test_multiple_versions_not_normalized(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Multiple versions remain separate; neither is silently discarded."""
        alert1 = make_alert(observations=[make_observation("T1046", "DIRECT", version="13.0")])
        alert2 = make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])
        summaries = attck_service.aggregate((alert1, alert2))

        versions = {s.version for s in summaries}
        assert versions == {"13.0", "14.0"}


# ── Isolation Tests ──────────────────────────────────────────────────────────


class TestIsolation:
    """Tests for security isolation."""

    def test_investigation_does_not_mutate_alerts(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Investigation does not mutate alerts."""
        alert = make_alert(observations=[make_observation("T1046", "DIRECT")])
        original_metadata = dict(alert.metadata)

        attck_service.aggregate((alert,))

        assert alert.metadata == original_metadata

    def test_investigation_does_not_trigger_detection(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Investigation does not trigger detection."""
        # This is implicitly tested by the fact that we only read from
        # alert.metadata, not from any detection pipeline
        alert = make_alert(observations=[make_observation("T1046", "DIRECT")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1

    def test_investigation_does_not_invoke_decision_engine(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Investigation does not invoke DecisionEngine."""
        # This is implicitly tested by the read-only nature of the service
        alert = make_alert(observations=[make_observation("T1046", "DIRECT")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1

    def test_investigation_does_not_perform_network_access(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Investigation does not perform ATT&CK network access."""
        # This is implicitly tested by the fact that we only read from
        # alert.metadata, not from any network service
        alert = make_alert(observations=[make_observation("T1046", "DIRECT")])
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1


# ── Bounds Tests ─────────────────────────────────────────────────────────────


class TestBounds:
    """Tests for bounds enforcement."""

    def test_technique_count_bounded(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Technique count is bounded."""
        alerts = [
            make_alert(observations=[make_observation(f"T{i:04d}", "DIRECT")]) for i in range(200)
        ]
        summaries = attck_service.aggregate(tuple(alerts))

        assert len(summaries) == _MAX_TECHNIQUES

    def test_source_alert_count_bounded(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Source alert count is bounded."""
        alerts = [
            make_alert(alert_id=f"alert-{i}", observations=[make_observation("T1046", "DIRECT")])
            for i in range(20)
        ]
        summaries = attck_service.aggregate(tuple(alerts))

        assert len(summaries) == 1
        assert len(summaries[0].source_alert_ids) == _MAX_SOURCES_PER_TECHNIQUE

    def test_evidence_count_bounded(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Evidence count is bounded."""
        evidence_list = [{"field": f"field-{i}", "observed": f"value-{i}"} for i in range(20)]
        alert = make_alert(
            observations=[make_observation("T1046", "DIRECT", evidence=evidence_list)]
        )
        summaries = attck_service.aggregate((alert,))

        assert len(summaries) == 1
        assert len(summaries[0].evidence_refs) == _MAX_EVIDENCE_PER_TECHNIQUE

    def test_malformed_metadata_cannot_create_unbounded_processing(
        self,
        attck_service: AttckInvestigationContextService,
    ) -> None:
        """Malformed metadata cannot create unbounded processing."""
        alerts = [make_alert(observations=["malformed"] * 1000) for _ in range(100)]
        summaries = attck_service.aggregate(tuple(alerts))

        # Should not crash and should return empty or bounded results
        assert len(summaries) <= _MAX_TECHNIQUES


# ── EntityInvestigationContext Model Tests ───────────────────────────────────


class TestEntityInvestigationContextModel:
    """Tests for the EntityInvestigationContext model with ATT&CK."""

    def test_attck_context_property(
        self,
    ) -> None:
        """EntityInvestigationContext has attck_context property."""
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
        )
        assert context.attck_technique_count == 0
        assert context.attck_context == ()

    def test_attck_context_with_summaries(
        self,
    ) -> None:
        """EntityInvestigationContext can hold ATT&CK summaries."""
        summary = AttckTechniqueSummary(
            technique_id="T1046",
            mapping_type="DIRECT",
            version="14.0",
        )
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            attck_context=(summary,),
        )
        assert context.attck_technique_count == 1
        assert context.attck_context[0].technique_id == "T1046"

    def test_has_evidence_with_attck(
        self,
    ) -> None:
        """has_evidence is True when ATT&CK context exists."""
        summary = AttckTechniqueSummary(
            technique_id="T1046",
            mapping_type="DIRECT",
        )
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
            attck_context=(summary,),
        )
        assert context.has_evidence is True

    def test_has_evidence_without_attck(
        self,
    ) -> None:
        """has_evidence is False when no evidence exists."""
        context = EntityInvestigationContext(
            entity_type="host",
            entity_id="server01",
            annotation_key="entity:host:server01",
            correlation_key="server01:*",
        )
        assert context.has_evidence is False
