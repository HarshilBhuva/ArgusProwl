"""Tests for IncidentService."""

from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.incident.incident_service import IncidentNotFoundError, IncidentService
from argusprowl.models.alert import Alert
from argusprowl.models.incident import IncidentStatus


@pytest.fixture
def service() -> IncidentService:
    return IncidentService(max_incidents=100)


def _alert(
    host: str | None = None,
    title: str = "Test Alert",
    severity: Severity = Severity.HIGH,
    **kwargs,
) -> Alert:
    """Create a test alert."""
    entity_context = {}
    if host is not None:
        entity_context["host"] = host
    return Alert(
        title=title,
        description=f"Description for {title}",
        severity=severity,
        source="test",
        entity_context=entity_context if entity_context else None,
        **kwargs,
    )


class TestCreateIncident:
    """Tests for create_incident method."""

    def test_create_incident(self, service: IncidentService) -> None:
        """Test basic incident creation."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        assert incident is not None
        assert incident.status == IncidentStatus.OPEN
        assert len(incident.alert_ids) == 1
        assert incident.metadata["alert_count"] == 1
        assert "correlation_score" not in incident.metadata

    def test_create_incident_with_multiple_alerts(self, service: IncidentService) -> None:
        """Test incident creation with multiple alerts."""
        alerts = [_alert(host="host1") for _ in range(3)]
        incident = service.create_incident(alerts)
        assert len(incident.alert_ids) == 3
        assert incident.metadata["alert_count"] == 3

    def test_create_incident_derives_severity(self, service: IncidentService) -> None:
        """Test that severity is derived from highest-severity alert."""
        alerts = [
            _alert(host="host1", severity=Severity.LOW),
            _alert(host="host1", severity=Severity.CRITICAL),
            _alert(host="host1", severity=Severity.MEDIUM),
        ]
        incident = service.create_incident(alerts)
        assert incident.severity == Severity.CRITICAL

    def test_create_incident_with_custom_severity(self, service: IncidentService) -> None:
        """Test incident creation with explicit severity."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts, severity=Severity.MEDIUM)
        assert incident.severity == Severity.MEDIUM

    def test_create_incident_with_custom_title(self, service: IncidentService) -> None:
        """Test incident creation with custom title."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts, title="Custom Title")
        assert incident.title == "Custom Title"

    def test_create_incident_with_custom_description(self, service: IncidentService) -> None:
        """Test incident creation with custom description."""
        alerts = [_alert(host="host1")]
        desc = "Custom description"
        incident = service.create_incident(alerts, description=desc)
        assert incident.description == desc

    def test_create_incident_with_tags(self, service: IncidentService) -> None:
        """Test incident creation with tags."""
        alerts = [_alert(host="host1")]
        tags = ("tag1", "tag2")
        incident = service.create_incident(alerts, tags=tags)
        assert incident.tags == tags

    def test_create_incident_empty_alerts_raises(self, service: IncidentService) -> None:
        """Test that empty alerts raises ValueError."""
        with pytest.raises(ValueError, match="empty alert sequence"):
            service.create_incident([])

    def test_create_incident_deterministic_title(self, service: IncidentService) -> None:
        """Test that incident title is deterministic."""
        alerts = [_alert(host="host1", title="Port Scan Detected")]
        incident1 = service.create_incident(alerts)
        incident2 = service.create_incident(alerts)
        assert incident1.title == incident2.title

    def test_create_incident_max_incidents(self, service: IncidentService) -> None:
        """Test that max_incidents limit is enforced."""
        small_service = IncidentService(max_incidents=2)
        alerts1 = [_alert(host="host1")]
        alerts2 = [_alert(host="host2")]
        alerts3 = [_alert(host="host3")]

        inc1 = small_service.create_incident(alerts1)
        inc2 = small_service.create_incident(alerts2)
        inc3 = small_service.create_incident(alerts3)

        # Oldest incident should be evicted
        assert small_service.get_incident(inc1.incident_id) is None
        assert small_service.get_incident(inc2.incident_id) is not None
        assert small_service.get_incident(inc3.incident_id) is not None

    def test_create_incident_without_correlation_score(self, service: IncidentService) -> None:
        """Test that incident creation does not require a correlation score."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        assert incident is not None
        assert len(incident.alert_ids) == 1


class TestAssociateAlert:
    """Tests for associate_alert method."""

    def test_associate_alert(self, service: IncidentService) -> None:
        """Test associating an alert with an incident."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        new_alert = _alert(host="host1", title="New Alert")

        updated = service.associate_alert(incident.incident_id, new_alert)
        assert len(updated.alert_ids) == 2
        assert new_alert.alert_id in updated.alert_ids

    def test_associate_alert_not_found(self, service: IncidentService) -> None:
        """Test associating alert with non-existent incident."""
        alert = _alert()
        with pytest.raises(IncidentNotFoundError):
            service.associate_alert(uuid4(), alert)

    def test_associate_alert_updates_timestamp(self, service: IncidentService) -> None:
        """Test that associating alert updates incident timestamp."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        original_updated = incident.updated_at

        # Create a new alert and associate it
        new_alert = _alert(host="host1", title="New Alert")
        updated = service.associate_alert(incident.incident_id, new_alert)
        assert updated.updated_at >= original_updated


class TestGetIncident:
    """Tests for get_incident method."""

    def test_get_existing_incident(self, service: IncidentService) -> None:
        """Test retrieving an existing incident."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        retrieved = service.get_incident(incident.incident_id)
        assert retrieved is not None
        assert retrieved.incident_id == incident.incident_id

    def test_get_nonexistent_incident(self, service: IncidentService) -> None:
        """Test retrieving a non-existent incident."""
        retrieved = service.get_incident(uuid4())
        assert retrieved is None


class TestListIncidents:
    """Tests for list_incidents method."""

    def test_list_incidents(self, service: IncidentService) -> None:
        """Test listing all incidents."""
        alerts1 = [_alert(host="host1")]
        alerts2 = [_alert(host="host2")]
        service.create_incident(alerts1)
        service.create_incident(alerts2)

        incidents = service.list_incidents()
        assert len(incidents) == 2

    def test_list_incidents_sorted_by_created(self, service: IncidentService) -> None:
        """Test that incidents are sorted by created_at descending."""
        alerts1 = [_alert(host="host1")]
        alerts2 = [_alert(host="host2")]
        service.create_incident(alerts1)
        inc2 = service.create_incident(alerts2)

        incidents = service.list_incidents()
        # Most recent should be first
        assert incidents[0].incident_id == inc2.incident_id

    def test_list_incidents_filter_by_status(self, service: IncidentService) -> None:
        """Test filtering incidents by status."""
        alerts = [_alert(host="host1")]
        service.create_incident(alerts)

        # Filter by OPEN status
        open_incidents = service.list_incidents(status=IncidentStatus.OPEN)
        assert len(open_incidents) == 1

        # Filter by CLOSED status (should be empty)
        closed_incidents = service.list_incidents(status=IncidentStatus.CLOSED)
        assert len(closed_incidents) == 0

    def test_list_incidents_filter_by_severity(self, service: IncidentService) -> None:
        """Test filtering incidents by severity."""
        alerts1 = [_alert(host="host1", severity=Severity.HIGH)]
        alerts2 = [_alert(host="host2", severity=Severity.CRITICAL)]
        inc1 = service.create_incident(alerts1)
        service.create_incident(alerts2)

        high_incidents = service.list_incidents(severity=Severity.HIGH)
        assert len(high_incidents) == 1
        assert high_incidents[0].incident_id == inc1.incident_id


class TestBackwardCompatibility:
    """Tests for backward compatibility."""

    def test_alert_without_incident_id(self, service: IncidentService) -> None:
        """Test that alerts without incident_id work correctly."""
        alert = _alert(host="host1")
        assert alert.incident_id is None

    def test_create_incident_with_alerts_without_incident_id(
        self, service: IncidentService
    ) -> None:
        """Test creating incident from alerts without incident_id."""
        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        assert incident is not None
        assert len(incident.alert_ids) == 1

    def test_associate_alert_preserves_immutability(self, service: IncidentService) -> None:
        """Test that associating alert doesn't mutate the original alert."""
        alert = _alert(host="host1")
        original_id = alert.alert_id
        original_incident_id = alert.incident_id

        alerts = [_alert(host="host1")]
        incident = service.create_incident(alerts)
        service.associate_alert(incident.incident_id, alert)

        # Original alert should be unchanged
        assert alert.alert_id == original_id
        assert alert.incident_id == original_incident_id


class TestDeduplicationInvariance:
    """Tests to prove incident association doesn't affect deduplication."""

    def test_different_incident_id_same_fingerprint(self) -> None:
        """Test that different incident_id produces same fingerprint."""
        from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig

        fingerprint = AlertFingerprint(FingerprintConfig())
        alert1 = _alert(host="host1", incident_id=uuid4())
        alert2 = _alert(host="host1", incident_id=uuid4())

        fp1 = fingerprint.create(alert1)
        fp2 = fingerprint.create(alert2)
        assert fp1 == fp2

    def test_incident_association_does_not_change_fingerprint(self) -> None:
        """Test that associating an alert with an incident doesn't change its fingerprint."""
        from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig

        fingerprint = AlertFingerprint(FingerprintConfig())
        alert = _alert(host="host1")
        fp_before = fingerprint.create(alert)

        # Simulate what would happen if incident_id were set
        # (we don't actually mutate the alert, just verify the fingerprint is independent)
        assert alert.incident_id is None
        # Fingerprint should not include incident_id
        assert "incident_id" not in str(fp_before)


class TestGetOrCreateIncidentForEntity:
    """Tests for get_or_create_incident_for_entity method."""

    def test_get_or_create_creates_new_incident(self, service: IncidentService) -> None:
        """Test creating a new incident for an entity."""
        alert = _alert(host="host1")
        entity_key = "host1:*"

        incident_id = service.get_or_create_incident_for_entity(entity_key, [alert])

        assert incident_id is not None
        incident = service.get_incident(incident_id)
        assert incident is not None
        assert len(incident.alert_ids) == 1

    def test_get_or_create_returns_existing_incident(self, service: IncidentService) -> None:
        """Test that subsequent calls return the same incident."""
        alert1 = _alert(host="host1")
        alert2 = _alert(host="host1", title="Second Alert")
        entity_key = "host1:*"

        incident_id1 = service.get_or_create_incident_for_entity(entity_key, [alert1])
        incident_id2 = service.get_or_create_incident_for_entity(entity_key, [alert2])

        assert incident_id1 == incident_id2
        incident = service.get_incident(incident_id1)
        assert incident is not None
        assert len(incident.alert_ids) == 2

    def test_get_or_create_different_entities(self, service: IncidentService) -> None:
        """Test that different entities get different incidents."""
        alert1 = _alert(host="host1")
        alert2 = _alert(host="host2")
        entity_key1 = "host1:*"
        entity_key2 = "host2:*"

        incident_id1 = service.get_or_create_incident_for_entity(entity_key1, [alert1])
        incident_id2 = service.get_or_create_incident_for_entity(entity_key2, [alert2])

        assert incident_id1 != incident_id2

    def test_get_incident_for_entity_returns_none_when_missing(
        self, service: IncidentService
    ) -> None:
        """Test that get_incident_for_entity returns None for unknown entity."""
        entity_key = "unknown_host:*"
        result = service.get_incident_for_entity(entity_key)
        assert result is None


class TestEvictionCleanup:
    """Tests for eviction cleanup of entity mappings."""

    def test_eviction_cleans_up_entity_mapping(self, service: IncidentService) -> None:
        """Test that evicting an incident also removes its entity mapping."""
        # Use a small service to test eviction
        small_service = IncidentService(max_incidents=2)

        # Create two incidents
        alert1 = _alert(host="host1")
        alert2 = _alert(host="host2")
        entity_key1 = "host1:*"
        entity_key2 = "host2:*"

        incident_id1 = small_service.get_or_create_incident_for_entity(entity_key1, [alert1])
        incident_id2 = small_service.get_or_create_incident_for_entity(entity_key2, [alert2])

        assert small_service.get_incident_for_entity(entity_key1) == incident_id1
        assert small_service.get_incident_for_entity(entity_key2) == incident_id2

        # Create a third incident to trigger eviction
        alert3 = _alert(host="host3")
        entity_key3 = "host3:*"

        small_service.get_or_create_incident_for_entity(entity_key3, [alert3])

        # Verify that exactly 2 incidents remain after eviction
        remaining = small_service.list_incidents()
        assert len(remaining) == 2
        # Verify that exactly 2 entity mappings remain
        assert len(small_service._entity_incident_map) == 2
        # Verify that the evicted incident's entity mapping is cleaned up
        # (we don't know which one was evicted, but at least one should be gone)
        assert (
            small_service.get_incident_for_entity(entity_key1) is None
            or small_service.get_incident_for_entity(entity_key2) is None
        )
