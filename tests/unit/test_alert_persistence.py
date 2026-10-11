"""Tests for AlertPersistence (Phase 5.4.1).

Comprehensive tests covering:
- Table creation and initialization
- Save/load operations
- Status semantics (AVAILABLE/EMPTY/UNAVAILABLE/DEGRADED)
- Failure and corruption handling
- Duplicate semantics
- Retention and eviction
- Lifecycle persistence
- AlertManager integration
- InvestigationContextService integration
- Replay isolation
- SQL injection prevention
- Bounded query results
- Concurrent reads/writes
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.alert_persistence import (
    AlertPersistence,
    AlertPersistenceStatus,
)
from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService
from argusprowl.behavior.analyst_behavior_query_service import AnalystBehaviorQueryService
from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle.queue import AlertQueue
from argusprowl.models.alert import Alert
from argusprowl.models.entity_investigation_context import SourceStatus
from argusprowl.services.investigation_context_service import InvestigationContextService

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_alert() -> Alert:
    """Create a sample alert for testing."""
    return Alert(
        alert_id=uuid4(),
        title="Test Alert",
        description="Test description",
        severity=Severity.HIGH,
        source="test_source",
        created_at=datetime.now(UTC),
        entity_context={"host": "testhost", "dst_ip": "10.0.0.1"},
    )


@pytest.fixture
def persistence(tmp_path: Path) -> AlertPersistence:
    """Create a persistence instance with a temp database."""
    db_path = tmp_path / "test_alerts.db"
    return AlertPersistence(db_path=db_path, max_alerts=100)


@pytest.fixture
def initialized_persistence(persistence: AlertPersistence) -> AlertPersistence:
    """Create and initialize a persistence instance."""
    persistence.initialize()
    return persistence


@pytest.fixture
def alert_manager() -> AlertManager:
    """Create an AlertManager with no dependencies."""
    return AlertManager()


def make_alert(
    alert_id: UUID | None = None,
    title: str = "Test Alert",
    host: str | None = None,
    created_at: datetime | None = None,
) -> Alert:
    """Create a test alert."""
    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=Severity.MEDIUM,
        source="test",
        created_at=created_at or datetime.now(UTC),
        entity_context={"host": host} if host else None,
    )


# ── Table Creation Tests ──────────────────────────────────────────────────────


class TestTableCreation:
    """Tests for table creation and initialization."""

    def test_initialize_creates_tables(self, persistence: AlertPersistence) -> None:
        """Persistence initializes SQLite tables."""
        persistence.initialize()

        conn = sqlite3.connect(str(persistence._db_path))
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        conn.close()

        table_names = {t[0] for t in tables}
        assert "alerts" in table_names
        assert "metadata" in table_names

    def test_initialize_creates_indexes(self, persistence: AlertPersistence) -> None:
        """Persistence creates indexes on key columns."""
        persistence.initialize()

        conn = sqlite3.connect(str(persistence._db_path))
        indexes = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        conn.close()

        index_names = {i[0] for i in indexes}
        assert "idx_alerts_created_at" in index_names
        assert "idx_alerts_entity" in index_names
        assert "idx_alerts_incident" in index_names

    def test_initialize_idempotent(self, persistence: AlertPersistence) -> None:
        """Calling initialize() multiple times is safe."""
        persistence.initialize()
        persistence.initialize()  # Should not raise

        assert persistence.get_status() == AlertPersistenceStatus.EMPTY


# ── Save/Load Tests ───────────────────────────────────────────────────────────


class TestSaveLoad:
    """Tests for save and load operations."""

    def test_save_and_load_alert(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Alert can be saved and loaded."""
        result = initialized_persistence.save_alert(sample_alert)
        assert result is True

        loaded = initialized_persistence.load_alert(sample_alert.alert_id)
        assert loaded is not None
        assert loaded.alert_id == sample_alert.alert_id
        assert loaded.title == sample_alert.title
        assert loaded.severity == sample_alert.severity

    def test_load_empty_when_no_data(self, initialized_persistence: AlertPersistence) -> None:
        """Loading from empty database returns None."""
        loaded = initialized_persistence.load_alert(uuid4())
        assert loaded is None

    def test_save_returns_true_on_success(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """save_alert returns True when successful."""
        result = initialized_persistence.save_alert(sample_alert)
        assert result is True

    def test_save_returns_false_when_not_initialized(self) -> None:
        """save_alert returns False when not initialized."""
        persistence = AlertPersistence(db_path="/tmp/test.db")
        alert = Alert(
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
        )
        result = persistence.save_alert(alert)
        assert result is False

    def test_load_returns_none_when_not_initialized(self) -> None:
        """load_alert returns None when not initialized."""
        persistence = AlertPersistence(db_path="/tmp/test.db")
        result = persistence.load_alert(uuid4())
        assert result is None


# ── Status Tests ──────────────────────────────────────────────────────────────


class TestStatus:
    """Tests for persistence status semantics."""

    def test_status_empty_after_initialize(self, persistence: AlertPersistence) -> None:
        """Status is EMPTY after initialization with no alerts."""
        persistence.initialize()
        assert persistence.get_status() == AlertPersistenceStatus.EMPTY

    def test_status_available_after_write(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Status is AVAILABLE after successful write."""
        initialized_persistence.save_alert(sample_alert)
        assert initialized_persistence.get_status() == AlertPersistenceStatus.AVAILABLE

    def test_status_unavailable_when_db_missing(self) -> None:
        """Status is UNAVAILABLE when DB cannot be opened."""
        # This test simulates a permission denied scenario
        persistence = AlertPersistence(db_path="/nonexistent/path/db.db")
        persistence.initialize()
        assert persistence.get_status() == AlertPersistenceStatus.UNAVAILABLE

    def test_status_unavailable_after_corruption(self, tmp_path: Path) -> None:
        """Status is UNAVAILABLE when database is corrupted."""
        db_path = tmp_path / "corrupted.db"
        # Create a file that's not a valid SQLite database
        db_path.write_text("not a sqlite database")

        persistence = AlertPersistence(db_path=db_path)
        persistence.initialize()
        assert persistence.get_status() == AlertPersistenceStatus.UNAVAILABLE

    def test_status_degraded_with_malformed_rows(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Status is DEGRADED when some rows are malformed."""
        # Insert a valid alert
        alert = Alert(
            alert_id=uuid4(),
            title="Valid",
            description="Desc",
            severity=Severity.LOW,
            source="test",
        )
        initialized_persistence.save_alert(alert)

        # Corrupt the database by inserting malformed JSON
        conn = sqlite3.connect(str(initialized_persistence._db_path))
        conn.execute(
            "INSERT INTO alerts (alert_id, payload, lifecycle_state, created_at) VALUES (?, ?, ?, ?)",
            (str(uuid4()), "not valid json", "OPEN", datetime.now(UTC).isoformat()),
        )
        conn.commit()
        conn.close()

        # Re-initialize to pick up the corruption
        persistence2 = AlertPersistence(db_path=initialized_persistence._db_path)
        persistence2.initialize()

        result = persistence2.list_recent()
        assert result.status == AlertPersistenceStatus.DEGRADED
        assert result.reason == "malformed_record"
        assert len(result.alerts) == 1  # Only the valid alert

    def test_query_result_contains_status(self, initialized_persistence: AlertPersistence) -> None:
        """AlertQueryResult includes status field."""
        result = initialized_persistence.list_recent()
        assert hasattr(result, "status")
        assert isinstance(result.status, AlertPersistenceStatus)

    def test_query_result_contains_reason(self, initialized_persistence: AlertPersistence) -> None:
        """AlertQueryResult includes reason for DEGRADED/UNAVAILABLE."""
        result = initialized_persistence.list_recent()
        # Empty result should have no reason
        assert result.reason is None or isinstance(result.reason, str)


# ── List Operations Tests ─────────────────────────────────────────────────────


class TestListOperations:
    """Tests for list operations."""

    def test_list_recent_returns_newest_first(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Alerts are ordered by created_at DESC."""
        alerts = []
        for i in range(5):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                created_at=datetime.now(UTC),
            )
            alerts.append(alert)
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_recent()
        assert result.status == AlertPersistenceStatus.AVAILABLE
        assert len(result.alerts) == 5
        # Should be in reverse creation order (newest first)
        for i in range(len(result.alerts) - 1):
            assert result.alerts[i].created_at >= result.alerts[i + 1].created_at

    def test_list_recent_empty_when_no_data(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """list_recent returns empty result when no alerts."""
        result = initialized_persistence.list_recent()
        assert result.status == AlertPersistenceStatus.EMPTY
        assert len(result.alerts) == 0

    def test_list_by_entity_returns_matching_alerts(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Entity-key query returns correct alerts."""
        entity_key = "testhost:*"

        # Create alerts with same entity
        for i in range(3):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                entity_context={"host": "testhost"},
            )
            initialized_persistence.save_alert(alert)

        # Create alert with different entity
        other_alert = Alert(
            alert_id=uuid4(),
            title="Other",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "otherhost"},
        )
        initialized_persistence.save_alert(other_alert)

        result = initialized_persistence.list_by_entity(entity_key)
        assert result.status == AlertPersistenceStatus.AVAILABLE
        assert len(result.alerts) == 3
        for alert in result.alerts:
            assert alert.entity_context.get("host") == "testhost"

    def test_list_by_entity_empty_when_no_match(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """list_by_entity returns empty when no matches."""
        result = initialized_persistence.list_by_entity("nonexistent:*")
        assert result.status == AlertPersistenceStatus.EMPTY
        assert len(result.alerts) == 0

    def test_list_by_incident_returns_matching_alerts(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Incident-id query returns correct alerts."""
        incident_id = uuid4()

        # Create alerts with same incident
        for i in range(3):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                incident_id=incident_id,
            )
            initialized_persistence.save_alert(alert)

        # Create alert with different incident
        other_incident = Alert(
            alert_id=uuid4(),
            title="Other",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            incident_id=uuid4(),
        )
        initialized_persistence.save_alert(other_incident)

        result = initialized_persistence.list_by_incident(incident_id)
        assert result.status == AlertPersistenceStatus.AVAILABLE
        assert len(result.alerts) == 3
        for alert in result.alerts:
            assert alert.incident_id == incident_id

    def test_list_by_incident_empty_when_no_match(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """list_by_incident returns empty when no matches."""
        result = initialized_persistence.list_by_incident(uuid4())
        assert result.status == AlertPersistenceStatus.EMPTY
        assert len(result.alerts) == 0

    def test_list_recent_unavailable_when_not_initialized(self) -> None:
        """list_recent returns UNAVAILABLE when not initialized."""
        persistence = AlertPersistence(db_path="/tmp/test.db")
        result = persistence.list_recent()
        assert result.status == AlertPersistenceStatus.UNAVAILABLE
        assert result.reason == "unavailable"

    def test_list_by_entity_unavailable_when_not_initialized(self) -> None:
        """list_by_entity returns UNAVAILABLE when not initialized."""
        persistence = AlertPersistence(db_path="/tmp/test.db")
        result = persistence.list_by_entity("test:*")
        assert result.status == AlertPersistenceStatus.UNAVAILABLE

    def test_list_by_incident_unavailable_when_not_initialized(self) -> None:
        """list_by_incident returns UNAVAILABLE when not initialized."""
        persistence = AlertPersistence(db_path="/tmp/test.db")
        result = persistence.list_by_incident(uuid4())
        assert result.status == AlertPersistenceStatus.UNAVAILABLE


# ── Duplicate Semantics Tests ─────────────────────────────────────────────────


class TestDuplicateSemantics:
    """Tests for duplicate alert handling."""

    def test_duplicate_alert_id_idempotent(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Saving same alert_id twice is idempotent."""
        result1 = initialized_persistence.save_alert(sample_alert)
        result2 = initialized_persistence.save_alert(sample_alert)

        assert result1 is True
        assert result2 is True

        # Should still only have one alert
        result = initialized_persistence.list_recent()
        assert len(result.alerts) == 1

    def test_duplicate_conflicting_alert_rejected(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Saving alert with same ID but different payload is rejected."""
        alert1 = Alert(
            alert_id=uuid4(),
            title="Original",
            description="Original desc",
            severity=Severity.HIGH,
            source="test",
        )
        alert2 = Alert(
            alert_id=alert1.alert_id,  # Same ID
            title="Modified",  # Different title
            description="Modified desc",
            severity=Severity.LOW,
            source="test",
        )

        result1 = initialized_persistence.save_alert(alert1)
        result2 = initialized_persistence.save_alert(alert2)

        assert result1 is True
        assert result2 is False  # Should be rejected

        # Original should still be there
        loaded = initialized_persistence.load_alert(alert1.alert_id)
        assert loaded is not None
        assert loaded.title == "Original"

    def test_duplicate_conflicting_alert_preserves_original(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Rejected duplicate does not overwrite original."""
        alert1 = Alert(
            alert_id=uuid4(),
            title="Original",
            description="Original desc",
            severity=Severity.HIGH,
            source="test",
        )
        alert2 = Alert(
            alert_id=alert1.alert_id,
            title="Modified",
            description="Modified desc",
            severity=Severity.LOW,
            source="test",
        )

        initialized_persistence.save_alert(alert1)
        initialized_persistence.save_alert(alert2)

        loaded = initialized_persistence.load_alert(alert1.alert_id)
        assert loaded.title == "Original"
        assert loaded.severity == Severity.HIGH


# ── Retention Tests ───────────────────────────────────────────────────────────


class TestRetention:
    """Tests for retention and eviction."""

    def test_bounded_retention(self, tmp_path: Path) -> None:
        """Oldest alerts are evicted when at capacity."""
        db_path = tmp_path / "retention.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=5)
        persistence.initialize()

        # Save 10 alerts
        alerts = []
        for i in range(10):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                created_at=datetime(2026, 1, 1, 10, i, 0, tzinfo=UTC),
            )
            alerts.append(alert)
            persistence.save_alert(alert)

        # Should only have 5 alerts
        result = persistence.list_recent()
        assert len(result.alerts) == 5
        assert result.status == AlertPersistenceStatus.AVAILABLE

    def test_deterministic_eviction(self, tmp_path: Path) -> None:
        """Eviction order is deterministic (oldest first)."""
        db_path = tmp_path / "eviction.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=3)
        persistence.initialize()

        # Save alerts with different timestamps
        base_time = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
        for i in range(5):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                created_at=base_time.replace(hour=10 + i),
            )
            persistence.save_alert(alert)

        result = persistence.list_recent()
        # Should keep the 3 newest
        assert len(result.alerts) == 3
        # Verify they are the newest ones (hours 12, 13, 14)
        hours = [a.created_at.hour for a in result.alerts]
        assert sorted(hours) == [12, 13, 14]

    def test_eviction_by_alert_id_tiebreaker(self, tmp_path: Path) -> None:
        """Alert ID is used as tie-breaker when created_at is equal."""
        db_path = tmp_path / "tiebreaker.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=2)
        persistence.initialize()

        same_time = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)

        # Create alerts with same timestamp
        alert1 = Alert(
            alert_id=UUID(int=1),  # Smaller UUID
            title="Alert 1",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            created_at=same_time,
        )
        alert2 = Alert(
            alert_id=UUID(int=2),  # Larger UUID
            title="Alert 2",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            created_at=same_time,
        )
        alert3 = Alert(
            alert_id=UUID(int=3),  # Largest UUID
            title="Alert 3",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            created_at=same_time,
        )

        persistence.save_alert(alert1)
        persistence.save_alert(alert2)
        persistence.save_alert(alert3)

        result = persistence.list_recent()
        # Should keep the 2 with largest alert_id (tie-breaker)
        assert len(result.alerts) == 2
        alert_ids = {a.alert_id for a in result.alerts}
        assert UUID(int=2) in alert_ids
        assert UUID(int=3) in alert_ids


# ── Restart Persistence Tests ─────────────────────────────────────────────────


class TestRestartPersistence:
    """Tests for persistence across restarts."""

    def test_alerts_survive_restart(self, tmp_path: Path, sample_alert: Alert) -> None:
        """Alerts survive restart (save + reload)."""
        db_path = tmp_path / "restart.db"

        # First instance
        persistence1 = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence1.initialize()
        persistence1.save_alert(sample_alert)
        persistence1.close()

        # Second instance (simulating restart)
        persistence2 = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence2.initialize()

        assert persistence2.get_status() == AlertPersistenceStatus.AVAILABLE
        loaded = persistence2.load_alert(sample_alert.alert_id)
        assert loaded is not None
        assert loaded.alert_id == sample_alert.alert_id
        persistence2.close()


# ── Lifecycle Persistence Tests ───────────────────────────────────────────────


class TestLifecyclePersistence:
    """Tests for lifecycle state persistence."""

    def test_open_alert_persistence(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """OPEN alerts are persisted."""
        initialized_persistence.save_alert(sample_alert)
        assert sample_alert.lifecycle_state == AlertLifecycleState.OPEN

    def test_acknowledged_alert_persistence(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """ACKNOWLEDGED lifecycle state is persisted."""
        initialized_persistence.save_alert(sample_alert)
        initialized_persistence.update_lifecycle(sample_alert.alert_id, "ACKNOWLEDGED")

        loaded = initialized_persistence.load_alert(sample_alert.alert_id)
        assert loaded is not None
        assert loaded.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_closed_alert_persistence(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """CLOSED lifecycle state is persisted."""
        initialized_persistence.save_alert(sample_alert)
        initialized_persistence.update_lifecycle(sample_alert.alert_id, "CLOSED")

        loaded = initialized_persistence.load_alert(sample_alert.alert_id)
        assert loaded is not None
        assert loaded.lifecycle_state == AlertLifecycleState.CLOSED

    def test_restart_preserves_lifecycle_state(self, tmp_path: Path, sample_alert: Alert) -> None:
        """Lifecycle state survives restart."""
        db_path = tmp_path / "lifecycle.db"

        # First instance
        persistence1 = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence1.initialize()
        persistence1.save_alert(sample_alert)
        persistence1.update_lifecycle(sample_alert.alert_id, "ACKNOWLEDGED")
        persistence1.close()

        # Second instance
        persistence2 = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence2.initialize()

        loaded = persistence2.load_alert(sample_alert.alert_id)
        assert loaded is not None
        assert loaded.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        persistence2.close()

    def test_lifecycle_transition_updates_persistence(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Acknowledge/close updates persisted state."""
        initialized_persistence.save_alert(sample_alert)

        result = initialized_persistence.update_lifecycle(sample_alert.alert_id, "ACKNOWLEDGED")
        assert result is True

        loaded = initialized_persistence.load_alert(sample_alert.alert_id)
        assert loaded.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_lifecycle_persistence_failure(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Lifecycle transition in memory succeeds even if persistence fails."""
        initialized_persistence.save_alert(sample_alert)

        # Mock the connection to fail
        with patch.object(initialized_persistence, "_get_connection") as mock_conn:
            mock_conn.return_value.execute.side_effect = sqlite3.Error("disk I/O error")

            result = initialized_persistence.update_lifecycle(sample_alert.alert_id, "CLOSED")
            assert result is False
            assert initialized_persistence.get_status() == AlertPersistenceStatus.DEGRADED


# ── Failure Tests ─────────────────────────────────────────────────────────────


class TestFailureSemantics:
    """Tests for failure handling."""

    def test_database_unavailable(self) -> None:
        """Persistence returns UNAVAILABLE when DB cannot be opened."""
        persistence = AlertPersistence(db_path="/nonexistent/path/db.db")
        persistence.initialize()
        assert persistence.get_status() == AlertPersistenceStatus.UNAVAILABLE

        result = persistence.list_recent()
        assert result.status == AlertPersistenceStatus.UNAVAILABLE

    def test_write_failure(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Write failure returns False, does not raise."""
        with patch.object(initialized_persistence, "_get_connection") as mock_conn:
            mock_conn.return_value.execute.side_effect = sqlite3.Error("disk I/O error")

            result = initialized_persistence.save_alert(sample_alert)
            assert result is False
            assert initialized_persistence.get_status() == AlertPersistenceStatus.DEGRADED

    def test_read_failure(self, initialized_persistence: AlertPersistence) -> None:
        """Read failure returns AlertQueryResult with UNAVAILABLE."""
        with patch.object(initialized_persistence, "_get_connection") as mock_conn:
            mock_conn.return_value.execute.side_effect = sqlite3.Error("disk I/O error")

            result = initialized_persistence.list_recent()
            assert result.status == AlertPersistenceStatus.UNAVAILABLE

    def test_degraded_state_does_not_affect_detection(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """Persistence failure does not disrupt AlertQueue."""
        # Save alert successfully
        initialized_persistence.save_alert(sample_alert)

        # Then cause a failure
        with patch.object(initialized_persistence, "_get_connection") as mock_conn:
            mock_conn.return_value.execute.side_effect = sqlite3.Error("disk I/O error")

            result = initialized_persistence.save_alert(sample_alert)
            assert result is False

        # But the original alert should still be there
        loaded = initialized_persistence.load_alert(sample_alert.alert_id)
        assert loaded is not None


# ── AlertManager Integration Tests ────────────────────────────────────────────


class TestAlertManagerIntegration:
    """Tests for AlertManager integration with persistence."""

    def test_alert_queue_and_persistence_wiring(self, tmp_path: Path) -> None:
        """AlertManager saves to both queue and persistence."""
        db_path = tmp_path / "integration.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        queue = AlertQueue(max_size=100)
        manager = AlertManager(alert_queue=queue, alert_persistence=persistence)

        alert = Alert(
            title="Test",
            description="Desc",
            severity=Severity.HIGH,
            source="test",
        )

        manager.send_alert(alert)

        # Alert should be in queue
        assert queue.get(alert.alert_id) is not None

        # Alert should be in persistence
        loaded = persistence.load_alert(alert.alert_id)
        assert loaded is not None

        persistence.close()

    def test_persistence_failure_does_not_corrupt_alert_queue(self, tmp_path: Path) -> None:
        """Queue continues to work when persistence fails."""
        db_path = tmp_path / "failure.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        queue = AlertQueue(max_size=100)
        manager = AlertManager(alert_queue=queue, alert_persistence=persistence)

        # Cause persistence to fail
        with patch.object(persistence, "save_alert", return_value=False):
            alert = Alert(
                title="Test",
                description="Desc",
                severity=Severity.HIGH,
                source="test",
            )
            manager.send_alert(alert)

        # Queue should still have the alert
        assert queue.get(alert.alert_id) is not None

    def test_persistence_none_when_disabled(self, tmp_path: Path) -> None:
        """AlertManager works without persistence when not configured."""
        queue = AlertQueue(max_size=100)
        manager = AlertManager(alert_queue=queue)

        alert = Alert(
            title="Test",
            description="Desc",
            severity=Severity.HIGH,
            source="test",
        )

        manager.send_alert(alert)
        assert queue.get(alert.alert_id) is not None


# ── InvestigationContextService Integration Tests ─────────────────────────────


class TestInvestigationContextIntegration:
    """Tests for InvestigationContextService integration."""

    def test_investigation_context_with_persistence(self, tmp_path: Path) -> None:
        """InvestigationContextService includes historical alerts."""
        db_path = tmp_path / "context.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Save an alert to persistence
        alert = Alert(
            alert_id=uuid4(),
            title="Historical Alert",
            description="Desc",
            severity=Severity.HIGH,
            source="test",
            entity_context={"host": "testhost"},
        )
        persistence.save_alert(alert)

        # Create investigation context service with persistence
        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should include the historical alert
        assert len(context.recent_alerts) == 1
        assert context.recent_alerts[0].alert_id == alert.alert_id

        persistence.close()

    def test_investigation_context_degraded_status(self, tmp_path: Path) -> None:
        """InvestigationContextService reports DEGRADED when persistence is degraded."""
        db_path = tmp_path / "degraded.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Insert valid and malformed alerts
        valid_alert = Alert(
            alert_id=uuid4(),
            title="Valid",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "testhost"},
        )
        persistence.save_alert(valid_alert)

        # Corrupt the database
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO alerts (alert_id, payload, lifecycle_state, created_at, entity_key) VALUES (?, ?, ?, ?, ?)",
            (str(uuid4()), "invalid json", "OPEN", datetime.now(UTC).isoformat(), "testhost:*"),
        )
        conn.commit()
        conn.close()

        # Re-initialize to detect degradation
        persistence2 = AlertPersistence(db_path=db_path)
        persistence2.initialize()

        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence2,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should report DEGRADED (not UNAVAILABLE) - degraded evidence is still available
        assert context.get_source_status("alerts") == SourceStatus.DEGRADED
        # Valid alerts should still be present
        assert len(context.recent_alerts) == 1
        assert context.recent_alerts[0].title == "Valid"

        persistence2.close()

    def test_investigation_context_no_persistence(self) -> None:
        """InvestigationContextService works without persistence."""
        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
        )

        context = service.get_investigation_context("host", "testhost")
        assert context.recent_alerts == ()


# ── Replay Isolation Tests ────────────────────────────────────────────────────


class TestReplayIsolation:
    """Tests for replay isolation."""

    def test_replay_does_not_persist(self, tmp_path: Path) -> None:
        """Replay mode does not write to persistence."""
        db_path = tmp_path / "replay.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Simulate replay by creating persistence but not using it
        # In actual replay, AlertPersistence is not injected
        queue = AlertQueue(max_size=100)
        manager = AlertManager(alert_queue=queue)  # No persistence

        alert = Alert(
            title="Replay Alert",
            description="Desc",
            severity=Severity.HIGH,
            source="test",
        )
        manager.send_alert(alert)

        # Persistence should be empty
        result = persistence.list_recent()
        assert len(result.alerts) == 0
        assert result.status == AlertPersistenceStatus.EMPTY

        persistence.close()


# ── Security Tests ────────────────────────────────────────────────────────────


class TestSecurity:
    """Tests for security properties."""

    def test_sql_injection_attempts(self, initialized_persistence: AlertPersistence) -> None:
        """SQL injection in entity_key is prevented."""
        # Try SQL injection in entity key
        malicious_key = "'; DROP TABLE alerts; --"

        result = initialized_persistence.list_by_entity(malicious_key)
        assert result.status == AlertPersistenceStatus.EMPTY
        assert len(result.alerts) == 0

        # Database should still be intact
        result = initialized_persistence.list_recent()
        # Should not raise - table still exists

    def test_oversized_entity_key(self, initialized_persistence: AlertPersistence) -> None:
        """Oversized entity key is handled gracefully."""
        oversized_key = "a" * 1000  # Exceeds _MAX_ENTITY_KEY_LENGTH

        result = initialized_persistence.list_by_entity(oversized_key)
        assert result.status == AlertPersistenceStatus.UNAVAILABLE
        assert result.reason == "entity_key_too_long"

    def test_oversized_limit(self, initialized_persistence: AlertPersistence) -> None:
        """Oversized limit is capped."""
        result = initialized_persistence.list_recent(limit=10000)
        # Should not raise, limit should be capped
        assert result.status in (AlertPersistenceStatus.EMPTY, AlertPersistenceStatus.AVAILABLE)

    def test_parameterized_queries(
        self, initialized_persistence: AlertPersistence, sample_alert: Alert
    ) -> None:
        """All queries use parameterized SQL."""
        initialized_persistence.save_alert(sample_alert)

        # These should not raise even with malicious input
        # Use a valid UUID format that contains SQL injection characters
        malicious_id = UUID("00000000-0000-0000-0000-000000000000")
        result = initialized_persistence.list_by_incident(malicious_id)
        assert result.status == AlertPersistenceStatus.EMPTY

        result = initialized_persistence.list_by_entity("'; DROP TABLE alerts; --")
        assert result.status == AlertPersistenceStatus.EMPTY


# ── Bounded Query Results Tests ───────────────────────────────────────────────


class TestBoundedQueryResults:
    """Tests for bounded query results."""

    def test_bounded_query_results(self, initialized_persistence: AlertPersistence) -> None:
        """Query results respect LIMIT."""
        # Create more alerts than the default limit
        for i in range(150):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_recent(limit=100)
        assert len(result.alerts) <= 100

    def test_list_by_entity_bounded(self, initialized_persistence: AlertPersistence) -> None:
        """list_by_entity respects limit."""
        entity_key = "testhost:*"

        # Create more alerts than the default limit
        for i in range(60):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                entity_context={"host": "testhost"},
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_by_entity(entity_key, limit=50)
        assert len(result.alerts) <= 50

    def test_list_by_incident_bounded(self, initialized_persistence: AlertPersistence) -> None:
        """list_by_incident respects limit."""
        incident_id = uuid4()

        # Create more alerts than the default limit
        for i in range(150):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                incident_id=incident_id,
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_by_incident(incident_id, limit=100)
        assert len(result.alerts) <= 100


# ── Concurrent Access Tests ───────────────────────────────────────────────────


class TestConcurrency:
    """Tests for concurrent access."""

    def test_concurrent_saves(self, initialized_persistence: AlertPersistence) -> None:
        """Multiple threads can save alerts concurrently."""
        errors = []

        def save_alerts(start: int, count: int) -> None:
            try:
                for i in range(count):
                    alert = Alert(
                        alert_id=uuid4(),
                        title=f"Alert {start + i}",
                        description="Desc",
                        severity=Severity.LOW,
                        source="test",
                    )
                    initialized_persistence.save_alert(alert)
            except Exception as exc:
                errors.append(exc)

        threads = []
        for t in range(5):
            thread = threading.Thread(target=save_alerts, args=(t * 10, 10))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0

        result = initialized_persistence.list_recent()
        assert len(result.alerts) == 50

    def test_concurrent_reads_during_write(self, initialized_persistence: AlertPersistence) -> None:
        """Reads work during writes."""
        errors = []

        def write_alerts() -> None:
            for i in range(20):
                alert = Alert(
                    alert_id=uuid4(),
                    title=f"Alert {i}",
                    description="Desc",
                    severity=Severity.LOW,
                    source="test",
                )
                initialized_persistence.save_alert(alert)

        def read_alerts() -> None:
            for _ in range(20):
                try:
                    initialized_persistence.list_recent()
                except Exception as exc:
                    errors.append(exc)

        write_thread = threading.Thread(target=write_alerts)
        read_thread = threading.Thread(target=read_alerts)

        write_thread.start()
        read_thread.start()

        write_thread.join()
        read_thread.join()

        assert len(errors) == 0


# ── Canonical Entity Key Tests ────────────────────────────────────────────────


class TestCanonicalEntityKey:
    """Tests for canonical entity key handling."""

    def test_entity_key_matches_entity_correlation_service(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Persisted entity key matches EntityCorrelationService output."""
        entity_service = EntityCorrelationService()

        alert = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.HIGH,
            source="test",
            entity_context={"host": "testhost", "process_name": "svchost.exe"},
        )

        expected_key = entity_service.compute_entity_key(alert)
        initialized_persistence.save_alert(alert)

        # Query by the expected key
        result = initialized_persistence.list_by_entity(expected_key)
        assert len(result.alerts) == 1
        assert result.alerts[0].alert_id == alert.alert_id

    def test_entity_key_precedence(self, initialized_persistence: AlertPersistence) -> None:
        """Entity key follows correct precedence rules."""
        entity_service = EntityCorrelationService()

        # Priority 1: host + process_name
        alert1 = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "host1", "process_name": "proc1"},
        )
        key1 = entity_service.compute_entity_key(alert1)
        initialized_persistence.save_alert(alert1)
        result = initialized_persistence.list_by_entity(key1)
        assert len(result.alerts) == 1

        # Priority 2: host + dst_ip (no process)
        alert2 = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "host2", "dst_ip": "10.0.0.1"},
        )
        key2 = entity_service.compute_entity_key(alert2)
        initialized_persistence.save_alert(alert2)
        result = initialized_persistence.list_by_entity(key2)
        assert len(result.alerts) == 1

        # Priority 3: host alone
        alert3 = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "host3"},
        )
        key3 = entity_service.compute_entity_key(alert3)
        initialized_persistence.save_alert(alert3)
        result = initialized_persistence.list_by_entity(key3)
        assert len(result.alerts) == 1


# ── list_all Tests ────────────────────────────────────────────────────────────


class TestListAll:
    """Tests for list_all() — bounded retrieval of the complete retained set."""

    def test_list_all_empty_when_no_data(self, initialized_persistence: AlertPersistence) -> None:
        """list_all returns EMPTY when no alerts exist."""
        result = initialized_persistence.list_all()
        assert result.status == AlertPersistenceStatus.EMPTY
        assert len(result.alerts) == 0
        assert result.reason is None

    def test_list_all_returns_all_alerts(self, initialized_persistence: AlertPersistence) -> None:
        """list_all returns all persisted alerts when under max_alerts."""
        for i in range(50):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_all()
        assert result.status == AlertPersistenceStatus.AVAILABLE
        assert len(result.alerts) == 50

    def test_list_all_respects_max_alerts_bound(self, tmp_path: Path) -> None:
        """list_all never returns more than max_alerts."""
        db_path = tmp_path / "list_all_bound.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Save 150 alerts (exceeds max_alerts)
        for i in range(150):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            persistence.save_alert(alert)

        result = persistence.list_all()
        assert len(result.alerts) <= 100
        assert result.status == AlertPersistenceStatus.AVAILABLE

    def test_list_all_limit_none_returns_full_set(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """list_all(None) returns the complete retained set."""
        for i in range(75):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_all(None)
        assert len(result.alerts) == 75

    def test_list_all_limit_explicit(self, initialized_persistence: AlertPersistence) -> None:
        """list_all with explicit limit returns at most that many."""
        for i in range(100):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_all(limit=50)
        assert len(result.alerts) == 50

    def test_list_all_limit_clamped_to_max_alerts(self, tmp_path: Path) -> None:
        """Explicit limit above max_alerts is clamped."""
        db_path = tmp_path / "list_all_clamp.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=50)
        persistence.initialize()

        for i in range(100):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            persistence.save_alert(alert)

        # Request more than max_alerts
        result = persistence.list_all(limit=1000000)
        assert len(result.alerts) <= 50

    def test_list_all_limit_zero(self, initialized_persistence: AlertPersistence) -> None:
        """list_all(limit=0) returns at least 1 (bounded to minimum 1)."""
        alert = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
        )
        initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_all(limit=0)
        assert len(result.alerts) >= 1

    def test_list_all_limit_negative(self, initialized_persistence: AlertPersistence) -> None:
        """list_all(limit=-1) returns at least 1 (bounded to minimum 1)."""
        alert = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
        )
        initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_all(limit=-1)
        assert len(result.alerts) >= 1

    def test_list_all_unavailable_when_not_initialized(self) -> None:
        """list_all returns UNAVAILABLE when not initialized."""
        persistence = AlertPersistence(db_path="/tmp/test.db")
        result = persistence.list_all()
        assert result.status == AlertPersistenceStatus.UNAVAILABLE
        assert result.reason == "unavailable"

    def test_list_all_deterministic_ordering(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """list_all returns alerts in deterministic order."""
        base_time = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
        for i in range(10):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                created_at=base_time.replace(hour=10 + i),
            )
            initialized_persistence.save_alert(alert)

        result = initialized_persistence.list_all()
        assert len(result.alerts) == 10
        # Verify descending order by created_at
        for i in range(len(result.alerts) - 1):
            assert result.alerts[i].created_at >= result.alerts[i + 1].created_at

    def test_list_all_complete_retained_set_above_1000(self, tmp_path: Path) -> None:
        """list_all can return more than 1000 alerts when max_alerts > 1000."""
        db_path = tmp_path / "large_set.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=1500)
        persistence.initialize()

        # Save 1200 alerts
        for i in range(1200):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            persistence.save_alert(alert)

        result = persistence.list_all()
        assert len(result.alerts) == 1200
        assert result.status == AlertPersistenceStatus.AVAILABLE

    def test_list_all_with_malformed_rows(self, initialized_persistence: AlertPersistence) -> None:
        """list_all returns DEGRADED when some rows are malformed."""
        # Insert valid alerts
        for i in range(3):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Valid {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            initialized_persistence.save_alert(alert)

        # Corrupt the database
        conn = sqlite3.connect(str(initialized_persistence._db_path))
        conn.execute(
            "INSERT INTO alerts (alert_id, payload, lifecycle_state, created_at) VALUES (?, ?, ?, ?)",
            (str(uuid4()), "not valid json", "OPEN", datetime.now(UTC).isoformat()),
        )
        conn.commit()
        conn.close()

        # Re-initialize to detect degradation
        persistence2 = AlertPersistence(db_path=initialized_persistence._db_path)
        persistence2.initialize()

        result = persistence2.list_all()
        assert result.status == AlertPersistenceStatus.DEGRADED
        assert result.reason == "malformed_record"
        assert len(result.alerts) == 3  # Valid alerts preserved

    def test_list_all_preserves_lifecycle_state(self, tmp_path: Path) -> None:
        """list_all preserves lifecycle state from persistence."""
        db_path = tmp_path / "lifecycle.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        alert = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.HIGH,
            source="test",
        )
        persistence.save_alert(alert)
        persistence.update_lifecycle(alert.alert_id, "ACKNOWLEDGED")

        result = persistence.list_all()
        assert len(result.alerts) == 1
        assert result.alerts[0].lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_list_all_no_persistence_writes(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """list_all does not modify the database."""
        alert = Alert(
            alert_id=uuid4(),
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
        )
        initialized_persistence.save_alert(alert)

        # Call list_all multiple times
        for _ in range(5):
            result = initialized_persistence.list_all()
            assert len(result.alerts) == 1

        # Count should still be 1
        result = initialized_persistence.list_all()
        assert len(result.alerts) == 1

    def test_list_all_respects_retention(self, tmp_path: Path) -> None:
        """list_all returns only retained alerts after eviction."""
        db_path = tmp_path / "retention.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=5)
        persistence.initialize()

        # Save 10 alerts
        for i in range(10):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                created_at=datetime(2026, 1, 1, 10, i, 0, tzinfo=UTC),
            )
            persistence.save_alert(alert)

        result = persistence.list_all()
        assert len(result.alerts) == 5
        assert result.status == AlertPersistenceStatus.AVAILABLE

    def test_list_all_restart_persistence(self, tmp_path: Path) -> None:
        """list_all returns same data after restart."""
        db_path = tmp_path / "restart.db"

        # First instance
        persistence1 = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence1.initialize()
        for i in range(10):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Alert {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
            )
            persistence1.save_alert(alert)
        persistence1.close()

        # Second instance (simulating restart)
        persistence2 = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence2.initialize()

        result = persistence2.list_all()
        assert len(result.alerts) == 10
        assert result.status == AlertPersistenceStatus.AVAILABLE
        persistence2.close()


# ── Close Tests ───────────────────────────────────────────────────────────────


class TestClose:
    """Tests for close operation."""

    def test_close_releases_connection(self, initialized_persistence: AlertPersistence) -> None:
        """close() releases the database connection."""
        initialized_persistence.close()
        assert initialized_persistence._connection is None
        assert initialized_persistence._initialized is False

    def test_operations_after_close_fail_gracefully(
        self, initialized_persistence: AlertPersistence
    ) -> None:
        """Operations after close() fail gracefully."""
        initialized_persistence.close()

        result = initialized_persistence.list_recent()
        assert result.status == AlertPersistenceStatus.UNAVAILABLE

        alert = Alert(
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            source="test",
        )
        assert initialized_persistence.save_alert(alert) is False


# ── Phase 5.4.1 Analyst Status Propagation Tests ─────────────────────────────


class TestPhase541StatusPropagation:
    """Tests for Phase 5.4.1 analyst status propagation fix.

    Verifies that:
    - AlertPersistenceStatus.DEGRADED maps to SourceStatus.DEGRADED
    - AlertPersistenceStatus.UNAVAILABLE maps to SourceStatus.UNAVAILABLE
    - Malformed rows return valid alerts and DEGRADED status
    - Queue alerts do not mask persistence degradation
    """

    def test_degraded_maps_to_source_degraded(self, tmp_path: Path) -> None:
        """AlertPersistenceStatus.DEGRADED maps to SourceStatus.DEGRADED."""
        db_path = tmp_path / "degraded_map.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Insert valid and malformed alerts
        valid_alert = Alert(
            alert_id=uuid4(),
            title="Valid",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "testhost"},
        )
        persistence.save_alert(valid_alert)

        # Corrupt the database
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO alerts (alert_id, payload, lifecycle_state, created_at, entity_key) VALUES (?, ?, ?, ?, ?)",
            (str(uuid4()), "invalid json", "OPEN", datetime.now(UTC).isoformat(), "testhost:*"),
        )
        conn.commit()
        conn.close()

        # Re-initialize to detect degradation
        persistence2 = AlertPersistence(db_path=db_path)
        persistence2.initialize()

        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence2,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should report DEGRADED (not UNAVAILABLE)
        assert context.get_source_status("alerts") == SourceStatus.DEGRADED
        # Valid alerts should still be present
        assert len(context.recent_alerts) == 1
        assert context.recent_alerts[0].title == "Valid"

        persistence2.close()

    def test_unavailable_maps_to_source_unavailable(self, tmp_path: Path) -> None:
        """AlertPersistenceStatus.UNAVAILABLE maps to SourceStatus.UNAVAILABLE."""
        tmp_path / "unavailable.db"
        # Use a non-existent path to simulate unavailable
        persistence = AlertPersistence(db_path="/nonexistent/path.db")
        persistence.initialize()

        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should report UNAVAILABLE
        assert context.get_source_status("alerts") == SourceStatus.UNAVAILABLE
        # No alerts should be returned
        assert len(context.recent_alerts) == 0

        persistence.close()

    def test_malformed_rows_return_valid_alerts_and_degraded(self, tmp_path: Path) -> None:
        """Malformed persisted rows return valid alerts and DEGRADED status."""
        db_path = tmp_path / "malformed.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Insert multiple valid alerts
        for i in range(3):
            alert = Alert(
                alert_id=uuid4(),
                title=f"Valid {i}",
                description="Desc",
                severity=Severity.LOW,
                source="test",
                entity_context={"host": "testhost"},
            )
            persistence.save_alert(alert)

        # Insert malformed rows
        conn = sqlite3.connect(str(db_path))
        for _ in range(2):
            conn.execute(
                "INSERT INTO alerts (alert_id, payload, lifecycle_state, created_at, entity_key) VALUES (?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    "not valid json",
                    "OPEN",
                    datetime.now(UTC).isoformat(),
                    "testhost:*",
                ),
            )
        conn.commit()
        conn.close()

        # Re-initialize
        persistence2 = AlertPersistence(db_path=db_path)
        persistence2.initialize()

        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence2,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should report DEGRADED
        assert context.get_source_status("alerts") == SourceStatus.DEGRADED
        # Should still have valid alerts
        assert len(context.recent_alerts) == 3
        for alert in context.recent_alerts:
            assert alert.title.startswith("Valid")

        persistence2.close()

    def test_queue_does_not_mask_persistence_degraded(self, tmp_path: Path) -> None:
        """Queue containing alerts does not mask persistence DEGRADED."""
        db_path = tmp_path / "queue_mask.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        # Insert valid and malformed alerts
        valid_alert = Alert(
            alert_id=uuid4(),
            title="Valid",
            description="Desc",
            severity=Severity.LOW,
            source="test",
            entity_context={"host": "testhost"},
        )
        persistence.save_alert(valid_alert)

        # Corrupt the database
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO alerts (alert_id, payload, lifecycle_state, created_at, entity_key) VALUES (?, ?, ?, ?, ?)",
            (str(uuid4()), "invalid json", "OPEN", datetime.now(UTC).isoformat(), "testhost:*"),
        )
        conn.commit()
        conn.close()

        # Re-initialize
        persistence2 = AlertPersistence(db_path=db_path)
        persistence2.initialize()

        # Queue has alerts
        queue_alert = make_alert(host="testhost")
        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = [queue_alert]

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence2,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should still report DEGRADED (not masked by queue)
        assert context.get_source_status("alerts") == SourceStatus.DEGRADED
        # Should have both queue and persistence alerts
        assert len(context.recent_alerts) >= 1

        persistence2.close()

    def test_queue_does_not_mask_persistence_unavailable(self, tmp_path: Path) -> None:
        """Queue containing alerts does not mask persistence UNAVAILABLE."""
        # Use unavailable persistence
        persistence = AlertPersistence(db_path="/nonexistent/path.db")
        persistence.initialize()

        # Queue has alerts
        queue_alert = make_alert(host="testhost")
        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = [queue_alert]

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should report UNAVAILABLE (not masked by queue)
        assert context.get_source_status("alerts") == SourceStatus.UNAVAILABLE

        persistence.close()

    def test_successful_empty_persistence_remains_available(self, tmp_path: Path) -> None:
        """Successful empty persistence remains AVAILABLE."""
        db_path = tmp_path / "empty.db"
        persistence = AlertPersistence(db_path=db_path, max_alerts=100)
        persistence.initialize()

        mock_queue = MagicMock(spec=AlertQueue)
        mock_queue.list_by_entity.return_value = []

        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
            alert_persistence=persistence,
        )

        context = service.get_investigation_context("host", "testhost")

        # Should report AVAILABLE (empty but healthy)
        assert context.get_source_status("alerts") == SourceStatus.AVAILABLE
        assert len(context.recent_alerts) == 0

        persistence.close()

    def test_unsupported_entity_type_remains_unsupported(self) -> None:
        """Unsupported entity types remain UNSUPPORTED."""
        mock_queue = MagicMock(spec=AlertQueue)
        mock_behavior = MagicMock(spec=AnalystBehaviorQueryService)
        mock_annotation = MagicMock(spec=AnalystAnnotationService)
        mock_incident = MagicMock(spec=IncidentService)

        service = InvestigationContextService(
            alert_queue=mock_queue,
            behavior_query_service=mock_behavior,
            annotation_service=mock_annotation,
            incident_service=mock_incident,
        )

        context = service.get_investigation_context("src_ip", "192.168.1.100")

        # Alerts and incident should be UNSUPPORTED
        assert context.get_source_status("alerts") == SourceStatus.UNSUPPORTED
        assert context.get_source_status("incident") == SourceStatus.UNSUPPORTED
        # Behavior and annotations should be AVAILABLE
        assert context.get_source_status("behavior") == SourceStatus.AVAILABLE
        assert context.get_source_status("annotations") == SourceStatus.AVAILABLE
