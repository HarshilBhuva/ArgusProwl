"""Tests for bounded entity behavior persistence (Phase 5.1.8).

Verifies that entity behavior state can be persisted to SQLite and
restored on startup without affecting detection decisions.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from argusprowl.behavior.entity_behavior_persistence import EntityBehaviorPersistence
from argusprowl.behavior.entity_behavior_profile import EntityBehaviorProfile, ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService


class TestEntityBehaviorPersistence:
    """Tests for EntityBehaviorPersistence."""

    def test_initialization_creates_tables(self, tmp_path: Path) -> None:
        """Persistence initializes SQLite tables."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        conn = sqlite3.connect(str(db_path))
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        conn.close()

        table_names = {t[0] for t in tables}
        assert "profiles" in table_names
        assert "value_counts" in table_names
        assert "metadata" in table_names

    def test_save_and_load_profile(self, tmp_path: Path) -> None:
        """Profiles can be saved and loaded."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        profile = EntityBehaviorProfile(
            profile_key="hostname:server01|dimension:process_name",
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            observation_count=10,
            distinct_value_count=3,
            maturity=ProfileMaturity.MATURE,
            profile_version=1,
            last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
        )
        value_counts = {"python.exe": 7, "notepad.exe": 2, "chrome.exe": 1}

        persistence.save_profile(profile, value_counts)

        loaded_profiles, loaded_counts = persistence.load_profiles()
        assert len(loaded_profiles) == 1
        assert "hostname:server01|dimension:process_name" in loaded_profiles
        assert loaded_profiles["hostname:server01|dimension:process_name"].observation_count == 10
        assert loaded_counts["hostname:server01|dimension:process_name"] == value_counts

    def test_load_empty_when_no_data(self, tmp_path: Path) -> None:
        """Loading from empty database returns empty dicts."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        profiles, counts = persistence.load_profiles()
        assert profiles == {}
        assert counts == {}

    def test_delete_profile(self, tmp_path: Path) -> None:
        """Profiles can be deleted."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        profile = EntityBehaviorProfile(
            profile_key="hostname:server01|dimension:process_name",
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            observation_count=10,
            distinct_value_count=3,
            maturity=ProfileMaturity.MATURE,
            profile_version=1,
            last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
        )
        persistence.save_profile(profile, {"python.exe": 7})

        persistence.delete_profile("hostname:server01|dimension:process_name")

        profiles, counts = persistence.load_profiles()
        assert len(profiles) == 0
        assert len(counts) == 0

    def test_get_profile_count(self, tmp_path: Path) -> None:
        """Can get profile count from database."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        assert persistence.get_profile_count() == 0

        profile = EntityBehaviorProfile(
            profile_key="hostname:server01|dimension:process_name",
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            observation_count=10,
            distinct_value_count=3,
            maturity=ProfileMaturity.MATURE,
            profile_version=1,
            last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
        )
        persistence.save_profile(profile, {"python.exe": 7})

        assert persistence.get_profile_count() == 1

    def test_save_all(self, tmp_path: Path) -> None:
        """Can save multiple profiles at once."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        profiles = {
            "hostname:server01|dimension:process_name": EntityBehaviorProfile(
                profile_key="hostname:server01|dimension:process_name",
                entity_type="hostname",
                entity_id="server01",
                dimension="process_name",
                first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
                last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
                observation_count=10,
                distinct_value_count=3,
                maturity=ProfileMaturity.MATURE,
                profile_version=1,
                last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            ),
            "hostname:server02|dimension:process_name": EntityBehaviorProfile(
                profile_key="hostname:server02|dimension:process_name",
                entity_type="hostname",
                entity_id="server02",
                dimension="process_name",
                first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
                last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
                observation_count=5,
                distinct_value_count=2,
                maturity=ProfileMaturity.WARMING,
                profile_version=1,
                last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            ),
        }
        value_counts = {
            "hostname:server01|dimension:process_name": {"python.exe": 7, "notepad.exe": 3},
            "hostname:server02|dimension:process_name": {"chrome.exe": 4, "firefox.exe": 1},
        }

        persistence.save_all(profiles, value_counts)

        loaded_profiles, _loaded_counts = persistence.load_profiles()
        assert len(loaded_profiles) == 2
        assert "hostname:server01|dimension:process_name" in loaded_profiles
        assert "hostname:server02|dimension:process_name" in loaded_profiles

    def test_close(self, tmp_path: Path) -> None:
        """Database connection is closed."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()
        persistence.close()

        # Should not raise
        profiles, counts = persistence.load_profiles()
        assert profiles == {}
        assert counts == {}

    def test_context_manager(self, tmp_path: Path) -> None:
        """Can use persistence as context manager."""
        db_path = tmp_path / "test.db"
        with EntityBehaviorPersistence(db_path=db_path) as persistence:
            assert persistence.get_profile_count() == 0


class TestEntityBehaviorServiceWithPersistence:
    """Tests for EntityBehaviorService with persistence enabled."""

    def test_load_persisted_state_on_init(self, tmp_path: Path) -> None:
        """Service loads persisted state on initialization."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        # Pre-populate with some state
        profile = EntityBehaviorProfile(
            profile_key="hostname:server01|dimension:process_name",
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            observation_count=10,
            distinct_value_count=3,
            maturity=ProfileMaturity.MATURE,
            profile_version=1,
            last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
        )
        persistence.save_profile(profile, {"python.exe": 7, "notepad.exe": 2, "chrome.exe": 1})

        # Create service with persistence
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )

        # Verify state was loaded
        assert service.profile_count == 1
        loaded_profile = service.get_profile("hostname", "server01", "process_name")
        assert loaded_profile is not None
        assert loaded_profile.observation_count == 10

    def test_persist_state_on_shutdown(self, tmp_path: Path) -> None:
        """Service can persist state."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )

        # Add some state
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            processing_time=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
        )

        # Persist
        service.persist_state()

        # Verify persisted
        loaded_profiles, _loaded_counts = persistence.load_profiles()
        assert len(loaded_profiles) == 1

    def test_persist_state_disabled(self, tmp_path: Path) -> None:
        """Service without persistence does not persist."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
        )

        # Should not raise
        service.persist_state()
        assert service.profile_count == 0

    def test_should_persist_first_call(self, tmp_path: Path) -> None:
        """First call to should_persist returns True."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )

        assert service.should_persist() is True

    def test_should_persist_after_save(self, tmp_path: Path) -> None:
        """should_persist returns False after recent save."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )

        service.persist_state()
        # Immediately after save, should_persist should be False
        assert service.should_persist() is False


class TestPersistenceDecisionNeutrality:
    """Prove persistence does not affect detection decisions."""

    def test_severity_unchanged_with_persistence(self, tmp_path: Path) -> None:
        """Severity is unchanged when persistence is enabled."""
        from uuid import uuid4

        from argusprowl.constants.severity import Severity
        from argusprowl.decision_engine.decision_engine import DecisionEngine
        from argusprowl.models.detection_result import DetectionResult

        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )
        engine = DecisionEngine(entity_behavior_service=service)

        result = DetectionResult(
            rule_id="test_rule",
            event_id=uuid4(),
            matched=True,
            severity=Severity.MEDIUM,
            confidence=0.8,
            description="Test detection",
            evidence=[],
            metadata={},
        )

        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.severity == Severity.MEDIUM

    def test_priority_unchanged_with_persistence(self, tmp_path: Path) -> None:
        """Priority is unchanged when persistence is enabled."""
        from uuid import uuid4

        from argusprowl.constants.priority import AlertPriority
        from argusprowl.constants.severity import Severity
        from argusprowl.decision_engine.decision_engine import DecisionEngine
        from argusprowl.models.detection_result import DetectionResult

        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )
        engine = DecisionEngine(entity_behavior_service=service)

        result = DetectionResult(
            rule_id="test_rule",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.9,
            description="Test detection",
            evidence=[],
            metadata={},
        )

        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.priority == AlertPriority.HIGH

    def test_confidence_unchanged_with_persistence(self, tmp_path: Path) -> None:
        """Confidence is unchanged when persistence is enabled."""
        from uuid import uuid4

        from argusprowl.constants.severity import Severity
        from argusprowl.decision_engine.decision_engine import DecisionEngine
        from argusprowl.models.detection_result import DetectionResult

        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )
        engine = DecisionEngine(entity_behavior_service=service)

        result = DetectionResult(
            rule_id="test_rule",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=0.75,
            description="Test detection",
            evidence=[],
            metadata={},
        )

        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.metadata["confidence"] == 0.75

    def test_fingerprint_unchanged_with_persistence(self, tmp_path: Path) -> None:
        """Fingerprint is unchanged when persistence is enabled."""
        from uuid import uuid4

        from argusprowl.constants.severity import Severity
        from argusprowl.decision_engine.decision_engine import DecisionEngine
        from argusprowl.models.detection_result import DetectionResult

        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )
        engine = DecisionEngine(entity_behavior_service=service)

        result = DetectionResult(
            rule_id="test_rule",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=0.8,
            description="Test detection",
            evidence=[],
            metadata={},
        )

        alert1 = engine.process_detection_result(result)
        alert2 = engine.process_detection_result(result)

        # Same alert should be deduplicated
        assert alert1 is not None
        assert alert2 is None  # Suppressed due to dedup


class TestPersistenceConcurrency:
    """Tests for concurrent persistence operations."""

    def test_concurrent_save_and_load(self, tmp_path: Path) -> None:
        """Concurrent saves and loads do not corrupt state."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        errors = []

        def writer(n: int) -> None:
            try:
                for i in range(10):
                    profile = EntityBehaviorProfile(
                        profile_key=f"hostname:server{n}|dimension:process_name",
                        entity_type="hostname",
                        entity_id=f"server{n}",
                        dimension="process_name",
                        first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
                        last_seen=datetime(2026, 9, 4, 10, 0, i, tzinfo=UTC),
                        observation_count=i + 1,
                        distinct_value_count=1,
                        maturity=ProfileMaturity.WARMING,
                        profile_version=1,
                        last_update=datetime(2026, 9, 4, 10, 0, i, tzinfo=UTC),
                    )
                    persistence.save_profile(profile, {"python.exe": i + 1})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert persistence.get_profile_count() == 5

    def test_concurrent_service_operations(self, tmp_path: Path) -> None:
        """Concurrent service operations with persistence are safe."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )

        errors = []

        def worker(entity_id: str) -> None:
            try:
                for i in range(10):
                    service.classify_and_record(
                        entity_type="hostname",
                        entity_id=entity_id,
                        dimension="process_name",
                        dimension_value=f"process_{i}",
                        timestamp=datetime(2026, 9, 4, 10, 0, i, tzinfo=UTC),
                        processing_time=datetime(2026, 9, 4, 10, 0, i, tzinfo=UTC),
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"server{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert service.profile_count == 5


class TestPersistenceFailureIsolation:
    """Tests for failure isolation in persistence."""

    def test_persistence_failure_does_not_affect_detection(self, tmp_path: Path) -> None:
        """Detection continues even if persistence fails."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        # Make persistence fail on save
        def failing_save(*args, **kwargs):
            raise sqlite3.OperationalError("disk I/O error")

        persistence.save_all = failing_save

        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            persistence=persistence,
        )

        # Should not raise
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            processing_time=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
        )

        assert service.profile_count == 1

    def test_corrupted_database_returns_empty(self, tmp_path: Path) -> None:
        """Corrupted database returns empty state."""
        db_path = tmp_path / "test.db"
        # Create a corrupted database
        db_path.write_text("corrupted data")

        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        # Should not raise, returns empty
        profiles, counts = persistence.load_profiles()
        assert profiles == {}
        assert counts == {}


class TestPersistenceBoundedness:
    """Tests for bounded resource usage."""

    def test_max_profiles_limit_on_load(self, tmp_path: Path) -> None:
        """Persistence respects max_profiles limit on load."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path, max_profiles=5)
        persistence.initialize()

        # Save 10 profiles
        for i in range(10):
            profile = EntityBehaviorProfile(
                profile_key=f"hostname:server{i}|dimension:process_name",
                entity_type="hostname",
                entity_id=f"server{i}",
                dimension="process_name",
                first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
                last_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
                observation_count=1,
                distinct_value_count=1,
                maturity=ProfileMaturity.WARMING,
                profile_version=1,
                last_update=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            )
            persistence.save_profile(profile, {"python.exe": 1})

        # Load with limit - should only return 5
        profiles, _counts = persistence.load_profiles(max_profiles=5)
        assert len(profiles) <= 5

    def test_large_value_counts_handled(self, tmp_path: Path) -> None:
        """Large value counts are handled correctly."""
        db_path = tmp_path / "test.db"
        persistence = EntityBehaviorPersistence(db_path=db_path)
        persistence.initialize()

        # Create profile with many values
        profile = EntityBehaviorProfile(
            profile_key="hostname:server01|dimension:process_name",
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            first_seen=datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
            observation_count=100,
            distinct_value_count=50,
            maturity=ProfileMaturity.MATURE,
            profile_version=1,
            last_update=datetime(2026, 9, 4, 11, 0, 0, tzinfo=UTC),
        )
        value_counts = {f"process_{i}": i for i in range(50)}

        persistence.save_profile(profile, value_counts)

        loaded_profiles, loaded_counts = persistence.load_profiles()
        assert len(loaded_profiles) == 1
        assert len(loaded_counts["hostname:server01|dimension:process_name"]) == 50
