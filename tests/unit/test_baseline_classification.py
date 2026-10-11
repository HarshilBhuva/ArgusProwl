"""Tests for baseline classification (Phase 5.1.5).

Comprehensive tests for the baseline behavioral state implementation including:
- Classification-before-recording semantics
- All five baseline classification states
- Maturity transitions (EMPTY → WARMING → MATURE)
- Stale behavior (MATURE → STALE → WARMING)
- Timestamp clamping for future-timestamp protection
- Replay parity verification
- Atomic concurrent classification/recording
- Result immutability
- Value bounds and counter saturation
"""

from datetime import UTC, datetime, timedelta
from threading import Thread

import pytest

from argusprowl.behavior.baseline import (
    BaselineClassification,
    BaselineClassificationResult,
    BaselineMaturityState,
)
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService


class TestBaselineModels:
    """Tests for baseline classification models."""

    def test_baseline_classification_enum_values(self) -> None:
        """Verify all expected classification enum values exist."""
        assert BaselineClassification.BASELINE_UNAVAILABLE.value == "baseline_unavailable"
        assert BaselineClassification.BASELINE_WARMING.value == "baseline_warming"
        assert BaselineClassification.BASELINE_NEW_VALUE.value == "baseline_new_value"
        assert BaselineClassification.BASELINE_RARE_VALUE.value == "baseline_rare_value"
        assert BaselineClassification.BASELINE_ESTABLISHED.value == "baseline_established"

    def test_baseline_maturity_state_values(self) -> None:
        """Verify all expected maturity state values exist."""
        assert BaselineMaturityState.EMPTY.value == "empty"
        assert BaselineMaturityState.WARMING.value == "warming"
        assert BaselineMaturityState.MATURE.value == "mature"
        assert BaselineMaturityState.STALE.value == "stale"

    def test_classification_result_immutability(self) -> None:
        """Verify BaselineClassificationResult is immutable (frozen)."""
        result = BaselineClassificationResult(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            classification=BaselineClassification.BASELINE_ESTABLISHED,
            profile_maturity=BaselineMaturityState.MATURE,
            pre_observation_value_count=5,
            observation_count=10,
            first_seen=datetime(2026, 9, 1, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, tzinfo=UTC),
        )

        # Attempting to modify should raise FrozenInstanceError
        with pytest.raises(AttributeError):
            result.classification = BaselineClassification.BASELINE_NEW_VALUE

        with pytest.raises(AttributeError):
            result.observation_count = 100

    def test_classification_result_to_dict(self) -> None:
        """Verify serialization of classification result."""
        first_seen = datetime(2026, 9, 1, tzinfo=UTC)
        last_seen = datetime(2026, 9, 4, tzinfo=UTC)
        result = BaselineClassificationResult(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            classification=BaselineClassification.BASELINE_ESTABLISHED,
            profile_maturity=BaselineMaturityState.MATURE,
            pre_observation_value_count=5,
            observation_count=10,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        d = result.to_dict()
        assert d["entity_id"] == "host1"
        assert d["field"] == "process_name"
        assert d["value"] == "notepad.exe"
        assert d["classification"] == "baseline_established"
        assert d["profile_maturity"] == "mature"
        assert d["pre_observation_value_count"] == 5
        assert d["observation_count"] == 10
        assert d["first_seen"] == first_seen.isoformat()
        assert d["last_seen"] == last_seen.isoformat()


class TestClassificationBeforeRecording:
    """Tests verifying classification occurs BEFORE recording."""

    def test_classification_before_recording(self) -> None:
        """Verify classify_and_record reflects pre-observation state."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=1.0,
            baseline_rare_threshold=3,
            baseline_stale_after_seconds=3600.0,
        )

        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        processing_time = ts + timedelta(seconds=10)

        # Record a few observations to build up count
        for i in range(6):
            result, _ = service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=processing_time + timedelta(seconds=i),
            )

        # Advance time so profile becomes MATURE
        # First seen at ts, last seen at ts+5s, maturity_window=1s, need 5 obs
        ts + timedelta(seconds=10)
        service2 = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=1.0,
            baseline_rare_threshold=3,
            baseline_stale_after_seconds=3600.0,
        )

        # Build profile to maturity
        for i in range(5):
            service2.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=60 + i),
            )

        # Verify classification reflects count BEFORE recording
        # notepad.exe has count 5 (observations 0-4)
        # rare_threshold is 3, so count=5 > 3 means ESTABLISHED
        result, _profile = service2.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_ESTABLISHED
        # The count BEFORE recording was 5, which is > rare_threshold (3)
        # and profile is MATURE (5 obs + age > 1s)

        # Verify observation_count is AFTER recording (incremented)
        assert result.observation_count == 6  # 5 before + 1 current


class TestFirstObservation:
    """Tests for first observation handling."""

    def test_first_observation_unavailable_classification(self) -> None:
        """First observation with no profile should be UNAVAILABLE."""
        service = EntityBehaviorService()
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        result, profile = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts,
            processing_time=ts,
        )

        # First observation: no profile exists yet
        assert result.classification == BaselineClassification.BASELINE_UNAVAILABLE
        assert result.profile_maturity == BaselineMaturityState.WARMING
        assert profile.observation_count == 1
        assert profile.maturity.value == "warming"


class TestNewValueClassification:
    """Tests for new value classification."""

    def test_new_value_with_mature_profile(self) -> None:
        """Unknown value with MATURE profile should be NEW_VALUE."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with known values
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Wait for maturity window
        # Now classify a NEW value
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="malware.exe",  # Never seen before
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_NEW_VALUE


class TestRareValueClassification:
    """Tests for rare value classification."""

    def test_rare_value_classification(self) -> None:
        """Known value with count <= rare_threshold should be RARE_VALUE."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,  # Count > 2 → ESTABLISHED
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with values
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add a few more observations of a second value
        for i in range(3):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="calc.exe",
                timestamp=ts + timedelta(seconds=50 + i),
                processing_time=ts + timedelta(seconds=50 + i),
            )

        # calc.exe count is 3, which is > rare_threshold (2)
        # So it should be ESTABLISHED, not RARE
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="calc.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )
        assert result.classification == BaselineClassification.BASELINE_ESTABLISHED

        # Test RARE: value seen only once
        service2 = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )

        for i in range(5):
            service2.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add a value only once (count = 1, which is <= rare_threshold of 2)
        service2.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=50),
            processing_time=ts + timedelta(seconds=50),
        )

        # Now observe rare.exe again
        result, _ = service2.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        # Count before recording was 1, which is <= rare_threshold (2)
        assert result.classification == BaselineClassification.BASELINE_RARE_VALUE


class TestEstablishedValueClassification:
    """Tests for established value classification."""

    def test_established_value_classification(self) -> None:
        """Known value with count > rare_threshold and MATURE profile should be ESTABLISHED."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add more observations of notepad.exe to exceed rare_threshold
        for i in range(3):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=50 + i),
                processing_time=ts + timedelta(seconds=50 + i),
            )

        # Now notepad.exe has count 5 (before this observation)
        # 5 > 2 (rare_threshold) → ESTABLISHED
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_ESTABLISHED


class TestWarmingProfileBlocksEstablished:
    """Tests that warming profile never returns ESTABLISHED."""

    def test_warming_profile_returns_warming(self) -> None:
        """Profile WARMING should never return ESTABLISHED regardless of count."""
        service = EntityBehaviorService(
            maturity_min_observations=100,  # High threshold - never reached
            maturity_window_seconds=3600.0,
            baseline_rare_threshold=1,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build profile with many observations but not mature
        for i in range(50):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Should still be WARMING, not ESTABLISHED
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_WARMING
        assert result.profile_maturity == BaselineMaturityState.WARMING


class TestMaturityTransitions:
    """Tests for maturity state transitions."""

    def test_maturity_requires_both_conditions(self) -> None:
        """Maturity requires both observation count AND age."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Test: Enough observations but not enough age
        service1 = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=3600.0,  # 1 hour
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )

        for i in range(5):
            service1.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Profile has 5 obs but only 4 seconds of age, not 1 hour
        result, _ = service1.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.profile_maturity == BaselineMaturityState.WARMING
        assert result.classification == BaselineClassification.BASELINE_WARMING

        # Test: Enough age but not enough observations
        service2 = EntityBehaviorService(
            maturity_min_observations=100,  # High threshold
            maturity_window_seconds=0.1,  # Short window
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )

        for i in range(10):
            service2.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service2.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.profile_maturity == BaselineMaturityState.WARMING

    def test_empty_to_warming_to_mature(self) -> None:
        """Verify EMPTY → WARMING → MATURE transition.

        Note: Classification reflects state BEFORE recording, maturity AFTER.
        """
        service = EntityBehaviorService(
            maturity_min_observations=3,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # First observation: no profile
        result1, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts,
            processing_time=ts,
        )
        assert result1.classification == BaselineClassification.BASELINE_UNAVAILABLE
        assert result1.profile_maturity == BaselineMaturityState.WARMING

        # Second observation
        result2, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=1),
            processing_time=ts + timedelta(seconds=1),
        )
        # Profile was WARMING before recording (only 1 obs)
        assert result2.classification == BaselineClassification.BASELINE_WARMING
        # After recording: 2 obs, 1s age < 0.1s window, still WARMING
        assert result2.profile_maturity == BaselineMaturityState.WARMING

        # Third observation
        result3, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=2),
            processing_time=ts + timedelta(seconds=2),
        )
        # Profile was WARMING before recording (2 obs < 3)
        assert result3.classification == BaselineClassification.BASELINE_WARMING
        # After recording: 3 obs, 2s age > 0.1s window → MATURE
        assert result3.profile_maturity == BaselineMaturityState.MATURE


class TestStaleBehavior:
    """Tests for stale profile behavior."""

    def test_stale_profile_transitions_to_warming(self) -> None:
        """Stale profile should transition to WARMING, not directly to MATURE.

        Note: Classification reflects state BEFORE recording, maturity AFTER.
        """
        service = EntityBehaviorService(
            maturity_min_observations=3,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=1.0,  # 1 second stale timeout
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(3):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Verify mature
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=2),
            processing_time=ts + timedelta(seconds=2),
        )
        assert result.profile_maturity == BaselineMaturityState.MATURE

        # Now advance time past stale threshold
        # Last seen was at ts+2s, stale_after is 1s
        # At ts+4s processing time, profile is stale
        result2, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=3),
            processing_time=ts + timedelta(seconds=10),  # 7 seconds since last event
        )

        # Should transition to WARMING (not MATURE) due to staleness
        # Classification reflects STALE → WARMING
        assert result2.classification == BaselineClassification.BASELINE_WARMING
        assert result2.profile_maturity == BaselineMaturityState.WARMING

        # Adding more observations - profile is WARMING so classification is WARMING
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=11 + i),
                processing_time=ts + timedelta(seconds=11 + i),
            )

        result3, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=20),
            processing_time=ts + timedelta(seconds=20),
        )

        # Now should be MATURE again (3+5+1=9 obs + sufficient age)
        assert result3.profile_maturity == BaselineMaturityState.MATURE


class TestFutureTimestampClamping:
    """Tests for future timestamp handling."""

    def test_future_timestamp_clamping(self) -> None:
        """Future timestamps beyond skew threshold should be clamped."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            future_skew_threshold_seconds=60.0,  # 60 seconds
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Create event with timestamp 2 hours in the future
        future_ts = ts + timedelta(hours=2)
        processing_time = ts

        _result, profile = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=future_ts,
            processing_time=processing_time,
        )

        # Timestamp should be clamped
        assert profile.first_seen is not None
        assert profile.first_seen <= processing_time + timedelta(seconds=60)

        # last_seen should also be clamped
        assert profile.last_seen is not None
        assert profile.last_seen <= processing_time + timedelta(seconds=60)


class TestReplayParity:
    """Tests for live/replay parity."""

    def test_replay_parity_identical_clamping(self) -> None:
        """Replay and live should produce identical results, including clamping."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Configuration
        config = dict(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            future_skew_threshold_seconds=60.0,
            baseline_stale_after_seconds=3600.0,
        )

        live_service = EntityBehaviorService(**config, is_replay_mode=False)
        replay_service = EntityBehaviorService(**config, is_replay_mode=True)

        # Event stream: identical ordered events, timestamps, processing_time
        events = [
            # 1. Normal event
            (ts, ts, "notepad.exe"),
            # 2. Normal event
            (ts + timedelta(seconds=1), ts + timedelta(seconds=1), "notepad.exe"),
            # 3. Future event (should be clamped)
            (ts + timedelta(hours=2), ts + timedelta(seconds=2), "notepad.exe"),
            # 4. Normal event
            (ts + timedelta(seconds=3), ts + timedelta(seconds=3), "notepad.exe"),
            # 5. Normal event (reaches maturity)
            (ts + timedelta(seconds=4), ts + timedelta(seconds=4), "notepad.exe"),
            # 6. New value
            (ts + timedelta(seconds=5), ts + timedelta(seconds=5), "new_app.exe"),
        ]

        for event_ts, proc_ts, value in events:
            live_result, live_profile = live_service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value=value,
                timestamp=event_ts,
                processing_time=proc_ts,
            )

            replay_result, replay_profile = replay_service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value=value,
                timestamp=event_ts,
                processing_time=proc_ts,
            )

            # Assert identical classification results
            assert live_result.classification == replay_result.classification
            assert live_result.profile_maturity == replay_result.profile_maturity
            assert live_result.observation_count == replay_result.observation_count
            assert live_result.first_seen == replay_result.first_seen
            assert live_result.last_seen == replay_result.last_seen

            # Assert identical profile state
            assert live_profile.first_seen == replay_profile.first_seen
            assert live_profile.last_seen == replay_profile.last_seen
            assert live_profile.observation_count == replay_profile.observation_count
            assert live_profile.maturity == replay_profile.maturity


class TestConcurrentObservations:
    """Tests for concurrent observation handling."""

    def test_concurrent_classification_recording(self) -> None:
        """Verify atomic classification/recording under concurrent access."""
        service = EntityBehaviorService(
            maturity_min_observations=20,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=5,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Pre-populate to near maturity
        for i in range(15):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        results: list[BaselineClassificationResult] = []
        errors: list[Exception] = []

        def classify_observation(value: str, delay: float = 0) -> None:
            try:
                if delay:
                    import time

                    time.sleep(delay)
                result, _ = service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value=value,
                    timestamp=ts + timedelta(seconds=100),
                    processing_time=ts + timedelta(seconds=100),
                )
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Run concurrent classifications
        threads = []
        for i in range(10):
            t = Thread(target=classify_observation, args=(f"app_{i}.exe", i * 0.001))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # No errors should have occurred
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # All results should be valid
        assert len(results) == 10
        for result in results:
            assert isinstance(result, BaselineClassificationResult)
            # New unique values should be classified as NEW_VALUE
            # But profile might be WARMING (15 obs < 20 maturity_min_observations)
            assert result.classification in (
                BaselineClassification.BASELINE_NEW_VALUE,
                BaselineClassification.BASELINE_WARMING,
            )


class TestValueBounds:
    """Tests for value bounds and counter limits."""

    def test_distinct_value_bounds(self) -> None:
        """Verify distinct value count respects max limit with LRU eviction.

        The BoundedValueSet enforces the limit; the profile's distinct_value_count
        reflects the number of times new values were added (not currently stored).
        """
        service = EntityBehaviorService(
            max_values_per_profile=5,  # Small limit for testing
            maturity_min_observations=100,
            maturity_window_seconds=3600.0,
            baseline_rare_threshold=5,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Add 10 distinct values
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value=f"app_{i}.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Check the actual value set is bounded
        values = service.get_profile_values(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )
        assert len(values) <= 5, f"Value set has {len(values)} values, expected <= 5"

        # Profile can still be queried
        profile = service.get_profile(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )
        assert profile is not None
        # Total observations should be 10
        assert profile.observation_count == 10

    def test_observation_count_saturates(self) -> None:
        """Verify observation count saturates at maximum."""
        service = EntityBehaviorService(
            maturity_min_observations=1000000,
            maturity_window_seconds=3600.0,
            baseline_rare_threshold=5,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Record many observations
        for i in range(2000):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        profile = service.get_profile(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )
        assert profile is not None
        # Count should saturate, not overflow
        assert profile.observation_count <= EntityBehaviorService._SATURATING_COUNTER_MAX


class TestQueryMethods:
    """Tests for query-only classification methods."""

    def test_get_baseline_classification_no_record(self) -> None:
        """Verify query doesn't modify state."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        profile_before = service.get_profile(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )
        assert profile_before is not None
        count_before = profile_before.observation_count

        # Query without recording - should return mature classification
        classification = service.get_baseline_classification(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
        )

        # Should return a valid classification
        assert classification is not None
        assert classification in (
            BaselineClassification.BASELINE_ESTABLISHED,
            BaselineClassification.BASELINE_RARE_VALUE,
            BaselineClassification.BASELINE_WARMING,
        )

        # Verify state unchanged
        profile_after = service.get_profile(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )
        assert profile_after is not None
        assert profile_after.observation_count == count_before

    def test_get_baseline_classification_no_profile(self) -> None:
        """Query on non-existent profile returns None."""
        service = EntityBehaviorService()
        classification = service.get_baseline_classification(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
            dimension_value="notepad.exe",
        )
        assert classification is None


class TestSummaryNotClassification:
    """Tests verifying EntityBehaviorSummary is descriptive only."""

    def test_summary_does_not_contain_classification(self) -> None:
        """Verify EntityBehaviorSummary doesn't embed classification."""
        # EntityBehaviorSummary should not have a classification field
        import inspect

        from argusprowl.behavior.entity_behavior_summary import EntityBehaviorSummary

        sig = inspect.signature(EntityBehaviorSummary)
        field_names = list(sig.parameters.keys())

        assert "classification" not in field_names
        assert "baseline_classification" not in field_names
        assert "risk_score" not in field_names
        assert "anomaly_score" not in field_names


class TestServiceConfiguration:
    """Tests for service configuration validation."""

    def test_invalid_maturity_min_observations(self) -> None:
        """Invalid maturity_min_observations raises ValueError."""
        with pytest.raises(ValueError, match="maturity_min_observations must be positive"):
            EntityBehaviorService(maturity_min_observations=0)

    def test_invalid_maturity_window(self) -> None:
        """Invalid maturity_window_seconds raises ValueError."""
        with pytest.raises(ValueError, match="maturity_window_seconds must be positive"):
            EntityBehaviorService(maturity_window_seconds=0)

    def test_invalid_rare_threshold(self) -> None:
        """Invalid baseline_rare_threshold raises ValueError."""
        with pytest.raises(ValueError, match="baseline_rare_threshold must be positive"):
            EntityBehaviorService(baseline_rare_threshold=0)

    def test_invalid_future_skew_threshold(self) -> None:
        """Invalid future_skew_threshold_seconds raises ValueError."""
        with pytest.raises(ValueError, match="future_skew_threshold_seconds must be non-negative"):
            EntityBehaviorService(future_skew_threshold_seconds=-1)

    def test_invalid_stale_after(self) -> None:
        """Invalid baseline_stale_after_seconds raises ValueError."""
        with pytest.raises(ValueError, match="baseline_stale_after_seconds must be positive"):
            EntityBehaviorService(baseline_stale_after_seconds=0)


class TestOutOfOrderTimestamps:
    """Tests for out-of-order timestamp handling."""

    def test_out_of_order_newer_then_older(self) -> None:
        service = EntityBehaviorService()
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Newer event
        _, _p1 = service.classify_and_record(
            "host", "h1", "proc", "a.exe", ts + timedelta(seconds=10), ts + timedelta(seconds=10)
        )
        # Older event
        _, p2 = service.classify_and_record(
            "host", "h1", "proc", "b.exe", ts, ts + timedelta(seconds=11)
        )

        assert p2.first_seen == ts
        assert p2.last_seen == ts + timedelta(seconds=10)

    def test_out_of_order_older_then_newer(self) -> None:
        service = EntityBehaviorService()
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Older event
        _, _p1 = service.classify_and_record("host", "h1", "proc", "a.exe", ts, ts)
        # Newer event
        _, p2 = service.classify_and_record(
            "host", "h1", "proc", "b.exe", ts + timedelta(seconds=10), ts + timedelta(seconds=10)
        )

        assert p2.first_seen == ts
        assert p2.last_seen == ts + timedelta(seconds=10)

    def test_out_of_order_mixed_with_clamping(self) -> None:
        service = EntityBehaviorService(future_skew_threshold_seconds=60.0)
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        events = [
            (ts + timedelta(seconds=10), ts + timedelta(seconds=10)),  # normal
            (
                ts + timedelta(hours=2),
                ts + timedelta(seconds=11),
            ),  # future (clamped to ts + 11s + 60s = ts + 71s)
            (ts, ts + timedelta(seconds=12)),  # older
            (ts + timedelta(seconds=5), ts + timedelta(seconds=13)),  # mixed
        ]

        for event_ts, proc_ts in events:
            _, p = service.classify_and_record("host", "h1", "proc", "a.exe", event_ts, proc_ts)

        assert p.first_seen == ts
        assert p.last_seen == ts + timedelta(seconds=71)
