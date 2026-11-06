"""Regression tests for bounded and optimized hot-path state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.temporal.temporal_state import TemporalBucket, TemporalObservation


def _observation(timestamp: datetime, *, source_record_id: str | None = None) -> TemporalObservation:
    return TemporalObservation(
        event_id=uuid4(), timestamp=timestamp, dst_ip="203.0.113.10", dst_port=443,
        source_record_id=source_record_id,
    )


def test_temporal_identity_index_tracks_capacity_eviction() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    bucket = TemporalBucket(key=("203.0.113.10", 443), max_observations=2)
    assert bucket.add(_observation(start, source_record_id="zeek-1"))
    assert bucket.add(_observation(start + timedelta(seconds=1), source_record_id="zeek-2"))
    assert bucket.add(_observation(start + timedelta(seconds=2), source_record_id="zeek-3"))
    assert len(bucket) == 2
    # Capacity eviction must also remove the old identity from the index.
    assert bucket.add(_observation(start + timedelta(seconds=3), source_record_id="zeek-1"))


def test_temporal_identity_index_rejects_duplicate_source_record() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    bucket = TemporalBucket(key=("203.0.113.10", 443))
    assert bucket.add(_observation(start, source_record_id="zeek-uid"))
    assert not bucket.add(_observation(start + timedelta(seconds=1), source_record_id="zeek-uid"))
    assert len(bucket) == 1


def test_temporal_append_fast_path_preserves_late_event_order() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    bucket = TemporalBucket(key=("203.0.113.10", 443), allowed_lateness=timedelta(seconds=30))
    for offset in (0, 20, 10, 30, 25):
        assert bucket.add(_observation(start + timedelta(seconds=offset)))
    timestamps = [item.timestamp for item in bucket.observations]
    assert timestamps == sorted(timestamps)
    assert len(bucket) == 5


def test_feature_extractor_bounds_source_window_registry() -> None:
    extractor = FeatureExtractor(window_size_seconds=60, max_active_windows=2)
    base = datetime.now(UTC)
    for index, source in enumerate(("192.0.2.1", "192.0.2.2", "192.0.2.3")):
        event = NormalizedEvent(
            source_type="test", event_type="network_connection",
            timestamp=base + timedelta(seconds=index), src_ip=source,
            dst_ip="203.0.113.10", dst_port=443,
        )
        assert extractor.extract(event) is not None
    assert extractor.active_window_count == 2
    assert extractor.get_window("192.0.2.1") is None
    assert extractor.get_window("192.0.2.2") is not None
    assert extractor.get_window("192.0.2.3") is not None


def test_feature_extractor_rejects_invalid_registry_bound() -> None:
    with pytest.raises(ValueError, match="max_active_windows"):
        FeatureExtractor(max_active_windows=0)
