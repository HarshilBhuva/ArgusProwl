from datetime import UTC, datetime
from uuid import UUID

import pytest

from argusprowl.models.normalized_event import NormalizedEvent


def test_normalized_event_has_uuid_schema_and_round_trip() -> None:
    event = NormalizedEvent(
        source_type="zeek",
        event_type="network_connection",
        timestamp=datetime.now(UTC),
        src_ip="192.0.2.10",
        src_port=443,
        tags=("network",),
        attributes={"uid": "C1"},
    )
    assert isinstance(event.event_id, UUID)
    assert event.schema_version == 1
    restored = NormalizedEvent.from_dict(event.to_dict())
    assert restored.event_id == event.event_id
    assert restored.event_type == "network_connection"


def test_normalized_event_rejects_invalid_network_values() -> None:
    with pytest.raises(ValueError, match="src_ip"):
        NormalizedEvent(source_type="x", event_type="y", src_ip="not-an-ip")
    with pytest.raises(ValueError, match="src_port"):
        NormalizedEvent(source_type="x", event_type="y", src_port=65536)


def test_normalized_event_source_record_id() -> None:
    # Default is None
    event1 = NormalizedEvent(source_type="x", event_type="y")
    assert event1.source_record_id is None

    # Accepts string
    event2 = NormalizedEvent(source_type="x", event_type="y", source_record_id="12345")
    assert event2.source_record_id == "12345"

    # Rejects non-string
    with pytest.raises(ValueError, match="source_record_id must be a string"):
        NormalizedEvent(source_type="x", event_type="y", source_record_id=12345)  # type: ignore

    # Round-trip
    restored = NormalizedEvent.from_dict(event2.to_dict())
    assert restored.source_record_id == "12345"


def test_normalized_event_raw_event_types() -> None:
    # String
    event1 = NormalizedEvent(source_type="x", event_type="y", raw_event="raw string")
    assert event1.raw_event == "raw string"

    # Dict
    event2 = NormalizedEvent(source_type="x", event_type="y", raw_event={"key": "value"})
    assert event2.raw_event == {"key": "value"}

    # List of strings
    event3 = NormalizedEvent(source_type="x", event_type="y", raw_event=["line1", "line2"])
    assert event3.raw_event == ["line1", "line2"]

    # None
    event4 = NormalizedEvent(source_type="x", event_type="y", raw_event=None)
    assert event4.raw_event is None


def test_normalized_event_serialization_isolation() -> None:
    event = NormalizedEvent(
        source_type="x",
        event_type="y",
        metadata={"nested": {"a": 1}},
        attributes={"nested": {"b": 2}},
        raw_event={"nested": {"c": 3}},
    )

    serialized = event.to_dict()

    # Mutate serialized dict
    serialized["metadata"]["nested"]["a"] = 99
    serialized["attributes"]["nested"]["b"] = 99
    serialized["raw_event"]["nested"]["c"] = 99

    # Original event should be unchanged
    assert event.metadata["nested"]["a"] == 1
    assert event.attributes["nested"]["b"] == 2
    assert event.raw_event["nested"]["c"] == 3  # type: ignore


def test_normalized_event_backward_compatibility() -> None:
    # Old event dictionary without source_record_id
    old_dict = {
        "schema_version": 1,
        "event_id": "12345678-1234-5678-1234-567812345678",
        "source_type": "x",
        "event_type": "y",
        "timestamp": datetime.now(UTC).isoformat(),
        "severity": 0,
        "tags": [],
        "metadata": {},
        "attributes": {},
    }

    restored = NormalizedEvent.from_dict(old_dict)
    assert restored.source_record_id is None
    assert restored.schema_version == 1
