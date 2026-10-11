"""Tests for CardinalityCorrelationDetector and CardinalityState."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from argusprowl.detection.detectors.cardinality_correlation import CardinalityCorrelationDetector
from argusprowl.detection.detectors.cardinality_state import CardinalityState
from argusprowl.models.normalized_event import NormalizedEvent


def create_event(
    timestamp: datetime,
    src_ip: str = "192.168.1.1",
    dst_port: int = 80,
    event_type: str = "connection",
) -> NormalizedEvent:
    """Helper to create a normalized event."""
    return NormalizedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        event_type=event_type,
        source_type="test",
        src_ip=src_ip,
        dst_port=dst_port,
        attributes={},
    )


class TestCardinalityState:
    """Tests for CardinalityState."""

    def test_threshold_not_reached(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)
        triggered, count, _ = state.check_threshold(3, event1)
        assert not triggered
        assert count == 1

        event2 = create_event(t0 + timedelta(seconds=1), dst_port=81)
        state.add(event2, 81)
        triggered, count, _ = state.check_threshold(3, event2)
        assert not triggered
        assert count == 2

    def test_exact_threshold_reached(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)

        event2 = create_event(t0 + timedelta(seconds=1), dst_port=81)
        state.add(event2, 81)

        event3 = create_event(t0 + timedelta(seconds=2), dst_port=82)
        state.add(event3, 82)

        triggered, count, trigger_id = state.check_threshold(3, event3)
        assert triggered
        assert count == 3
        assert trigger_id == event3.event_id

    def test_duplicate_cardinality_value(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)

        event2 = create_event(t0 + timedelta(seconds=1), dst_port=80)
        state.add(event2, 80)

        triggered, count, _ = state.check_threshold(2, event2)
        assert not triggered
        assert count == 1

    def test_sliding_window_expiration(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)

        event2 = create_event(t0 + timedelta(minutes=4), dst_port=81)
        state.add(event2, 81)

        # event3 is 6 minutes after event1, so event1 should expire
        event3 = create_event(t0 + timedelta(minutes=6), dst_port=82)
        state.add(event3, 82)

        triggered, count, _ = state.check_threshold(3, event3)
        assert not triggered
        assert count == 2  # 81 and 82

    def test_exact_boundary(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)

        # Exactly 5 minutes later. Cutoff is t0. event1 timestamp is t0.
        # cutoff = t0 + 5m - 5m = t0.
        # event1.timestamp < cutoff is False (t0 < t0 is False).
        # So event1 should NOT expire.
        event2 = create_event(t0 + timedelta(minutes=5), dst_port=81)
        state.add(event2, 81)

        triggered, count, _ = state.check_threshold(2, event2)
        assert triggered
        assert count == 2

    def test_just_outside_boundary(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)

        # 5 minutes and 1 microsecond later.
        event2 = create_event(t0 + timedelta(minutes=5, microseconds=1), dst_port=81)
        state.add(event2, 81)

        triggered, count, _ = state.check_threshold(2, event2)
        assert not triggered
        assert count == 1

    def test_no_repeated_detection_while_triggered(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)
        event2 = create_event(t0 + timedelta(seconds=1), dst_port=81)
        state.add(event2, 81)

        triggered, count, trigger_id = state.check_threshold(2, event2)
        assert triggered
        assert trigger_id == event2.event_id

        # Add another unique value
        event3 = create_event(t0 + timedelta(seconds=2), dst_port=82)
        state.add(event3, 82)

        triggered, count, trigger_id = state.check_threshold(2, event3)
        assert not triggered  # Already triggered
        assert count == 3

    def test_re_arm_after_condition_clears(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)
        event2 = create_event(t0 + timedelta(seconds=1), dst_port=81)
        state.add(event2, 81)

        triggered, _count, _ = state.check_threshold(2, event2)
        assert triggered

        # event3 is 6 minutes after event1, so event1 expires.
        # Count drops to 1 (event2).
        event3 = create_event(t0 + timedelta(minutes=6), dst_port=80)
        state.add(event3, 80)

        triggered, _count, _ = state.check_threshold(2, event3)
        # Let's trace:
        # t0: 80
        # t0+1s: 81 -> triggers (count 2)
        # t0+6m: 80 -> event1 expires. Window has event2(81) and event3(80). Count is 2.
        # Does it trigger? The original trigger event was event2. event2 is still in the window!
        # So it should NOT re-arm yet.
        assert not triggered

        # Let's push event2 out of the window.
        event4 = create_event(t0 + timedelta(minutes=7), dst_port=82)
        state.add(event4, 82)
        # Now window has event3(80) and event4(82). Count is 2.
        # event2 has expired, so it should re-arm and trigger again!
        triggered, _count, trigger_id = state.check_threshold(2, event4)
        assert triggered
        assert trigger_id == event4.event_id

    def test_old_occurrence_expires_but_newer_remains(self):
        state = CardinalityState(group_key=("192.168.1.1",), window_duration=timedelta(minutes=5))
        t0 = datetime.now(UTC)

        event1 = create_event(t0, dst_port=80)
        state.add(event1, 80)

        event2 = create_event(t0 + timedelta(minutes=1), dst_port=80)
        state.add(event2, 80)

        event3 = create_event(t0 + timedelta(minutes=2), dst_port=81)
        state.add(event3, 81)

        # At t0 + 6m, event1 expires, but event2 (also port 80) is still in window.
        # So unique count should still be 2 (80 and 81).
        event4 = create_event(t0 + timedelta(minutes=6), dst_port=82)
        state.add(event4, 82)

        triggered, count, _ = state.check_threshold(3, event4)
        assert triggered
        assert count == 3  # 80, 81, 82


# ---------------------------------------------------------------------------
# Replay tests
# ---------------------------------------------------------------------------


class TestCardinalityReplay:
    def test_semantic_replay_sequence(self) -> None:
        """Test semantic replay sequence with threshold crossing, re-arming, and evidence."""
        from argusprowl.detection.detection_manager import DetectionManager
        from argusprowl.replay.replay_engine import ReplayEngine

        log_path = Path("/tmp/test_cardinality_semantic.log")
        base_time = datetime.now(UTC)

        # 1. produces fewer than threshold events (2 unique ports, threshold is 3)
        events = [
            create_event(timestamp=base_time, src_ip="10.0.0.1", dst_port=80),
            create_event(
                timestamp=base_time + timedelta(seconds=10), src_ip="10.0.0.1", dst_port=81
            ),
        ]

        # 2. reaches threshold (3rd unique port)
        events.append(
            create_event(
                timestamp=base_time + timedelta(seconds=20), src_ip="10.0.0.1", dst_port=82
            )
        )

        # 3. adds another event while already triggered (4th unique port)
        events.append(
            create_event(
                timestamp=base_time + timedelta(seconds=30), src_ip="10.0.0.1", dst_port=83
            )
        )

        # 4. lets the window clear (wait 6 minutes, window is 5 minutes)
        clear_time = base_time + timedelta(minutes=6)

        # 5. reaches threshold again (3 more unique ports)
        events.extend(
            [
                create_event(timestamp=clear_time, src_ip="10.0.0.1", dst_port=80),
                create_event(
                    timestamp=clear_time + timedelta(seconds=10), src_ip="10.0.0.1", dst_port=81
                ),
                create_event(
                    timestamp=clear_time + timedelta(seconds=20), src_ip="10.0.0.1", dst_port=82
                ),
            ]
        )

        # Mock ReplayReader to yield our events directly instead of parsing a file
        class MockReplayReader:
            def __init__(self, log_path):
                self._log_path = log_path

            def read_events(self):
                yield from events

        try:
            correlator = CardinalityCorrelationDetector(
                cardinality_field="dst_port",
                threshold=3,
                timespan=timedelta(minutes=5),
                group_by=["src_ip"],
            )
            manager = DetectionManager()
            manager.register_detector(correlator)

            # We need to capture DetectionResults, not just Alerts
            # ReplayEngine._process_replay_event returns DetectionResults
            results = []

            # Mock ReplayEngine to capture results and use MockReplayReader
            class CapturingReplayEngine(ReplayEngine):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self._reader = MockReplayReader(kwargs.get("log_path"))

                def _process_replay_event(self, event, on_feature_vector=None):
                    res = super()._process_replay_event(event, on_feature_vector)
                    results.extend([r for r in res if r.matched])
                    return res

            # Create a dummy file so ReplayReader init doesn't fail before we replace it
            with log_path.open("w") as f:
                f.write("")

            replay = CapturingReplayEngine(
                log_path=log_path,
                detection_manager=manager,
            )
            replay.run()

            # Verify the expected DetectionResults
            assert len(results) == 2

            # First threshold crossing
            res1 = results[0]
            assert res1.event_id == events[2].event_id
            assert len(res1.contributing_event_ids) == 3
            assert set(res1.contributing_event_ids) == {e.event_id for e in events[0:3]}

            # Check evidence
            evidence_dict1 = {e["field"]: e["observed"] for e in res1.evidence}
            assert evidence_dict1["src_ip"] == "10.0.0.1"
            assert evidence_dict1["dst_port"] == 3

            # Second detection after re-arm
            res2 = results[1]
            assert res2.event_id == events[6].event_id
            assert len(res2.contributing_event_ids) == 3
            assert set(res2.contributing_event_ids) == {e.event_id for e in events[4:7]}

            # Check evidence
            evidence_dict2 = {e["field"]: e["observed"] for e in res2.evidence}
            assert evidence_dict2["src_ip"] == "10.0.0.1"
            assert evidence_dict2["dst_port"] == 3

        finally:
            log_path.unlink(missing_ok=True)


class TestCardinalityCorrelationDetector:
    """Tests for CardinalityCorrelationDetector."""

    def test_basic_detection(self):
        detector = CardinalityCorrelationDetector(
            cardinality_field="dst_port",
            threshold=3,
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        res1 = detector.detect(create_event(t0, dst_port=80))
        assert not res1.matched
        detector.observe(create_event(t0, dst_port=80))

        res2 = detector.detect(create_event(t0 + timedelta(seconds=1), dst_port=81))
        assert not res2.matched
        detector.observe(create_event(t0 + timedelta(seconds=1), dst_port=81))

        event3 = create_event(t0 + timedelta(seconds=2), dst_port=82)
        detector.observe(event3)
        res3 = detector.detect(event3)
        assert res3.matched
        assert res3.event_id == event3.event_id
        assert len(res3.evidence) == 2
        assert res3.evidence[0]["field"] == "dst_port"
        assert res3.evidence[0]["observed"] == 3
        assert res3.evidence[1]["field"] == "src_ip"
        assert res3.evidence[1]["observed"] == "192.168.1.1"

    def test_different_groups_isolated(self):
        detector = CardinalityCorrelationDetector(
            cardinality_field="dst_port",
            threshold=2,
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, src_ip="192.168.1.1", dst_port=80))
        detector.observe(create_event(t0, src_ip="192.168.1.2", dst_port=81))

        res1 = detector.detect(
            create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1", dst_port=80)
        )
        assert not res1.matched  # Same port, count is 1

        event3 = create_event(t0 + timedelta(seconds=1), src_ip="192.168.1.1", dst_port=82)
        detector.observe(event3)
        res3 = detector.detect(event3)
        assert res3.matched

    def test_missing_group_field(self):
        detector = CardinalityCorrelationDetector(
            cardinality_field="dst_port",
            threshold=2,
            timespan=timedelta(minutes=5),
            group_by=["username"],  # Event doesn't have username
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, dst_port=80))
        event2 = create_event(t0 + timedelta(seconds=1), dst_port=81)
        detector.observe(event2)
        res = detector.detect(event2)
        assert res.matched
        assert res.evidence[1]["field"] == "username"
        assert res.evidence[1]["observed"] == ""

    def test_missing_cardinality_field(self):
        detector = CardinalityCorrelationDetector(
            cardinality_field="nonexistent_field",
            threshold=2,
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0))
        res = detector.detect(create_event(t0 + timedelta(seconds=1)))
        assert not res.matched

    def test_filtering(self):
        detector = CardinalityCorrelationDetector(
            cardinality_field="dst_port",
            threshold=2,
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
            filter_config={"event_type": "connection"},
        )
        t0 = datetime.now(UTC)

        detector.observe(create_event(t0, dst_port=80, event_type="connection"))

        # This event should be ignored due to filter
        detector.observe(create_event(t0 + timedelta(seconds=1), dst_port=81, event_type="other"))

        event3 = create_event(t0 + timedelta(seconds=2), dst_port=82, event_type="connection")
        detector.observe(event3)
        res = detector.detect(event3)
        assert res.matched
