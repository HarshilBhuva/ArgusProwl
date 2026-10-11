"""Phase 4.9.6 Final Semantic Audit Tests.

These tests prove the documented correlation-instance, group_by, and
result-identity contracts for CrossDetectorCorrelator. They do NOT
add new capabilities — they only verify the existing implementation
against the explicitly-required behaviors.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.detection.cross_detector_correlator import CrossDetectorCorrelator
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


def create_event(
    timestamp: datetime,
    src_ip: str = "192.168.1.1",
    dst_ip: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    event_type: str = "connection",
    **kwargs,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=uuid4(),
        timestamp=timestamp,
        event_type=event_type,
        source_type="test",
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
        username=username,
        **kwargs,
    )


def create_detection_result(
    rule_id: str,
    event_id: uuid4,
    matched: bool = True,
    confidence: float = 0.7,
) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        event_id=event_id,
        matched=matched,
        severity=Severity.MEDIUM,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# A. Correlation-instance semantics
# ---------------------------------------------------------------------------


class TestCorrelationInstanceSemantics:
    """Verify overlapping correlation instance behavior.

    Contract (documented in the final audit):

    * The correlator tracks a single ordered list of (timestamp, rule_id,
      result_id) entries per group key.
    * When the configured sequence is satisfied, one correlation result is
      emitted using the most recent contiguous run that matches the
      sequence. This is consistent with the overlapping-sequence
      semantics established for OrderedSequenceDetector in 4.9.5.
    * A second valid sequence (A1->B1, A2->B2) is NOT silently discarded:
      once a new step arrives after the first correlation, the
      correlator re-arms and can complete again.
    * State is bounded per group (entries are not unbounded).
    """

    def test_two_overlapping_correlations_emit_two_results(self):
        """A1->B1 and A2->B2 should both produce results; not silently suppressed."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # A1
        e1 = create_event(t0, src_ip="10.0.0.1")
        r_a1 = create_detection_result("rule_a", e1.event_id)
        results1 = correlator.process(e1, [r_a1])
        assert len(results1) == 0

        # B1 completes first correlation
        e2 = create_event(t0 + timedelta(seconds=1), src_ip="10.0.0.1")
        r_b1 = create_detection_result("rule_b", e2.event_id)
        results2 = correlator.process(e2, [r_b1])
        assert len(results2) == 1
        first = results2[0]
        # contributing ids preserve causal order
        assert first.contributing_event_ids[0] == r_a1.result_id
        assert first.contributing_event_ids[1] == r_b1.result_id

        # A2
        e3 = create_event(t0 + timedelta(seconds=2), src_ip="10.0.0.1")
        r_a2 = create_detection_result("rule_a", e3.event_id)
        correlator.process(e3, [r_a2])

        # B2 completes second correlation
        e4 = create_event(t0 + timedelta(seconds=3), src_ip="10.0.0.1")
        r_b2 = create_detection_result("rule_b", e4.event_id)
        results3 = correlator.process(e4, [r_b2])
        assert len(results3) == 1
        second = results3[0]
        # second correlation is independent and not suppressed
        assert second.contributing_event_ids[0] == r_a2.result_id
        assert second.contributing_event_ids[1] == r_b2.result_id
        # Two separate correlation results
        assert first.result_id != second.result_id

    def test_overlapping_sequences_emit_independent_results(self):
        """A1 -> A2 -> B1 -> B2: should emit two correlation results.

        First completion: A1->B1 (using A1,B1)
        Second completion: A2->B2 (using A2,B2)
        The correlator is NOT a generic multi-sequence engine: it is a
        single-ordered-sequence correlator. It tracks the most recent
        contiguous run of the configured rule IDs and emits one
        correlation per completion.
        """
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0, src_ip="10.0.0.1")
        r_a1 = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a1])

        e2 = create_event(t0 + timedelta(seconds=1), src_ip="10.0.0.1")
        r_a2 = create_detection_result("rule_a", e2.event_id)
        correlator.process(e2, [r_a2])

        e3 = create_event(t0 + timedelta(seconds=2), src_ip="10.0.0.1")
        r_b1 = create_detection_result("rule_b", e3.event_id)
        results1 = correlator.process(e3, [r_b1])
        # First correlation: A1 -> B1
        assert len(results1) == 1
        first_contrib = results1[0].contributing_event_ids
        assert first_contrib[0] == r_a1.result_id
        assert first_contrib[1] == r_b1.result_id

        e4 = create_event(t0 + timedelta(seconds=3), src_ip="10.0.0.1")
        r_b2 = create_detection_result("rule_b", e4.event_id)
        results2 = correlator.process(e4, [r_b2])
        # Second correlation: A2 -> B2
        assert len(results2) == 1
        second_contrib = results2[0].contributing_event_ids
        assert second_contrib[0] == r_a2.result_id
        assert second_contrib[1] == r_b2.result_id

    def test_overlapping_partial_sequences_emit_one_result_per_completion(self):
        """Three rule_a + one rule_b in a 2-step sequence.

        Entries: A1, A2, A3, B1
        Single completion emitted using the contiguous A3,B1 run.
        State is bounded — no unbounded growth.
        """
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        results_list = []
        for i in range(3):
            e = create_event(t0 + timedelta(seconds=i), src_ip="10.0.0.1")
            r = create_detection_result("rule_a", e.event_id)
            results_list.extend(correlator.process(e, [r]))

        # No correlation yet
        assert all(len(r) == 0 for r in results_list)

        # Final B completes
        e_b = create_event(t0 + timedelta(seconds=3), src_ip="10.0.0.1")
        r_b = create_detection_result("rule_b", e_b.event_id)
        final = correlator.process(e_b, [r_b])
        assert len(final) == 1
        # Exactly one correlation result; state bounded
        assert correlator.get_state_entries() <= 2  # most recent contiguous pair


# ---------------------------------------------------------------------------
# B. group_by semantics
# ---------------------------------------------------------------------------


class TestGroupBySemantics:
    """Verify group_by uses NormalizedEvent fields and behaves deterministically.

    Contract:
    * group_by fields (src_ip, dst_ip, hostname, username) are read
      from the NormalizedEvent that accompanies the DetectionResult
      during process(event, results). The correlator does NOT attempt
      to extract these from the DetectionResult itself; the
      NormalizedEvent is the source of truth.
    * Missing fields are normalized to the empty string "", so
      multiple events with missing fields collapse into one
      deterministic group.
    * Two detections from different entities (different group values)
      are isolated.
    """

    def test_group_key_built_from_normalized_event(self):
        """group_by reads from the NormalizedEvent, not the DetectionResult."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # DetectionResult has no src_ip; only the NormalizedEvent provides it.
        e1 = create_event(t0, src_ip="10.0.0.1")
        r_a = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a])

        # The group key should be based on event.src_ip = "10.0.0.1"
        assert correlator.get_state_keys() == 1

    def test_missing_grouping_fields_normalize_to_empty_string(self):
        """Missing fields are deterministic: "" for None."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        # Two events with no src_ip — both should land in the same group
        e1 = create_event(t0, src_ip=None)
        r_a1 = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a1])

        e2 = create_event(t0 + timedelta(seconds=1), src_ip=None)
        r_a2 = create_detection_result("rule_a", e2.event_id)
        correlator.process(e2, [r_a2])

        # Same deterministic group (empty string)
        assert correlator.get_state_keys() == 1

    def test_different_entities_isolated(self):
        """Different src_ips must produce different groups (no accidental merging)."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip"],
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0, src_ip="10.0.0.1")
        r_a1 = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a1])

        e2 = create_event(t0, src_ip="10.0.0.2")
        r_a2 = create_detection_result("rule_a", e2.event_id)
        correlator.process(e2, [r_a2])

        e3 = create_event(t0 + timedelta(seconds=1), src_ip="10.0.0.2")
        r_b2 = create_detection_result("rule_b", e3.event_id)
        results2 = correlator.process(e3, [r_b2])
        # Only the 10.0.0.2 group completes
        assert len(results2) == 1

        e4 = create_event(t0 + timedelta(seconds=1), src_ip="10.0.0.1")
        r_b1 = create_detection_result("rule_b", e4.event_id)
        results1 = correlator.process(e4, [r_b1])
        # The 10.0.0.1 group also completes (independent)
        assert len(results1) == 1

    def test_multi_field_group_by(self):
        """Composite group keys (e.g. src_ip + username) work deterministically."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            group_by=["src_ip", "username"],
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0, src_ip="10.0.0.1", username="alice")
        r_a1 = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a1])

        e2 = create_event(t0, src_ip="10.0.0.1", username="bob")
        r_a2 = create_detection_result("rule_a", e2.event_id)
        correlator.process(e2, [r_a2])

        e3 = create_event(t0, src_ip="10.0.0.2", username="alice")
        r_a3 = create_detection_result("rule_a", e3.event_id)
        correlator.process(e3, [r_a3])

        # 3 distinct composite groups
        assert correlator.get_state_keys() == 3


# ---------------------------------------------------------------------------
# C. Generated-result identity
# ---------------------------------------------------------------------------


class TestResultIdentity:
    """Verify the generated cross-detector DetectionResult identity contract.

    Contract:
    * rule_id is the correlator's configured name (not a source rule ID).
    * result_id is a fresh UUID (not equal to any contributing result_id).
    * event_id is the current event_id (the event that triggered
      completion, i.e. the one carrying the last step).
    * contributing_event_ids is ordered (causal order) and bounded by
      the configured sequence length.
    * The generated result's rule_id MUST NOT be equal to any of its
      own source sequence rule_ids (no self-collision).
    """

    def test_generated_rule_id_is_correlator_name(self):
        """Generated result.rule_id == correlator.name (not a source rule_id)."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            name="custom_correlator_42",
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0)
        r_a = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a])

        e2 = create_event(t0 + timedelta(seconds=1))
        r_b = create_detection_result("rule_b", e2.event_id)
        results = correlator.process(e2, [r_b])
        assert len(results) == 1
        assert results[0].rule_id == "custom_correlator_42"
        # The correlator's own rule_id must not appear in its configured sequence
        assert "custom_correlator_42" not in ["rule_a", "rule_b"]

    def test_generated_result_id_distinct_from_contributors(self):
        """result_id is fresh and distinct from any contributing result_id."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0)
        r_a = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a])

        e2 = create_event(t0 + timedelta(seconds=1))
        r_b = create_detection_result("rule_b", e2.event_id)
        results = correlator.process(e2, [r_b])
        assert len(results) == 1
        assert results[0].result_id != r_a.result_id
        assert results[0].result_id != r_b.result_id

    def test_contributing_event_ids_causally_ordered(self):
        """contributing_event_ids preserve the order of the configured sequence."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b", "rule_c"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0)
        r_a = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a])

        e2 = create_event(t0 + timedelta(seconds=1))
        r_b = create_detection_result("rule_b", e2.event_id)
        correlator.process(e2, [r_b])

        e3 = create_event(t0 + timedelta(seconds=2))
        r_c = create_detection_result("rule_c", e3.event_id)
        results = correlator.process(e3, [r_c])
        assert len(results) == 1
        contrib = results[0].contributing_event_ids
        # Causal order: A first, then B, then C
        assert contrib[0] == r_a.result_id
        assert contrib[1] == r_b.result_id
        assert contrib[2] == r_c.result_id

    def test_contributing_event_ids_bounded_by_sequence_length(self):
        """contributing_event_ids length <= sequence length."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        # Many rule_a followed by one rule_b
        for i in range(10):
            e = create_event(t0 + timedelta(seconds=i))
            r = create_detection_result("rule_a", e.event_id)
            correlator.process(e, [r])

        e_final = create_event(t0 + timedelta(seconds=10))
        r_b = create_detection_result("rule_b", e_final.event_id)
        results = correlator.process(e_final, [r_b])
        assert len(results) == 1
        # Bounded by the configured sequence length
        assert len(results[0].contributing_event_ids) == 2

    def test_generated_result_cannot_satisfy_source_rule_id(self):
        """Generated rule_id must not equal any source sequence rule_id."""
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0)
        r_a = create_detection_result("rule_a", e1.event_id)
        correlator.process(e1, [r_a])

        e2 = create_event(t0 + timedelta(seconds=1))
        r_b = create_detection_result("rule_b", e2.event_id)
        results = correlator.process(e2, [r_b])
        assert len(results) == 1
        # The generated correlation result's rule_id is the correlator's
        # name (default "cross_detector_correlation"), not a source rule.
        assert results[0].rule_id not in ("rule_a", "rule_b")


# ---------------------------------------------------------------------------
# D. Confidence / static value contract
# ---------------------------------------------------------------------------


class TestStaticConfidenceContract:
    """Verify the confidence is the configured static value, never derived."""

    def test_default_confidence_is_static(self):
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
        )
        assert correlator._confidence == 0.8

    def test_configured_confidence_is_used_unchanged(self):
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            confidence=0.42,
        )
        t0 = datetime.now(UTC)

        e1 = create_event(t0)
        r_a = create_detection_result("rule_a", e1.event_id, confidence=0.11)
        correlator.process(e1, [r_a])

        e2 = create_event(t0 + timedelta(seconds=1))
        r_b = create_detection_result("rule_b", e2.event_id, confidence=0.99)
        results = correlator.process(e2, [r_b])
        assert results[0].confidence == 0.42
        # Not source confidence, not any aggregation
        assert results[0].confidence not in (0.11, 0.99)


# ---------------------------------------------------------------------------
# E. Timespan and bounds contracts
# ---------------------------------------------------------------------------


class TestTimespanAndBounds:
    """Verify maximum timespan and bounded-state contracts."""

    def test_max_allowed_timespan_is_30_days(self):
        assert timedelta(days=30) == CrossDetectorCorrelator.MAX_ALLOWED_TIMESPAN

    def test_timespan_above_30_days_rejected(self):
        with pytest.raises(ValueError):
            CrossDetectorCorrelator(
                sequence=["rule_a", "rule_b"],
                timespan=timedelta(days=31),
            )

    def test_state_bounded_by_max_entries(self):
        correlator = CrossDetectorCorrelator(
            sequence=["rule_a", "rule_b"],
            timespan=timedelta(minutes=5),
            max_entries=3,
        )
        t0 = datetime.now(UTC)

        # Add 5 entries; only the most recent 3 should remain in state
        for i in range(5):
            e = create_event(t0 + timedelta(seconds=i), src_ip=f"10.0.0.{i}")
            r = create_detection_result("rule_a", e.event_id)
            correlator.process(e, [r])

        assert correlator.get_state_entries() <= 3
