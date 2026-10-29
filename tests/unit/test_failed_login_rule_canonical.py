"""Regression test: failed-login brute-force rule must use canonical event type.

The rule config at config/rules/failed_login_brute_force.yaml was historically
using ``authentication_failed`` (misspelled) instead of the canonical
``authentication_failure`` defined in EventType.  Because the detector's
_matches_filter() performs exact string comparison, the rule silently matched
nothing — no alert was ever produced.

This test loads the real rule through RuleLoader and asserts two things:
  1. Canonical ``authentication_failure`` events DO trigger the detection.
  2. The old wrong name ``authentication_failed`` does NOT trigger it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from argusprowl.constants.event_type import EventType
from argusprowl.constants.paths import ProjectPath
from argusprowl.detection.detectors.event_count_correlation import EventCountCorrelationDetector
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.models.normalized_event import NormalizedEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    src_ip: str,
    event_type: str,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """Create a minimal NormalizedEvent."""
    return NormalizedEvent(
        source_type="sysmon",
        event_type=event_type,
        timestamp=timestamp or datetime.now(UTC),
        src_ip=src_ip,
    )


# ---------------------------------------------------------------------------
# Rule-load regression
# ---------------------------------------------------------------------------


class TestFailedLoginRuleCanonicalName:
    """Verify the brute-force rule and detector use the canonical event type."""

    def test_rule_filter_uses_canonical_name(self) -> None:
        """The loaded rule's filter must reference EventType.AUTHENTICATION_FAILURE."""
        rules_dir = ProjectPath.RULES_DIR
        loader = RuleLoader(rules_dir)
        rule = loader.load_rule(rules_dir / "failed_login_brute_force.yaml")
        correlation = rule.parameters.get("correlation", {})
        filter_config = correlation.get("filter", {})
        assert filter_config.get("event_type") == EventType.AUTHENTICATION_FAILURE

    def test_detector_filter_uses_canonical_name(self) -> None:
        """The detector created from the rule must carry the canonical filter."""
        rules_dir = ProjectPath.RULES_DIR
        loader = RuleLoader(rules_dir)
        rule = loader.load_rule(rules_dir / "failed_login_brute_force.yaml")
        detector = loader.create_detector(rule)
        assert isinstance(detector, EventCountCorrelationDetector)
        assert detector._filter_config.get("event_type") == EventType.AUTHENTICATION_FAILURE

    def test_canonical_events_trigger_detection(self) -> None:
        """Five canonical authentication_failure events from same src_ip must fire."""
        rules_dir = ProjectPath.RULES_DIR
        loader = RuleLoader(rules_dir)
        rule = loader.load_rule(rules_dir / "failed_login_brute_force.yaml")
        detector = loader.create_detector(rule)

        base_time = datetime.now(UTC)
        events = [
            _make_event(
                src_ip="192.168.1.100",
                event_type=EventType.AUTHENTICATION_FAILURE,
                timestamp=base_time + timedelta(seconds=i * 30),
            )
            for i in range(5)
        ]
        for event in events:
            detector.observe(event)
        result = detector.detect(events[-1])
        assert result.matched is True

    def test_old_wrong_name_does_not_trigger(self) -> None:
        """Events using the stale 'authentication_failed' must NOT match the rule."""
        rules_dir = ProjectPath.RULES_DIR
        loader = RuleLoader(rules_dir)
        rule = loader.load_rule(rules_dir / "failed_login_brute_force.yaml")
        detector = loader.create_detector(rule)

        base_time = datetime.now(UTC)
        events = [
            _make_event(
                src_ip="192.168.1.100",
                event_type="authentication_failed",  # old wrong name
                timestamp=base_time + timedelta(seconds=i * 30),
            )
            for i in range(5)
        ]
        for event in events:
            detector.observe(event)
        result = detector.detect(events[-1])
        assert result.matched is False

    def test_mixed_events_only_canonical_counted(self) -> None:
        """Mixing canonical and non-canonical events should only count canonical ones."""
        rules_dir = ProjectPath.RULES_DIR
        loader = RuleLoader(rules_dir)
        rule = loader.load_rule(rules_dir / "failed_login_brute_force.yaml")
        detector = loader.create_detector(rule)

        base_time = datetime.now(UTC)
        events = []
        for i in range(10):
            if i % 2 == 0:
                events.append(
                    _make_event(
                        src_ip="192.168.1.100",
                        event_type=EventType.AUTHENTICATION_FAILURE,
                        timestamp=base_time + timedelta(seconds=i * 10),
                    )
                )
            else:
                events.append(
                    _make_event(
                        src_ip="192.168.1.100",
                        event_type="authentication_failed",  # wrong — should be ignored
                        timestamp=base_time + timedelta(seconds=i * 10),
                    )
                )
        for event in events:
            detector.observe(event)
        # Only 5 canonical events should have been counted — below threshold
        result = detector.detect(events[-1])
        assert result.matched is False
