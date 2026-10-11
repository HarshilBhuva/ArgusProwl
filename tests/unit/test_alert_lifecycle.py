"""Tests for Phase 4.7.5A — Alert Lifecycle State + Transition Validation.

Covers:
- AlertLifecycleState enum
- Default lifecycle state on Alert
- Valid lifecycle transitions
- Invalid lifecycle transitions
- Immutability preservation
- Serialization round-trip
- Backward compatibility (missing lifecycle_state)
- Deduplication invariance across lifecycle changes
"""

from uuid import uuid4

import pytest

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.severity import Severity
from argusprowl.deduplication import AlertDeduplicationEngine, AlertFingerprint, FingerprintConfig
from argusprowl.lifecycle.transition import transition_lifecycle
from argusprowl.models.alert import Alert

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_alert() -> Alert:
    """Create a minimal Alert with default lifecycle state."""
    return Alert(
        title="Port Scan Detected",
        description="Port scan from 192.168.1.100",
        severity=Severity.HIGH,
        source="port_scan",
        metadata={
            "rule_id": "port_scan",
            "evidence": {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 443},
        },
    )


@pytest.fixture
def fingerprint() -> AlertFingerprint:
    """Create a fingerprint generator with default config."""
    return AlertFingerprint(FingerprintConfig())


# ---------------------------------------------------------------------------
# Enum Tests
# ---------------------------------------------------------------------------


class TestAlertLifecycleStateEnum:
    """Tests for the AlertLifecycleState enum."""

    def test_open_state_exists(self) -> None:
        """OPEN state must exist."""
        assert hasattr(AlertLifecycleState, "OPEN")
        assert AlertLifecycleState.OPEN.value == "OPEN"

    def test_acknowledged_state_exists(self) -> None:
        """ACKNOWLEDGED state must exist."""
        assert hasattr(AlertLifecycleState, "ACKNOWLEDGED")
        assert AlertLifecycleState.ACKNOWLEDGED.value == "ACKNOWLEDGED"

    def test_closed_state_exists(self) -> None:
        """CLOSED state must exist."""
        assert hasattr(AlertLifecycleState, "CLOSED")
        assert AlertLifecycleState.CLOSED.value == "CLOSED"

    def test_from_string_open(self) -> None:
        """Parse OPEN from string."""
        assert AlertLifecycleState.from_string("open") == AlertLifecycleState.OPEN
        assert AlertLifecycleState.from_string("OPEN") == AlertLifecycleState.OPEN

    def test_from_string_acknowledged(self) -> None:
        """Parse ACKNOWLEDGED from string."""
        assert AlertLifecycleState.from_string("acknowledged") == AlertLifecycleState.ACKNOWLEDGED
        assert AlertLifecycleState.from_string("ACKNOWLEDGED") == AlertLifecycleState.ACKNOWLEDGED

    def test_from_string_closed(self) -> None:
        """Parse CLOSED from string."""
        assert AlertLifecycleState.from_string("closed") == AlertLifecycleState.CLOSED
        assert AlertLifecycleState.from_string("CLOSED") == AlertLifecycleState.CLOSED

    def test_from_string_invalid_raises(self) -> None:
        """Invalid string must raise ValueError."""
        with pytest.raises(ValueError, match="Unknown alert lifecycle state"):
            AlertLifecycleState.from_string("INVALID")

    def test_from_string_missing_raises(self) -> None:
        """Missing state must raise ValueError."""
        with pytest.raises(ValueError, match="Unknown alert lifecycle state"):
            AlertLifecycleState.from_string("ASSIGNED")


# ---------------------------------------------------------------------------
# Default State Tests
# ---------------------------------------------------------------------------


class TestDefaultLifecycleState:
    """Tests for default lifecycle state on Alert."""

    def test_new_alert_defaults_to_open(self, sample_alert: Alert) -> None:
        """Newly created alerts must default to OPEN."""
        assert sample_alert.lifecycle_state == AlertLifecycleState.OPEN

    def test_explicit_open(self) -> None:
        """Explicit OPEN must be preserved."""
        alert = Alert(
            title="Test",
            description="Test desc",
            severity=Severity.LOW,
            source="test",
            lifecycle_state=AlertLifecycleState.OPEN,
        )
        assert alert.lifecycle_state == AlertLifecycleState.OPEN

    def test_explicit_acknowledged(self) -> None:
        """Explicit ACKNOWLEDGED must be preserved."""
        alert = Alert(
            title="Test",
            description="Test desc",
            severity=Severity.LOW,
            source="test",
            lifecycle_state=AlertLifecycleState.ACKNOWLEDGED,
        )
        assert alert.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_explicit_closed(self) -> None:
        """Explicit CLOSED must be preserved."""
        alert = Alert(
            title="Test",
            description="Test desc",
            severity=Severity.LOW,
            source="test",
            lifecycle_state=AlertLifecycleState.CLOSED,
        )
        assert alert.lifecycle_state == AlertLifecycleState.CLOSED


# ---------------------------------------------------------------------------
# Valid Transition Tests
# ---------------------------------------------------------------------------


class TestValidTransitions:
    """Tests for valid lifecycle transitions."""

    def test_open_to_acknowledged(self, sample_alert: Alert) -> None:
        """OPEN -> ACKNOWLEDGED must succeed."""
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        assert transitioned.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_open_to_closed(self, sample_alert: Alert) -> None:
        """OPEN -> CLOSED must succeed."""
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        assert transitioned.lifecycle_state == AlertLifecycleState.CLOSED

    def test_acknowledged_to_closed(self, sample_alert: Alert) -> None:
        """ACKNOWLEDGED -> CLOSED must succeed."""
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        closed = transition_lifecycle(acknowledged, AlertLifecycleState.CLOSED)
        assert closed.lifecycle_state == AlertLifecycleState.CLOSED

    def test_full_workflow(self, sample_alert: Alert) -> None:
        """Full workflow: OPEN -> ACKNOWLEDGED -> CLOSED."""
        step1 = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        step2 = transition_lifecycle(step1, AlertLifecycleState.CLOSED)
        assert step1.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        assert step2.lifecycle_state == AlertLifecycleState.CLOSED


# ---------------------------------------------------------------------------
# Invalid Transition Tests
# ---------------------------------------------------------------------------


class TestInvalidTransitions:
    """Tests for invalid lifecycle transitions."""

    def test_acknowledged_to_open_raises(self, sample_alert: Alert) -> None:
        """ACKNOWLEDGED -> OPEN must raise ValueError."""
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            transition_lifecycle(acknowledged, AlertLifecycleState.OPEN)

    def test_closed_to_open_raises(self, sample_alert: Alert) -> None:
        """CLOSED -> OPEN must raise ValueError."""
        closed = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            transition_lifecycle(closed, AlertLifecycleState.OPEN)

    def test_closed_to_acknowledged_raises(self, sample_alert: Alert) -> None:
        """CLOSED -> ACKNOWLEDGED must raise ValueError."""
        closed = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            transition_lifecycle(closed, AlertLifecycleState.ACKNOWLEDGED)

    def test_closed_to_closed_raises(self, sample_alert: Alert) -> None:
        """CLOSED -> CLOSED must raise ValueError."""
        closed = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            transition_lifecycle(closed, AlertLifecycleState.CLOSED)

    def test_open_to_open_raises(self, sample_alert: Alert) -> None:
        """OPEN -> OPEN must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            transition_lifecycle(sample_alert, AlertLifecycleState.OPEN)

    def test_acknowledged_to_acknowledged_raises(self, sample_alert: Alert) -> None:
        """ACKNOWLEDGED -> ACKNOWLEDGED must raise ValueError."""
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            transition_lifecycle(acknowledged, AlertLifecycleState.ACKNOWLEDGED)


# ---------------------------------------------------------------------------
# Immutability Tests
# ---------------------------------------------------------------------------


class TestImmutability:
    """Tests for Alert immutability during lifecycle transitions."""

    def test_original_alert_unchanged_after_open_to_acknowledged(self, sample_alert: Alert) -> None:
        """Original alert must remain OPEN after transition."""
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        assert sample_alert.lifecycle_state == AlertLifecycleState.OPEN
        assert transitioned.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_original_alert_unchanged_after_open_to_closed(self, sample_alert: Alert) -> None:
        """Original alert must remain OPEN after transition to CLOSED."""
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        assert sample_alert.lifecycle_state == AlertLifecycleState.OPEN
        assert transitioned.lifecycle_state == AlertLifecycleState.CLOSED

    def test_all_fields_preserved_after_transition(self, sample_alert: Alert) -> None:
        """All alert fields must be preserved after lifecycle transition."""
        original_id = sample_alert.alert_id
        original_title = sample_alert.title
        original_severity = sample_alert.severity
        original_source = sample_alert.source

        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)

        assert transitioned.alert_id == original_id
        assert transitioned.title == original_title
        assert transitioned.severity == original_severity
        assert transitioned.source == original_source
        assert transitioned.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED


# ---------------------------------------------------------------------------
# Serialization Tests
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for Alert serialization with lifecycle state."""

    def test_to_dict_includes_lifecycle_state(self, sample_alert: Alert) -> None:
        """to_dict() must include lifecycle_state."""
        alert_dict = sample_alert.to_dict()
        assert "lifecycle_state" in alert_dict
        assert alert_dict["lifecycle_state"] == "OPEN"

    def test_to_dict_with_acknowledged(self, sample_alert: Alert) -> None:
        """to_dict() must reflect ACKNOWLEDGED state."""
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        alert_dict = acknowledged.to_dict()
        assert alert_dict["lifecycle_state"] == "ACKNOWLEDGED"

    def test_to_dict_with_closed(self, sample_alert: Alert) -> None:
        """to_dict() must reflect CLOSED state."""
        closed = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        alert_dict = closed.to_dict()
        assert alert_dict["lifecycle_state"] == "CLOSED"

    def test_from_dict_roundtrip(self, sample_alert: Alert) -> None:
        """Round-trip serialization must preserve lifecycle state."""
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        alert_dict = acknowledged.to_dict()
        restored = Alert.from_dict(alert_dict)
        assert restored.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        assert restored.alert_id == acknowledged.alert_id
        assert restored.title == acknowledged.title

    def test_from_dict_preserves_all_states(self) -> None:
        """All lifecycle states must survive round-trip."""
        for state in AlertLifecycleState:
            alert = Alert(
                title="Test",
                description="Test desc",
                severity=Severity.LOW,
                source="test",
                lifecycle_state=state,
            )
            alert_dict = alert.to_dict()
            restored = Alert.from_dict(alert_dict)
            assert restored.lifecycle_state == state


# ---------------------------------------------------------------------------
# Backward Compatibility Tests
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Tests for backward compatibility with legacy alerts."""

    def test_from_dict_without_lifecycle_defaults_to_open(self) -> None:
        """Missing lifecycle_state must default to OPEN."""
        legacy_dict = {
            "alert_id": str(uuid4()),
            "title": "Legacy Alert",
            "description": "Old format",
            "severity": "HIGH",
            "priority": "HIGH",
            "source": "port_scan",
            "created_at": "2024-01-01T00:00:00+00:00",
            "tags": [],
            "metadata": {},
            "schema_version": 2,
        }
        alert = Alert.from_dict(legacy_dict)
        assert alert.lifecycle_state == AlertLifecycleState.OPEN

    def test_from_dict_with_null_lifecycle_defaults_to_open(self) -> None:
        """Null lifecycle_state must default to OPEN."""
        legacy_dict = {
            "alert_id": str(uuid4()),
            "title": "Legacy Alert",
            "description": "Old format",
            "severity": "HIGH",
            "priority": "HIGH",
            "source": "port_scan",
            "created_at": "2024-01-01T00:00:00+00:00",
            "tags": [],
            "metadata": {},
            "schema_version": 2,
            "lifecycle_state": None,
        }
        alert = Alert.from_dict(legacy_dict)
        assert alert.lifecycle_state == AlertLifecycleState.OPEN

    def test_legacy_alerts_can_be_transited(self) -> None:
        """Legacy alerts without lifecycle can be transitioned."""
        legacy_dict = {
            "alert_id": str(uuid4()),
            "title": "Legacy Alert",
            "description": "Old format",
            "severity": "HIGH",
            "priority": "HIGH",
            "source": "port_scan",
            "created_at": "2024-01-01T00:00:00+00:00",
            "tags": [],
            "metadata": {},
            "schema_version": 2,
        }
        alert = Alert.from_dict(legacy_dict)
        # Should default to OPEN and be transitable
        acknowledged = transition_lifecycle(alert, AlertLifecycleState.ACKNOWLEDGED)
        assert acknowledged.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED


# ---------------------------------------------------------------------------
# Deduplication Invariance Tests
# ---------------------------------------------------------------------------


class TestDeduplicationInvariance:
    """Tests that lifecycle state does not affect fingerprint identity."""

    def test_fingerprint_unchanged_after_open_to_acknowledged(
        self, sample_alert: Alert, fingerprint: AlertFingerprint
    ) -> None:
        """Fingerprint must be identical after OPEN -> ACKNOWLEDGED."""
        original_fp = fingerprint.create(sample_alert)
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        transitioned_fp = fingerprint.create(acknowledged)
        assert original_fp == transitioned_fp

    def test_fingerprint_unchanged_after_open_to_closed(
        self, sample_alert: Alert, fingerprint: AlertFingerprint
    ) -> None:
        """Fingerprint must be identical after OPEN -> CLOSED."""
        original_fp = fingerprint.create(sample_alert)
        closed = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        transitioned_fp = fingerprint.create(closed)
        assert original_fp == transitioned_fp

    def test_fingerprint_unchanged_after_full_workflow(
        self, sample_alert: Alert, fingerprint: AlertFingerprint
    ) -> None:
        """Fingerprint must be identical after full workflow."""
        original_fp = fingerprint.create(sample_alert)
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        closed = transition_lifecycle(acknowledged, AlertLifecycleState.CLOSED)
        assert fingerprint.create(acknowledged) == original_fp
        assert fingerprint.create(closed) == original_fp

    def test_deduplication_engine_ignores_lifecycle(self, sample_alert: Alert) -> None:
        """Deduplication engine must suppress lifecycle-changed alerts."""
        engine = AlertDeduplicationEngine(cooldown=60)

        # First alert (OPEN)
        first = engine.process(sample_alert)
        assert first.emit is True

        # Transition to ACKNOWLEDGED
        acknowledged = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        second = engine.process(acknowledged)
        assert second.suppressed is True
        assert second.state.occurrence_count == 2

        # Transition to CLOSED
        closed = transition_lifecycle(acknowledged, AlertLifecycleState.CLOSED)
        third = engine.process(closed)
        assert third.suppressed is True
        assert third.state.occurrence_count == 3

    def test_different_alerts_have_different_fingerprints(
        self, fingerprint: AlertFingerprint
    ) -> None:
        """Different alerts must have different fingerprints."""
        alert1 = Alert(
            title="Alert 1",
            description="Desc 1",
            severity=Severity.HIGH,
            source="port_scan",
            metadata={"evidence": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443}},
        )
        alert2 = Alert(
            title="Alert 2",
            description="Desc 2",
            severity=Severity.HIGH,
            source="port_scan",
            metadata={"evidence": {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "dst_port": 80}},
        )
        fp1 = fingerprint.create(alert1)
        fp2 = fingerprint.create(alert2)
        assert fp1 != fp2


# ---------------------------------------------------------------------------
# Transition Function Tests
# ---------------------------------------------------------------------------


class TestTransitionFunction:
    """Tests for the transition_lifecycle function."""

    def test_returns_new_alert(self, sample_alert: Alert) -> None:
        """transition_lifecycle must return a new Alert instance."""
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        assert transitioned is not sample_alert

    def test_transition_preserves_uuid(self, sample_alert: Alert) -> None:
        """Alert UUID must be preserved across transitions."""
        original_id = sample_alert.alert_id
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        assert transitioned.alert_id == original_id

    def test_transition_preserves_timestamp(self, sample_alert: Alert) -> None:
        """Created timestamp must be preserved across transitions."""
        original_time = sample_alert.created_at
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        assert transitioned.created_at == original_time

    def test_transition_preserves_severity(self, sample_alert: Alert) -> None:
        """Severity must be preserved across transitions."""
        original_severity = sample_alert.severity
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.CLOSED)
        assert transitioned.severity == original_severity

    def test_transition_preserves_priority(self, sample_alert: Alert) -> None:
        """Priority must be preserved across transitions."""
        original_priority = sample_alert.priority
        transitioned = transition_lifecycle(sample_alert, AlertLifecycleState.ACKNOWLEDGED)
        assert transitioned.priority == original_priority
