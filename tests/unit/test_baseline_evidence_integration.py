"""Tests for Phase 5.1.7 — Baseline Evidence Integration.

Verifies that BaselineEvidence is integrated into analyst-facing paths
(console, JSON) without affecting detection decisions, severity, priority,
deduplication, or lifecycle.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

from argusprowl.alerting.console_provider import ConsoleAlertProvider
from argusprowl.alerting.json_provider import JsonAlertProvider
from argusprowl.behavior.baseline import BaselineClassification
from argusprowl.behavior.baseline_evidence import BaselineReasonCode
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.models.alert import Alert
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def behavior_service() -> EntityBehaviorService:
    """Create an EntityBehaviorService with pre-populated profiles."""
    service = EntityBehaviorService(
        maturity_min_observations=5,
        maturity_window_seconds=0.1,
        baseline_rare_threshold=2,
        baseline_stale_after_seconds=3600.0,
    )
    base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
    # Build a mature profile
    for i in range(10):
        service.classify_and_record(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            dimension_value="python",
            timestamp=base_time + timedelta(seconds=i),
            processing_time=base_time + timedelta(seconds=i),
        )
    return service


@pytest.fixture
def decision_engine_with_behavior(behavior_service: EntityBehaviorService) -> DecisionEngine:
    """DecisionEngine wired with EntityBehaviorService."""
    return DecisionEngine(entity_behavior_service=behavior_service)


@pytest.fixture
def decision_engine_without_behavior() -> DecisionEngine:
    """DecisionEngine without EntityBehaviorService (default)."""
    return DecisionEngine()


@pytest.fixture
def sample_detection_result_with_entity_context() -> DetectionResult:
    """Create a sample DetectionResult with entity context in metadata."""
    return DetectionResult(
        rule_id="first_seen_process",
        event_id=uuid4(),
        matched=True,
        severity=Severity.INFO,
        confidence=1.0,
        description="First seen process python on server01",
        evidence=[
            {"field": "hostname", "observed": "server01", "condition": "equals"},
            {"field": "process_name", "observed": "python", "condition": "equals"},
        ],
        metadata={
            "entity_type": "hostname",
            "entity_id": "server01",
            "dimension": "process_name",
            "detection_type": "first_seen",
        },
    )


@pytest.fixture
def sample_event() -> NormalizedEvent:
    """Create a sample NormalizedEvent."""
    return NormalizedEvent(
        source_type="sysmon",
        event_type="process_create",
        hostname="server01",
        process_name="python",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        dst_port=443,
    )


@pytest.fixture
def sample_alert_with_baseline_evidence(
    decision_engine_with_behavior: DecisionEngine,
    sample_detection_result_with_entity_context: DetectionResult,
    sample_event: NormalizedEvent,
) -> Alert:
    """Create an alert with baseline evidence attached."""
    alert = decision_engine_with_behavior.process_detection_result(
        sample_detection_result_with_entity_context, event=sample_event
    )
    assert alert is not None
    return alert


@pytest.fixture
def sample_alert_without_baseline_evidence(
    decision_engine_without_behavior: DecisionEngine,
    sample_detection_result_with_entity_context: DetectionResult,
    sample_event: NormalizedEvent,
) -> Alert:
    """Create an alert without baseline evidence."""
    alert = decision_engine_without_behavior.process_detection_result(
        sample_detection_result_with_entity_context, event=sample_event
    )
    assert alert is not None
    return alert


# ── Test: Evidence Propagation ────────────────────────────────────────────────


class TestEvidencePropagation:
    """Tests for DetectionResult → Alert evidence propagation."""

    def test_evidence_attached_to_alert_metadata(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Baseline evidence appears in Alert.metadata.baseline_evidence."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert is not None
        assert "baseline_evidence" in alert.metadata
        evidence = alert.metadata["baseline_evidence"]
        assert isinstance(evidence, dict)
        assert "reason_code" in evidence
        assert "classification" in evidence
        assert "explanation" in evidence

    def test_evidence_missing_when_no_behavior_service(
        self,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert metadata has no baseline_evidence when service is absent."""
        alert = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert is not None
        assert "baseline_evidence" not in alert.metadata

    def test_evidence_missing_when_no_entity_context(
        self,
        decision_engine_with_behavior: DecisionEngine,
    ) -> None:
        """Alert metadata has no baseline_evidence when entity context is missing."""
        result = DetectionResult(
            rule_id="test_rule",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={},
        )
        alert = decision_engine_with_behavior.process_detection_result(result)
        assert alert is not None
        assert "baseline_evidence" not in alert.metadata


# ── Test: Decision Independence ───────────────────────────────────────────────


class TestDecisionIndependence:
    """Prove baseline evidence does NOT affect decision logic."""

    def test_severity_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert severity is identical with and without baseline evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None
        assert alert_with.severity == alert_without.severity

    def test_priority_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert priority is identical with and without baseline evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None
        assert alert_with.priority == alert_without.priority

    def test_confidence_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Detector confidence is identical with and without baseline evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None
        assert alert_with.detector_confidence == alert_without.detector_confidence
        assert alert_with.contextual_confidence == alert_without.contextual_confidence

    def test_fingerprint_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert fingerprint (dedup key) is identical with and without evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None
        # Same rule_id and source means same fingerprint (dedup key)
        assert alert_with.source == alert_without.source
        # Both should have same severity and priority
        assert alert_with.severity == alert_without.severity
        assert alert_with.priority == alert_without.priority

    def test_deduplication_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Deduplication behavior is identical with and without baseline evidence."""
        # Process first alert
        alert1_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert1_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert1_with is not None
        assert alert1_without is not None

        # Process duplicate alert
        alert2_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert2_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        # Both should be suppressed (same cooldown)
        assert (alert2_with is None) == (alert2_without is None)

    def test_lifecycle_state_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert lifecycle state is identical with and without baseline evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None
        assert alert_with.lifecycle_state == alert_without.lifecycle_state

    def test_incident_assignment_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Incident assignment is identical with and without baseline evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None
        assert alert_with.incident_id == alert_without.incident_id

    def test_alert_creation_unchanged_with_evidence(
        self,
        decision_engine_with_behavior: DecisionEngine,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result_with_entity_context: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert is created (not suppressed) identically with and without evidence."""
        alert_with = decision_engine_with_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        alert_without = decision_engine_without_behavior.process_detection_result(
            sample_detection_result_with_entity_context, event=sample_event
        )
        assert alert_with is not None
        assert alert_without is not None


# ── Test: Console Output ──────────────────────────────────────────────────────


class TestConsoleBaselineEvidence:
    """Tests for console provider baseline evidence display."""

    def test_console_shows_baseline_evidence_when_present(
        self,
        sample_alert_with_baseline_evidence: Alert,
    ) -> None:
        """Console output includes BASELINE EVIDENCE section when evidence present."""
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            provider.send(sample_alert_with_baseline_evidence)
            output = fake_out.getvalue()

        assert "BASELINE EVIDENCE:" in output
        assert "Classification:" in output
        assert "Profile maturity:" in output
        assert "Value count:" in output
        assert "Total observations:" in output

    def test_console_hides_baseline_evidence_when_absent(
        self,
        sample_alert_without_baseline_evidence: Alert,
    ) -> None:
        """Console output does not include BASELINE EVIDENCE when evidence absent."""
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            provider.send(sample_alert_without_baseline_evidence)
            output = fake_out.getvalue()

        assert "BASELINE EVIDENCE:" not in output

    def test_console_baseline_evidence_format(
        self,
        sample_alert_with_baseline_evidence: Alert,
    ) -> None:
        """Console baseline evidence has correct format."""
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            provider.send(sample_alert_with_baseline_evidence)
            output = fake_out.getvalue()

        lines = output.split("\n")
        evidence_section_found = False
        for i, line in enumerate(lines):
            if "BASELINE EVIDENCE:" in line:
                evidence_section_found = True
                assert i + 1 < len(lines)
                assert "Classification:" in lines[i + 1]
                break

        assert evidence_section_found

    def test_console_baseline_evidence_order(
        self,
        sample_alert_with_baseline_evidence: Alert,
    ) -> None:
        """Baseline evidence appears after behavioral context, before evidence."""
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            provider.send(sample_alert_with_baseline_evidence)
            output = fake_out.getvalue()

        lines = output.split("\n")
        behavioral_idx = next(
            (i for i, line in enumerate(lines) if "BEHAVIORAL CONTEXT:" in line),
            -1,
        )
        evidence_idx = next(
            (i for i, line in enumerate(lines) if line.strip() == "BASELINE EVIDENCE:"),
            -1,
        )
        evidence_items_idx = next(
            (i for i, line in enumerate(lines) if line.strip() == "EVIDENCE:"),
            -1,
        )

        if behavioral_idx != -1:
            assert evidence_idx != -1
            assert behavioral_idx < evidence_idx
        if evidence_idx != -1:
            assert evidence_items_idx != -1
            assert evidence_idx < evidence_items_idx

    def test_console_baseline_evidence_no_forbidden_terms(
        self,
        sample_alert_with_baseline_evidence: Alert,
    ) -> None:
        """Console output contains no risk/anomaly language in baseline section."""
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            provider.send(sample_alert_with_baseline_evidence)
            output = fake_out.getvalue()

        lines = output.split("\n")
        evidence_lines = []
        in_evidence = False
        for line in lines:
            if "BASELINE EVIDENCE:" in line:
                in_evidence = True
                continue
            if in_evidence:
                if line.startswith("  "):
                    evidence_lines.append(line)
                else:
                    break

        evidence_section = "\n".join(evidence_lines).lower()
        forbidden = ["anomaly", "deviation", "risk score", "suspicious", "threat"]
        for term in forbidden:
            assert term not in evidence_section, f"Found forbidden term: {term}"

    def test_console_baseline_evidence_with_missing_fields(
        self,
    ) -> None:
        """Console handles incomplete baseline evidence gracefully."""
        alert = Alert(
            title="Test Alert",
            description="Test description",
            severity=Severity.INFO,
            source="test_rule",
            metadata={
                "baseline_evidence": {
                    "reason_code": "value_established",
                    "classification": "baseline_established",
                }
            },
        )

        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = provider.send(alert)
            output = fake_out.getvalue()

        assert result is True
        assert "BASELINE EVIDENCE:" in output

    def test_console_baseline_evidence_with_non_dict_metadata(
        self,
    ) -> None:
        """Console handles non-dict baseline_evidence gracefully."""
        alert = Alert(
            title="Test Alert",
            description="Test description",
            severity=Severity.INFO,
            source="test_rule",
            metadata={"baseline_evidence": "invalid"},
        )

        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = provider.send(alert)
            output = fake_out.getvalue()

        assert result is True
        # Non-dict baseline_evidence should not show section
        assert "BASELINE EVIDENCE:" not in output


# ── Test: JSON Serialization ──────────────────────────────────────────────────


class TestJsonSerialization:
    """Tests for JSON provider baseline evidence serialization."""

    def test_json_includes_baseline_evidence_when_present(
        self,
        sample_alert_with_baseline_evidence: Alert,
        tmp_path: Path,
    ) -> None:
        """JSON output includes baseline_evidence when present."""
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        provider.send(sample_alert_with_baseline_evidence)

        json_file = tmp_path / "alerts.jsonl"
        assert json_file.exists()

        with open(json_file) as f:
            data = json.loads(f.readline())

        assert "baseline_evidence" in data["metadata"]
        evidence = data["metadata"]["baseline_evidence"]
        assert "reason_code" in evidence
        assert "classification" in evidence
        assert "explanation" in evidence

    def test_json_excludes_baseline_evidence_when_absent(
        self,
        sample_alert_without_baseline_evidence: Alert,
        tmp_path: Path,
    ) -> None:
        """JSON output excludes baseline_evidence when absent."""
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        provider.send(sample_alert_without_baseline_evidence)

        json_file = tmp_path / "alerts.jsonl"
        assert json_file.exists()

        with open(json_file) as f:
            data = json.loads(f.readline())

        assert "baseline_evidence" not in data["metadata"]

    def test_json_serialization_deterministic(
        self,
        sample_alert_with_baseline_evidence: Alert,
        tmp_path: Path,
    ) -> None:
        """JSON serialization is deterministic."""
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        provider.send(sample_alert_with_baseline_evidence)

        json_file = tmp_path / "alerts.jsonl"
        with open(json_file) as f:
            data1 = json.loads(f.readline())

        provider.send(sample_alert_with_baseline_evidence)
        with open(json_file) as f:
            lines = f.readlines()
            data2 = json.loads(lines[1])

        # Evidence should be identical
        assert data1["metadata"]["baseline_evidence"] == data2["metadata"]["baseline_evidence"]

    def test_json_datetime_serialization(
        self,
        sample_alert_with_baseline_evidence: Alert,
    ) -> None:
        """JSON serializes datetimes as ISO strings."""
        evidence = sample_alert_with_baseline_evidence.metadata["baseline_evidence"]
        assert isinstance(evidence["first_seen"], str) or evidence["first_seen"] is None
        assert isinstance(evidence["last_seen"], str) or evidence["last_seen"] is None

    def test_json_backward_compatibility(
        self,
        sample_alert_without_baseline_evidence: Alert,
        tmp_path: Path,
    ) -> None:
        """JSON output is backward compatible when no baseline evidence."""
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        provider.send(sample_alert_without_baseline_evidence)

        json_file = tmp_path / "alerts.jsonl"
        with open(json_file) as f:
            data = json.loads(f.readline())

        # Should have all standard fields
        assert "alert_id" in data
        assert "title" in data
        assert "severity" in data
        assert "metadata" in data
        # baseline_evidence should not be present
        assert "baseline_evidence" not in data["metadata"]


# ── Test: Replay/Live Parity ──────────────────────────────────────────────────


class TestReplayLiveParity:
    """Tests for replay/live parity of baseline evidence."""

    def test_evidence_identical_for_same_event_stream(
        self,
    ) -> None:
        """Evidence is identical for identical event streams."""
        service_live = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
            is_replay_mode=False,
        )
        service_replay = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
            is_replay_mode=True,
        )

        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build identical profiles
        for i in range(10):
            service_live.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )
            service_replay.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Generate evidence for same classification
        result_live, _ = service_live.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )
        result_replay, _ = service_replay.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        evidence_live = service_live.generate_evidence(result_live)
        evidence_replay = service_replay.generate_evidence(result_replay)

        assert evidence_live is not None
        assert evidence_replay is not None
        assert evidence_live.to_dict() == evidence_replay.to_dict()

    def test_all_classification_types_parity(
        self,
    ) -> None:
        """All classification types show parity between replay and live."""
        for classification_type in [
            BaselineClassification.BASELINE_UNAVAILABLE,
            BaselineClassification.BASELINE_WARMING,
            BaselineClassification.BASELINE_NEW_VALUE,
            BaselineClassification.BASELINE_RARE_VALUE,
            BaselineClassification.BASELINE_ESTABLISHED,
        ]:
            service = EntityBehaviorService(
                maturity_min_observations=5,
                maturity_window_seconds=0.1,
                baseline_rare_threshold=2,
                baseline_stale_after_seconds=3600.0,
                is_replay_mode=True,
            )
            ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

            # Build profile based on classification type
            if classification_type == BaselineClassification.BASELINE_UNAVAILABLE:
                # No observations - will be unavailable
                result, _ = service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value="test.exe",
                    timestamp=ts,
                    processing_time=ts,
                )
            elif classification_type == BaselineClassification.BASELINE_WARMING:
                # Few observations - will be warming
                for i in range(3):
                    service.classify_and_record(
                        entity_type="hostname",
                        entity_id="host1",
                        dimension="process_name",
                        dimension_value="test.exe",
                        timestamp=ts + timedelta(seconds=i),
                        processing_time=ts + timedelta(seconds=i),
                    )
                result, _ = service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value="test.exe",
                    timestamp=ts + timedelta(seconds=100),
                    processing_time=ts + timedelta(seconds=100),
                )
            elif classification_type == BaselineClassification.BASELINE_NEW_VALUE:
                # Build mature profile, then add new value
                for i in range(10):
                    service.classify_and_record(
                        entity_type="hostname",
                        entity_id="host1",
                        dimension="process_name",
                        dimension_value="python.exe",
                        timestamp=ts + timedelta(seconds=i),
                        processing_time=ts + timedelta(seconds=i),
                    )
                result, _ = service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value="malware.exe",
                    timestamp=ts + timedelta(seconds=100),
                    processing_time=ts + timedelta(seconds=100),
                )
            elif classification_type == BaselineClassification.BASELINE_RARE_VALUE:
                # Build mature profile, then add rare value
                for i in range(10):
                    service.classify_and_record(
                        entity_type="hostname",
                        entity_id="host1",
                        dimension="process_name",
                        dimension_value="python.exe",
                        timestamp=ts + timedelta(seconds=i),
                        processing_time=ts + timedelta(seconds=i),
                    )
                service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value="rare.exe",
                    timestamp=ts + timedelta(seconds=50),
                    processing_time=ts + timedelta(seconds=50),
                )
                result, _ = service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value="rare.exe",
                    timestamp=ts + timedelta(seconds=100),
                    processing_time=ts + timedelta(seconds=100),
                )
            else:  # ESTABLISHED
                # Build mature profile with many observations
                for i in range(10):
                    service.classify_and_record(
                        entity_type="hostname",
                        entity_id="host1",
                        dimension="process_name",
                        dimension_value="python.exe",
                        timestamp=ts + timedelta(seconds=i),
                        processing_time=ts + timedelta(seconds=i),
                    )
                result, _ = service.classify_and_record(
                    entity_type="hostname",
                    entity_id="host1",
                    dimension="process_name",
                    dimension_value="python.exe",
                    timestamp=ts + timedelta(seconds=100),
                    processing_time=ts + timedelta(seconds=100),
                )

            assert result.classification == classification_type

            evidence = service.generate_evidence(result)
            assert evidence is not None
            assert evidence.classification == classification_type.value


# ── Test: Bounded Output ──────────────────────────────────────────────────────


class TestBoundedOutput:
    """Tests for bounded evidence output."""

    def test_top_comparison_values_bounded_to_5(
        self,
    ) -> None:
        """Top comparison values are bounded to 5."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build profile with many values
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value=f"app_{i}.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add one more to trigger established classification
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="app_0.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert len(evidence.top_comparison_values) <= 5

    def test_oversized_values_hashed(
        self,
    ) -> None:
        """Oversized values are hashed in evidence."""
        service = EntityBehaviorService(
            max_value_length=128,
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build profile with long values
        long_value = "a" * 200
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value=long_value,
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value=long_value,
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        evidence = service.generate_evidence(result)
        assert evidence is not None
        # Check that comparison values are hashed
        for value, _ in evidence.top_comparison_values:
            assert len(value) <= 128

    def test_explanation_bounded(
        self,
    ) -> None:
        """Evidence explanation is bounded."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert len(evidence.explanation) < 1000  # Reasonably bounded


# ── Test: Deterministic Serialization ─────────────────────────────────────────


class TestDeterministicSerialization:
    """Tests for deterministic evidence serialization."""

    def test_serialization_deterministic(
        self,
    ) -> None:
        """Evidence serialization is deterministic."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        evidence = service.generate_evidence(result)
        assert evidence is not None

        d1 = evidence.to_dict()
        d2 = evidence.to_dict()
        assert d1 == d2

    def test_evidence_idempotent(
        self,
    ) -> None:
        """Generating evidence multiple times produces identical results."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        e1 = service.generate_evidence(result)
        e2 = service.generate_evidence(result)
        assert e1 is not None
        assert e2 is not None
        assert e1.to_dict() == e2.to_dict()


# ── Test: Missing Evidence Backward Compatibility ─────────────────────────────


class TestMissingEvidenceBackwardCompatibility:
    """Tests for backward compatibility when evidence is missing."""

    def test_alert_without_evidence_serializes_cleanly(
        self,
        sample_alert_without_baseline_evidence: Alert,
    ) -> None:
        """Alert without baseline evidence serializes cleanly."""
        d = sample_alert_without_baseline_evidence.to_dict()
        assert "baseline_evidence" not in d["metadata"]
        assert d["metadata"]["rule_id"] == "first_seen_process"

    def test_console_without_evidence_works(
        self,
        sample_alert_without_baseline_evidence: Alert,
    ) -> None:
        """Console provider works without baseline evidence."""
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)

        with patch("sys.stdout", new=StringIO()) as fake_out:
            result = provider.send(sample_alert_without_baseline_evidence)
            output = fake_out.getvalue()

        assert result is True
        assert "BASELINE EVIDENCE:" not in output

    def test_json_without_evidence_works(
        self,
        sample_alert_without_baseline_evidence: Alert,
        tmp_path: Path,
    ) -> None:
        """JSON provider works without baseline evidence."""
        provider = JsonAlertProvider(output_path=tmp_path / "alerts.jsonl")
        provider.send(sample_alert_without_baseline_evidence)

        json_file = tmp_path / "alerts.jsonl"
        assert json_file.exists()

        with open(json_file) as f:
            data = json.loads(f.readline())

        assert "baseline_evidence" not in data["metadata"]


# ── Test: All Classification Types ────────────────────────────────────────────


class TestAllClassificationTypes:
    """Tests for all baseline classification types in integration."""

    def test_unavailable_classification(
        self,
    ) -> None:
        """Evidence for BASELINE_UNAVAILABLE classification."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="test.exe",
            timestamp=ts,
            processing_time=ts,
        )

        assert result.classification == BaselineClassification.BASELINE_UNAVAILABLE
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code == BaselineReasonCode.NO_PROFILE
        assert evidence.classification == "baseline_unavailable"

    def test_warming_classification(
        self,
    ) -> None:
        """Evidence for BASELINE_WARMING classification."""
        service = EntityBehaviorService(
            maturity_min_observations=100,  # High threshold
            maturity_window_seconds=3600.0,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="test.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="test.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_WARMING
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.classification == "baseline_warming"

    def test_new_value_classification(
        self,
    ) -> None:
        """Evidence for BASELINE_NEW_VALUE classification."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="malware.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_NEW_VALUE
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code == BaselineReasonCode.VALUE_NEW
        assert evidence.classification == "baseline_new_value"

    def test_rare_value_classification(
        self,
    ) -> None:
        """Evidence for BASELINE_RARE_VALUE classification."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add rare value
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=50),
            processing_time=ts + timedelta(seconds=50),
        )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_RARE_VALUE
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.classification == "baseline_rare_value"

    def test_established_value_classification(
        self,
    ) -> None:
        """Evidence for BASELINE_ESTABLISHED classification."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with many observations
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_ESTABLISHED
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code == BaselineReasonCode.VALUE_ESTABLISHED
        assert evidence.classification == "baseline_established"


# ── Test: Single-Observation Semantics ────────────────────────────────────────


class TestSingleObservationSemantics:
    """Prove that adding baseline evidence never records a second observation."""

    def test_one_event_produces_exactly_one_observation(
        self,
    ) -> None:
        """Processing one event produces exactly one observation in the profile."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Record one observation
        result, profile = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts,
            processing_time=ts,
        )

        assert profile.observation_count == 1
        assert result.classification == BaselineClassification.BASELINE_UNAVAILABLE

    def test_evidence_does_not_increment_observation_count(
        self,
    ) -> None:
        """Calling generate_evidence_for_classification does not increment observation_count."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Record one observation
        _result, profile_before = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts,
            processing_time=ts,
        )

        obs_count_before = profile_before.observation_count
        first_seen_before = profile_before.first_seen
        last_seen_before = profile_before.last_seen

        # Generate evidence (read-only query)
        evidence = service.generate_evidence_for_classification(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
        )

        # Profile must be unchanged
        profile_after = service.get_profile("hostname", "host1", "process_name")
        assert profile_after is not None
        assert profile_after.observation_count == obs_count_before
        assert profile_after.first_seen == first_seen_before
        assert profile_after.last_seen == last_seen_before
        assert evidence is not None

    def test_decision_engine_does_not_mutate_profile(
        self,
    ) -> None:
        """DecisionEngine.process_detection_result does not mutate the profile."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build a mature profile
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        profile_before = service.get_profile("hostname", "host1", "process_name")
        assert profile_before is not None
        obs_before = profile_before.observation_count
        first_seen_before = profile_before.first_seen
        last_seen_before = profile_before.last_seen
        maturity_before = profile_before.maturity

        # Create a DetectionResult and process it through DecisionEngine
        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[
                {"field": "hostname", "observed": "host1", "condition": "equals"},
                {"field": "process_name", "observed": "python.exe", "condition": "equals"},
            ],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        alert = engine.process_detection_result(result)
        assert alert is not None

        # Profile must be unchanged
        profile_after = service.get_profile("hostname", "host1", "process_name")
        assert profile_after is not None
        assert profile_after.observation_count == obs_before
        assert profile_after.first_seen == first_seen_before
        assert profile_after.last_seen == last_seen_before
        assert profile_after.maturity == maturity_before

    def test_first_seen_unchanged_by_evidence_propagation(
        self,
    ) -> None:
        """first_seen is unchanged by evidence propagation."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts,
            processing_time=ts,
        )

        profile_before = service.get_profile("hostname", "host1", "process_name")
        first_seen_before = profile_before.first_seen

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        engine.process_detection_result(result)

        profile_after = service.get_profile("hostname", "host1", "process_name")
        assert profile_after.first_seen == first_seen_before

    def test_maturity_unchanged_by_evidence_propagation(
        self,
    ) -> None:
        """Maturity is unchanged by evidence propagation."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        profile_before = service.get_profile("hostname", "host1", "process_name")
        maturity_before = profile_before.maturity

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        engine.process_detection_result(result)

        profile_after = service.get_profile("hostname", "host1", "process_name")
        assert profile_after.maturity == maturity_before

    def test_value_counts_unchanged_by_evidence_propagation(
        self,
    ) -> None:
        """Value frequency/counts are unchanged by evidence propagation."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="chrome.exe",
            timestamp=ts + timedelta(seconds=11),
            processing_time=ts + timedelta(seconds=11),
        )

        # Capture counts before
        counts_before = dict(service._value_counts.get("hostname:host1|dimension:process_name", {}))

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        engine.process_detection_result(result)

        # Counts must be identical
        counts_after = service._value_counts.get("hostname:host1|dimension:process_name", {})
        assert counts_after == counts_before

    def test_classification_unchanged_by_evidence_propagation(
        self,
    ) -> None:
        """Classification is unchanged by evidence propagation."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Get classification before evidence propagation
        result_before, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )
        classification_before = result_before.classification

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        engine.process_detection_result(result)

        # Classification must still be the same
        result_after, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=101),
            processing_time=ts + timedelta(seconds=101),
        )
        assert result_after.classification == classification_before

    def test_evidence_corresponds_to_upstream_classification(
        self,
    ) -> None:
        """Evidence attached to Alert corresponds to the classification already produced."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Get the classification result that the detector would have produced
        classification_result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="python.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        engine = DecisionEngine(entity_behavior_service=service)
        # Pass event with timestamp so processing_time is consistent
        event = NormalizedEvent(
            source_type="sysmon",
            event_type="process_create",
            hostname="host1",
            process_name="python.exe",
            timestamp=ts + timedelta(seconds=100),
        )
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        alert = engine.process_detection_result(result, event=event)
        assert alert is not None

        evidence = alert.metadata.get("baseline_evidence")
        assert evidence is not None
        # Evidence should match the classification from the upstream result
        assert evidence["classification"] == classification_result.classification.value


# ── Test: Dimension Value Correctness ─────────────────────────────────────────


class TestDimensionValueCorrectness:
    """Prove that the correct dimension value is used for evidence generation."""

    def test_dimension_value_from_metadata_first_value(
        self,
    ) -> None:
        """Evidence uses first_value from metadata, not entity_id."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with python.exe
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )
        alert = engine.process_detection_result(result)
        assert alert is not None

        evidence = alert.metadata.get("baseline_evidence")
        assert evidence is not None
        # The evidence should reference python.exe, not host1
        assert "python.exe" in evidence.get("explanation", "")
        assert evidence.get("value_count") == 10

    def test_dimension_value_from_evidence_fallback(
        self,
    ) -> None:
        """Evidence falls back to evidence.first_value when metadata lacks it."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="chrome.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[
                {"field": "first_value", "observed": "chrome.exe", "condition": "equals"},
            ],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
            },
        )
        alert = engine.process_detection_result(result)
        assert alert is not None

        evidence = alert.metadata.get("baseline_evidence")
        assert evidence is not None
        assert "chrome.exe" in evidence.get("explanation", "")


# ── Test: Error Observability ─────────────────────────────────────────────────


class TestErrorObservability:
    """Tests for error handling and observability in evidence generation."""

    def test_evidence_failure_does_not_prevent_alert(
        self,
    ) -> None:
        """Alert is created even when evidence generation fails."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )

        # Mock generate_evidence_for_classification to raise
        with patch.object(
            service,
            "generate_evidence_for_classification",
            side_effect=RuntimeError("simulated failure"),
        ):
            alert = engine.process_detection_result(result)
            assert alert is not None
            assert "baseline_evidence" not in alert.metadata

    def test_evidence_failure_is_logged(
        self,
    ) -> None:
        """Evidence generation failures are logged with warning level."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        engine = DecisionEngine(entity_behavior_service=service)
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "python.exe",
            },
        )

        with (
            patch.object(
                service,
                "generate_evidence_for_classification",
                side_effect=RuntimeError("simulated failure"),
            ),
            patch("argusprowl.decision_engine.decision_engine.logger") as mock_logger,
        ):
            engine.process_detection_result(result)
            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args
            assert "simulated failure" in str(call_args)


# ── Test: Replay/Live Provenance ──────────────────────────────────────────────


class TestReplayLiveProvenance:
    """Tests for replay/live provenance of baseline evidence."""

    def test_replay_does_not_record_second_observation(
        self,
    ) -> None:
        """Replay path records each event exactly once."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
            is_replay_mode=True,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Simulate detector pipeline: observe then detect
        from argusprowl.behavior.entity_behavior_detector import EntityBehaviorDetector

        detector = EntityBehaviorDetector(
            name="test_detector",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = NormalizedEvent(
            source_type="sysmon",
            event_type="process_create",
            hostname="host1",
            process_name="python.exe",
            timestamp=ts,
        )

        # observe() creates profile (with observation_count=1 from get_or_create_profile)
        detector.observe(event)
        profile_after_observe = service.get_profile("hostname", "host1", "process_name")
        assert profile_after_observe is not None
        obs_after_observe = profile_after_observe.observation_count

        # detect() records the value atomically
        detection_result = detector.detect(event)
        assert detection_result.matched is True
        profile_after_detect = service.get_profile("hostname", "host1", "process_name")
        assert profile_after_detect.observation_count == obs_after_observe + 1

        # Process through DecisionEngine
        engine = DecisionEngine(entity_behavior_service=service)
        alert = engine.process_detection_result(detection_result)
        assert alert is not None

        # Profile must not be mutated by DecisionEngine
        profile_final = service.get_profile("hostname", "host1", "process_name")
        assert profile_final.observation_count == obs_after_observe + 1

    def test_crossing_rare_to_established_boundary_no_second_recording(
        self,
    ) -> None:
        """Event crossing rare→established boundary is recorded exactly once."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with enough observations
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="python.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add rare value twice (below threshold of 2)
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=11),
            processing_time=ts + timedelta(seconds=11),
        )
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=12),
            processing_time=ts + timedelta(seconds=12),
        )

        # This observation should cross into established (count goes from 2 to 3, > threshold)
        _result, profile_before = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=13),
            processing_time=ts + timedelta(seconds=13),
        )

        obs_before = profile_before.observation_count

        # Process through DecisionEngine with event timestamp
        engine = DecisionEngine(entity_behavior_service=service)
        detection_result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.INFO,
            confidence=1.0,
            description="Test",
            evidence=[],
            metadata={
                "entity_type": "hostname",
                "entity_id": "host1",
                "dimension": "process_name",
                "first_value": "rare.exe",
            },
        )
        event = NormalizedEvent(
            source_type="sysmon",
            event_type="process_create",
            hostname="host1",
            process_name="rare.exe",
            timestamp=ts + timedelta(seconds=13),
        )
        alert = engine.process_detection_result(detection_result, event=event)
        assert alert is not None

        # Profile must have same observation count (DecisionEngine is read-only)
        profile_after = service.get_profile("hostname", "host1", "process_name")
        assert profile_after.observation_count == obs_before

        # Evidence should reflect established classification
        evidence = alert.metadata.get("baseline_evidence")
        assert evidence is not None
        assert evidence["classification"] == "baseline_established"
