"""Phase 4.7.2 — Decision / Alert Hardening tests.

Focused contract tests for the DetectionResult → ContextualAssessment →
DecisionEngine → Alert boundary. These tests encode the production-safe
invariants that 4.7.1 left incomplete:

- DecisionEngine consumes ContextualAssessment.severity without remapping.
- Legacy DetectionResult-only behaviour is unchanged.
- Contextual score is not part of alert identity.
- Alert contextual fields round-trip.
- AlertManager / providers do not discard contextual reasoning.
- Replay uses the same assessment → decision path as live processing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.console_provider import ConsoleAlertProvider
from argusprowl.alerting.json_provider import JsonAlertProvider
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.deduplication.fingerprint import AlertFingerprint
from argusprowl.intelligence.fusion import EvidenceFusionEngine
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.interfaces.alert_provider import AlertProvider
from argusprowl.models.alert import Alert
from argusprowl.models.context import (
    ContextualAssessment,
    EntityContext,
    EvidenceType,
    FusionEvidence,
    PrevalenceResult,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.models.detection_result import DetectionResult
from argusprowl.replay.replay_engine import ReplayEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    *,
    rule_id: str = "beaconing_c2",
    src_ip: str = "10.0.0.5",
    confidence: float = 0.85,
    severity: Severity = Severity.HIGH,
    matched: bool = True,
    extra_evidence: list[dict[str, object]] | None = None,
) -> DetectionResult:
    evidence: list[dict[str, object]] = [
        {"field": "src_ip", "observed": src_ip, "condition": "equals"},
    ]
    if extra_evidence:
        evidence.extend(extra_evidence)
    return DetectionResult(
        rule_id=rule_id,
        event_id=uuid4(),
        matched=matched,
        severity=severity,
        confidence=confidence,
        description=f"{rule_id} from {src_ip}",
        evidence=evidence,
    )


def _assessment(
    detection_result: DetectionResult,
    *,
    final_confidence: float,
    severity: Severity,
    explanation: str = "contextual assessment",
    supporting: tuple[FusionEvidence, ...] = (),
    contradictory: tuple[FusionEvidence, ...] = (),
    pivots: tuple[str, ...] = ("Inspect destination", "Review process tree"),
    entity_context: EntityContext | None = None,
) -> ContextualAssessment:
    return ContextualAssessment(
        detection_result=detection_result,
        final_confidence=final_confidence,
        severity=severity,
        entity_context=entity_context,
        supporting_evidence=supporting,
        contradictory_evidence=contradictory,
        explanation=explanation,
        investigation_pivots=pivots,
    )


def _supporting(category: str, description: str, weight: float) -> FusionEvidence:
    return FusionEvidence(
        evidence_type=EvidenceType.SUPPORTING,
        category=category,
        description=description,
        weight=weight,
    )


def _contradictory(category: str, description: str, weight: float) -> FusionEvidence:
    return FusionEvidence(
        evidence_type=EvidenceType.CONTRADICTORY,
        category=category,
        description=description,
        weight=weight,
    )


@pytest.fixture
def decision_engine() -> DecisionEngine:
    return DecisionEngine(cooldown_seconds=60)


# ===========================================================================
# 1. Dual severity mapping — DecisionEngine must consume assessment.severity
# ===========================================================================


class TestContextualSeverityConsumption:
    """When an assessment exists, Alert.severity must equal assessment.severity.

    DecisionEngine must not re-run fusion scoring and must not apply the
    legacy DetectionResult confidence-downgrade table to contextual scores.
    """

    @pytest.mark.parametrize(
        ("final_confidence", "expected_severity"),
        [
            (0.00, Severity.INFO),
            (0.29, Severity.INFO),
            (0.30, Severity.LOW),
            (0.44, Severity.LOW),
            (0.45, Severity.MEDIUM),
            (0.59, Severity.MEDIUM),
            (0.60, Severity.HIGH),
            (0.84, Severity.HIGH),
            (0.85, Severity.CRITICAL),
            (1.00, Severity.CRITICAL),
        ],
    )
    def test_alert_severity_equals_assessment_severity_at_every_boundary(
        self,
        decision_engine: DecisionEngine,
        final_confidence: float,
        expected_severity: Severity,
    ) -> None:
        result = _result(src_ip=f"10.0.0.{int(final_confidence * 100)}")
        assessment = _assessment(
            result,
            final_confidence=final_confidence,
            severity=expected_severity,
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.severity == expected_severity
        assert alert.contextual_confidence == final_confidence
        assert alert.detector_confidence == result.confidence

    def test_does_not_apply_legacy_downgrade_to_contextual_score(
        self, decision_engine: DecisionEngine
    ) -> None:
        """0.30 contextual confidence is LOW in fusion, not MEDIUM via legacy table."""
        result = _result()
        assessment = _assessment(result, final_confidence=0.30, severity=Severity.LOW)
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.severity == Severity.LOW
        assert alert.severity != result.severity

    def test_does_not_recalculate_contextual_confidence(
        self, decision_engine: DecisionEngine
    ) -> None:
        result = _result()
        assessment = _assessment(result, final_confidence=0.4237, severity=Severity.LOW)
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.contextual_confidence == 0.4237
        assert alert.detector_confidence == 0.85

    def test_does_not_use_assessment_severity_when_no_assessment(
        self, decision_engine: DecisionEngine
    ) -> None:
        """Legacy path still uses DetectionResult.confidence + original severity."""
        high = _result(confidence=0.85, severity=Severity.HIGH, src_ip="10.1.1.1")
        low = _result(confidence=0.25, severity=Severity.HIGH, src_ip="10.1.1.2")
        high_alert = decision_engine.process_detection_result(high)
        low_alert = decision_engine.process_detection_result(low)
        assert high_alert is not None and high_alert.severity == Severity.HIGH
        assert low_alert is not None and low_alert.severity == Severity.LOW
        assert high_alert.assessment_id is None
        assert high_alert.detector_confidence is None
        assert high_alert.contextual_confidence is None


# ===========================================================================
# 2. Fusion → DecisionEngine end-to-end severity (no second scoring)
# ===========================================================================


class TestFusionToDecisionSeverity:
    """Prove fusion severity survives DecisionEngine unchanged."""

    def test_strong_support_yields_critical_alert(self, decision_engine: DecisionEngine) -> None:
        fusion = EvidenceFusionEngine()
        result = _result(
            extra_evidence=[
                {"field": "destination", "observed": "203.0.113.50", "condition": "equals"},
            ]
        )
        assessment = fusion.fuse(
            detection_result=result,
            entity_context=EntityContext(
                host="ws01",
                process_name="powershell.exe",
                pid=1234,
                src_ip="10.0.0.5",
                dst_ip="203.0.113.50",
                dst_port=8443,
            ),
            prevalence=PrevalenceResult(
                dest_host_count=1, process_dest_count=1, is_rare_destination=True
            ),
            reputation=ThreatIntelReputation(
                indicator="203.0.113.50",
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=1.0,
                source="local",
            ),
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert assessment.severity == Severity.CRITICAL
        assert alert.severity == assessment.severity
        assert alert.contextual_confidence == assessment.final_confidence
        assert alert.detector_confidence == result.confidence
        assert len(alert.supporting_evidence) >= 2
        assert alert.contradictory_evidence == () or all(
            item["evidence_type"] == "CONTRADICTORY" for item in alert.contradictory_evidence
        )

    def test_strong_contradiction_lowers_severity(self, decision_engine: DecisionEngine) -> None:
        fusion = EvidenceFusionEngine()
        result = _result()
        assessment = fusion.fuse(
            detection_result=result,
            prevalence=PrevalenceResult(
                dest_host_count=120, process_dest_count=80, is_environment_wide=True
            ),
            reputation=ThreatIntelReputation(
                indicator="203.0.113.1",
                verdict=ThreatIntelVerdict.BENIGN,
                confidence=1.0,
            ),
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        # 0.85 - 0.40 - 0.30 = 0.15 → INFO
        assert assessment.final_confidence == 0.15
        assert assessment.severity == Severity.INFO
        assert alert.severity == Severity.INFO
        assert alert.detector_confidence == 0.85
        assert len(alert.contradictory_evidence) >= 1

    def test_unknown_ti_is_neutral(self, decision_engine: DecisionEngine) -> None:
        fusion = EvidenceFusionEngine()
        result = _result()
        assessment = fusion.fuse(
            detection_result=result,
            reputation=ThreatIntelReputation(
                indicator="203.0.113.50",
                verdict=ThreatIntelVerdict.UNKNOWN,
                confidence=0.0,
            ),
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert assessment.final_confidence == result.confidence
        assert alert.contextual_confidence == result.confidence
        assert alert.severity == assessment.severity
        assert "No threat-intelligence verdict was available" in assessment.explanation

    def test_conflicting_evidence_is_deterministic(self, decision_engine: DecisionEngine) -> None:
        fusion = EvidenceFusionEngine()
        result = _result()
        assessment = fusion.fuse(
            detection_result=result,
            prevalence=PrevalenceResult(
                dest_host_count=1, process_dest_count=1, is_rare_destination=True
            ),
            reputation=ThreatIntelReputation(
                indicator="10.0.0.1",
                verdict=ThreatIntelVerdict.BENIGN,
                confidence=1.0,
            ),
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        # 0.85 + 0.15 - 0.30 = 0.70 → HIGH
        assert assessment.final_confidence == 0.70
        assert assessment.severity == Severity.HIGH
        assert alert.severity == Severity.HIGH
        assert len(alert.supporting_evidence) >= 1
        assert len(alert.contradictory_evidence) >= 1


# ===========================================================================
# 3. Deduplication identity independent of contextual score
# ===========================================================================


class TestDeduplicationIndependence:
    def test_same_detection_different_contextual_score_same_identity(
        self, decision_engine: DecisionEngine
    ) -> None:
        result = _result()
        first = decision_engine.process_detection_result(
            result,
            assessment=_assessment(result, final_confidence=0.95, severity=Severity.CRITICAL),
        )
        second = decision_engine.process_detection_result(
            result,
            assessment=_assessment(result, final_confidence=0.20, severity=Severity.INFO),
        )
        assert first is not None
        assert second is None

    def test_fingerprint_ignores_contextual_fields(self) -> None:
        fingerprint = AlertFingerprint()
        base_meta = {
            "rule_id": "beaconing_c2",
            "evidence": [{"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"}],
        }
        a = Alert(
            title="A",
            description="d",
            severity=Severity.HIGH,
            source="beaconing_c2",
            metadata=dict(base_meta),
        )
        b = Alert(
            title="A",
            description="d",
            severity=Severity.INFO,
            source="beaconing_c2",
            metadata=dict(base_meta),
            contextual_confidence=0.12,
            detector_confidence=0.85,
            assessment_id=uuid4(),
            contextual_explanation="different context",
        )
        assert fingerprint.create(a) == fingerprint.create(b)

    def test_different_hosts_remain_independent(self, decision_engine: DecisionEngine) -> None:
        r1 = _result(src_ip="10.0.0.1")
        r2 = _result(src_ip="10.0.0.2")
        a1 = decision_engine.process_detection_result(
            r1, assessment=_assessment(r1, final_confidence=0.9, severity=Severity.CRITICAL)
        )
        a2 = decision_engine.process_detection_result(
            r2, assessment=_assessment(r2, final_confidence=0.2, severity=Severity.INFO)
        )
        assert a1 is not None
        assert a2 is not None
        assert a1.alert_id != a2.alert_id

    def test_assessment_present_vs_absent_same_identity(
        self, decision_engine: DecisionEngine
    ) -> None:
        result = _result()
        with_assessment = decision_engine.process_detection_result(
            result,
            assessment=_assessment(result, final_confidence=0.9, severity=Severity.CRITICAL),
        )
        without_assessment = decision_engine.process_detection_result(result)
        assert with_assessment is not None
        assert without_assessment is None

    def test_legacy_cooldown_still_suppresses_identical_detection(
        self, decision_engine: DecisionEngine
    ) -> None:
        result = _result()
        first = decision_engine.process_detection_result(result)
        second = decision_engine.process_detection_result(result)
        assert first is not None
        assert second is None


# ===========================================================================
# 4. Alert contract: construction, validation, round-trip, empty behaviour
# ===========================================================================


class TestAlertContextualContract:
    def test_roundtrip_preserves_every_contextual_field(self) -> None:
        original = Alert(
            title="Beaconing C2",
            description="Beaconing detected",
            severity=Severity.CRITICAL,
            source="beaconing_c2",
            tags=("beaconing_c2", "threat_detection"),
            metadata={"rule_id": "beaconing_c2", "confidence": 0.85},
            assessment_id=uuid4(),
            detector_confidence=0.85,
            contextual_confidence=0.95,
            contextual_explanation="Rare destination with malicious TI",
            supporting_evidence=(
                {
                    "evidence_type": "SUPPORTING",
                    "category": "prevalence",
                    "description": "Rare dest",
                    "weight": 0.15,
                    "metadata": {},
                },
            ),
            contradictory_evidence=(
                {
                    "evidence_type": "CONTRADICTORY",
                    "category": "reputation",
                    "description": "Benign TI",
                    "weight": -0.30,
                    "metadata": {},
                },
            ),
            investigation_pivots=("Check DNS logs", "Inspect process tree"),
            entity_context={
                "host": "ws01",
                "process_name": "svchost.exe",
                "pid": 1234,
                "src_ip": "10.0.0.5",
                "dst_ip": "203.0.113.50",
                "dst_port": 8443,
                "username": None,
                "domain": None,
            },
        )
        restored = Alert.from_dict(original.to_dict())
        assert restored.alert_id == original.alert_id
        assert restored.assessment_id == original.assessment_id
        assert restored.detector_confidence == original.detector_confidence
        assert restored.contextual_confidence == original.contextual_confidence
        assert restored.contextual_explanation == original.contextual_explanation
        assert restored.supporting_evidence == original.supporting_evidence
        assert restored.contradictory_evidence == original.contradictory_evidence
        assert restored.investigation_pivots == original.investigation_pivots
        assert restored.entity_context == original.entity_context
        assert restored.severity == original.severity
        assert restored.schema_version == original.schema_version

    def test_from_dict_accepts_legacy_payload_without_contextual_keys(self) -> None:
        payload = {
            "alert_id": str(uuid4()),
            "title": "Legacy Alert",
            "description": "old payload",
            "severity": "HIGH",
            "source": "port_scan",
            "created_at": datetime.now(UTC).isoformat(),
            "tags": ["port_scan"],
            "metadata": {"confidence": 0.8},
            "schema_version": 1,
        }
        alert = Alert.from_dict(payload)
        assert alert.assessment_id is None
        assert alert.detector_confidence is None
        assert alert.contextual_confidence is None
        assert alert.contextual_explanation == ""
        assert alert.supporting_evidence == ()
        assert alert.contradictory_evidence == ()
        assert alert.investigation_pivots == ()
        assert alert.entity_context is None
        assert alert.schema_version == 1

    def test_zero_confidence_roundtrips(self) -> None:
        original = Alert(
            title="Zero",
            description="zero confidence",
            severity=Severity.INFO,
            source="test",
            detector_confidence=0.0,
            contextual_confidence=0.0,
        )
        restored = Alert.from_dict(original.to_dict())
        assert restored.detector_confidence == 0.0
        assert restored.contextual_confidence == 0.0

    def test_empty_evidence_and_pivots_are_deterministic(self) -> None:
        alert = Alert(
            title="Empty",
            description="empty context",
            severity=Severity.LOW,
            source="test",
            supporting_evidence=(),
            contradictory_evidence=(),
            investigation_pivots=(),
            entity_context=None,
        )
        payload = alert.to_dict()
        assert payload["supporting_evidence"] == []
        assert payload["contradictory_evidence"] == []
        assert payload["investigation_pivots"] == []
        assert payload["entity_context"] is None
        restored = Alert.from_dict(payload)
        assert restored.supporting_evidence == ()
        assert restored.entity_context is None

    def test_decision_engine_alert_roundtrip(self, decision_engine: DecisionEngine) -> None:
        result = _result()
        entity = EntityContext(
            host="ws01",
            process_name="powershell.exe",
            pid=99,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        assessment = _assessment(
            result,
            final_confidence=0.95,
            severity=Severity.CRITICAL,
            explanation="Rare dest + malicious TI",
            supporting=(_supporting("prevalence", "Rare destination", 0.15),),
            contradictory=(),
            pivots=("Inspect destination", "Review process tree"),
            entity_context=entity,
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        restored = Alert.from_dict(alert.to_dict())
        assert restored.assessment_id == assessment.assessment_id
        assert restored.detector_confidence == 0.85
        assert restored.contextual_confidence == 0.95
        assert restored.severity == Severity.CRITICAL
        assert restored.contextual_explanation == "Rare dest + malicious TI"
        assert restored.entity_context is not None
        assert restored.entity_context["process_name"] == "powershell.exe"
        assert restored.investigation_pivots == ("Inspect destination", "Review process tree")


# ===========================================================================
# 5. AlertManager / providers preserve contextual reasoning
# ===========================================================================


class TestAlertManagerPreservation:
    def test_manager_dispatches_full_alert_object(self) -> None:
        received: list[Alert] = []

        class CaptureProvider(AlertProvider):
            @property
            def provider_name(self) -> str:
                return "capture"

            def is_available(self) -> bool:
                return True

            def send(self, alert: Alert) -> bool:
                received.append(alert)
                return True

        manager = AlertManager()
        manager.register_provider(CaptureProvider())
        result = _result()
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(
            result,
            assessment=_assessment(
                result,
                final_confidence=0.95,
                severity=Severity.CRITICAL,
                explanation="why context changed",
                supporting=(_supporting("reputation", "Malicious TI", 0.25),),
                contradictory=(_contradictory("prevalence", "Environment-wide", -0.40),),
                pivots=("Inspect destination",),
                entity_context=EntityContext(host="ws01", dst_ip="203.0.113.50"),
            ),
        )
        assert alert is not None
        results = manager.send_alert(alert)
        assert results["capture"] is True
        dispatched = received[0]
        assert dispatched.assessment_id == alert.assessment_id
        assert dispatched.detector_confidence == 0.85
        assert dispatched.contextual_confidence == 0.95
        assert dispatched.contextual_explanation == "why context changed"
        assert dispatched.supporting_evidence
        assert dispatched.contradictory_evidence
        assert dispatched.investigation_pivots
        assert dispatched.entity_context is not None

    def test_json_provider_writes_contextual_fields(self, tmp_path: Path) -> None:
        import json

        path = tmp_path / "alerts.jsonl"
        provider = JsonAlertProvider(output_path=path)
        alert = Alert(
            title="Beaconing C2",
            description="Beaconing detected",
            severity=Severity.CRITICAL,
            source="beaconing_c2",
            assessment_id=uuid4(),
            detector_confidence=0.85,
            contextual_confidence=0.95,
            contextual_explanation="Rare destination",
            supporting_evidence=({"category": "prevalence", "weight": 0.15},),
            contradictory_evidence=(),
            investigation_pivots=("Inspect destination",),
            entity_context={"host": "ws01"},
        )
        assert provider.send(alert) is True
        payload = json.loads(path.read_text().splitlines()[0])
        assert payload["assessment_id"] == str(alert.assessment_id)
        assert payload["detector_confidence"] == 0.85
        assert payload["contextual_confidence"] == 0.95
        assert payload["contextual_explanation"] == "Rare destination"
        assert payload["investigation_pivots"] == ["Inspect destination"]
        assert payload["entity_context"] == {"host": "ws01"}

    def test_console_provider_renders_list_evidence_and_contextual_fields(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        provider = ConsoleAlertProvider(use_colors=False, include_timestamp=False)
        alert = Alert(
            title="Beaconing C2",
            description="Beaconing detected",
            severity=Severity.HIGH,
            source="beaconing_c2",
            assessment_id=uuid4(),
            detector_confidence=0.85,
            contextual_confidence=0.15,
            contextual_explanation="Environment-wide CDN traffic",
            supporting_evidence=(),
            contradictory_evidence=(
                {"category": "prevalence", "description": "Environment-wide", "weight": -0.40},
            ),
            investigation_pivots=("Inspect destination", "Review process tree"),
            entity_context={"host": "ws01", "dst_ip": "203.0.113.50"},
            metadata={
                "confidence": 0.85,
                "evidence": [
                    {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
                    {"field": "destination", "observed": "203.0.113.50", "condition": "equals"},
                ],
            },
        )
        assert provider.send(alert) is True
        output = capsys.readouterr().out
        assert "Detector confidence: 0.85" in output
        assert "Contextual confidence: 0.15" in output
        assert "WHY:" in output
        assert "Environment-wide CDN traffic" in output
        assert "INVESTIGATION PIVOTS:" in output
        assert "src_ip: 10.0.0.5" in output
        assert "destination: 203.0.113.50" in output
        assert "CONTRADICTORY EVIDENCE:" in output
        assert "Host: ws01" in output
        assert "Destination: 203.0.113.50" in output


# ===========================================================================
# 6. Live / replay semantic equivalence of the assessment → decision path
# ===========================================================================


class TestLiveReplayAssessmentEquivalence:
    def test_same_inputs_produce_equivalent_alerts(self) -> None:
        fusion = EvidenceFusionEngine()
        result = _result(
            extra_evidence=[
                {"field": "destination", "observed": "203.0.113.50", "condition": "equals"},
                {"field": "process_name", "observed": "powershell.exe", "condition": "equals"},
            ]
        )
        entity = EntityContext(
            host="ws01",
            process_name="powershell.exe",
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        prevalence = PrevalenceResult(
            dest_host_count=1, process_dest_count=1, is_rare_destination=True
        )
        reputation = ThreatIntelReputation(
            indicator="203.0.113.50",
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
        )

        live_assessment = fusion.fuse(result, entity, prevalence, reputation)
        replay_assessment = fusion.fuse(result, entity, prevalence, reputation)

        live_engine = DecisionEngine(cooldown_seconds=0)
        replay_engine = DecisionEngine(cooldown_seconds=0)
        live_alert = live_engine.process_detection_result(result, assessment=live_assessment)
        replay_alert = replay_engine.process_detection_result(result, assessment=replay_assessment)

        assert live_alert is not None and replay_alert is not None
        assert live_alert.severity == replay_alert.severity
        assert live_alert.detector_confidence == replay_alert.detector_confidence
        assert live_alert.contextual_confidence == replay_alert.contextual_confidence
        assert live_alert.contextual_explanation == replay_alert.contextual_explanation
        assert live_alert.supporting_evidence == replay_alert.supporting_evidence
        assert live_alert.contradictory_evidence == replay_alert.contradictory_evidence
        assert live_alert.investigation_pivots == replay_alert.investigation_pivots
        assert live_alert.entity_context == replay_alert.entity_context
        assert live_assessment.final_confidence == replay_assessment.final_confidence
        assert live_assessment.severity == replay_assessment.severity

    def test_replay_engine_can_emit_contextual_alerts(self, tmp_path: Path) -> None:
        """Replay must be able to run the same assessment → decision path as live."""
        log_file = tmp_path / "conn.log"
        log_file.write_text(
            "#separator \\x09\n"
            "#set_separator\t,\n"
            "#empty_field\t(empty)\n"
            "#unset_field\t-\n"
            "#path\tconn\n"
            "#open\t2019-01-01-00-00-00\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
            "service\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\t"
            "orig_pkts\tresp_pkts\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\t"
            "count\tcount\tstring\tstring\tcount\tcount\n"
            "1550000000.000000\tC1\t192.168.1.100\t12345\t10.0.0.1\t80\ttcp\thttp\t"
            "400.0\t1024\t2048\tSF\tShADadfF\t10\t8\n"
        )
        intelligence = ContextualIntelligenceService()
        decision = DecisionEngine(cooldown_seconds=0)
        engine = ReplayEngine(
            log_path=log_file,
            intelligence_service=intelligence,
            decision_engine=decision,
        )
        alerts = engine.run()
        assert isinstance(alerts, list)
        for alert in alerts:
            assert alert.assessment_id is not None
            assert alert.detector_confidence is not None
            assert alert.contextual_confidence is not None
            assert alert.contextual_explanation
            restored = Alert.from_dict(alert.to_dict())
            assert restored.assessment_id == alert.assessment_id
            assert restored.contextual_confidence == alert.contextual_confidence
