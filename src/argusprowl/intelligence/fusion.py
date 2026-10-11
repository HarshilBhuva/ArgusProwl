"""Evidence Fusion Engine for argusprowl Context & Intelligence Layer (Phase 4.6C).

Fuses raw DetectionResults with contextual signals (EntityContext, PrevalenceResult,
ThreatIntelReputation) to compute deterministic, explainable ContextualAssessments.
"""

from __future__ import annotations

from argusprowl.constants.severity import Severity
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


class EvidenceFusionEngine:
    """Deterministic evidence fusion engine combining detection results and contextual signals.

    This engine operates purely as a reasoning layer. It does not perform network calls,
    query external APIs, or rediscover contextual facts.
    """

    def __init__(
        self,
        weight_process_attribution: float = 0.10,
        weight_rare_destination: float = 0.15,
        weight_malicious_ti: float = 0.25,
        weight_suspicious_ti: float = 0.10,
        weight_suspicious_process: float = 0.10,
        weight_environment_wide: float = -0.40,
        weight_benign_infrastructure: float = -0.35,
        weight_benign_ti: float = -0.30,
        weight_expected_system_process: float = -0.10,
    ) -> None:
        """Initialize evidence fusion engine with configurable scoring weights."""
        self.weight_process_attribution = float(weight_process_attribution)
        self.weight_rare_destination = float(weight_rare_destination)
        self.weight_malicious_ti = float(weight_malicious_ti)
        self.weight_suspicious_ti = float(weight_suspicious_ti)
        self.weight_suspicious_process = float(weight_suspicious_process)
        self.weight_environment_wide = float(weight_environment_wide)
        self.weight_benign_infrastructure = float(weight_benign_infrastructure)
        self.weight_benign_ti = float(weight_benign_ti)
        self.weight_expected_system_process = float(weight_expected_system_process)

    def fuse(
        self,
        detection_result: DetectionResult,
        entity_context: EntityContext | None = None,
        prevalence: PrevalenceResult | None = None,
        reputation: ThreatIntelReputation | None = None,
    ) -> ContextualAssessment:
        """Fuse detection result and contextual facts into a ContextualAssessment.

        Args:
            detection_result: The raw detection result from a detector.
            entity_context: Optional entity context (host, process, network).
            prevalence: Optional environmental prevalence observations.
            reputation: Optional threat intelligence lookup reputation.

        Returns:
            An immutable ContextualAssessment instance.
        """
        if not detection_result.matched:
            return ContextualAssessment(
                detection_result=detection_result,
                final_confidence=0.0,
                severity=Severity.INFO,
                entity_context=entity_context,
                supporting_evidence=(),
                contradictory_evidence=(),
                explanation=f"Rule '{detection_result.rule_id}' did not match (matched=False).",
                investigation_pivots=(),
            )

        supporting_evidence: list[FusionEvidence] = []
        contradictory_evidence: list[FusionEvidence] = []

        # 1. Base Detector Evidence (Category: "detector" or "temporal")
        detector_cat = (
            "temporal"
            if "beacon" in detection_result.rule_id.lower()
            or "temporal" in detection_result.rule_id.lower()
            else "detector"
        )
        supporting_evidence.append(
            FusionEvidence(
                evidence_type=EvidenceType.SUPPORTING,
                category=detector_cat,
                description=f"Base detector '{detection_result.rule_id}' matched with confidence {detection_result.confidence:.2f}.",
                weight=0.0,
                metadata={
                    "rule_id": detection_result.rule_id,
                    "base_confidence": detection_result.confidence,
                },
            )
        )

        # 2. Process / Network Attribution Evidence (Category: "attribution")
        if entity_context is not None and entity_context.process_name:
            proc_desc = (
                f"Network activity was attributed to process '{entity_context.process_name}'"
            )
            if entity_context.pid is not None:
                proc_desc += f" (PID {entity_context.pid})"
            proc_desc += "."
            supporting_evidence.append(
                FusionEvidence(
                    evidence_type=EvidenceType.SUPPORTING,
                    category="attribution",
                    description=proc_desc,
                    weight=self.weight_process_attribution,
                    metadata={
                        "process_name": entity_context.process_name,
                        "pid": entity_context.pid,
                    },
                )
            )

        # 3. Prevalence Evidence (Category: "prevalence")
        if prevalence is not None:
            if prevalence.is_rare_destination:
                supporting_evidence.append(
                    FusionEvidence(
                        evidence_type=EvidenceType.SUPPORTING,
                        category="prevalence",
                        description=f"Destination was observed on only {prevalence.dest_host_count} host(s) in local environment.",
                        weight=self.weight_rare_destination,
                        metadata={
                            "dest_host_count": prevalence.dest_host_count,
                            "process_dest_count": prevalence.process_dest_count,
                        },
                    )
                )

            if prevalence.is_environment_wide:
                contradictory_evidence.append(
                    FusionEvidence(
                        evidence_type=EvidenceType.CONTRADICTORY,
                        category="prevalence",
                        description=f"Destination is environment-wide, observed across {prevalence.dest_host_count} hosts.",
                        weight=self.weight_environment_wide,
                        metadata={
                            "dest_host_count": prevalence.dest_host_count,
                            "process_dest_count": prevalence.process_dest_count,
                        },
                    )
                )

        # 4. Threat Intelligence Reputation Evidence (Category: "reputation" / "infrastructure")
        if reputation is not None:
            indicator_str = reputation.indicator
            conf = reputation.confidence
            verdict = reputation.verdict

            is_benign_infra = detection_result.metadata.get(
                "is_benign_infrastructure"
            ) is True or any(
                cat.lower() in ("enterprise", "cdn", "infrastructure", "cloud", "trusted")
                for cat in reputation.categories
            )

            if is_benign_infra and (verdict == ThreatIntelVerdict.BENIGN or conf > 0.0):
                w = round(self.weight_benign_infrastructure * (conf if conf > 0.0 else 1.0), 4)
                contradictory_evidence.append(
                    FusionEvidence(
                        evidence_type=EvidenceType.CONTRADICTORY,
                        category="infrastructure",
                        description=f"Target '{indicator_str}' is recognized benign enterprise infrastructure.",
                        weight=w if w < 0.0 else self.weight_benign_infrastructure,
                        metadata={
                            "indicator": indicator_str,
                            "categories": list(reputation.categories),
                        },
                    )
                )
            elif verdict == ThreatIntelVerdict.MALICIOUS:
                w = round(self.weight_malicious_ti * conf, 4)
                if w > 0.0:
                    supporting_evidence.append(
                        FusionEvidence(
                            evidence_type=EvidenceType.SUPPORTING,
                            category="reputation",
                            description=f"Threat intelligence classifies indicator '{indicator_str}' as MALICIOUS (confidence: {conf:.2f}).",
                            weight=w,
                            metadata={
                                "indicator": indicator_str,
                                "categories": list(reputation.categories),
                                "source": reputation.source,
                            },
                        )
                    )
            elif verdict == ThreatIntelVerdict.SUSPICIOUS:
                w = round(self.weight_suspicious_ti * conf, 4)
                if w > 0.0:
                    supporting_evidence.append(
                        FusionEvidence(
                            evidence_type=EvidenceType.SUPPORTING,
                            category="reputation",
                            description=f"Threat intelligence classifies indicator '{indicator_str}' as SUSPICIOUS (confidence: {conf:.2f}).",
                            weight=w,
                            metadata={
                                "indicator": indicator_str,
                                "categories": list(reputation.categories),
                                "source": reputation.source,
                            },
                        )
                    )
            elif verdict == ThreatIntelVerdict.BENIGN:
                w = round(self.weight_benign_ti * conf, 4)
                if w < 0.0:
                    contradictory_evidence.append(
                        FusionEvidence(
                            evidence_type=EvidenceType.CONTRADICTORY,
                            category="reputation",
                            description=f"Threat intelligence classifies indicator '{indicator_str}' as BENIGN (confidence: {conf:.2f}).",
                            weight=w,
                            metadata={
                                "indicator": indicator_str,
                                "categories": list(reputation.categories),
                                "source": reputation.source,
                            },
                        )
                    )

        # 5. Execution Context Evidence (Category: "execution_context")
        if entity_context is not None and entity_context.process_name:
            proc_lower = entity_context.process_name.lower()
            is_susp_proc = detection_result.metadata.get(
                "is_suspicious_process"
            ) is True or proc_lower in (
                "powershell.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "bash",
                "sh",
            )
            is_expected_proc = (
                detection_result.metadata.get("is_expected_system_process") is True
                or detection_result.metadata.get("is_system_process") is True
            )

            if is_susp_proc:
                supporting_evidence.append(
                    FusionEvidence(
                        evidence_type=EvidenceType.SUPPORTING,
                        category="execution_context",
                        description=f"Process '{entity_context.process_name}' represents a script interpreter or suspicious execution context.",
                        weight=self.weight_suspicious_process,
                        metadata={"process_name": entity_context.process_name},
                    )
                )

            if is_expected_proc:
                contradictory_evidence.append(
                    FusionEvidence(
                        evidence_type=EvidenceType.CONTRADICTORY,
                        category="execution_context",
                        description=f"Process '{entity_context.process_name}' operates within expected system execution context.",
                        weight=self.weight_expected_system_process,
                        metadata={"process_name": entity_context.process_name},
                    )
                )

        # Enforce deterministic Category ordering
        category_order = {
            "detector": 0,
            "temporal": 0,
            "attribution": 1,
            "prevalence": 2,
            "reputation": 3,
            "infrastructure": 3,
            "execution_context": 4,
        }
        supporting_evidence.sort(
            key=lambda ev: (category_order.get(ev.category, 99), ev.category, ev.description)
        )
        contradictory_evidence.sort(
            key=lambda ev: (category_order.get(ev.category, 99), ev.category, ev.description)
        )

        # Calculate final clamped score
        base_confidence = float(detection_result.confidence)
        sup_weight_sum = sum(ev.weight for ev in supporting_evidence)
        con_weight_sum = sum(ev.weight for ev in contradictory_evidence)

        raw_score = base_confidence + sup_weight_sum + con_weight_sum
        final_confidence = round(min(1.0, max(0.0, raw_score)), 4)

        severity = self._map_confidence_to_severity(final_confidence)

        explanation = self._build_explanation(
            detection_result=detection_result,
            entity_context=entity_context,
            supporting_evidence=supporting_evidence,
            contradictory_evidence=contradictory_evidence,
            reputation=reputation,
            final_confidence=final_confidence,
            severity=severity,
        )

        pivots = self._build_investigation_pivots(
            detection_result=detection_result,
            entity_context=entity_context,
            prevalence=prevalence,
            reputation=reputation,
        )

        return ContextualAssessment(
            detection_result=detection_result,
            final_confidence=final_confidence,
            severity=severity,
            entity_context=entity_context,
            supporting_evidence=tuple(supporting_evidence),
            contradictory_evidence=tuple(contradictory_evidence),
            explanation=explanation,
            investigation_pivots=pivots,
        )

    def _map_confidence_to_severity(self, confidence: float) -> Severity:
        """Map final confidence score to deterministic Severity level."""
        if confidence < 0.30:
            return Severity.INFO
        if confidence < 0.45:
            return Severity.LOW
        if confidence < 0.60:
            return Severity.MEDIUM
        if confidence < 0.85:
            return Severity.HIGH
        return Severity.CRITICAL

    def _build_explanation(
        self,
        detection_result: DetectionResult,
        entity_context: EntityContext | None,
        supporting_evidence: list[FusionEvidence],
        contradictory_evidence: list[FusionEvidence],
        reputation: ThreatIntelReputation | None,
        final_confidence: float,
        severity: Severity,
    ) -> str:
        """Construct human-readable, evidence-derived explanation narrative."""
        parts: list[str] = []
        parts.append(
            f"The activity was detected as rule '{detection_result.rule_id}' with base detector confidence {detection_result.confidence:.2f}."
        )

        if entity_context is not None:
            ctx_items: list[str] = []
            if entity_context.host:
                ctx_items.append(f"host='{entity_context.host}'")
            if entity_context.process_name:
                proc_str = f"process='{entity_context.process_name}'"
                if entity_context.pid is not None:
                    proc_str += f" (PID {entity_context.pid})"
                ctx_items.append(proc_str)
            target = entity_context.domain or entity_context.dst_ip
            if target:
                if entity_context.dst_port:
                    ctx_items.append(f"destination='{target}:{entity_context.dst_port}'")
                else:
                    ctx_items.append(f"destination='{target}'")
            if ctx_items:
                parts.append(f"Target entity context: {', '.join(ctx_items)}.")

        active_supporting = [ev for ev in supporting_evidence if ev.weight > 0.0]
        if active_supporting:
            facts = "; ".join(ev.description.rstrip(".") for ev in active_supporting)
            parts.append(f"Supporting context includes: {facts}.")

        if contradictory_evidence:
            facts = "; ".join(ev.description.rstrip(".") for ev in contradictory_evidence)
            parts.append(f"Contradictory context includes: {facts}.")

        if reputation is None or reputation.verdict == ThreatIntelVerdict.UNKNOWN:
            parts.append("No threat-intelligence verdict was available.")

        parts.append(
            f"The resulting contextual confidence is {final_confidence:.2f} ({severity.name})."
        )
        return " ".join(parts)

    def _build_investigation_pivots(
        self,
        detection_result: DetectionResult,
        entity_context: EntityContext | None,
        prevalence: PrevalenceResult | None,
        reputation: ThreatIntelReputation | None,
    ) -> tuple[str, ...]:
        """Generate bounded, actionable investigation pivots based on available facts."""
        pivots: list[str] = []

        if entity_context is not None:
            if entity_context.process_name and entity_context.pid is not None:
                pivots.append(
                    f"Inspect the parent process and ancestry of PID {entity_context.pid} ('{entity_context.process_name}')."
                )

            target = entity_context.domain or entity_context.dst_ip
            if target:
                pivots.append(
                    f"Search the environment for other host connections to target '{target}'."
                )

            if entity_context.process_name and entity_context.process_name.lower() in (
                "powershell.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
            ):
                pivots.append(
                    "Inspect or decode the process command line arguments for obfuscated payload instructions."
                )

            if entity_context.domain:
                pivots.append(f"Inspect DNS query history for domain '{entity_context.domain}'.")

        if reputation is None or reputation.verdict == ThreatIntelVerdict.UNKNOWN:
            pivots.append("Perform an external threat intelligence lookup for target indicator.")

        if prevalence is not None and prevalence.is_rare_destination:
            pivots.append("Inspect network traffic volume and payload data for rare destination.")

        # Fallback to keep pivot count bounded between 2 and 5
        if len(pivots) < 2:
            pivots.append(
                f"Review raw telemetry events and trigger conditions for rule '{detection_result.rule_id}'."
            )
        if len(pivots) < 2:
            pivots.append(
                "Inspect host event logs for concurrent privilege escalation or persistence activity."
            )

        return tuple(pivots[:5])
