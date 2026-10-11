"""Contextual Intelligence Service for argusprowl (Phase 4.6D).

Orchestrates environmental prevalence tracking, threat intelligence lookups,
and evidence fusion into ContextualAssessments.
"""

from __future__ import annotations

from ipaddress import ip_address

from argusprowl.intelligence.fusion import EvidenceFusionEngine
from argusprowl.intelligence.prevalence import EnvironmentPrevalenceTracker
from argusprowl.intelligence.threat_intel import (
    InMemoryThreatIntelProvider,
    ThreatIntelProvider,
)
from argusprowl.models.context import (
    ContextualAssessment,
    EntityContext,
    PrevalenceResult,
    ThreatIntelReputation,
    ThreatIntelVerdict,
)
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class ContextualIntelligenceService:
    """Orchestrates context signals and evidence fusion for detection results.

    Provides a clean, dependency-injected orchestration layer between detection
    results, entity context extraction, prevalence tracking, threat intelligence,
    and evidence fusion.
    """

    def __init__(
        self,
        fusion_engine: EvidenceFusionEngine | None = None,
        prevalence_tracker: EnvironmentPrevalenceTracker | None = None,
        threat_intel_provider: ThreatIntelProvider | None = None,
    ) -> None:
        """Initialize ContextualIntelligenceService.

        Args:
            fusion_engine: Optional EvidenceFusionEngine instance.
            prevalence_tracker: Optional EnvironmentPrevalenceTracker instance.
            threat_intel_provider: Optional ThreatIntelProvider instance.
        """
        self.fusion_engine = fusion_engine or EvidenceFusionEngine()
        self.prevalence_tracker = prevalence_tracker or EnvironmentPrevalenceTracker()
        self.threat_intel_provider = threat_intel_provider or InMemoryThreatIntelProvider()

    def record_event(self, event: NormalizedEvent) -> None:
        """Record telemetry event into prevalence tracker.

        Args:
            event: The normalized event to record.
        """
        self.prevalence_tracker.record_event(event)

    def extract_entity_context(
        self,
        detection_result: DetectionResult,
        event: NormalizedEvent | None = None,
    ) -> EntityContext:
        """Extract EntityContext from normalized event and detection result evidence.

        Args:
            detection_result: DetectionResult containing evidence mappings.
            event: Optional NormalizedEvent source.

        Returns:
            An immutable EntityContext object.
        """
        host = event.hostname if event else None
        process_name = event.process_name if event else None
        pid = event.pid if event else None
        username = event.username if event else None
        src_ip = event.src_ip if event else None
        dst_ip = event.dst_ip if event else None
        dst_port = event.dst_port if event else None
        domain = None

        if event and isinstance(event.attributes, dict):
            dom_candidate = event.attributes.get("domain") or event.attributes.get("query")
            if isinstance(dom_candidate, str) and dom_candidate.strip():
                domain = dom_candidate.strip()

        # Extract missing fields from DetectionResult evidence mappings if needed
        for item in detection_result.evidence:
            if not isinstance(item, dict):
                continue
            field_name = item.get("field")
            obs = item.get("observed")

            if field_name == "hostname" and host is None and isinstance(obs, str):
                host = obs
            elif field_name == "process_name" and process_name is None and isinstance(obs, str):
                process_name = obs
            elif field_name == "process_id" and pid is None and isinstance(obs, int) and obs >= 0:
                pid = obs
            elif field_name == "username" and username is None and isinstance(obs, str):
                username = obs
            elif field_name == "destination" and dst_ip is None and isinstance(obs, str):
                try:
                    ip_address(obs)
                    dst_ip = obs
                except ValueError:
                    if domain is None:
                        domain = obs
            elif field_name == "destination_port" and dst_port is None and isinstance(obs, int):
                dst_port = obs
            elif field_name == "domain" and domain is None and isinstance(obs, str):
                domain = obs

        return EntityContext(
            host=host,
            process_name=process_name,
            pid=pid,
            username=username,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            domain=domain,
        )

    def evaluate(
        self,
        detection_result: DetectionResult,
        event: NormalizedEvent | None = None,
    ) -> ContextualAssessment:
        """Evaluate detection result with contextual signals into ContextualAssessment.

        Args:
            detection_result: The raw detection result to evaluate.
            event: Optional normalized event associated with the detection.

        Returns:
            A ContextualAssessment instance.
        """
        entity_ctx = self.extract_entity_context(detection_result, event)

        # Prevalence lookup — use the event timestamp so historical telemetry
        # is queried against the correct sliding-window position rather than
        # ``datetime.now()``, which would prune all past observations.
        prevalence_res: PrevalenceResult | None = None
        if entity_ctx.dst_ip or entity_ctx.domain:
            prevalence_res = self.prevalence_tracker.get_prevalence(
                dst_ip=entity_ctx.dst_ip,
                dst_port=entity_ctx.dst_port,
                domain=entity_ctx.domain,
                process_name=entity_ctx.process_name,
                timestamp=event.timestamp if event else None,
            )

        # Threat intelligence lookup
        reputation: ThreatIntelReputation | None = None
        if entity_ctx.domain:
            reputation = self.threat_intel_provider.lookup_domain(entity_ctx.domain)
            if (
                reputation is None or reputation.verdict == ThreatIntelVerdict.UNKNOWN
            ) and entity_ctx.dst_ip:
                ip_rep = self.threat_intel_provider.lookup_ip(entity_ctx.dst_ip)
                if ip_rep.verdict != ThreatIntelVerdict.UNKNOWN:
                    reputation = ip_rep
        elif entity_ctx.dst_ip:
            reputation = self.threat_intel_provider.lookup_ip(entity_ctx.dst_ip)

        return self.fusion_engine.fuse(
            detection_result=detection_result,
            entity_context=entity_ctx,
            prevalence=prevalence_res,
            reputation=reputation,
        )
