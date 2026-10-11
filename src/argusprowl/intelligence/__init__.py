"""argusprowl Intelligence and Context layer module (Phase 4.6D).

Provides environmental prevalence tracking, threat intelligence lookup interfaces,
evidence fusion, and contextual intelligence orchestration.
"""

from argusprowl.intelligence.fusion import EvidenceFusionEngine
from argusprowl.intelligence.prevalence import EnvironmentPrevalenceTracker
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.intelligence.threat_intel import (
    InMemoryThreatIntelProvider,
    ThreatIntelProvider,
)

__all__ = [
    "ContextualIntelligenceService",
    "EnvironmentPrevalenceTracker",
    "EvidenceFusionEngine",
    "InMemoryThreatIntelProvider",
    "ThreatIntelProvider",
]
