"""Endpoint ↔ network correlation package.

Provides bounded in-memory correlation between process identity and
network observations for enrichment of detection results.
"""

from argusprowl.correlation.correlation_model import (
    CorrelatedActivity,
    NetworkDirection,
    NetworkObservation,
    ProcessIdentity,
)
from argusprowl.correlation.correlator import EndpointCorrelator

__all__ = [
    "CorrelatedActivity",
    "EndpointCorrelator",
    "NetworkDirection",
    "NetworkObservation",
    "ProcessIdentity",
]
