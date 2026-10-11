"""ATT&CK knowledge status enumeration.

Defines the four-state model for ATT&CK knowledge service availability.
"""

from enum import StrEnum


class AttckKnowledgeStatus(StrEnum):
    """Status of the ATT&CK knowledge layer.

    Semantics:
        AVAILABLE: Valid active snapshot is loaded and operational.
        EMPTY: No snapshot has ever been successfully installed.
        DEGRADED: Active snapshot is usable but the preferred/current
                  snapshot failed, so a previous known-good snapshot is
                  being used. Operator should be notified to update.
        UNAVAILABLE: ATT&CK was expected/required but no usable snapshot
                     can be loaded. Both current and previous snapshots
                     are corrupt or missing. Enrichment returns empty
                     observations.
    """

    AVAILABLE = "AVAILABLE"
    EMPTY = "EMPTY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
