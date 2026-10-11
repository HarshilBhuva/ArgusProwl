"""Alert-only deduplication services.

Events are never passed to this package: every raw and normalized event
continues through ingestion and detection independently.
"""

from argusprowl.deduplication.cache import DeduplicationCache, InMemoryDeduplicationCache
from argusprowl.deduplication.engine import AlertDeduplicationEngine, DeduplicationResult
from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig
from argusprowl.deduplication.models import DeduplicationState

__all__ = [
    "AlertDeduplicationEngine",
    "AlertFingerprint",
    "DeduplicationCache",
    "DeduplicationResult",
    "DeduplicationState",
    "FingerprintConfig",
    "InMemoryDeduplicationCache",
]
