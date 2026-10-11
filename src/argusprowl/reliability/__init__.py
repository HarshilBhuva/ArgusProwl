"""Bounded ingestion reliability primitives.

These services sit between parsing and downstream processing.  They do not
deduplicate events; alert deduplication is deliberately a separate concern.
"""

from argusprowl.reliability.buffer import BoundedIngestionBuffer, OverflowPolicy

__all__ = [
    "BoundedIngestionBuffer",
    "OverflowPolicy",
]
