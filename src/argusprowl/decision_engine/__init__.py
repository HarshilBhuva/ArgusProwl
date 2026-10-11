"""Decision engine package.

Provides alert creation, deduplication, correlation, severity normalization,
and suppression logic for the threat detection pipeline.
"""

from argusprowl.decision_engine.decision_engine import DecisionEngine

__all__ = ["DecisionEngine"]
