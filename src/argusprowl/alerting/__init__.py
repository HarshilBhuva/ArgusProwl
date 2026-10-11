"""Alerting package.

Provides alert delivery framework with pluggable providers for
dispatching security alerts to various destinations.
"""

from argusprowl.alerting.alert_manager import AlertManager

__all__ = ["AlertManager"]
