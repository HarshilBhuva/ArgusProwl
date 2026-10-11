"""Deterministic, versioned alert fingerprinting."""

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from argusprowl.models.alert import Alert


@dataclass(frozen=True, slots=True)
class FingerprintConfig:
    identity_fields: tuple[str, ...] = (
        "detector",
        "source",
        "src_ip",
        "dst_ip",
        "dst_port",
        "username",
    )
    version: int = 1

    def __post_init__(self) -> None:
        if self.version < 1 or not self.identity_fields:
            raise ValueError("fingerprint version and identity_fields must be positive/non-empty")


class AlertFingerprint:
    """SHA-256 fingerprint generator with explicitly selected identity fields."""

    def __init__(self, config: FingerprintConfig | None = None) -> None:
        self.config = config or FingerprintConfig()

    def create(self, alert: Alert) -> str:
        values = {
            field: self._normalize(self._value(alert, field))
            for field in self.config.identity_fields
        }
        payload = json.dumps(
            {"version": self.config.version, "identity": values},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return f"v{self.config.version}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"

    @staticmethod
    def _value(alert: Alert, field: str) -> Any:
        if field == "detector":
            return alert.metadata.get("detector", alert.metadata.get("rule_id", alert.source))
        if field == "source":
            return alert.source

        if field in alert.metadata:
            return alert.metadata[field]

        evidence = alert.metadata.get("evidence")
        if isinstance(evidence, dict):
            return evidence.get(field)
        elif isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, dict) and item.get("field") == field:
                    return item.get("observed")
        return None

    @staticmethod
    def _normalize(value: Any) -> Any:
        if isinstance(value, str):
            return " ".join(value.strip().lower().split())
        if isinstance(value, (list, tuple, set)):
            return [AlertFingerprint._normalize(item) for item in value]
        if isinstance(value, dict):
            return {
                str(key): AlertFingerprint._normalize(item) for key, item in sorted(value.items())
            }
        return value
