"""Canonical rule fingerprints shared by loading, revision storage, and detection."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID, uuid5

_RULE_REVISION_NAMESPACE = UUID("af1a4b3d-93b8-4e93-b6f1-24aaf1d57a5e")


def rule_snapshot(rule: Any) -> dict[str, object]:
    """Return the canonical runtime-relevant rule snapshot."""
    return {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "detector": rule.detector,
        "enabled": rule.enabled,
        "confidence_threshold": float(rule.confidence),
        "parameters": rule.parameters,
        "tactic": rule.tactic,
        "technique": rule.technique,
        "source_path": rule.path.as_posix(),
    }


def canonical_rule_json(rule: Any) -> str:
    """Serialize a rule snapshot deterministically and reject non-finite values."""
    return json.dumps(
        rule_snapshot(rule),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def rule_content_sha256(rule: Any) -> str:
    """Return the SHA-256 digest used by immutable rule revisions."""
    return hashlib.sha256(canonical_rule_json(rule).encode("utf-8")).hexdigest()


def rule_revision_id(rule_id: str, version: int) -> str:
    """Return the stable UUID for one rule identity and version."""
    return str(uuid5(_RULE_REVISION_NAMESPACE, f"{rule_id}:{version}"))
