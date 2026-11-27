"""Authenticated rule lifecycle operations with validation and atomic activation."""

from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from argusprowl.api.audit import AuditLog
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.rule_loader import RuleDefinition, RuleLoader
from argusprowl.detection.rule_revision_store import RuleRevisionStore
from argusprowl.exceptions.exceptions import DetectionError


class RuleLifecycleError(RuntimeError):
    """Base error for rule lifecycle operations."""


class RuleVersionConflict(RuleLifecycleError):
    """Raised when the caller's expected version is stale."""


class RuleLifecycleService:
    """Validate, version, audit, and atomically activate detector rule changes.

    Active YAML remains the startup source of truth. Every mutation validates a
    temporary candidate before persisting a revision or changing live state.
    """

    def __init__(
        self,
        *,
        rules_dir: str | Path,
        revision_store: RuleRevisionStore,
        detection_manager: DetectionManager,
        audit_log: AuditLog,
    ) -> None:
        self._rules_dir = Path(rules_dir)
        self._revision_store = revision_store
        self._manager = detection_manager
        self._audit_log = audit_log

    def history(self, rule_id: str, *, limit: int = 100) -> list[dict[str, object]]:
        return [
            {
                "rule_id": item.rule_id,
                "version": item.version,
                "content_sha256": item.content_sha256,
                "detector": item.detector,
                "enabled": item.enabled,
                "confidence_threshold": item.confidence_threshold,
                "parameters": item.parameters,
                "tactic": item.tactic,
                "technique": item.technique,
                "source_path": item.source_path,
                "actor": item.actor,
                "change_reason": item.change_reason,
                "created_at": item.created_at,
                "revision_id": item.revision_id,
                "rollback_from_version": item.rollback_from_version,
            }
            for item in self._revision_store.history(rule_id, limit=limit)
        ]

    def update(
        self,
        rule_id: str,
        *,
        expected_version: int,
        actor: str,
        change_reason: str,
        enabled: bool | None = None,
        confidence_threshold: float | None = None,
        parameters: dict[str, Any] | None = None,
        tactic: str | None = None,
        technique: str | None = None,
        request_id: str | None = None,
        client_ip: str | None = None,
    ) -> dict[str, object]:
        current = self._find_rule(rule_id)
        if current.version != expected_version:
            raise RuleVersionConflict(
                f"Expected rule version {expected_version}, current version is {current.version}."
            )
        candidate = replace(
            current,
            version=current.version + 1,
            enabled=current.enabled if enabled is None else enabled,
            confidence=current.confidence if confidence_threshold is None else confidence_threshold,
            parameters=current.parameters if parameters is None else parameters,
            tactic=current.tactic if tactic is None else tactic,
            technique=current.technique if technique is None else technique,
        )
        return self._commit_candidate(
            current,
            candidate,
            actor=actor,
            change_reason=change_reason,
            request_id=request_id,
            client_ip=client_ip,
        )

    def rollback(
        self,
        rule_id: str,
        *,
        target_version: int,
        expected_version: int,
        actor: str,
        change_reason: str,
        request_id: str | None = None,
        client_ip: str | None = None,
    ) -> dict[str, object]:
        current = self._find_rule(rule_id)
        if current.version != expected_version:
            raise RuleVersionConflict(
                f"Expected rule version {expected_version}, current version is {current.version}."
            )
        revisions = self._revision_store.history(rule_id, limit=1000)
        target = next((item for item in revisions if item.version == target_version), None)
        if target is None:
            raise DetectionError(
                "Requested rule revision does not exist.",
                details={"rule_id": rule_id, "version": target_version},
            )
        candidate = replace(
            current,
            version=current.version + 1,
            detector=target.detector,
            enabled=target.enabled,
            confidence=target.confidence_threshold,
            parameters=dict(target.parameters),
            tactic=target.tactic,
            technique=target.technique,
        )
        return self._commit_candidate(
            current,
            candidate,
            actor=actor,
            change_reason=change_reason,
            request_id=request_id,
            client_ip=client_ip,
            rollback_from_version=target_version,
        )

    def _find_rule(self, rule_id: str) -> RuleDefinition:
        if not rule_id or len(rule_id) > 128:
            raise ValueError("Invalid rule_id.")
        loader = RuleLoader(self._rules_dir)
        for rule in loader.load_rules():
            if rule.rule_id == rule_id:
                return rule
        raise KeyError(rule_id)

    def _commit_candidate(
        self,
        current: RuleDefinition,
        candidate: RuleDefinition,
        *,
        actor: str,
        change_reason: str,
        request_id: str | None,
        client_ip: str | None,
        rollback_from_version: int | None = None,
    ) -> dict[str, object]:
        target_path = current.path.resolve()
        if target_path.parent != self._rules_dir.resolve():
            raise DetectionError("Rule path is outside the configured rules directory.")

        try:
            payload = yaml.safe_load(target_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise DetectionError("Unable to read the active rule configuration.") from exc
        if not isinstance(payload, dict):
            raise DetectionError("Active rule configuration must be a YAML mapping.")
        payload.update(
            {
                "rule_id": candidate.rule_id,
                "detector": candidate.detector,
                "enabled": candidate.enabled,
                "confidence_threshold": candidate.confidence,
                "version": candidate.version,
                "parameters": candidate.parameters,
                "tactic": candidate.tactic,
                "technique": candidate.technique,
            }
        )
        serialized = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target_path.stem}.", suffix=".yaml", dir=target_path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())

            loader = RuleLoader(self._rules_dir)
            validated = loader.load_rule(temporary_path)
            validated = replace(validated, path=target_path)
            detector = loader.create_detector(validated)

            history = self._revision_store.history(candidate.rule_id, limit=1)
            if not history:
                if current.version != 1:
                    raise DetectionError(
                        "Existing rule history must be imported before changing a rule "
                        "whose active version is greater than 1."
                    )
                self._revision_store.record_revision(
                    current, actor="system", change_reason="Initial active-rule import"
                )

            revision = self._revision_store.record_revision(
                validated,
                actor=actor,
                change_reason=change_reason,
                rollback_from_version=rollback_from_version,
            )
            audit_request_id = request_id or str(uuid4())
            self._audit_log.append(
                event_type="RULE_REVISION_PREPARED",
                actor_id=actor,
                role="admin",
                method="PUT",
                path=f"/api/v1/rules/{candidate.rule_id}",
                status_code=202,
                request_id=audit_request_id,
                client_ip=client_ip,
            )

            original = target_path.read_bytes()
            try:
                os.replace(temporary_path, target_path)
                self._manager.get_registry().replace(candidate.rule_id, detector)
            except Exception:
                restore_descriptor, restore_name = tempfile.mkstemp(
                    prefix=f".{target_path.stem}.restore.", dir=target_path.parent
                )
                with os.fdopen(restore_descriptor, "wb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(restore_name, target_path)
                raise

            self._audit_log.append(
                event_type="RULE_REVISION_ACTIVATED",
                actor_id=actor,
                role="admin",
                method="PUT",
                path=f"/api/v1/rules/{candidate.rule_id}",
                status_code=200,
                request_id=revision.revision_id,
                client_ip=client_ip,
            )
            return {
                "rule_id": revision.rule_id,
                "version": revision.version,
                "content_sha256": revision.content_sha256,
                "revision_id": revision.revision_id,
                "enabled": revision.enabled,
                "activated": True,
                "rollback_from_version": revision.rollback_from_version,
            }
        finally:
            temporary_path.unlink(missing_ok=True)
