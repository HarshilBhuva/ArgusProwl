"""Fail-closed object-level authorization for analyst-owned records."""

from __future__ import annotations

import hmac
import logging
from collections.abc import Iterable
from typing import Any

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


def _owner_subject(resource: Any) -> str | None:
    """Resolve an explicit owner from a domain object or its metadata.

    Unowned legacy records are deliberately not visible to non-admin
    principals once authentication is enabled.
    """
    assigned = getattr(resource, "assigned_analyst", None)
    if isinstance(assigned, str) and assigned.strip():
        return assigned.strip()

    metadata = getattr(resource, "metadata", None)
    if isinstance(resource, dict):
        metadata = resource.get("metadata", metadata)
    if isinstance(metadata, dict):
        for key in ("owner_subject", "assigned_analyst"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def can_access_object(request: Request, resource: Any) -> bool:
    """Return whether the authenticated principal may access this object."""
    if not getattr(request.app.state, "auth_enabled", False):
        return True

    principal = getattr(request.state, "principal", None)
    role = getattr(principal, "role", "anonymous")
    if role == "admin":
        return True
    if role not in {"analyst", "viewer"}:
        return False

    subject = getattr(principal, "subject", "")
    owner = _owner_subject(resource)
    return bool(
        isinstance(subject, str)
        and subject
        and owner
        and hmac.compare_digest(subject.encode("utf-8"), owner.encode("utf-8"))
    )


def require_object_access(
    request: Request,
    resource: Any,
    *,
    resource_type: str,
    resource_id: str,
) -> None:
    """Enforce owner/admin access and conceal inaccessible object existence."""
    if can_access_object(request, resource):
        return

    principal = getattr(request.state, "principal", None)
    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        try:
            audit_log.append(
                event_type="OBJECT_AUTHORIZATION_DENIED",
                actor_id=getattr(principal, "subject", "anonymous"),
                role=getattr(principal, "role", "anonymous"),
                method=request.method,
                path=request.url.path,
                status_code=404,
                request_id=getattr(request.state, "request_id", ""),
                client_ip=request.client.host if request.client else None,
            )
        except Exception:
            logger.exception("Failed to persist object-authorization denial audit event")

    raise HTTPException(status_code=404, detail=f"{resource_type} not found")


def filter_accessible(request: Request, resources: Iterable[Any]) -> list[Any]:
    """Filter a collection without disclosing inaccessible object counts."""
    return [resource for resource in resources if can_access_object(request, resource)]
